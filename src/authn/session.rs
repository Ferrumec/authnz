//! Cookie-based session data handle.
//!
//! [`Session<T>`] is the extractor handlers use to read and mutate the
//! current request's session value once
//! [`SessionMiddleware`](crate::middleware::SessionMiddleware) has populated
//! it into the request extensions.

use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, dev::Payload, error};
use std::{
    future::{Ready, ready},
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::RwLock;

type SharedSession<T> = Arc<RwLock<T>>;

/// A handle to the current request's session data, obtained via
/// [`FromRequest`] once [`SessionMiddleware`] has populated the request extensions.
///
/// Cloning is cheap (it clones the underlying `Arc`s and shares the same data).
/// Call [`read`](Self::read) for a read-only view or [`write`](Self::write) to mutate
/// the session; any call to `write` marks the session dirty so
/// [`SessionMiddleware`] persists it via the store after the handler returns.
pub struct Session<T> {
    data: SharedSession<T>,
    pub(crate) dirty: Arc<AtomicBool>,
}

impl<T> Clone for Session<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            dirty: self.dirty.clone(),
        }
    }
}

impl<T> Session<T> {
    /// Wrap a session value fresh from the store (or a default), starting
    /// out clean.
    pub(crate) fn new(session: T) -> Self {
        Self {
            data: Arc::new(RwLock::new(session)),
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }
    /// Acquire a read lock and view the current session value.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, T> {
        self.data.read().await
    }
    /// Acquire a write lock to mutate the session value.
    ///
    /// Marks the session dirty (regardless of whether the guard is actually used to
    /// change anything), so [`SessionMiddleware`] will persist it via the store once
    /// the handler finishes.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, T> {
        self.dirty.store(true, Ordering::Relaxed);
        self.data.write().await
    }
    /// Returns `true` if the session has been written to since it was last
    /// persisted (or since it was created).
    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Relaxed)
    }
    /// Clear the dirty flag after persisting the session.
    pub(crate) fn set_clean(&self) {
        self.dirty.store(false, Ordering::Relaxed);
    }
}

impl<T: Send + Sync + 'static> FromRequest for Session<T> {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        match req.extensions().get::<Arc<Session<T>>>() {
            Some(session) => ready(Ok((**session).clone())),
            None => {
                tracing::error!("No session in request. Did you forget to wrap SessionMiddleware?");
                ready(Err(error::ErrorInternalServerError(
                    "Session requested without SessionMiddleware",
                )))
            }
        }
    }
}

pub struct SessionParams {
    pub ip_address: IpAddr,
    pub user_agent: String,
}

impl FromRequest for SessionParams {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let ip_address = req
            .peer_addr()
            .map(|a| a.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        ready(Ok(Self {
            ip_address,
            user_agent,
        }))
    }
}
