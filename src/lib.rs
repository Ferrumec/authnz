//! # `authnz`
//!
//! Core library for the Authn/Authz service: session management, JWT,
//! passwordless / passkey flows, and authorization helpers.
//!
//! ## Layout
//!
//! - [`authn`] — authentication (sessions, JWT, passwordless, passkey).
//! - [`authz`] — authorization (roles / permissions).
//! - [`models`] — shared request-scoped identity types.
//! - [`proxy`] — upstream reverse-proxy identity assertion.
//!
//! The binary entry point (`main.rs`) supplies a concrete
//! [`CacheFactory`] (typically an in-process `moka` factory) and wires the
//! modules into an `actix-web` `HttpServer`.

pub mod authn;
pub mod authz;
pub mod models;
pub mod proxy;

pub use authn::{Module as AuthnModule, Session, SessionMiddleware, SessionRepo, SessionService};
pub use authz::Module as AuthzModule;
pub use models::User;
pub use proxy::{Proxy, proxy};

use actixutils::Store;
use actixutils::middleware::Principal;
use authn::SessionRepo as DomainSessionRepo;
use models::User as ActiveUser;
use std::error::Error;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use viewset::Repository;

/// Constructs the [`actixutils::Store`] caches used throughout the crate.
///
/// Implementations decide the concrete cache backend (the binary uses an
/// in-memory `moka` cache; tests may prefer a no-op or deterministic
/// implementation). `name` identifies the logical cache (e.g.
/// `"session_items"`) and `ttl` is the requested expiry for entries.
pub trait CacheFactory: Clone {
    /// Create a new cache named `name` with entries expiring after `ttl`.
    fn new_cache<K, V>(&self, name: &str, ttl: Duration) -> Arc<dyn Store<K, V>>
    where
        K: Hash + Eq + Clone + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static;
}

/// Adapts [`SessionRepo`] so [`SessionMiddleware`] can load / persist the
/// request-scoped [`User`] identity from the sessions table.
#[async_trait::async_trait]
impl Store<Uuid, ActiveUser> for DomainSessionRepo {
    async fn get(&self, id: &Uuid) -> Result<Option<ActiveUser>, Box<dyn Error>> {
        // Missing / deleted sessions must be `Ok(None)` so SessionMiddleware
        // can return 401 Unauthorized. Treating NotFound as an error made
        // logout and post-password-change access look like 500s instead.
        match self.retrieve(id).await {
            Ok(session) => Ok(Some(ActiveUser {
                sub: session.sub,
                email: session.email,
                username: session.username,
                role: session.role.as_u128(),
                expires_at: session.expires_at,
            })),
            Err(viewset::ApiError::NotFound) => Ok(None),
            Err(e) => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
    async fn set(&self, _id: &Uuid, _value: ActiveUser) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    async fn delete(&self, id: &Uuid) -> Result<(), Box<dyn Error>> {
        // Idempotent: deleting an already-gone session is fine.
        match Repository::delete(self, id).await {
            Ok(_) | Err(viewset::ApiError::NotFound) => Ok(()),
            Err(e) => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
}

impl Principal for ActiveUser {
    fn role(&self) -> u128 {
        self.role
    }
}
