//! Cookie-based session authentication.
//!
//! Coexists with `AuthService`'s JWT flow rather than replacing it: browser
//! clients log in through here and get a `session_id` cookie value back;
//! API/service clients keep using `AuthService` and bearer JWTs. Both paths
//! validate credentials through the same `UserService`, so there is exactly
//! one place password checking happens.
//!
//! Session state lives in whatever `Store` is wired up (see
//! `session::store` — intended to be backed by actixutils' `CacheStore`,
//! i.e. the same Moka/Redis layer as the existing session middleware).
//! Sessions use sliding expiration: every successful `validate` call
//! extends the TTL.
use crate::authn::domain::user::errors::AuthError;
use crate::models::User;
use crate::{SessionRepo, authn::session::SessionParams};
use uuid::Uuid;
use viewset::{ApiError, Repository};
// ── SessionService ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SessionService {
    store: SessionRepo,
}

impl From<ApiError> for AuthError {
    fn from(value: ApiError) -> Self {
        match value {
            ApiError::Database(e) => AuthError::Database(e),
            ApiError::NotFound
            | ApiError::Validation(_)
            | ApiError::Forbidden
            | ApiError::Unauthorized
            | ApiError::Conflict(_)
            | ApiError::StaleVersion
            | ApiError::Internal(_) => AuthError::InvalidCredentials,
        }
    }
}

impl SessionService {
    pub fn new(store: SessionRepo) -> Self {
        Self { store }
    }

    pub async fn issue_session(
        &self,
        user: User,
        params: SessionParams,
    ) -> Result<Uuid, AuthError> {
        let mut session = self.store.create(&user).await?;
        session.ip_address = params.ip_address;
        self.store.update(&session.id, &session).await?;
        Ok(session.id)
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    /// Destroy a single session. Idempotent — logging out twice is fine.
    pub async fn logout(&self, session_id: &str) -> Result<(), AuthError> {
        let session_id = match Uuid::parse_str(session_id) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Error in parsing session uuid: {e}");
                return Err(AuthError::InvalidToken);
            }
        };
        if let Err(e) = self.store.delete(&session_id).await {
            tracing::error!("failed to delete session: {e}");
            return Err(AuthError::Cache);
        }
        Ok(())
    }
}
