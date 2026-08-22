use crate::authn::domain::SessionService;
use crate::authn::domain::user::{UserService, token::generate_raw_token};
use crate::authn::passwdless::PasswdlessService;
use crate::models::User as ActiveUser;
use actixutils::Store;
use sqlx::Pool;
use std::sync::Arc;
use uuid::Uuid;

pub struct AppState {
    pub pool: Pool<sqlx::Postgres>,
    pub passwdless_service: PasswdlessService,
    pub session_service: SessionService,
    pub session_store: Arc<dyn Store<Uuid, ActiveUser>>,
    /// WebAuthn config + in-flight ceremony state for the passkey module.
    /// Built from `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN` (see
    /// `passkey::state::AppState::from_env`).
    #[cfg(feature = "passkey")]
    pub passkey: crate::authn::passkey::state::AppState,
}

impl AppState {
    pub async fn new(
        pool: Pool<sqlx::Postgres>,
        session_store: Arc<dyn Store<Uuid, ActiveUser>>,
    ) -> Self {
        let user_service = UserService::new(pool.clone());
        let session_service = SessionService::new(session_store.clone());
        let passwdless_service = PasswdlessService::new(user_service.clone());

        Self {
            pool,
            passwdless_service,
            session_service,
            session_store,
            #[cfg(feature = "passkey")]
            passkey: crate::authn::passkey::state::AppState::from_env(),
        }
    }
}

pub fn random_token() -> String {
    generate_raw_token()
}
