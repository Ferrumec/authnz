use crate::authn::domain::user::{UserService, token::generate_raw_token};
use crate::authn::passwdless::PasswdlessService;
use sqlx::Pool;

pub struct AppState {
    pub pool: Pool<sqlx::Postgres>,
    pub passwdless_service: PasswdlessService,
    /// WebAuthn config + in-flight ceremony state for the passkey module.
    /// Built from `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN` (see
    /// `passkey::state::AppState::from_env`).
    #[cfg(feature = "passkey")]
    pub passkey: crate::authn::passkey::state::AppState,
}

impl AppState {
    pub async fn new(pool: Pool<sqlx::Postgres>) -> Self {
        let user_service = UserService::new(pool.clone());
        let passwdless_service = PasswdlessService::new(user_service.clone());

        Self {
            pool,
            passwdless_service,
            #[cfg(feature = "passkey")]
            passkey: {
                let reg_store = Arc::new(DefaultCache::new(1000));
                let auth_store = Arc::new(DefaultCache::new(1000));
                crate::authn::passkey::state::AppState::from_env(reg_store, auth_store)
            },
        }
    }
}

pub fn random_token() -> String {
    generate_raw_token()
}
