use crate::CacheFactory;
use crate::authn::domain::user::{UserService, token::generate_raw_token};
use crate::authn::passwdless::PasswdlessService;
use sqlx::Pool;
#[cfg(feature = "passkey")]
use std::time::Duration;

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
    pub async fn new<Cf: CacheFactory + 'static>(
        pool: Pool<sqlx::Postgres>,
        #[cfg_attr(not(feature = "passkey"), allow(unused_variables))] cache_factory: Cf,
    ) -> Self {
        let user_service = UserService::new(pool.clone());
        let passwdless_service = PasswdlessService::new(user_service.clone());

        Self {
            pool,
            passwdless_service,
            #[cfg(feature = "passkey")]
            passkey: {
                let reg_store = cache_factory.new_cache("passkey_reg", Duration::from_secs(300));
                let auth_store = cache_factory.new_cache("passkey_auth", Duration::from_secs(300));
                crate::authn::passkey::state::AppState::from_env(reg_store, auth_store)
            },
        }
    }
}

pub fn random_token() -> String {
    generate_raw_token()
}
