use actixutils::Store;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, Url, Webauthn, WebauthnBuilder,
};

const CHALLENGE_TTL: Duration = Duration::from_secs(300);

/// Wrapper so we can store ceremony state with an issued-at timestamp for TTL.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TimedRegState {
    issued_at_secs: u64,
    state: PasskeyRegistration,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TimedAuthState {
    issued_at_secs: u64,
    state: PasskeyAuthentication,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct AppState {
    pub webauthn: Webauthn,
    reg_store: Arc<dyn Store<String, TimedRegState>>,
    auth_store: Arc<dyn Store<String, TimedAuthState>>,
}

impl AppState {
    pub fn new(
        webauthn: Webauthn,
        reg_store: Arc<dyn Store<String, TimedRegState>>,
        auth_store: Arc<dyn Store<String, TimedAuthState>>,
    ) -> Self {
        Self {
            webauthn,
            reg_store,
            auth_store,
        }
    }

    pub fn from_env(
        reg_store: Arc<dyn Store<String, TimedRegState>>,
        auth_store: Arc<dyn Store<String, TimedAuthState>>,
    ) -> Self {
        let rp_id = std::env::var("WEBAUTHN_RP_ID").expect("WEBAUTHN_RP_ID env var not set");
        let rp_origin_raw =
            std::env::var("WEBAUTHN_RP_ORIGIN").expect("WEBAUTHN_RP_ORIGIN env var not set");
        let rp_name = std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| rp_id.clone());

        let rp_origin = Url::parse(&rp_origin_raw).expect("WEBAUTHN_RP_ORIGIN is not a valid URL");

        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("invalid WebAuthn RP configuration (check WEBAUTHN_RP_ID / WEBAUTHN_RP_ORIGIN)")
            .rp_name(&rp_name)
            .build()
            .expect("failed to build WebAuthn instance");

        Self::new(webauthn, reg_store, auth_store)
    }

    pub async fn store_reg_state(&self, user_id: Uuid, state: PasskeyRegistration) {
        let timed = TimedRegState {
            issued_at_secs: now_secs(),
            state,
        };
        if let Err(e) = self.reg_store.set(&user_id.to_string(), timed).await {
            tracing::error!("failed to store passkey reg state: {e}");
        }
    }

    pub async fn take_reg_state(&self, user_id: &Uuid) -> Option<PasskeyRegistration> {
        let key = user_id.to_string();
        let timed = match self.reg_store.get(&key).await {
            Ok(v) => v?,
            Err(e) => {
                tracing::error!("failed to get passkey reg state: {e}");
                return None;
            }
        };
        let _ = self.reg_store.delete(&key).await;
        let age = now_secs().saturating_sub(timed.issued_at_secs);
        if age > CHALLENGE_TTL.as_secs() {
            return None;
        }
        Some(timed.state)
    }

    pub async fn store_auth_state(&self, username: String, state: PasskeyAuthentication) {
        let timed = TimedAuthState {
            issued_at_secs: now_secs(),
            state,
        };
        if let Err(e) = self.auth_store.set(&username, timed).await {
            tracing::error!("failed to store passkey auth state: {e}");
        }
    }

    pub async fn take_auth_state(&self, username: &str) -> Option<PasskeyAuthentication> {
        let timed = match self.auth_store.get(&username.to_string()).await {
            Ok(v) => v?,
            Err(e) => {
                tracing::error!("failed to get passkey auth state: {e}");
                return None;
            }
        };
        let _ = self.auth_store.delete(&username.to_string()).await;
        let age = now_secs().saturating_sub(timed.issued_at_secs);
        if age > CHALLENGE_TTL.as_secs() {
            return None;
        }
        Some(timed.state)
    }
}
