use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, Url, Webauthn, WebauthnBuilder,
};

const CHALLENGE_TTL: Duration = Duration::from_secs(300);

pub struct AppState {
    pub webauthn: Webauthn,
    reg_states: Mutex<HashMap<Uuid, (Instant, PasskeyRegistration)>>,
    auth_states: Mutex<HashMap<String, (Instant, PasskeyAuthentication)>>,
}

impl AppState {
    pub fn new(webauthn: Webauthn) -> Self {
        Self {
            webauthn,
            reg_states: Mutex::new(HashMap::new()),
            auth_states: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_env() -> Self {
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

        Self::new(webauthn)
    }

    pub fn store_reg_state(&self, user_id: Uuid, state: PasskeyRegistration) {
        let mut guard = self.reg_states.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, (t, _)| t.elapsed() < CHALLENGE_TTL);
        guard.insert(user_id, (Instant::now(), state));
    }

    pub fn take_reg_state(&self, user_id: &Uuid) -> Option<PasskeyRegistration> {
        let mut guard = self.reg_states.lock().unwrap_or_else(|e| e.into_inner());
        match guard.remove(user_id) {
            Some((t, s)) if t.elapsed() < CHALLENGE_TTL => Some(s),
            _ => None,
        }
    }

    pub fn store_auth_state(&self, username: String, state: PasskeyAuthentication) {
        let mut guard = self.auth_states.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, (t, _)| t.elapsed() < CHALLENGE_TTL);
        guard.insert(username, (Instant::now(), state));
    }

    pub fn take_auth_state(&self, username: &str) -> Option<PasskeyAuthentication> {
        let mut guard = self.auth_states.lock().unwrap_or_else(|e| e.into_inner());
        match guard.remove(username) {
            Some((t, s)) if t.elapsed() < CHALLENGE_TTL => Some(s),
            _ => None,
        }
    }
}
