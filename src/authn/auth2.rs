use crate::authn::domain::SessionService;
use crate::authn::domain::auth::service::AuthService;
use crate::authn::domain::user::ActiveUser;
use crate::authn::domain::user::{UserService, token::generate_raw_token};
use crate::authn::passwdless::PasswdlessService;
use actixutils::{Identity, Provider};
use actixutils::{Sign, Store, Validate};
use serde::Deserialize;
use sqlx::{Pool, Postgres, query};
use std::sync::Arc;
use typed_eventbus::{Event, EventStream, Subscribable, Subscriber};
use uuid::Uuid;

pub struct AppState {
    pub pool: Pool<sqlx::Postgres>,
    pub validator: Arc<dyn Validate<Identity>>,
    pub passwdless_service: PasswdlessService,
    pub auth_service: AuthService,
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
        signer: Arc<dyn Sign<Identity>>,
        validator: Arc<dyn Validate<Identity>>,
        es: Arc<dyn EventStream>,
        session_store: Arc<dyn Store<Uuid, ActiveUser>>,
    ) -> Self {
        let auth_service = AuthService::new(pool.clone(), signer.clone());
        let user_service = UserService::new(pool.clone(), es.clone());
        let session_service = SessionService::new(session_store.clone());
        let passwdless_service = PasswdlessService::new(user_service.clone());
        subscribe(es.clone(), pool.clone()).await;
        Self {
            pool,
            validator,
            passwdless_service,
            auth_service,
            session_service,
            session_store,
            #[cfg(feature = "passkey")]
            passkey: crate::authn::passkey::state::AppState::from_env(),
        }
    }
}

impl Provider<Arc<dyn Validate<Identity>>> for AppState {
    fn provide(&self) -> Arc<dyn Validate<Identity>> {
        self.validator.clone()
    }
}

pub fn random_token() -> String {
    generate_raw_token()
}

#[derive(Deserialize)]
struct ChannelConfirmed {
    user: Uuid,
    address: String,
    channel: String,
}

struct OnChannelConfirmed {
    db: Pool<Postgres>,
}

#[async_trait::async_trait]
impl Subscriber<ChannelConfirmed> for OnChannelConfirmed {
    async fn on_message(&self, event: Event<ChannelConfirmed>, _subject: &str) {
        // this is to ensure that email, or any other primary contact info, can only be confirme through a specific channel
        // set to console for development purposes only,
        // TODO please change to a better channel in production
        if event.payload.channel != "console".to_string() {
            return;
        }
        if let Err(e) = query!(
            "UPDATE users SET email = $1 WHERE id = $2",
            event.payload.address,
            event.payload.user.to_string(),
        )
        .execute(&self.db)
        .await
        {
            tracing::warn!("error in saving contact info: {e}");
        };
    }
}

impl Subscribable for ChannelConfirmed {
    const SUBJECT: &'static str = "contact.channel.confirmed";
}

async fn subscribe(es: Arc<dyn EventStream>, db: Pool<Postgres>) {
    let subscriber = OnChannelConfirmed { db };
    if let Err(e) = subscriber.subscribe(es.clone()).await {
        tracing::error!(
            "Error in subscribing to contact.channel.confirmed: {e} . This is critical!"
        );
    };
}
