use crate::authn::{auth2::random_token, domain::user::UserService};
use moka::future::Cache;
use rand::Rng;
use serde::Serialize;
use std::time::Duration;
use typed_eventbus::Publishable;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum PasswdlessError {
    DbError,
    BadToken,
    UserNotFound,
}

impl From<sqlx::Error> for PasswdlessError {
    fn from(_value: sqlx::Error) -> Self {
        PasswdlessError::DbError
    }
}

pub struct Caches {
    links: Cache<String, FA2Entry>,
    tokens: Cache<String, FA2Entry>,
}

#[derive(Clone, PartialEq, Hash, Eq)]
struct FA2Entry {
    link: String,
    token: u32,
    email: Uuid,
    nonce: String,
}

impl Caches {
    pub fn new() -> Self {
        let tokens = Cache::builder()
            .time_to_live(Duration::from_secs(120))
            .build();
        let links = Cache::builder()
            .time_to_live(Duration::from_secs(120))
            .build();

        Self { tokens, links }
    }
}

pub struct PasswdlessService {
    pub auth_service: UserService,
    pub caches: Caches,
}

fn random_otp() -> u32 {
    let mut rng = rand::prelude::ThreadRng::default();
    rng.gen_range(100000..999999)
}

async fn release_pair(email: Uuid, caches: &Caches) -> ChallengeRequested {
    let link = random_token();
    let nonce = random_token();
    let token = random_otp();
    let fa2 = FA2Entry {
        link: link.clone(),
        token,
        email,
        nonce: nonce.clone(),
    };
    caches.tokens.insert(nonce.clone(), fa2.clone()).await;
    caches.links.insert(link.clone(), fa2.clone()).await;
    ChallengeRequested { token, link, nonce }
}

impl PasswdlessService {
    pub fn new(auth_service: UserService) -> Self {
        Self {
            auth_service,
            caches: Caches::new(),
        }
    }

    pub async fn confirm_link(&self, token: String) -> Result<Uuid, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let fa2 = match self.caches.links.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        };
        self.caches.tokens.remove(&fa2.nonce).await;
        Ok(fa2.email)
    }

    pub async fn confirm_token(&self, token: u32, nonce: String) -> Result<Uuid, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let fa2 = match self.caches.tokens.remove(&nonce).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => {
                if e.token != token {
                    return Err(PasswdlessError::BadToken);
                };
                e
            }
        };
        self.caches.links.remove(&fa2.link).await;
        Ok(fa2.email)
    }

    pub async fn challenge_by_email(
        &self,
        email: &str,
    ) -> Result<ChallengeRequested, PasswdlessError> {
        let user = match self.auth_service.get_user_by_email(email).await {
            Ok(r) => r,
            Err(_) => return Err(PasswdlessError::UserNotFound),
        };

        let payload = release_pair(user.id, &self.caches).await;

        Ok(payload)
    }
    pub async fn challenge_by_username(
        &self,
        email: &str,
    ) -> Result<ChallengeRequested, PasswdlessError> {
        let user = match self.auth_service.get_user_by_username(email).await {
            Ok(r) => r,
            Err(_) => return Err(PasswdlessError::UserNotFound),
        };

        let payload = release_pair(user.id, &self.caches).await;

        Ok(payload)
    }
}

#[derive(Serialize)]
pub struct ChallengeRequested {
    token: u32,
    link: String,
    nonce: String,
}

impl Publishable for ChallengeRequested {
    const SUBJECT: &'static str = "auth.2fa.challenge.requested";
}
