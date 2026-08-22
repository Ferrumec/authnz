use crate::authn::{auth2::random_token, domain::user::UserService};
use moka::future::Cache;
use rand::random;
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
    tokens: Cache<u32, FA2Entry>,
}

#[derive(Clone, PartialEq, Hash, Eq)]
struct FA2Entry {
    link: String,
    token: u32,
    email: Uuid,
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

fn random_int(minimum: u32) -> u32 {
    let mut number = 1;
    while number < minimum {
        number *= random::<u32>();
    }
    number
}

async fn release_pair(email: Uuid, caches: &Caches) -> (u32, String) {
    let link = random_token();
    let token = random_int(100000);
    let fa2 = FA2Entry {
        link: link.clone(),
        token,
        email,
    };
    caches.tokens.insert(token, fa2.clone()).await;
    (token, link)
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
        self.caches.tokens.remove(&fa2.token).await;
        Ok(fa2.email)
    }

    pub async fn confirm_token(&self, token: u32) -> Result<Uuid, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let fa2 = match self.caches.tokens.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        };
        self.caches.links.remove(&fa2.link).await;
        Ok(fa2.email)
    }

    pub async fn challenge_by_email(
        &self,
        email: &String,
    ) -> Result<ChallengeRequested, PasswdlessError> {
        let user = match self.auth_service.get_user_by_email(email).await {
            Ok(r) => r,
            Err(_) => return Err(PasswdlessError::UserNotFound),
        };

        let (token, link) = release_pair(user.id, &self.caches).await;
        let payload = ChallengeRequested { token, link };

        Ok(payload)
    }
    pub async fn challenge_by_username(
        &self,
        email: &String,
    ) -> Result<ChallengeRequested, PasswdlessError> {
        let user = match self.auth_service.get_user_by_username(email).await {
            Ok(r) => r,
            Err(_) => return Err(PasswdlessError::UserNotFound),
        };

        let (token, link) = release_pair(user.id, &self.caches).await;
        let payload = ChallengeRequested { token, link };

        Ok(payload)
    }
}

#[derive(Serialize)]
pub(super) struct ChallengeRequested {
    token: u32,
    link: String,
}

impl Publishable for ChallengeRequested {
    const SUBJECT: &'static str = "auth.2fa.challenge.requested";
}
