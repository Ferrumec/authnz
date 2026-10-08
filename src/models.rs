use crate::authn::User as CoreUser;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct User {
    pub sub: Uuid,
    pub username: String,
    pub email: String,
    pub expires_at: DateTime<Utc>,
}

impl User {
    pub fn new(user: CoreUser) -> Self {
        Self {
            username: user.username,
            email: user.email,
            sub: user.id,
            expires_at: Utc::now() + Duration::minutes(30),
        }
    }
}
