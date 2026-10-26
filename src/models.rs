use crate::authn::UserResponse;
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
    /// Accepts either a full `User` entity (credential lookups) or the
    /// `UserResponse` returned by repository reads.
    pub fn new(user: impl Into<UserResponse>) -> Self {
        let user = user.into();
        Self {
            username: user.username,
            email: user.email,
            sub: user.id,
            expires_at: Utc::now() + Duration::minutes(30),
        }
    }
}
