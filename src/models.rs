use crate::authn::User as CoreUser;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct User {
    pub sub: Uuid,
    pub username: String,
    pub email: String,
    pub role: u128,
}

impl User {
    pub fn new(user: CoreUser, role: u128) -> Self {
        Self {
            role,
            username: user.username,
            email: user.email,
            sub: user.id,
        }
    }
}
