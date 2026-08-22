use uuid::Uuid;

pub struct User {
    pub sub: Uuid,
    pub username: String,
    pub email: String,
    pub role: u128,
}
