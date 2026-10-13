mod auth2;
mod config;
mod domain;
mod handlers;
mod models;
#[cfg(feature = "passkey")]
mod passkey;
mod passwdless;
pub mod session;
mod user_id;
pub use config::AuthModule as Module;
mod admin;
pub use admin::{Session, SessionRepo, User};
pub use domain::SessionService;
pub use viewset::web::{Identity, SessionMiddleware};
