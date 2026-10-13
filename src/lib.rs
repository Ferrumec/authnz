//! # `authnz`
//!
//! Core library for the Authn/Authz service: session management, JWT,
//! passwordless / passkey flows, and authorization helpers.
//!
//! ## Layout
//!
//! - [`authn`] — authentication (sessions, JWT, passwordless, passkey).
//! - [`authz`] — authorization (roles / permissions).
//! - [`models`] — shared request-scoped identity types.
//! - [`proxy`] — upstream reverse-proxy identity assertion.
//!
//! The binary entry point (`main.rs`) supplies a concrete
//! [`ferrumec::cache::CacheFactory`] (the `redis::aio::ConnectionManager`
//! from `infra::Infrastructure`) and wires the modules into an `actix-web`
//! `HttpServer`.

pub mod authn;
pub mod models;

pub use authn::{Module as AuthnModule, Session, SessionMiddleware, SessionRepo, SessionService};
pub use models::User;
