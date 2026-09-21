//! Binary entry point: wires up the database pool, an in-memory
//! (`moka`)-backed [`CacheFactory`], the authn/authz modules, and the
//! upstream proxy, then serves on `BIND_ADDR` (default `127.0.0.1:8080`).
//!
//! ## Required environment / files
//!
//! - `DATABASE_URL` — Postgres connection string (loaded via `.env` if
//!   present, through `dotenv`).
//! - `BIND_ADDR` — optional; defaults to `127.0.0.1:8080`. The Docker
//!   image sets this to `0.0.0.0:8080` so the port is reachable from
//!   outside the container.
//! - `permissions.json` — permission set for protected routes.
//! - `signer.secret` / `signer.aud` — JWT HS256 configuration.
//! - `GET /health` — unauthenticated liveness/readiness probe (checks DB
//!   connectivity), used by the Docker `HEALTHCHECK`.
use actix_web::{App, HttpServer, web};
use actixutils::middleware::PermissionSet;
use authnz::{
    AuthnModule, AuthzModule, Proxy, SessionMiddleware, SessionRepo, SessionService,
    proxy,
};
use actixutils::locals::CacheFactory;
use dotenv::dotenv;
use std::sync::Arc;
use std::time::Duration;
use infra::Infrastructure;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};


/// Loads configuration, connects to Postgres, and serves the authn/authz
/// HTTP app on `BIND_ADDR` (default `127.0.0.1:8080`). Panics on missing
/// `DATABASE_URL`, a failed DB connection, or a missing/invalid
/// `permissions.json`.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    
    

    let infra = Infrastructure::from_env().await.expect("could not connect to infrastructures");
    let cache_factory = infra.redis.clone();
    let cache = cache_factory.new_cache("session_items",Duration::from_mins(30));
    let session_repo: SessionRepo = SessionRepo::new(infra.postgres.clone(), cache);
    let session_service = web::Data::new(SessionService::new(session_repo.clone()));
    let store = Arc::new(session_repo);

    let permissions = match PermissionSet::from_file("permissions.json") {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("failed to load permission set: {e}");
            panic!()
        }
    };

    let authentication = Arc::new(
        AuthnModule::new(
            infra.postgres.clone(),
            store.clone(),
            permissions.clone(),
            cache_factory.clone(),
        )
        .await,
    );
    let health_pool = web::Data::new(infra.postgres.clone());
    let authorization = Arc::new(AuthzModule::new(infra.postgres.clone(), cache_factory));

    HttpServer::new(move || {
        // Create one awc client for this Actix worker.
        let client = Proxy::new();

        App::new()
            .app_data(web::Data::new(client))
            .app_data(session_service.clone())
            .app_data(health_pool.clone())
            // Unauthenticated liveness/readiness probe — must stay outside
            // the SessionMiddleware scope below so it never needs a
            // session and is never handed off to the upstream proxy.
            .service(authnz::health::health)
            .configure(|cfg| authentication.clone().config(cfg, "authn"))
            // SessionMiddleware is required for /authz/* (claim, grant, deny)
            // and for the upstream proxy identity assertion.
            // Permissions is applied only to the routes that declare bits in
            // permissions.json — claim_admin is intentionally reachable by any
            // authenticated user so it can return 404/406 when the caller's id
            // does not match ADMIN.
            .service(
                web::scope("")
                    .wrap(SessionMiddleware::new(store.clone()))
                    .configure(|cfg| {
                        authorization.clone().config_with_permissions(
                            cfg,
                            "authz",
                            permissions.clone(),
                        )
                    })
                    .default_service(web::route().to(proxy)),
            )
    })
    .bind(std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into()))?
    .run()
    .await
}
