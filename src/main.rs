//! Binary entry point: wires up the database pool, an in-memory
//! (`moka`)-backed [`CacheFactory`], the authn/authz modules, and the
//! upstream proxy, then serves on `127.0.0.1:8080`.
//!
//! ## Required environment / files
//!
//! - `DATABASE_URL` — Postgres connection string (loaded via `.env` if
//!   present, through `dotenv`).
//! - `permissions.json` — permission set for protected routes.
//! - `signer.secret` / `signer.aud` — JWT HS256 configuration.
use actix_web::{App, HttpServer, web};
use actixutils::Store;
use actixutils::middleware::PermissionSet;
use authnz::{
    AuthnModule, AuthzModule, CacheFactory, Proxy, SessionMiddleware, SessionRepo, SessionService,
    proxy,
};
use dotenv::dotenv;
use moka::future::Cache;
use sqlx::PgPool;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// [`CacheFactory`] backed by in-process [`moka`] caches.
///
/// Note: `_name` and `_ttl` are currently ignored — every cache is created
/// with a fixed max capacity of 1000 entries and no expiry policy, so the
/// `Duration` values passed by callers have no effect yet under this
/// implementation. Entries are evicted only by the capacity-based (LRU-ish)
/// policy `moka` applies once the cache is full.
#[derive(Clone)]
struct MokaCacheFactory;

impl CacheFactory for MokaCacheFactory {
    fn new_cache<K: Hash + Clone + Eq + Send + Sync + 'static, V: Clone + Send + Sync + 'static>(
        &self,
        _name: &str,
        _ttl: Duration,
    ) -> Arc<dyn Store<K, V>> {
        let cache: Cache<K, V> = Cache::new(1000);
        Arc::new(cache)
    }
}

/// Loads configuration, connects to Postgres, and serves the authn/authz
/// HTTP app on `127.0.0.1:8080`. Panics on missing `DATABASE_URL`, a failed
/// DB connection, or a missing/invalid `permissions.json`.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cache_factory = MokaCacheFactory {};
    let cache = cache_factory.new_cache("session_items", Duration::from_mins(60));
    let db_url = std::env::var("DATABASE_URL").expect("var DATABASE_URL not provided");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("could not connect to db");
    let session_repo: SessionRepo = SessionRepo::new(pool.clone(), cache);
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
            pool.clone(),
            store.clone(),
            permissions.clone(),
            cache_factory.clone(),
        )
        .await,
    );
    let authorization = Arc::new(AuthzModule::new(pool, cache_factory));

    HttpServer::new(move || {
        // Create one awc client for this Actix worker.
        let client = Proxy::new();

        App::new()
            .app_data(web::Data::new(client))
            .app_data(session_service.clone())
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
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
