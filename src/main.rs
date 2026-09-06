mod authn;
mod authz;
mod models;
mod proxy;

use crate::authn::SessionMiddleware;
use crate::authn::{Session, SessionRepo, SessionService};
use actix_web::{App, HttpServer, web};
use actixutils::middleware::PermissionSet;
use actixutils::Store;
use actixutils::middleware::Principal;
use authn::Module as AuthnModule;
use authz::Module as AuthzModule;
use dotenv::dotenv;
use models::User;
use moka::future::Cache;
use proxy::{Proxy, proxy};
use sqlx::PgPool;
use std::error::Error;
use std::sync::Arc;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use uuid::Uuid;
use viewset::Repository;

#[async_trait::async_trait]
impl Store<Uuid, User> for SessionRepo {
    async fn get(&self, id: &Uuid) -> Result<Option<User>, Box<dyn Error>> {
        // Missing / deleted sessions must be `Ok(None)` so SessionMiddleware
        // can return 401 Unauthorized. Treating NotFound as an error made
        // logout and post-password-change access look like 500s instead.
        match self.retrieve(id).await {
            Ok(session) => Ok(Some(User {
                sub: session.sub,
                email: session.email,
                username: session.username,
                role: session.role.as_u128(),
                expires_at: session.expires_at,
            })),
            Err(viewset::ApiError::NotFound) => Ok(None),
            Err(e) => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
    async fn set(&self, _id: &Uuid, _value: User) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    async fn delete(&self, id: &Uuid) -> Result<(), Box<dyn Error>> {
        // Idempotent: deleting an already-gone session is fine.
        match Repository::delete(self, id).await {
            Ok(_) | Err(viewset::ApiError::NotFound) => Ok(()),
            Err(e) => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
}

impl Principal for User {
    fn role(&self) -> u128 {
        self.role
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cache: Arc<dyn Store<Uuid, Session>> = Arc::new(Cache::new(1000));
    let db_url = std::env::var("DATABASE_URL").expect("var DATABASE_URL not provided");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("could not connect to db");
    let session_repo: SessionRepo = SessionRepo::new(pool.clone(), cache.clone());
    let session_service = web::Data::new(SessionService::new(session_repo.clone()));
    let store = Arc::new(session_repo);

    let permissions = match PermissionSet::from_file("permissions.json") {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("failed to load permission set: {e}");
            panic!()
        }
    };

    let authentication =
        Arc::new(AuthnModule::new(pool.clone(), store.clone(), permissions.clone()).await);
    let authorization = Arc::new(AuthzModule::new(pool));

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
                        authorization
                            .clone()
                            .config_with_permissions(cfg, "authz", permissions.clone())
                    })
                    .default_service(web::route().to(proxy)),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
