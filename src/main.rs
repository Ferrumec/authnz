mod authn;
mod authz;
mod models;
mod proxy;
use crate::authn::{Session, SessionRepo, SessionService};
use actix_web::{App, HttpServer, web};
use actixutils::Store;
use actixutils::middleware::{PermissionSet, Permissions, Principal, SessionMiddleware};
use authn::Module as AuthnModule;
use authz::Module as AuthzModule;
use awc::Client;
use models::User;
use proxy::proxy;
use sqlx::PgPool;
use std::error::Error;
use std::sync::Arc;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use uuid::Uuid;
use viewset::DefaultCache;
use viewset::Repository;

#[async_trait::async_trait]
impl Store<Uuid, User> for SessionRepo {
    async fn get(&self, id: &Uuid) -> Result<Option<User>, Box<dyn Error>> {
        let session = self.retrieve(id).await?;
        Ok(Some(User {
            sub: session.sub,
            email: session.email,
            username: session.username,
            role: session.role.parse().unwrap(),
        }))
    }
    async fn set(&self, _id: &Uuid, _value: User) -> Result<(), Box<dyn Error>> {
        // This session store is meant to be used session middleware
        // which we don't expect to be minting sessions
        //self.create(&value).await?;
        Ok(())
    }
    async fn delete(&self, id: &Uuid) -> Result<(), Box<dyn Error>> {
        Repository::delete(self, id).await?;
        Ok(())
    }
    async fn clear(&self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

impl Principal for User {
    fn role(&self) -> u128 {
        self.role
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cache: Arc<dyn Store<Uuid, Session>> = Arc::new(DefaultCache::new(1000));
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
        let client = Client::default();

        App::new()
            .app_data(web::Data::new(client))
            .app_data(session_service.clone())
            .configure(|cfg| authentication.clone().config(cfg, "authn"))
            .service(
                web::scope("")
                    .wrap(Permissions::<User>::new(permissions.clone()))
                    .wrap(SessionMiddleware::required(store.clone()))
                    .configure(|cfg| authorization.clone().config(cfg, "authz"))
                    .default_service(web::route().to(proxy)),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
