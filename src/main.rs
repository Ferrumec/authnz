mod authn;
mod authz;
mod models;
mod proxy;
use crate::authn::{Session, SessionRepo};
use actix_web::{App, HttpServer, web};
use actixutils::Store;
use actixutils::middleware::SessionMiddleware;
use authn::Module as AuthnModule;
use authz::Module as AuthzModule;
use awc::Client;
use models::User;
use proxy::proxy;
use sqlx::PgPool;
use std::error::Error;
use std::sync::Arc;
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
    async fn set(&self, _id: &Uuid, value: User) -> Result<(), Box<dyn Error>> {
        self.create(&value).await?;
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cache: Arc<dyn Store<Uuid, Session>> = Arc::new(DefaultCache::new(1000));
    let db_url = std::env::var("DATABASE_URL").expect("var DATABASE_URL not provided");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("could not connect to db");
    let session_repo: SessionRepo = SessionRepo::new(pool.clone(), cache.clone());
    let store = Arc::new(session_repo);
    let authentication = Arc::new(AuthnModule::new(pool.clone(), store.clone()).await);
    let authorization = Arc::new(AuthzModule::new(pool));

    HttpServer::new(move || {
        // Create one awc client for this Actix worker.
        let client = Client::default();

        App::new()
            .app_data(web::Data::new(client))
            .configure(|cfg| authentication.clone().config(cfg, "authn"))
            .service(
                web::scope("")
                    .wrap(SessionMiddleware::required(store.clone()))
                    .configure(|cfg| authorization.clone().config(cfg, "authz"))
                    .default_service(web::route().to(proxy)),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
