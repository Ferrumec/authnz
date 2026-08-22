mod authn;
mod authz;
mod models;
mod proxy;
use actix_web::{App, HttpServer, web};
use actixutils::middleware::SessionMiddleware;
use authn::Module as AuthnModule;
use authz::Module as AuthzModule;
use awc::Client;
use models::User;
use proxy::proxy;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use viewset::DefaultCache;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let store = Arc::new(DefaultCache::new(1000));
    let session_store = Arc::new(DefaultCache::<Uuid, User>::new(1000));
    let db_url = std::env::var("DATABASE_URL").expect("var DATABASE_URL not provided");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("could not connect to db");
    let authentication = Arc::new(AuthnModule::new(pool.clone(), store).await);
    let authorization = Arc::new(AuthzModule::new(pool));

    HttpServer::new(move || {
        // Create one awc client for this Actix worker.
        let client = Client::default();

        App::new()
            .app_data(web::Data::new(client))
            .configure(|cfg| authentication.clone().config(cfg, "authn"))
            .configure(|cfg| authorization.clone().config(cfg, "authz"))
            .service(
                web::scope("")
                    .wrap(SessionMiddleware::required(session_store.clone()))
                    .default_service(web::route().to(proxy)),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
