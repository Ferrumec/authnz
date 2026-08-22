mod authn;
mod authz;
mod models;
mod proxy;

use actix_web::{App, HttpServer, web};
use awc::Client;
use proxy::proxy;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Create one awc client for this Actix worker.
        let client = Client::default();

        App::new()
            .app_data(web::Data::new(client))
            .default_service(web::route().to(proxy))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
