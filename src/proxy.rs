use crate::authz::Service;
use crate::models::User;
use actix_web::{Error, HttpRequest, HttpResponse, http::header, web};
use actixutils::Session;
use awc::Client;
const UPSTREAM: &str = "http://127.0.0.1:8081";

pub async fn proxy(
    client: web::Data<Client>,
    req: HttpRequest,
    body: web::Bytes,
    session: Session<User>,
    authz: web::Data<Service>,
) -> Result<HttpResponse, Error> {
    let user = session.read().await;
    let uri = req
        .uri()
        .path_and_query()
        .map(|x| x.as_str())
        .unwrap_or(req.uri().path());

    let perm = match authz.get_permission(uri.to_string()).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("error in getting permission: {e}");
            return Ok(HttpResponse::InternalServerError().finish());
        }
    };
    if let Some(p) = perm {
        if !(user.role & (1 << p.value) == (1 << p.value)) {
            return Ok(HttpResponse::Forbidden().finish());
        }
    }

    let url = format!("{UPSTREAM}{uri}");

    let mut upstream_req = client.request(req.method().clone(), url);

    for (name, value) in req.headers() {
        if name != header::HOST {
            upstream_req = upstream_req.insert_header((name.clone(), value.clone()));
        }
    }

    let mut upstream_res = upstream_req
        .insert_header(("X-User-Id", user.sub.to_string()))
        .insert_header(("X-User-Email", user.email.clone()))
        .insert_header(("X-User-Name", user.username.clone()))
        .send_body(body)
        .await
        .map_err(|e| actix_web::error::ErrorBadGateway(format!("Upstream request failed: {e}")))?;

    let status = upstream_res.status();

    let mut response = HttpResponse::build(status);

    for (name, value) in upstream_res.headers() {
        response.insert_header((name.clone(), value.clone()));
    }

    let body = upstream_res.body().await.map_err(|e| {
        actix_web::error::ErrorBadGateway(format!("Failed to read upstream response: {e}"))
    })?;

    Ok(response.body(body))
}
