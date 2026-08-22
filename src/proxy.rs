use actix_web::{Error, HttpRequest, HttpResponse, http::header, web};
use awc::Client;

const UPSTREAM: &str = "http://127.0.0.1:8081";

pub async fn proxy(
    client: web::Data<Client>,
    req: HttpRequest,
    body: web::Bytes,
) -> Result<HttpResponse, Error> {
    let uri = req
        .uri()
        .path_and_query()
        .map(|x| x.as_str())
        .unwrap_or(req.uri().path());

    let url = format!("{UPSTREAM}{uri}");

    let mut upstream_req = client.request(req.method().clone(), url);

    for (name, value) in req.headers() {
        if name != header::HOST {
            upstream_req = upstream_req.insert_header((name.clone(), value.clone()));
        }
    }

    let mut upstream_res = upstream_req
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
