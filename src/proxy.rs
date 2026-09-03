use crate::authn::session::Session;
use crate::models::User;
use actix_web::{Error, HttpRequest, HttpResponse, http::header, web};
use awc::Client;

/// Identity headers this proxy asserts on the authenticated user's behalf.
/// A client-supplied header of the same name must never reach upstream —
/// otherwise an unauthenticated or under-privileged caller could spoof
/// another user's identity by simply setting these on their request.
const TRUSTED_IDENTITY_HEADERS: [&str; 3] = ["x-user-id", "x-user-email", "x-user-name"];

pub struct Proxy {
    client: Client,
    upstream: String,
}

impl Proxy {
    pub fn new() -> Self {
        let client = Client::default();
        let upstream = std::env::var("UPSTREAM").expect("var UPSTREAM not set");
        Self { client, upstream }
    }

    pub async fn call(
        &self,
        req: HttpRequest,
        body: web::Bytes,
        session: Session<User>,
    ) -> Result<HttpResponse, Error> {
        let user = session.read().await;
        let uri = req
            .uri()
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or(req.uri().path());

        let url = format!("{0}{uri}", self.upstream);

        let mut upstream_req = self.client.request(req.method().clone(), url);

        for (name, value) in req.headers() {
            if name == header::HOST {
                continue;
            }
            // Strip any client-supplied copy of the headers we're about to
            // assert ourselves below — never forward an incoming
            // X-User-Id/-Email/-Name as-is.
            if TRUSTED_IDENTITY_HEADERS.contains(&name.as_str().to_ascii_lowercase().as_str()) {
                continue;
            }
            upstream_req = upstream_req.insert_header((name.clone(), value.clone()));
        }

        // Overwrite with the identity from the authenticated session —
        // the only source of truth for who the caller is.
        let mut upstream_res = upstream_req
            .insert_header(("X-User-Id", user.sub.to_string()))
            .insert_header(("X-User-Email", user.email.clone()))
            .insert_header(("X-User-Name", user.username.clone()))
            .send_body(body)
            .await
            .map_err(|e| {
                actix_web::error::ErrorBadGateway(format!("Upstream request failed: {e}"))
            })?;

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
}

pub async fn proxy(
    state: web::Data<Proxy>,
    req: HttpRequest,
    body: web::Bytes,
    session: Session<User>,
) -> Result<HttpResponse, Error> {
    state.call(req, body, session).await
}
