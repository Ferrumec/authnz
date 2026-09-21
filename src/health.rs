//! Liveness/readiness endpoint.
//!
//! Exposed at `GET /health`, outside the session/permission middleware
//! stack so it never requires auth and never gets proxied upstream.
//! Checks Postgres reachability only — sessions live in the DB-backed
//! [`crate::SessionRepo`], so a dead DB means the service can't
//! authenticate anyone regardless of the in-memory cache state.

use actix_web::{HttpResponse, get, web};
use sqlx::PgPool;

#[get("/health")]
pub async fn health(pool: web::Data<PgPool>) -> HttpResponse {
    let db_ok = sqlx::query("SELECT 1").execute(pool.get_ref()).await.is_ok();

    if db_ok {
        HttpResponse::Ok().json(serde_json::json!({ "status": "ok", "db": db_ok }))
    } else {
        HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({ "status": "degraded", "db": db_ok }))
    }
}
