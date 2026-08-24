use std::env;

use crate::authz::{
    models::{AppState, PermissionReq},
    services::AdminError,
};
use crate::models::User;
use actix_web::{HttpResponse, Responder, get, post, web};
use actixutils::Session;
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

#[derive(Serialize)]
struct PermissionView {
    name: String,
}

#[derive(Serialize)]
struct PermView {
    name: String,
    value: i64,
}

/// Common handling for the Forbidden/Sqlx split every admin endpoint hits.
fn admin_error_response(e: AdminError) -> HttpResponse {
    match e {
        AdminError::Forbidden => HttpResponse::Forbidden().json(json!({
            "success": false,
            "error": "not authorized as admin for this namespace"
        })),
        AdminError::Sqlx(e) => {
            tracing::error!("Error in admin operation: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/list_permissions")]
pub async fn list_permissions(session: Session<User>, state: web::Data<AppState>) -> HttpResponse {
    let claims = session.read().await;
    match state.service.list_permissions(claims.sub).await {
        Ok(perms) => {
            let permissions: Vec<PermissionView> = perms
                .into_iter()
                .map(|perm| PermissionView { name: perm.name })
                .collect();
            HttpResponse::Ok().json(json!({
                "success": true,
                "permissions": permissions
            }))
        }
        Err(e) => {
            tracing::error!("Error in listing permissions: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/admin/grant")]
pub async fn admin_grant_permission(
    sess: Session<User>,
    state: web::Data<AppState>,
    body: web::Json<PermissionReq>,
) -> HttpResponse {
    let claims = sess.read().await;
    let required_perm: u128 = 1 << 127;
    if !(claims.role & required_perm == required_perm) {
        return HttpResponse::Forbidden().finish();
    }
    match state
        .service
        .admin_grant_permission(body.into_inner())
        .await
    {
        Ok(Some(r)) => HttpResponse::Ok().json(json!({
            "success": true,
            "new_role": r
        })),
        Ok(None) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "invalid operation"
        })),
        Err(e) => admin_error_response(e),
    }
}

#[post("/admin/deny")]
pub async fn admin_deny_permission(
    sess: Session<User>,
    state: web::Data<AppState>,
    body: web::Json<PermissionReq>,
) -> HttpResponse {
    let claims = sess.read().await;
    let required_perm: u128 = 1 << 126;
    if !(claims.role & required_perm == required_perm) {
        return HttpResponse::Forbidden().finish();
    }
    match state.service.admin_deny_permission(body.into_inner()).await {
        Ok(Some(r)) => HttpResponse::Ok().json(json!({
            "success": true,
            "new_role": r
        })),
        Ok(None) => HttpResponse::NotAcceptable()
            .body("Error in denying permission, please confirm that the permission was granted"),
        Err(e) => admin_error_response(e),
    }
}

#[post("/admin/claim")]
pub async fn claim_admin(_state: web::Data<AppState>, sess: Session<User>) -> impl Responder {
    let mut id = sess.write().await;
    let admin = match env::var("ADMIN") {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("error in getting admin id: {e}");
            return HttpResponse::NotFound().finish();
        }
    };
    let admin = match Uuid::parse_str(&admin) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Invalid admin id: {e}");
            return HttpResponse::NotFound().finish();
        }
    };
    if admin != id.sub {
        return HttpResponse::NotAcceptable().finish();
    }
    id.role = u128::MAX;
    HttpResponse::Ok().into()
}
