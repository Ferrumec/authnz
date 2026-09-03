use crate::SessionService;
use crate::authn::session::Session;
use crate::authz::{
    models::{AppState, PermissionReq},
    //services::AdminError,
};
use crate::models::User;
use actix_web::{HttpResponse, Responder, post, web};
use serde_json::json;
use std::env;
use uuid::Uuid;

#[post("/admin/grant")]
pub async fn admin_grant_permission(
    sess: Session<User>,
    state: web::Data<AppState>,
    body: web::Json<PermissionReq>,
) -> HttpResponse {
    let claims = sess.read().await;
    let required_perm: u128 = 1 << 106;
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
        Err(_e) => HttpResponse::InternalServerError().finish(),
    }
}

#[post("/admin/deny")]
pub async fn admin_deny_permission(
    sess: Session<User>,
    sess_svc: web::Data<SessionService>,
    state: web::Data<AppState>,
    body: web::Json<PermissionReq>,
) -> HttpResponse {
    let claims = sess.read().await;
    let required_perm: u128 = 1 << 105;
    if !(claims.role & required_perm == required_perm) {
        return HttpResponse::Forbidden().finish();
    }
    let req = body.into_inner();
    match state.service.admin_deny_permission(req.clone()).await {
        Ok(Some(r)) => {
            if let Err(_e) = sess_svc.revoke_all_for_user(&req.target).await {
                tracing::warn!("could not revoke user sessions after denying permisson")
            }
            HttpResponse::Ok().json(json!({
                "success": true,
                "new_role": r
            }))
        }
        Ok(None) => HttpResponse::NotAcceptable()
            .body("Error in denying permission, please confirm that the permission was granted"),
        Err(_e) => HttpResponse::InternalServerError().finish(),
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
