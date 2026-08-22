use actix_web::{HttpResponse, Responder, get, web};

use crate::authn::auth2::AppState;

#[get("/user_id/username/{username}")]
pub async fn username2userid(
    state: web::Data<AppState>,
    username: web::Path<String>,
) -> impl Responder {
    let username = username.into_inner();

    let result = sqlx::query_scalar!("SELECT id FROM users WHERE username = $1", username)
        .fetch_optional(&state.pool)
        .await;

    match result {
        Ok(Some(id)) => HttpResponse::Ok().body(id),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}
