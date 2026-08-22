use crate::authn::domain::SessionService;
use crate::authn::domain::user::UserService;
use crate::authn::handlers::session_cookie;
use crate::authn::{auth2::AppState, passwdless::PasswdlessError};
use crate::authz::Service as AuthzService;
use crate::models::User;
use actix_web::{
    HttpResponse, Responder, ResponseError, get, post,
    web::{self, ServiceConfig},
};
use serde::Deserialize;
use std::fmt::Display;

fn translate_error(error: PasswdlessError) -> HttpResponse {
    match error {
        PasswdlessError::DbError => HttpResponse::InternalServerError().finish(),
        PasswdlessError::BadToken => HttpResponse::BadRequest().body("Invalid or expired token"),
        PasswdlessError::UserNotFound => HttpResponse::NotFound().body("User not found"),
    }
}

impl Display for PasswdlessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = match self {
            PasswdlessError::DbError => "service unavailable, please try again later",
            PasswdlessError::BadToken => "Invalid or expired token",
            PasswdlessError::UserNotFound => "User not found",
        };
        write!(f, "{}", r)
    }
}

impl ResponseError for PasswdlessError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        translate_error(self.clone()).status()
    }

    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        translate_error(self.clone())
    }
}

#[derive(Deserialize)]
struct Token {
    token: u32,
}

#[derive(Deserialize)]
struct Email {
    email: String,
}

#[get("/challenge/email")]
async fn challenge1(data: web::Data<AppState>, email: web::Json<Email>) -> impl Responder {
    match data
        .passwdless_service
        .challenge_by_email(&email.email)
        .await
    {
        Ok(_r) => HttpResponse::Created().finish(),
        Err(e) => translate_error(e),
    }
}

#[get("/challenge/username/{username}")]
async fn challenge2(data: web::Data<AppState>, username: web::Path<String>) -> impl Responder {
    match data
        .passwdless_service
        .challenge_by_username(&username.into_inner())
        .await
    {
        Ok(_r) => HttpResponse::Created().finish(),
        Err(e) => translate_error(e),
    }
}

#[get("/confirm_link/{link}")]
async fn confirm(
    data: web::Data<AppState>,
    token: web::Path<String>,
    svc: web::Data<UserService>,
    sess: web::Data<SessionService>,
    authz: web::Data<AuthzService>,
) -> impl Responder {
    let token = token.into_inner();
    let user_id = match data.passwdless_service.confirm_link(token).await {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };

    let user = match svc.get_user_by_id(&user_id).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let role = match authz.get_absolute_role(&user_id).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let user = User::new(user, role);
    let sess_id = match sess.issue_session(user).await {
        Ok(sess_id) => sess_id,
        Err(_e) => return HttpResponse::InternalServerError().finish(),
    };

    HttpResponse::Ok().cookie(session_cookie(&sess_id)).finish()
}

#[post("/confirm_token")]
async fn confirm_token(
    data: web::Data<AppState>,
    token: web::Json<Token>,
    svc: web::Data<UserService>,
    sess: web::Data<SessionService>,
    authz: web::Data<AuthzService>,
) -> impl Responder {
    let token = token.into_inner();
    let user_id = match data.passwdless_service.confirm_token(token.token).await {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };

    let user = match svc.get_user_by_id(&user_id).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let role = match authz.get_absolute_role(&user_id).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let user = User::new(user, role);

    let sess_id = match sess.issue_session(user).await {
        Ok(sess_id) => sess_id,
        Err(_e) => return HttpResponse::InternalServerError().finish(),
    };

    HttpResponse::Ok().cookie(session_cookie(&sess_id)).finish()
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("")
            .service(confirm)
            .service(confirm_token)
            .service(challenge1)
            .service(challenge2),
    );
}
