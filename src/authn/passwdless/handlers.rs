use actix_web::{
    HttpResponse, Responder, ResponseError, get, post,
    web::{self, ServiceConfig},
};

use serde::Deserialize;
use std::fmt::Display;

use crate::authn::{auth2::AppState, models::LoginResponse, passwdless::PasswdlessError};

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
async fn challenge1(
    data: web::Data<AppState>,
    email: web::Json<Email>,
) -> impl Responder {
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
async fn challenge2(
    data: web::Data<AppState>,
    username: web::Path<String>,
) -> impl Responder {
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
async fn confirm(data: web::Data<AppState>, token: web::Path<String>) -> impl Responder {
    let token = token.into_inner();
    let user_id = match data.passwdless_service.confirm_link(token).await {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };

    // Issue tokens for passwordless authentication
    match data.auth_service.issue_for_passwordless(user_id).await {
        Ok(auth_result) => HttpResponse::Ok().json(LoginResponse {
            access_token: auth_result.access_token,
            refresh_token: auth_result.refresh_token,
            expires_in: auth_result.expires_in,
        }),
        Err(e) => {
            tracing::warn!("Error creating token pair: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/confirm_token")]
async fn confirm_token(data: web::Data<AppState>, token: web::Json<Token>) -> impl Responder {
    let token = token.into_inner();
    let user_id = match data.passwdless_service.confirm_token(token.token).await {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };

    // Issue tokens for passwordless authentication
    match data.auth_service.issue_for_passwordless(user_id).await {
        Ok(auth_result) => HttpResponse::Ok().json(LoginResponse {
            access_token: auth_result.access_token,
            refresh_token: auth_result.refresh_token,
            expires_in: auth_result.expires_in,
        }),
        Err(e) => {
            tracing::warn!("Error creating token pair: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
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
