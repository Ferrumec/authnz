use actix_web::HttpResponse;
use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl ErrorResponse {
    pub fn bad_request(msg: impl Into<String>) -> HttpResponse {
        HttpResponse::BadRequest().json(Self { error: msg.into() })
    }

    pub fn not_found(msg: impl Into<String>) -> HttpResponse {
        HttpResponse::NotFound().json(Self { error: msg.into() })
    }

    pub fn unauthorized(msg: impl Into<String>) -> HttpResponse {
        HttpResponse::Unauthorized().json(Self { error: msg.into() })
    }

    pub fn internal() -> HttpResponse {
        HttpResponse::InternalServerError().json(Self {
            error: "Internal server error".to_string(),
        })
    }
}
