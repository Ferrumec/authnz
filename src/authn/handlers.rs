use crate::authn::domain::SessionService;
use crate::authn::domain::auth::{
    AuthService,
    models::{AuthResult, LogoutCmd, RefreshCmd},
};
use crate::authn::domain::user::{
    UserService,
    errors::AuthError,
    models::{
        ChangePasswordCmd, ConfirmPasswordResetCmd, PasswordLoginCmd, RequestPasswordResetCmd,
    },
};
use crate::authn::models::{
    ApiResponse, ChangePasswordRequest, LoginRequest, LoginResponse, LogoutRequest,
    PasswordResetConfirmRequest, PasswordResetRequest, RefreshRequest, RegisterRequest,
};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use actixutils::{Identity, Session};
use uuid::Uuid;

// ── Error → HTTP ──────────────────────────────────────────────────────────────

fn auth_error_to_response(e: AuthError) -> HttpResponse {
    match e {
        AuthError::MissingCredentials
        | AuthError::PasswordTooShort
        | AuthError::MissingRefreshToken => {
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e.to_string()))
        }
        AuthError::InvalidCredentials
        | AuthError::RefreshTokenNotFound
        | AuthError::RefreshTokenExpired
        | AuthError::InvalidToken
        | AuthError::UserNotFound => {
            HttpResponse::Unauthorized().json(ApiResponse::<()>::error(&e.to_string()))
        }
        AuthError::UserAlreadyExists => {
            HttpResponse::Conflict().json(ApiResponse::<()>::error(&e.to_string()))
        }
        AuthError::Database(_)
        | AuthError::Bcrypt(_)
        | AuthError::TokenSigning(_)
        | AuthError::Cache => {
            tracing::error!("Internal auth error: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn auth_result_to_login_response(r: AuthResult) -> LoginResponse {
    LoginResponse {
        access_token: r.access_token,
        refresh_token: r.refresh_token,
        expires_in: r.expires_in,
    }
}

pub fn access_cookie(token: &str) -> Cookie<'static> {
    Cookie::build("access_token", token.to_owned())
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .finish()
}

pub fn session_cookie(session: &Uuid) -> Cookie<'static> {
    Cookie::build("session", session.to_string())
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .finish()
}

pub async fn register(
    svc: web::Data<UserService>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    match svc.register(&req.username, &req.password).await {
        Ok(res) => {
            HttpResponse::Created().json(ApiResponse::success(res, "User registered successfully"))
        }
        Err(e) => auth_error_to_response(e),
    }
}

pub async fn login(
    svc: web::Data<UserService>,
    jwt: web::Data<AuthService>,
    sess: web::Data<SessionService>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    let cmd = PasswordLoginCmd {
        username: req.identifier.clone(),
        password: req.password.clone(),
    };

    let user = match svc.password_login(cmd).await {
        Ok(user) => user,
        Err(e) => return auth_error_to_response(e),
    };

    let result = match jwt.issue_token_pair(user.id, "password").await {
        Ok(result) => result,
        Err(e) => return auth_error_to_response(e),
    };

    let sess_id = match sess.issue_session(user).await {
        Ok(sess_id) => sess_id,
        Err(e) => return auth_error_to_response(e),
    };

    HttpResponse::Ok()
        .cookie(access_cookie(&result.access_token))
        .cookie(session_cookie(&sess_id))
        .json(ApiResponse::success(
            auth_result_to_login_response(result),
            "Login successful",
        ))
}

pub async fn username_login(
    svc: web::Data<UserService>,
    jwt: web::Data<AuthService>,
    req: web::Json<LoginRequest>,
    sess: web::Data<SessionService>,
) -> impl Responder {
    let cmd = PasswordLoginCmd {
        username: req.identifier.clone(),
        password: req.password.clone(),
    };

    let user = match svc.username_login(cmd).await {
        Ok(user) => user,
        Err(e) => return auth_error_to_response(e),
    };

    let result = match jwt.issue_token_pair(user.id, "password").await {
        Ok(result) => result,
        Err(e) => return auth_error_to_response(e),
    };

    let sess_id = match sess.issue_session(user).await {
        Ok(sess_id) => sess_id,
        Err(e) => return auth_error_to_response(e),
    };

    HttpResponse::Ok()
        .cookie(access_cookie(&result.access_token))
        .cookie(session_cookie(&sess_id))
        .json(ApiResponse::success(
            auth_result_to_login_response(result),
            "Login successful",
        ))
}

pub async fn refresh(
    svc: web::Data<AuthService>,
    req: web::Json<RefreshRequest>,
) -> impl Responder {
    let cmd = RefreshCmd {
        refresh_token: req.refresh_token.clone(),
    };
    match svc.refresh(cmd).await {
        Ok(result) => {
            let cookie = access_cookie(&result.access_token);
            HttpResponse::Ok().cookie(cookie).json(ApiResponse::success(
                auth_result_to_login_response(result),
                "Refresh successful",
            ))
        }
        Err(e) => auth_error_to_response(e),
    }
}

pub async fn logout(
    svc: web::Data<AuthService>,
    sess: web::Data<SessionService>,
    payload: web::Json<LogoutRequest>,
    req: HttpRequest,
) -> impl Responder {
    let cmd = LogoutCmd {
        refresh_token: payload.refresh_token.clone(),
    };
    if let Err(e) = svc.logout(cmd).await {
        return auth_error_to_response(e);
    }

    if let Some(sess_id) = req.cookie("session") {
        if let Err(e) = sess.logout(sess_id.value()).await {
            return auth_error_to_response(e);
        }
    }

    HttpResponse::Ok().json(ApiResponse::success((), "Logged out successfully"))
}

pub async fn change_password(
    svc: web::Data<UserService>,
    user_session: Session<Identity>,
    req: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    let user_id = user_session.read().await.sub;
    let cmd = ChangePasswordCmd {
        user_id,
        current_password: req.current_password.clone(),
        new_password: req.new_password.clone(),
    };
    match svc.change_password(cmd).await {
        Ok(()) => {
            HttpResponse::Ok().json(ApiResponse::success((), "Password changed successfully"))
        }
        Err(e) => auth_error_to_response(e),
    }
}

pub async fn request_password_reset(
    svc: web::Data<UserService>,
    req: web::Json<PasswordResetRequest>,
) -> impl Responder {
    // Always return 200 regardless of whether the email was found.
    svc.request_password_reset(RequestPasswordResetCmd {
        email: req.email.clone(),
    })
    .await;
    HttpResponse::Ok().json(ApiResponse::success(
        (),
        "If the account exists, a reset link has been sent",
    ))
}

pub async fn confirm_password_reset(
    svc: web::Data<UserService>,
    jwt: web::Data<AuthService>,
    req: web::Json<PasswordResetConfirmRequest>,
) -> impl Responder {
    let cmd = ConfirmPasswordResetCmd {
        token: req.token.clone(),
        new_password: req.new_password.clone(),
    };
    match svc.confirm_password_reset(cmd).await {
        Ok(user_id) => match jwt.revoke_all_user_tokens(&user_id).await {
            Ok(_) => HttpResponse::Ok().json(ApiResponse::success((), "Password reset successful")),
            Err(e) => auth_error_to_response(e),
        },
        Err(e) => auth_error_to_response(e),
    }
}

/// Protected route: validates the JWT from the middleware and echoes the
/// user ID back. Kept on `AppState` so the existing `actixutils::Access`
/// extractor + `libsigners` validator continue to work unchanged.
pub async fn protected(sess: Session<Identity>) -> impl Responder {
    let id = sess.read().await;
    HttpResponse::Ok().json(ApiResponse::success(
        crate::authn::models::ProtectedResponse {
            user_id: id.sub,
            message: "Access granted to protected route".to_string(),
        },
        "Protected data retrieved successfully",
    ))
}
