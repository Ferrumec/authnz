use crate::authn::domain::SessionService;
use crate::authn::domain::user::{
    UserService,
    errors::AuthError,
    models::{
        ChangePasswordCmd, ConfirmPasswordResetCmd, PasswordLoginCmd, RequestPasswordResetCmd,
    },
};
use crate::authn::models::{
    ApiResponse, ChangePasswordRequest, LoginRequest, PasswordResetConfirmRequest,
    PasswordResetRequest, RegisterRequest,
};
use crate::authz::Service as AuthzService;
use crate::models::User;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use actixutils::Session;
use uuid::Uuid;

// ── Error → HTTP ──────────────────────────────────────────────────────────────

pub fn auth_error_to_response(e: AuthError) -> HttpResponse {
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
    sess: web::Data<SessionService>,
    req: web::Json<LoginRequest>,
    authz: web::Data<AuthzService>,
) -> impl Responder {
    let cmd = PasswordLoginCmd {
        username: req.identifier.clone(),
        password: req.password.clone(),
    };

    let user = match svc.password_login(cmd).await {
        Ok(user) => user,
        Err(e) => return auth_error_to_response(e),
    };

    let role = match authz.get_role(&user.id).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let user = User::new(user, role);

    let sess_id = match sess.issue_session(user).await {
        Ok(sess_id) => sess_id,
        Err(e) => return auth_error_to_response(e),
    };

    HttpResponse::Ok().cookie(session_cookie(&sess_id)).finish()
}

pub async fn username_login(
    svc: web::Data<UserService>,
    req: web::Json<LoginRequest>,
    sess: web::Data<SessionService>,
    authz: web::Data<AuthzService>,
) -> impl Responder {
    let cmd = PasswordLoginCmd {
        username: req.identifier.clone(),
        password: req.password.clone(),
    };

    let user = match svc.username_login(cmd).await {
        Ok(user) => user,
        Err(e) => return auth_error_to_response(e),
    };

    let role = match authz.get_role(&user.id).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let user = User::new(user, role);

    let sess_id = match sess.issue_session(user).await {
        Ok(sess_id) => sess_id,
        Err(e) => return auth_error_to_response(e),
    };

    HttpResponse::Ok().cookie(session_cookie(&sess_id)).finish()
}

pub async fn logout(sess: web::Data<SessionService>, req: HttpRequest) -> impl Responder {
    if let Some(sess_id) = req.cookie("session")
        && let Err(e) = sess.logout(sess_id.value()).await
    {
        return auth_error_to_response(e);
    }

    HttpResponse::Ok().json(ApiResponse::success((), "Logged out successfully"))
}

pub async fn change_password(
    svc: web::Data<UserService>,
    user_session: Session<User>,
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
    sess: web::Data<SessionService>,
    payload: web::Json<PasswordResetConfirmRequest>,
    req: HttpRequest,
) -> impl Responder {
    let cmd = ConfirmPasswordResetCmd {
        token: payload.token.clone(),
        new_password: payload.new_password.clone(),
    };
    match svc.confirm_password_reset(cmd).await {
        Ok(_user_id) => {
            if let Some(sess_id) = req.cookie("session")
                && let Err(e) = sess.logout(sess_id.value()).await
            {
                return auth_error_to_response(e);
            };
            HttpResponse::Ok().finish()
        }
        Err(e) => auth_error_to_response(e),
    }
}

/// Protected route: validates the JWT from the middleware and echoes the
/// user ID back. Kept on `AppState` so the existing `actixutils::Access`
/// extractor + `libsigners` validator continue to work unchanged.
pub async fn protected(sess: Session<User>) -> impl Responder {
    let id = sess.read().await;
    HttpResponse::Ok().json(ApiResponse::success(
        crate::authn::models::ProtectedResponse {
            user_id: id.sub,
            message: "Access granted to protected route".to_string(),
        },
        "Protected data retrieved successfully",
    ))
}
