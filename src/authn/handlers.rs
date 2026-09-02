use crate::authn::domain::JwtService;
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
use crate::authn::session::SessionParams;
use crate::authz::Service as AuthzService;
use crate::models::User;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use actixutils::Session;
use actixutils::locals::Context;
use typed_eventbus::Event;
use uuid::Uuid;
use validator::Validate;

// ── Error → HTTP ──────────────────────────────────────────────────────────────

pub fn auth_error_to_response(e: AuthError) -> HttpResponse {
    match e {
        AuthError::MissingCredentials | AuthError::PasswordTooShort => {
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e.to_string()))
        }
        AuthError::InvalidCredentials | AuthError::InvalidToken | AuthError::UserNotFound => {
            HttpResponse::Unauthorized().json(ApiResponse::<()>::error(&e.to_string()))
        }
        AuthError::UserAlreadyExists => {
            HttpResponse::Conflict().json(ApiResponse::<()>::error(&e.to_string()))
        }
        AuthError::Database(_) | AuthError::Bcrypt(_) | AuthError::Cache => {
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
    let req = req.into_inner();
    if let Err(e) = req.validate() {
        return HttpResponse::BadRequest().body(format!("Invalid request: {e}"));
    }
    match svc.register(&req.username, &req.email, &req.password).await {
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
    params: SessionParams,
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
        Err(e) => {
            tracing::error!("get_role failed during login: {e}");
            return HttpResponse::InternalServerError().finish();
        }
    };
    let user = User::new(user, role);

    let sess_id = match sess.issue_session(user, params).await {
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
    params: SessionParams,
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
        Err(e) => {
            tracing::error!("get_role failed during login: {e}");
            return HttpResponse::InternalServerError().finish();
        }
    };
    let user = User::new(user, role);

    let sess_id = match sess.issue_session(user, params).await {
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
    sess: web::Data<SessionService>,
    authz: web::Data<AuthzService>,
    user_session: Session<User>,
    req: web::Json<ChangePasswordRequest>,
    params: SessionParams,
) -> impl Responder {
    let user_id = user_session.read().await.sub;
    let cmd = ChangePasswordCmd {
        user_id,
        current_password: req.current_password.clone(),
        new_password: req.new_password.clone(),
    };
    match svc.change_password(cmd).await {
        Ok(()) => {
            // The old password no longer works anywhere, so nothing
            // issued under it should keep working either — revoke every
            // session for this user...
            if let Err(e) = sess.revoke_all_for_user(&user_id).await {
                tracing::error!("failed to revoke sessions after password change: {e}");
            }

            // ...then issue a fresh one so the device that just changed
            // the password doesn't get logged out by its own request.
            let user = match svc.get_user_by_id(&user_id).await {
                Ok(u) => u,
                Err(e) => return auth_error_to_response(e),
            };
            let role = match authz.get_role(&user_id).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("get_role failed after password change: {e}");
                    return HttpResponse::InternalServerError().finish();
                }
            };
            let sess_id = match sess.issue_session(User::new(user, role), params).await {
                Ok(id) => id,
                Err(e) => return auth_error_to_response(e),
            };

            HttpResponse::Ok()
                .cookie(session_cookie(&sess_id))
                .json(ApiResponse::success((), "Password changed successfully"))
        }
        Err(e) => auth_error_to_response(e),
    }
}

pub async fn request_password_reset(
    svc: web::Data<UserService>,
    req: web::Json<PasswordResetRequest>,
    ctx: web::ReqData<Context>,
) -> impl Responder {
    // Always return 200 regardless of whether the email was found.
    // Errors (DB, etc.) are logged inside the service but never leaked to the client.
    match svc
        .request_password_reset(RequestPasswordResetCmd {
            email: req.email.clone(),
        })
        .await
    {
        Ok(Some(event)) => {
            // Hand the raw token off to the event bus (e.g. an email
            // service subscriber) instead of logging it.
            ctx.publish(Event::new(event)).await;
        }
        Ok(None) => {} // no account for that address – stay silent
        Err(e) => tracing::error!("password-reset request failed: {e}"),
    }
    HttpResponse::Ok().json(ApiResponse::success(
        (),
        "If the account exists, a reset link has been sent",
    ))
}

pub async fn confirm_password_reset(
    svc: web::Data<UserService>,
    sess: web::Data<SessionService>,
    payload: web::Json<PasswordResetConfirmRequest>,
) -> impl Responder {
    let cmd = ConfirmPasswordResetCmd {
        token: payload.token.clone(),
        new_password: payload.new_password.clone(),
    };
    match svc.confirm_password_reset(cmd).await {
        Ok(user_id) => {
            // Revoke every session for this user, not just the caller's
            // current cookie — resetting a password is often done from a
            // device that was never logged in to begin with, and any
            // session (including a stolen one) issued under the old
            // password should not survive the reset.
            if let Err(e) = sess.revoke_all_for_user(&user_id).await {
                tracing::error!("failed to revoke sessions after password reset: {e}");
            }
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

pub async fn jwt(sess: Session<User>, jwt_svc: web::Data<JwtService>) -> impl Responder {
    let user = sess.read().await;
    let result = match jwt_svc.issue_token_pair(user.sub, "session").await {
        Ok(result) => result,
        Err(_e) => return HttpResponse::InternalServerError().finish(),
    };
    HttpResponse::Ok().json(result)
}
