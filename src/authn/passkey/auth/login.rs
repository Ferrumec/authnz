use crate::authn::domain::user::UserService;
use crate::authn::passkey::repository::CredsRepo;
use crate::authn::session::SessionParams;
use crate::authn::{
    auth2::AppState,
    domain::SessionService,
    handlers::{auth_error_to_response, session_cookie},
    passkey::{error::ErrorResponse, models::UsernameRequest},
};
use crate::authz::Service as AuthzService;
use crate::models::User;
use actix_web::{HttpResponse, web};
use webauthn_rs::prelude::PublicKeyCredential;

/// `POST /passkey/login/start` — begin a passkey login for the given
/// username. Public route: no session exists yet.
pub async fn start(
    auth_service: web::Data<UserService>,
    req: web::Json<UsernameRequest>,
    repo: web::Data<CredsRepo>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let username = req.username.trim().to_string();
    if username.is_empty() {
        return ErrorResponse::bad_request("Username is required");
    }

    // Same response whether the account exists or just has no passkeys,
    // so this endpoint can't be used to enumerate registered usernames.
    let user = match auth_service.get_user_by_username(&username).await {
        Ok(u) => u,
        Err(_) => return ErrorResponse::bad_request("No passkeys registered for this account"),
    };

    let credentials = match repo.credentials_for_user(user.id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("passkey login/start: could not load credentials: {e}");
            return ErrorResponse::internal();
        }
    };

    if credentials.is_empty() {
        return ErrorResponse::bad_request("No passkeys registered for this account");
    }

    let (options, auth_state) = match state
        .passkey
        .webauthn
        .start_passkey_authentication(&credentials)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("WebAuthn start_passkey_authentication: {}", e);
            return ErrorResponse::bad_request(format!("WebAuthn error: {}", e));
        }
    };

    state.passkey.store_auth_state(username.clone(), auth_state).await;

    tracing::info!("Passkey authentication started for user: {}", username);
    HttpResponse::Ok().json(options)
}

/// `POST /passkey/login/finish?username=...` — verify the authenticator's
/// assertion and, on success, issue the same access/refresh token pair
/// every other login method returns.
pub async fn finish(
    auth_service: web::Data<UserService>,
    credential: web::Json<PublicKeyCredential>,
    query: web::Query<UsernameRequest>,
    repo: web::Data<CredsRepo>,
    sess: web::Data<SessionService>,
    authz: web::Data<AuthzService>,
    state: web::Data<AppState>,
    params: SessionParams,
) -> HttpResponse {
    let username = query.username.trim().to_string();

    let user = match auth_service.get_user_by_username(&username).await {
        Ok(u) => u,
        Err(_) => {
            return ErrorResponse::bad_request("No authentication in progress for this account");
        }
    };

    let auth_state = match state.passkey.take_auth_state(&username).await {
        Some(s) => s,
        None => {
            return ErrorResponse::bad_request(
                "No authentication in progress for this account, or it expired. Please try again.",
            );
        }
    };

    let result = match state
        .passkey
        .webauthn
        .finish_passkey_authentication(&credential, &auth_state)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("WebAuthn finish_passkey_authentication: {}", e);
            return ErrorResponse::bad_request(format!("WebAuthn error: {}", e));
        }
    };

    // WebAuthn tracks a per-credential signature counter to detect cloned
    // authenticators. If the library says the stored state needs updating,
    // persist the refreshed credential.
    match repo.credentials_for_user(user.id).await {
        Ok(mut credentials) => {
            if let Some(cred) = credentials
                .iter_mut()
                .find(|c| c.cred_id() == result.cred_id())
            {
                if let Some(true) = cred.update_credential(&result) {
                    if let Err(e) = repo.update_credential(cred).await {
                        tracing::warn!(
                            "passkey login/finish: failed to persist counter update: {e}"
                        );
                    }
                }
            }
        }
        Err(e) => tracing::warn!("passkey login/finish: could not reload credentials: {e}"),
    }

    let role = match authz.get_role(&user.id).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let user = User::new(user, role);

    let sess_id = match sess.issue_session(user, params).await {
        Ok(sess_id) => sess_id,
        Err(e) => return auth_error_to_response(e),
    };

    HttpResponse::Ok().cookie(session_cookie(&sess_id)).finish()
}
