use crate::authn::{
    auth2::AppState,
    handlers::access_cookie,
    models::{ApiResponse, LoginResponse},
    passkey::{error::ErrorResponse, models::UsernameRequest, repository},
};
use actix_web::{HttpResponse, web};
use webauthn_rs::prelude::PublicKeyCredential;

/// `POST /passkey/login/start` — begin a passkey login for the given
/// username. Public route: no session exists yet.
pub async fn start(state: web::Data<AppState>, req: web::Json<UsernameRequest>) -> HttpResponse {
    let username = req.username.trim().to_string();
    if username.is_empty() {
        return ErrorResponse::bad_request("Username is required");
    }

    // Same response whether the account exists or just has no passkeys,
    // so this endpoint can't be used to enumerate registered usernames.
    let user = match state.auth_service.get_user_by_username(&username).await {
        Ok(u) => u,
        Err(_) => return ErrorResponse::bad_request("No passkeys registered for this account"),
    };

    let credentials = match repository::credentials_for_user(&state.pool, user.id).await {
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

    state.passkey.store_auth_state(username.clone(), auth_state);

    tracing::info!("Passkey authentication started for user: {}", username);
    HttpResponse::Ok().json(options)
}

/// `POST /passkey/login/finish?username=...` — verify the authenticator's
/// assertion and, on success, issue the same access/refresh token pair
/// every other login method returns.
pub async fn finish(
    state: web::Data<AppState>,
    credential: web::Json<PublicKeyCredential>,
    query: web::Query<UsernameRequest>,
) -> HttpResponse {
    let username = query.username.trim().to_string();

    let user = match state.auth_service.get_user_by_username(&username).await {
        Ok(u) => u,
        Err(_) => {
            return ErrorResponse::bad_request("No authentication in progress for this account");
        }
    };

    let auth_state = match state.passkey.take_auth_state(&username) {
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
    match repository::credentials_for_user(&state.pool, user.id).await {
        Ok(mut credentials) => {
            if let Some(cred) = credentials
                .iter_mut()
                .find(|c| c.cred_id() == result.cred_id())
            {
                if let Some(true) = cred.update_credential(&result) {
                    if let Err(e) = repository::update_credential(&state.pool, cred).await {
                        tracing::warn!(
                            "passkey login/finish: failed to persist counter update: {e}"
                        );
                    }
                }
            }
        }
        Err(e) => tracing::warn!("passkey login/finish: could not reload credentials: {e}"),
    }

    let auth_result = match state.auth_service.issue_for_passwordless(user.id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("passkey login/finish: failed to issue tokens: {e}");
            return ErrorResponse::internal();
        }
    };

    tracing::info!(
        "Passkey login successful for user: {} (verified: {})",
        username,
        result.user_verified()
    );

    let cookie = access_cookie(&auth_result.access_token);
    HttpResponse::Ok().cookie(cookie).json(ApiResponse::success(
        LoginResponse {
            access_token: auth_result.access_token,
            refresh_token: auth_result.refresh_token,
            expires_in: auth_result.expires_in,
        },
        "Passkey login successful",
    ))
}
