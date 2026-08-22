use crate::authn::{
    auth2::AppState,
    passkey::{error::ErrorResponse, models::LabelQuery, repository},
};
use actix_web::{HttpResponse, web};
use actixutils::{Identity, Jwt as Auth};
use uuid::Uuid;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

/// `POST /passkey/register/start` — begin registering a new passkey for
/// the *currently authenticated* account (JWT required). The account must
/// already exist; passkeys are added to an account, not used to create
/// one, so ownership of the account is proven up front the normal way.
pub async fn start(state: web::Data<AppState>, Auth(identity): Auth<Identity>) -> HttpResponse {
    let user_id = identity.sub;

    let user = match state.auth_service.get_user_by_id(&user_id).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!("passkey register/start: user lookup failed: {e}");
            return ErrorResponse::internal();
        }
    };

    // Don't let the same authenticator be registered twice for this account.
    let existing = match repository::credentials_for_user(&state.pool, user_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("passkey register/start: could not load existing credentials: {e}");
            return ErrorResponse::internal();
        }
    };
    let exclude_credentials = if existing.is_empty() {
        None
    } else {
        Some(existing.iter().map(|p| p.cred_id().clone()).collect())
    };

    let (options, reg_state) = match state.passkey.webauthn.start_passkey_registration(
        user_id,
        &user.username,
        &user.username,
        exclude_credentials,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("WebAuthn start_passkey_registration: {}", e);
            return ErrorResponse::bad_request(format!("WebAuthn error: {}", e));
        }
    };

    state.passkey.store_reg_state(user_id, reg_state);

    tracing::info!("Passkey registration started for user: {}", user.username);
    HttpResponse::Ok().json(options)
}

/// `POST /passkey/register/finish` — verify the authenticator's response
/// and persist the new credential against the authenticated account.
/// Optional `?label=` query param to name the device.
pub async fn finish(
    state: web::Data<AppState>,
    Auth(identity): Auth<Identity>,
    query: web::Query<LabelQuery>,
    credential: web::Json<RegisterPublicKeyCredential>,
) -> HttpResponse {
    let user_id = identity.sub;

    let reg_state = match state.passkey.take_reg_state(&user_id) {
        Some(s) => s,
        None => {
            return ErrorResponse::bad_request(
                "No registration in progress for this account, or it expired. Please start again.",
            );
        }
    };

    let passkey = match state
        .passkey
        .webauthn
        .finish_passkey_registration(&credential, &reg_state)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("WebAuthn finish_passkey_registration: {}", e);
            return ErrorResponse::bad_request(format!("WebAuthn error: {}", e));
        }
    };

    if let Err(e) =
        repository::insert_credential(&state.pool, user_id, &passkey, query.label.as_deref()).await
    {
        tracing::error!("passkey register/finish: failed to store credential: {e}");
        return ErrorResponse::internal();
    }

    tracing::info!("Passkey registered for user id: {}", user_id);
    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "Passkey registered"
    }))
}

/// `GET /passkey/register` — list the authenticated user's passkeys
/// (metadata only) for an account-settings "manage your passkeys" view.
pub async fn list(state: web::Data<AppState>, Auth(identity): Auth<Identity>) -> HttpResponse {
    match repository::list_for_user(&state.pool, identity.sub).await {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => {
            tracing::warn!("passkey list: {e}");
            ErrorResponse::internal()
        }
    }
}

/// `DELETE /passkey/register/{id}` — remove one of the authenticated
/// user's passkeys by its row id (from the list endpoint).
pub async fn remove(
    state: web::Data<AppState>,
    Auth(identity): Auth<Identity>,
    row_id: web::Path<Uuid>,
) -> HttpResponse {
    match repository::delete_credential(&state.pool, identity.sub, row_id.into_inner()).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({ "status": "success" })),
        Ok(false) => ErrorResponse::not_found("Passkey not found"),
        Err(e) => {
            tracing::warn!("passkey remove: {e}");
            ErrorResponse::internal()
        }
    }
}
