use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Refresh an access token using a long-lived refresh token.
#[derive(Debug, Deserialize)]
pub struct RefreshCmd {
    pub refresh_token: String,
}

/// Revoke a refresh token (logout).
#[derive(Debug, Deserialize)]
pub struct LogoutCmd {
    pub refresh_token: String,
}

// ── Result types (outputs) ────────────────────────────────────────────────────

/// Returned after any successful authentication flow.
#[derive(Debug, Serialize)]
pub struct AuthResult {
    pub access_token: String,
    pub refresh_token: String,
    /// Seconds until the access token expires.
    pub expires_in: u64,
}

/// A row from the `refresh_tokens` table.
/// `token_hash` is SHA-256(raw_token). The raw token is **never** stored.
pub struct RefreshTokenRow {
    pub user_id: Uuid,
    pub issuer: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}
