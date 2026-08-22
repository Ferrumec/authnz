use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Command types (inputs) ────────────────────────────────────────────────────

/// Password-based login.
#[derive(Debug, Deserialize)]
pub struct PasswordLoginCmd {
    pub username: String,
    pub password: String,
}

/// Change the current user's password.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordCmd {
    pub user_id: Uuid,
    pub current_password: String,
    pub new_password: String,
}

/// Request a password-reset email.
#[derive(Debug, Deserialize)]
pub struct RequestPasswordResetCmd {
    pub email: String,
}

/// Confirm a password reset using the token from the email.
#[derive(Debug, Deserialize)]
pub struct ConfirmPasswordResetCmd {
    pub token: String,
    pub new_password: String,
}

// ── DB row types ──────────────────────────────────────────────────────────────

/// A row from the `users` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A row from the `password_resets` table.
#[derive(sqlx::FromRow)]
pub struct PasswordReset {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}
