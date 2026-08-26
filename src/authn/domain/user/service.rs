//! The single authoritative home for all authentication business logic.
//!
//! HTTP handlers are thin wrappers: parse → call AuthService → map to HTTP.
//! No database queries and no crypto live outside this module and its
//! submodules.

use crate::authn::domain::user::token::{generate_raw_token, hash_token};
use crate::authn::domain::user::{
    errors::AuthError,
    models::{
        ChangePasswordCmd, ConfirmPasswordResetCmd, PasswordLoginCmd, PasswordReset,
        RequestPasswordResetCmd,
    },
};

use crate::authn::admin::{User, UserRepository};
use chrono::Utc;
use serde::Serialize;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use typed_eventbus::Publishable;
use uuid::Uuid;
use viewset::Repository;

extern crate zxcvbn;
use zxcvbn::zxcvbn;
// ── Constants ─────────────────────────────────────────────────────────────────

const MIN_PASSWORD_LEN: usize = 6;

#[derive(Serialize)]
struct UserCreated {
    email: String,
    phone: Option<String>,
    country: Option<String>,
}

impl Publishable for UserCreated {
    const SUBJECT: &'static str = "auth.user.created";
}
// ── AuthService ───────────────────────────────────────────────────────────────

/// Central service for all authentication flows.
///
/// Owns the database pool and JWT configuration. Constructed once at
/// application startup and shared via `Arc` or Actix `web::Data`.
#[derive(Clone)]
pub struct UserService {
    pool: Pool<Postgres>,
    repo: Arc<UserRepository>,
}

impl UserService {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self {
            pool: pool.clone(),
            repo: Arc::new(pool.into()),
        }
    }

    // ── Password login ────────────────────────────────────────────────────────

    /// Validate credentials and issue a token pair.
    pub async fn password_login(&self, cmd: PasswordLoginCmd) -> Result<User, AuthError> {
        if cmd.username.is_empty() || cmd.password.is_empty() {
            return Err(AuthError::MissingCredentials);
        }

        let user = self.get_user_by_email(&cmd.username).await?;

        match bcrypt::verify(&cmd.password, &user.password_hash) {
            Ok(true) => {}
            Ok(false) => return Err(AuthError::InvalidCredentials),
            Err(e) => return Err(AuthError::Bcrypt(e)),
        }
        Ok(user)
    }

    pub async fn username_login(&self, cmd: PasswordLoginCmd) -> Result<User, AuthError> {
        if cmd.username.is_empty() || cmd.password.is_empty() {
            return Err(AuthError::MissingCredentials);
        }

        let user = self.get_user_by_username(&cmd.username).await?;

        match bcrypt::verify(&cmd.password, &user.password_hash) {
            Ok(true) => {}
            Ok(false) => return Err(AuthError::InvalidCredentials),
            Err(e) => return Err(AuthError::Bcrypt(e)),
        }
        Ok(user)
    }

    // ── Registration ──────────────────────────────────────────────────────────

    /// Hash the password and create a new user row.
    ///
    /// Returns the new user's ID so callers can optionally auto-login.
    pub async fn register(&self, username: &str, password: &str) -> Result<(), AuthError> {
        if username.is_empty() || password.is_empty() {
            return Err(AuthError::MissingCredentials);
        }
        let entropy = zxcvbn(password, &[]);
        if entropy.score() < u8::try_into(3).unwrap() {
            return Err(AuthError::PasswordTooShort);
        }

        let hash = bcrypt::hash(password, 10)?;
        let _user = self.create_user(username, &hash).await?;

        Ok(())
    }

    // ── Change password ───────────────────────────────────────────────────────

    /// Verify the current password, set a new one, and revoke all sessions.
    pub async fn change_password(&self, cmd: ChangePasswordCmd) -> Result<(), AuthError> {
        let entropy = zxcvbn(&cmd.new_password, &[]);
        if entropy.score() < u8::try_into(3).unwrap() {
            return Err(AuthError::PasswordTooShort);
        }

        let user = self.get_user_by_id(&cmd.user_id).await?;

        let valid = bcrypt::verify(&cmd.current_password, &user.password_hash).unwrap_or(false);
        if !valid {
            return Err(AuthError::InvalidCredentials);
        }

        let new_hash = bcrypt::hash(&cmd.new_password, 10)?;

        sqlx::query!(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            new_hash,
            cmd.user_id.to_string()
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Password reset (request) ──────────────────────────────────────────────

    /// Generate and store a reset token. Always returns `Ok` even if the
    /// user is not found (prevents email enumeration).
    pub async fn request_password_reset(&self, cmd: RequestPasswordResetCmd) {
        // Look up by email column in the `emails` table.
        let user_id: Option<String> =
            sqlx::query_scalar!("SELECT id FROM users WHERE email = $1", cmd.email)
                .fetch_optional(&self.pool)
                .await
                .unwrap_or(None);

        let user_id = match user_id {
            Some(id) => id,
            None => return, // silent – do not leak whether address is registered
        };

        let raw = generate_raw_token();
        let hash = hash_token(&raw);
        let expires_at = Utc::now() + chrono::Duration::minutes(30);
        let id = Uuid::new_v4().to_string();

        let _ = sqlx::query!(
            "INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
            id,
            user_id,
            hash,
            expires_at
        )
        .execute(&self.pool)
        .await;

        // In production: hand `raw` to your email service here.
        tracing::info!("Password reset token for {}: {}", cmd.email, raw);
    }

    // ── Password reset (confirm) ──────────────────────────────────────────────

    /// Validate the reset token, apply the new password, and revoke sessions.
    pub async fn confirm_password_reset(
        &self,
        cmd: ConfirmPasswordResetCmd,
    ) -> Result<Uuid, AuthError> {
        let token_hash = hash_token(&cmd.token);

        let reset = sqlx::query_as!(
            PasswordReset,
            r#"
            SELECT
                id          as "id!",
                user_id     as "user_id!: Uuid",
                expires_at  as "expires_at!: chrono::DateTime<chrono::Utc>",
                used        as "used!" 
            FROM password_resets
            WHERE token_hash = $1 AND used = FALSE
            "#,
            token_hash
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthError::InvalidToken)?;

        if reset.used || reset.expires_at < Utc::now() {
            return Err(AuthError::InvalidToken);
        }

        let new_hash = bcrypt::hash(&cmd.new_password, 10)?;
        let now = Utc::now();
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            "UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3",
            new_hash,
            now,
            reset.user_id.to_string()
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "UPDATE password_resets SET used = TRUE WHERE id = $1",
            reset.id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(reset.user_id)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User, AuthError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id          as "id!: Uuid",
                username    as "username!",
        email,
                password_hash as "password_hash!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at  as "updated_at!: chrono::DateTime<chrono::Utc>"
            FROM users WHERE username = $1
            "#,
            username
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthError::InvalidCredentials) // mask whether user exists
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<User, AuthError> {
        match sqlx::query_as!(
            User,
            r#"
            SELECT
                id          as "id!: Uuid",
                username    as "username!",
        email,
                password_hash as "password_hash!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at  as "updated_at!: chrono::DateTime<chrono::Utc>"
            FROM users WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        {
            Ok(r) => match r {
                Some(r) => Ok(r),
                None => Err(AuthError::InvalidCredentials),
            },
            Err(e) => {
                tracing::warn!("Error in getting user by email: {e}");
                Err(AuthError::Database(e))
            }
        }
    }

    pub async fn get_user_by_id(&self, id: &Uuid) -> Result<User, AuthError> {
        self.repo
            .retrieve(id)
            .await
            .map_err(|_| AuthError::UserNotFound)
    }

    async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, AuthError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, username, password_hash, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING
                id          as "id!: Uuid",
                username    as "username!",
        email,
                password_hash as "password_hash!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at  as "updated_at!: chrono::DateTime<chrono::Utc>"
            "#,
            id,
            username,
            password_hash,
            now,
            now
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => AuthError::UserAlreadyExists,
            _ => AuthError::Database(e),
        })
    }
}
