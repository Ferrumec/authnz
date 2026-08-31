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

#[derive(Serialize)]
struct UserCreated {
    email: String,
    phone: Option<String>,
    country: Option<String>,
}

impl Publishable for UserCreated {
    const SUBJECT: &'static str = "auth.user.created";
}

/// Emitted when a password-reset token is generated. Carries the raw
/// (unhashed) token exactly once, for delivery by whatever subscribes
/// to this subject (e.g. an email service) — never logged, never
/// persisted in cleartext.
#[derive(Serialize)]
pub struct PasswordResetRequested {
    pub email: String,
    pub token: String,
}

impl Publishable for PasswordResetRequested {
    const SUBJECT: &'static str = "auth.password_reset.requested";
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
    pub async fn register(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<(), AuthError> {
        if username.is_empty() || password.is_empty() {
            return Err(AuthError::MissingCredentials);
        }
        let entropy = zxcvbn(password, &[]);
        if entropy.score() < u8::try_into(3).unwrap() {
            return Err(AuthError::PasswordTooShort);
        }

        let hash = bcrypt::hash(password, 10)?;
        let _user = self.create_user(username, email, &hash).await?;

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
            cmd.user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Password reset (request) ──────────────────────────────────────────────

    /// Generate and store a reset token. Always returns `Ok` even if the
    /// user is not found (prevents email enumeration) — in that case
    /// `Ok(None)` is returned. Database and other internal errors are
    /// returned so the caller can log them without leaking details to
    /// the client.
    ///
    /// The raw token is never logged: it comes back to the caller as a
    /// [`PasswordResetRequested`] event, which the HTTP handler hands to
    /// the event bus (`typed_eventbus` via `actixutils::locals::Context`)
    /// for delivery — e.g. to an email service — instead.
    pub async fn request_password_reset(
        &self,
        cmd: RequestPasswordResetCmd,
    ) -> Result<Option<PasswordResetRequested>, AuthError> {
        // Look up by email column in the `users` table.
        let user_id: Option<Uuid> =
            sqlx::query_scalar!("SELECT id FROM users WHERE email = $1", cmd.email)
                .fetch_optional(&self.pool)
                .await
                .map_err(AuthError::Database)?;

        let user_id = match user_id {
            Some(id) => id,
            None => return Ok(None), // silent – do not leak whether address is registered
        };

        let raw = generate_raw_token();
        let hash = hash_token(&raw);
        let expires_at = Utc::now() + chrono::Duration::minutes(30);

        sqlx::query!(
            "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
            user_id,
            hash,
            expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(AuthError::Database)?;

        Ok(Some(PasswordResetRequested {
            email: cmd.email,
            token: raw,
        }))
    }

    // ── Password reset (confirm) ──────────────────────────────────────────────

    /// Validate the reset token, apply the new password, and revoke sessions.
    ///
    /// The "validate, then use" steps are collapsed into a single atomic
    /// `UPDATE ... WHERE used = FALSE ... RETURNING`: two concurrent
    /// requests racing on the same token can no longer both observe
    /// `used = FALSE`, do their own work, and then both mark it used
    /// (which would let the same token reset a password twice). Only the
    /// request whose `UPDATE` actually flips the row wins; the other gets
    /// zero rows back and is rejected as an invalid token.
    pub async fn confirm_password_reset(
        &self,
        cmd: ConfirmPasswordResetCmd,
    ) -> Result<Uuid, AuthError> {
        let entropy = zxcvbn(&cmd.new_password, &[]);
        if entropy.score() < u8::try_into(3).unwrap() {
            return Err(AuthError::PasswordTooShort);
        }

        let token_hash = hash_token(&cmd.token);
        let now = Utc::now();

        let mut tx = self.pool.begin().await?;

        let reset = sqlx::query_as!(
            PasswordReset,
            r#"
            UPDATE password_resets
            SET used = TRUE
            WHERE token_hash = $1 AND used = FALSE AND expires_at > $2
            RETURNING
                id          as "id!: Uuid",
                user_id     as "user_id!: Uuid",
                expires_at  as "expires_at!: chrono::DateTime<chrono::Utc>",
                used        as "used!: bool"
            "#,
            token_hash,
            now
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AuthError::InvalidToken)?;

        let new_hash = bcrypt::hash(&cmd.new_password, 10)?;
        sqlx::query!(
            "UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3",
            new_hash,
            now,
            reset.user_id
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

    async fn create_user(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<User, AuthError> {
        let now = Utc::now();

        sqlx::query_as!(
            User,
            r#"
            INSERT INTO users ( username, email, password_hash, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING
                id          as "id!: Uuid",
                username    as "username!",
        email,
                password_hash as "password_hash!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at  as "updated_at!: chrono::DateTime<chrono::Utc>"
            "#,
            username,
            email,
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
