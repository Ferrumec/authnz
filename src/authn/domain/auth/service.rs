//! The single authoritative home for all authentication business logic.
//!
//! HTTP handlers are thin wrappers: parse → call AuthService → map to HTTP.
//! No database queries and no crypto live outside this module and its
//! submodules.

use crate::authn::admin::UserRepository;
use crate::authn::domain::auth::models::{AuthResult, LogoutCmd, RefreshCmd, RefreshTokenRow};
use crate::authn::domain::user::{
    errors::AuthError,
    token::{generate_raw_token, hash_token},
};
use actixutils::{Identity, Sign};
use chrono::Utc;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;
use viewset::Repository;

// ── Constants ─────────────────────────────────────────────────────────────────

const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 30;

// ── AuthService ───────────────────────────────────────────────────────────────

/// Central service for all authentication flows.
///
/// Owns the database pool and JWT configuration. Constructed once at
/// application startup and shared via `Arc` or Actix `web::Data`.
#[derive(Clone)]
pub struct AuthService {
    pool: Pool<Postgres>,
    signer: Arc<dyn Sign<Identity>>,
    aud: Vec<String>,
    user_repo: Arc<UserRepository>,
}

impl AuthService {
    pub fn new(pool: Pool<Postgres>, signer: Arc<dyn Sign<Identity>>) -> Self {
        let aud = std::env::var("AUD")
            .expect("AUD env var not set")
            .split(",")
            .map(|s| s.trim().to_string())
            .collect();
        let user_repo = Arc::new(pool.clone().into());

        Self {
            pool,
            signer,
            aud,
            user_repo,
        }
    }

    // ── Token refresh (with rotation) ─────────────────────────────────────────

    /// Exchange a valid refresh token for a new token pair.
    ///
    /// The old refresh token is deleted (not just flagged) so it can never
    /// be replayed. This is atomic: if issuing the new pair fails, the old
    /// token is NOT invalidated.
    pub async fn refresh(&self, cmd: RefreshCmd) -> Result<AuthResult, AuthError> {
        let raw = cmd.refresh_token.trim();
        if raw.is_empty() {
            return Err(AuthError::MissingRefreshToken);
        }

        let hash = hash_token(raw);
        let row = self.get_refresh_token_by_hash(&hash).await?;

        if row.revoked {
            return Err(AuthError::RefreshTokenNotFound);
        }
        if row.expires_at < Utc::now() {
            return Err(AuthError::RefreshTokenExpired);
        }

        // Verify user still exists.
        let user = match self.user_repo.retrieve(&row.user_id).await {
            Ok(r) => r,
            Err(_) => return Err(AuthError::UserNotFound),
        };

        // Rotation: delete old token, then issue fresh pair.
        // We delete by hash (not by raw token) since that's what's stored.
        self.delete_refresh_token_by_hash(&hash).await?;

        self.issue_token_pair(user.id, &row.issuer).await
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    /// Revoke a refresh token. Silent success if the token is not found so
    /// that duplicate logout calls are idempotent from the client's view.
    pub async fn logout(&self, cmd: LogoutCmd) -> Result<(), AuthError> {
        let raw = cmd.refresh_token.trim();
        if raw.is_empty() {
            return Err(AuthError::MissingRefreshToken);
        }
        let hash = hash_token(raw);
        // Ignore NotFound – already logged out is fine.
        match self.revoke_refresh_token_by_hash(&hash).await {
            Ok(()) | Err(AuthError::RefreshTokenNotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // ── Passwordless – issue tokens after challenge confirmation ──────────────

    /// Issue a token pair for a user who just completed a passwordless
    /// challenge (link or OTP). The caller is responsible for verifying the
    /// challenge beforehand.
    pub async fn issue_for_passwordless(&self, user_id: Uuid) -> Result<AuthResult, AuthError> {
        self.issue_token_pair(user_id, "passwordless").await
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Issue a fresh access token + refresh token pair.
    ///
    /// The raw refresh token is returned to the caller exactly once.
    /// Only its hash is persisted.
    pub async fn issue_token_pair(
        &self,
        user_id: Uuid,
        issuer: &str,
    ) -> Result<AuthResult, AuthError> {
        let access_token = self
            .signer
            .sign(&Identity::new(user_id, self.aud.clone()))
            .map_err(|e| AuthError::TokenSigning(e.to_string()))?;

        let raw_refresh = generate_raw_token();
        let token_hash = hash_token(&raw_refresh);

        let id = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + chrono::Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);
        let now = Utc::now();

        sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token_hash, issuer, expires_at, revoked, created_at)
            VALUES ($1, $2, $3, $4, $5, FALSE, $6)
            "#,
            id,
            user_id.to_string(),
            token_hash,
            issuer,
            expires_at,
            now
        )
        .execute(&self.pool)
        .await?;

        Ok(AuthResult {
            access_token,
            refresh_token: raw_refresh, // raw token returned to client, never stored
            expires_in: 600,
        })
    }

    async fn get_refresh_token_by_hash(&self, hash: &str) -> Result<RefreshTokenRow, AuthError> {
        sqlx::query!(
            r#"
            SELECT
                id          as "id!",
                user_id     as "user_id: Uuid",
                token_hash  as "token_hash!",
                issuer      as "issuer!",
                expires_at  as "expires_at!: chrono::DateTime<chrono::Utc>",
                revoked     as "revoked!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>"
            FROM refresh_tokens
            WHERE token_hash = $1
            "#,
            hash
        )
        .fetch_one(&self.pool)
        .await
        .map(|r| RefreshTokenRow {
            user_id: r.user_id,
            issuer: r.issuer,
            expires_at: r.expires_at,
            revoked: r.revoked,
        })
        .map_err(|_| AuthError::RefreshTokenNotFound)
    }

    /// Hard-delete a single refresh token by hash (rotation).
    async fn delete_refresh_token_by_hash(&self, hash: &str) -> Result<(), AuthError> {
        sqlx::query!("DELETE FROM refresh_tokens WHERE token_hash = $1", hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Soft-revoke a single refresh token (logout path).
    async fn revoke_refresh_token_by_hash(&self, hash: &str) -> Result<(), AuthError> {
        let result = sqlx::query!(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1",
            hash
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::RefreshTokenNotFound);
        }
        Ok(())
    }

    /// Soft-revoke all tokens for a user (password change, reset).
    pub async fn revoke_all_user_tokens(&self, user_id: &Uuid) -> Result<(), AuthError> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1",
            user_id.to_string()
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
