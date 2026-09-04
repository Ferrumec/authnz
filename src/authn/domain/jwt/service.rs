//! The single authoritative home for all jwt authentication business logic.
//!
//! HTTP handlers are thin wrappers: parse → call JwtService → map to HTTP.
//! No database queries and no crypto live outside this module and its
//! submodules.

use super::JwtError as AuthError;
use super::models::{JwtResult, LogoutCmd, RefreshCmd, RefreshTokenRow};
use crate::authn::admin::UserRepository;
use crate::authn::domain::user::token::{generate_raw_token, hash_token};
use actixutils::{Identity, Sign};
use chrono::Utc;
use sqlx::{Executor, Pool, Postgres};
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
pub struct JwtService {
    pool: Pool<Postgres>,
    signer: Arc<dyn Sign<Identity>>,
    aud: Vec<String>,
    user_repo: Arc<UserRepository>,
}

impl JwtService {
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
    /// The old refresh token is deleted and a new pair is issued inside a
    /// single database transaction. If anything fails before commit, the
    /// old token remains valid and can be replayed (by design).
    pub async fn refresh(&self, cmd: RefreshCmd) -> Result<JwtResult, AuthError> {
        let raw = cmd.refresh_token.trim();
        if raw.is_empty() {
            return Err(AuthError::MissingRefreshToken);
        }

        let hash = hash_token(raw);
        let mut tx = self.pool.begin().await?;

        let row = self.get_refresh_token_by_hash(&mut *tx, &hash).await?;

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

        // Rotation: delete old token and issue fresh pair atomically.
        self.delete_refresh_token_by_hash(&mut *tx, &hash).await?;
        let result = self
            .issue_token_pair_with(&mut *tx, user.id, &row.issuer)
            .await?;

        tx.commit().await?;
        Ok(result)
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
    pub async fn issue_for_passwordless(&self, user_id: Uuid) -> Result<JwtResult, AuthError> {
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
    ) -> Result<JwtResult, AuthError> {
        self.issue_token_pair_with(&self.pool, user_id, issuer)
            .await
    }

    /// Generic backing for `issue_token_pair` so it can run inside a tx.
    async fn issue_token_pair_with<'e, E>(
        &self,
        executor: E,
        user_id: Uuid,
        issuer: &str,
    ) -> Result<JwtResult, AuthError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let access_token = self
            .signer
            .sign(&Identity::new(user_id, self.aud.clone()))
            .map_err(|e| AuthError::TokenSigning(e.to_string()))?;

        let raw_refresh = generate_raw_token();
        let token_hash = hash_token(&raw_refresh);

        let expires_at = Utc::now() + chrono::Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);
        let now = Utc::now();

        sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (user_id, token_hash, issuer, expires_at, revoked, created_at)
            VALUES ($1, $2, $3, $4, FALSE, $5)
            "#,
            user_id,
            token_hash,
            issuer,
            expires_at,
            now
        )
        .execute(executor)
        .await?;

        Ok(JwtResult {
            access_token,
            refresh_token: raw_refresh, // raw token returned to client, never stored
            expires_in: 600,
        })
    }

    async fn get_refresh_token_by_hash<'e, E>(
        &self,
        executor: E,
        hash: &str,
    ) -> Result<RefreshTokenRow, AuthError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
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
        .fetch_one(executor)
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
    async fn delete_refresh_token_by_hash<'e, E>(
        &self,
        executor: E,
        hash: &str,
    ) -> Result<(), AuthError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query!("DELETE FROM refresh_tokens WHERE token_hash = $1", hash)
            .execute(executor)
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
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
