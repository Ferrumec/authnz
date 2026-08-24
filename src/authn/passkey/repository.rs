//! Database access for stored passkey credentials.
//!
//! A `Passkey` (public key, sign counter, transport hints, etc — no
//! private key material ever leaves the authenticator) is serialized to
//! JSON and stored per-user. This is the same pattern `webauthn-rs`'s own
//! examples use for persisting credentials between requests.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("stored passkey credential could not be decoded")]
    Corrupt,
}

/// Metadata about a stored credential, safe to hand back to the client
/// (never includes the credential's public key material).
#[derive(Serialize)]
pub struct CredentialSummary {
    pub id: Uuid,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

fn credential_id_b64(passkey: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(passkey.cred_id())
}

pub struct CredsRepo {
    pool: PgPool,
}

impl CredsRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Persist a newly registered credential for a user.
    pub async fn insert_credential(
        &self,
        user_id: Uuid,
        passkey: &Passkey,
        label: Option<&str>,
    ) -> Result<(), RepoError> {
        let id = Uuid::new_v4().to_string();
        let user_id = user_id.to_string();
        let credential_id = credential_id_b64(passkey);
        let data = serde_json::to_string(passkey).map_err(|_| RepoError::Corrupt)?;
        let now = Utc::now();

        sqlx::query!(
        r#"
        INSERT INTO passkey_credentials (id, user_id, credential_id, passkey_data, label, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        id,
        user_id,
        credential_id,
        data,
        label,
        now,
    )
    .execute(&self.pool)
    .await?;

        Ok(())
    }

    /// Load every credential registered for a user — used both to build the
    /// WebAuthn "allow list" at login time and to exclude already-registered
    /// authenticators when starting a new registration.
    pub async fn credentials_for_user(&self, user_id: Uuid) -> Result<Vec<Passkey>, RepoError> {
        let user_id = user_id.to_string();
        let rows = sqlx::query!(
            r#"SELECT passkey_data as "passkey_data!" FROM passkey_credentials WHERE user_id = $1"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                serde_json::from_str::<Passkey>(&r.passkey_data).map_err(|_| RepoError::Corrupt)
            })
            .collect()
    }

    /// Re-persist a credential after a successful login. WebAuthn tracks a
    /// per-credential signature counter so cloned authenticators can be
    /// detected; this must be saved back or that protection is lost.
    pub async fn update_credential(&self, passkey: &Passkey) -> Result<(), RepoError> {
        let credential_id = credential_id_b64(passkey);
        let data = serde_json::to_string(passkey).map_err(|_| RepoError::Corrupt)?;
        let now = Utc::now();

        sqlx::query!(
        "UPDATE passkey_credentials SET passkey_data = $1, last_used_at = $2 WHERE credential_id = $3",
        data,
        now,
        credential_id
    )
    .execute(&self.pool)
    .await?;

        Ok(())
    }

    /// List a user's registered passkeys (metadata only) for an account
    /// settings / "manage your passkeys" page.
    pub async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<CredentialSummary>, RepoError> {
        let user_id = user_id.to_string();
        let rows = sqlx::query!(
            r#"
        SELECT
            id            as "id!: Uuid",
            label,
            created_at    as "created_at!: DateTime<Utc>",
            last_used_at  as "last_used_at: DateTime<Utc>"
        FROM passkey_credentials
        WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| CredentialSummary {
                id: r.id,
                label: r.label,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
            })
            .collect())
    }

    /// Remove one of a user's passkeys by its row id. Scoped to `user_id` so a
    /// user can never delete someone else's credential. Returns `true` if a
    /// row was actually deleted.
    pub async fn delete_credential(
        &self,
        user_id: Uuid,
        credential_row_id: Uuid,
    ) -> Result<bool, RepoError> {
        let credential_row_id = credential_row_id.to_string();
        let user_id = user_id.to_string();
        let result = sqlx::query!(
            "DELETE FROM passkey_credentials WHERE id = $1 AND user_id = $2",
            credential_row_id,
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
