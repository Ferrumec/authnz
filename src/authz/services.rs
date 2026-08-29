use crate::authz::admin::AbsoluteRepo;
use crate::authz::models::PermissionReq;
use sqlx::{Error as SqlxError, Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;
use viewset::Repository;

#[derive(Clone)]
pub struct Service {
    pub db: Pool<Postgres>,
    pub absolute_repo: Arc<AbsoluteRepo>,
}

impl Service {
    pub async fn get_role(&self, to_id: &Uuid) -> Result<u128, SqlxError> {
        match self.absolute_repo.retrieve(to_id).await {
            Ok(grant) => Ok(grant.role.as_u128()),
            Err(_e) => Err(SqlxError::RowNotFound),
        }
    }

    async fn insert_role(&self, to_id: &Uuid, role: u128) -> Result<(), SqlxError> {
        let role = role.to_string();
        sqlx::query!(
            r#"
        INSERT INTO absolutes (to_id, role)
        VALUES ($1, $2)
        ON CONFLICT(to_id) DO UPDATE SET role = excluded.role
        "#,
            to_id,
            role
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn update_role(&self, to_id: &Uuid, role: u128) -> Result<(), SqlxError> {
        let role = role.to_string();
        sqlx::query!(
            r#"UPDATE absolutes SET role = $1 WHERE to_id = $2"#,
            role,
            to_id
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Grants `request.target` the permission in `request`, unconditionally.
    /// Callers MUST verify the caller is actually authorized (e.g. via
    /// `is_admin_for`) before calling this — it performs no auth check itself.
    async fn admin_grant_unchecked(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        // Validate permission
        if request.permission > 127 {
            return Ok(None);
        }
        let perm_value = 1 << request.permission;
        let current_role = self.get_role(&request.target).await?;

        let new_role = current_role | perm_value;
        // Grant the permission
        self.insert_role(&request.target, new_role).await?;

        Ok(Some(new_role))
    }

    /// Revokes the permission in `request` from `request.target`'s absolute role.
    /// Same caveat as `admin_grant_unchecked`: no auth check performed here.
    async fn admin_deny_unchecked(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        if request.permission > 127 {
            return Ok(None);
        }
        let perm_value = 1 << request.permission;

        let role = self.get_role(&request.target).await?;

        let role = role & !perm_value;
        self.update_role(&request.target, role).await?;

        Ok(Some(role))
    }

    /// Grant a permission as admin. Requires a super-admin token scoped to
    /// `request.namespace` (checked via `is_admin_for`).
    pub async fn admin_grant_permission(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        Ok(self.admin_grant_unchecked(request).await?)
    }

    /// Deny (revoke) a permission as admin. Requires a super-admin token scoped
    /// to `request.namespace`.
    pub async fn admin_deny_permission(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        Ok(self.admin_deny_unchecked(request).await?)
    }
}
