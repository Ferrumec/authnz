use crate::authz::admin::{AbsoluteRepo, Perm, PermRepo};
use crate::authz::models::Permission;
use crate::authz::models::{PermissionReq, perm2permission, permission2perm};
use sqlx::{Error as SqlxError, Pool, Postgres, query_as};
use std::sync::Arc;
use uuid::Uuid;
use viewset::Repository;

pub enum GetTokenError {
    Sqlx(SqlxError),
}

impl From<SqlxError> for GetTokenError {
    fn from(value: SqlxError) -> Self {
        GetTokenError::Sqlx(value)
    }
}

fn parse_role(s: String) -> Result<u128, SqlxError> {
    s.parse()
        .map_err(|_| SqlxError::Decode("invalid role bitmask".into()))
}

pub enum CreateTenantTokenError {
    NoPermission,
    Sqlx(SqlxError),
}

impl From<SqlxError> for CreateTenantTokenError {
    fn from(value: SqlxError) -> Self {
        CreateTenantTokenError::Sqlx(value)
    }
}

#[derive(Debug)]
pub enum AdminError {
    Sqlx(SqlxError),
    /// The caller's token is not a super-admin token scoped to this namespace.
    Forbidden,
}

impl From<SqlxError> for AdminError {
    fn from(value: SqlxError) -> Self {
        AdminError::Sqlx(value)
    }
}

#[derive(Clone)]
pub struct Service {
    pub db: Pool<Postgres>,
    pub absolute_repo: Arc<AbsoluteRepo>,
    pub perm_repo: Arc<PermRepo>,
}

impl Service {
    pub async fn get_permission(&self, name: String) -> Result<Option<Permission>, SqlxError> {
        let perm = match self
            .perm_repo
            .retrieve(&name)
            .await
        {
            Ok(list ) => list,
            Err(_) => return Ok(None),
        };
        Ok(Some(perm2permission(perm)))
    }

    pub async fn get_absolute_role(&self, to_id: &Uuid) -> Result<u128, SqlxError> {
        match self.absolute_repo.retrieve(to_id).await {
            Ok(grant) => Ok(parse_role(grant.role)?),
            Err(_) => return Ok(0),
        }
    }

    async fn insert_absolute_role(&self, to_id: &Uuid, role: u128) -> Result<(), SqlxError> {
        let role = role.to_string();
        sqlx::query!(
            r#"
        INSERT INTO absolutes (to_id, role)
        VALUES ($1, $2)
        ON CONFLICT(to_id, aud) DO UPDATE SET role = absolutes.role || excluded.role
        "#,
            to_id,
            role
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn update_absolute_role(&self, to_id: &Uuid, role: u128) -> Result<(), SqlxError> {
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

    pub async fn list_permissions(&self, user: Uuid) -> Result<Vec<Perm>, SqlxError> {
        let perms = query_as!(Perm, "SELECT name, value FROM permissions",)
            .fetch_all(&self.db)
            .await?;
        let role = self.get_absolute_role(&user).await?;

        let permissions: Vec<Perm> = perms
            .iter()
            // Convert perms to permissions
            .map(|p| perm2permission(p.clone()))
            // Filter for the current role
            .filter(|p| role & p.value == p.value)
            // Convert back to perms
            .map(|p| permission2perm(p.clone()))
            .collect();

        Ok(permissions)
    }

    /// Grants `request.target` the permission in `request`, unconditionally.
    /// Callers MUST verify the caller is actually authorized (e.g. via
    /// `is_admin_for`) before calling this — it performs no auth check itself.
    async fn admin_grant_unchecked(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        // Validate permission
        let perm = match self.get_permission(request.permission).await? {
            Some(p) => p,
            None => {
                println!("Invalid permission");
                return Ok(None);
            }
        };
        let current_role = self.get_absolute_role(&request.target).await?;

        let new_role = current_role | perm.value;
        // Grant the permission
        self.insert_absolute_role(&request.target, new_role).await?;

        Ok(Some(new_role))
    }

    /// Revokes the permission in `request` from `request.target`'s absolute role.
    /// Same caveat as `admin_grant_unchecked`: no auth check performed here.
    async fn admin_deny_unchecked(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, SqlxError> {
        let perm = match self.get_permission(request.permission).await? {
            Some(p) => p,
            None => return Ok(None),
        };

        let role = self.get_absolute_role(&request.target).await?;

        if role & perm.value == 0 {
            return Ok(None);
        }

        let role = role & !perm.value;
        self.update_absolute_role(&request.target, role).await?;

        Ok(Some(role))
    }

    /// Grant a permission as admin. Requires a super-admin token scoped to
    /// `request.namespace` (checked via `is_admin_for`).
    pub async fn admin_grant_permission(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, AdminError> {
        Ok(self.admin_grant_unchecked(request).await?)
    }

    /// Deny (revoke) a permission as admin. Requires a super-admin token scoped
    /// to `request.namespace`.
    pub async fn admin_deny_permission(
        &self,
        request: PermissionReq,
    ) -> Result<Option<u128>, AdminError> {
        Ok(self.admin_deny_unchecked(request).await?)
    }
}
