use crate::authz::admin::{AbsoluteViewSet, PermViewSet};
use crate::authz::models::Permission;
use crate::authz::{
    handlers::*,
    models::{AppState, CapacityError, LoadError, PermissionSet, ReadError},
    services::Service,
};
use actix_web::web::{self, ServiceConfig};
use sqlx::{Error, Pool, Postgres};
use std::{convert::From, env::VarError, sync::Arc};
use viewset::ViewSet;

#[derive(Clone)]
pub struct AuthorizModule {
    state: web::Data<AppState>,
    absolute_viewset: Arc<AbsoluteViewSet>,
    perm_viewset: Arc<PermViewSet>,
}

#[derive(Debug)]
pub enum AddPermsError {
    Sqlx(Error),
    CapacityError(CapacityError),
    DataCorruption,
}

impl From<LoadError> for AddPermsError {
    fn from(value: LoadError) -> Self {
        match value {
            LoadError::Sqlx(error) => AddPermsError::Sqlx(error),
            LoadError::Capacity(capacity_error) => AddPermsError::CapacityError(capacity_error),
            LoadError::CorruptedData => AddPermsError::DataCorruption,
        }
    }
}

impl From<Error> for AddPermsError {
    fn from(value: Error) -> Self {
        AddPermsError::Sqlx(value)
    }
}

impl From<CapacityError> for AddPermsError {
    fn from(value: CapacityError) -> Self {
        AddPermsError::CapacityError(value)
    }
}

pub enum InitError {
    DbConnection(Error),
    DbInit(Error),
    Secret(VarError),
    Permissions(ReadError),
}

impl AuthorizModule {
    pub fn new(db: Pool<Postgres>) -> Self {
        Self {
            state: web::Data::new(AppState {
                service: Service {
                    db: db.clone(),
                    perm_repo: Arc::new(db.clone().into()),
                    absolute_repo: Arc::new(db.clone().into()),
                },
            }),
            absolute_viewset: Arc::new(db.clone().into()),
            perm_viewset: Arc::new(db.clone().into()),
        }
    }

    /// Adds permissions to the permission namespace provided.
    /// The permissions are added to the database for granting.
    /// Returns a vector of permissions added, or,
    /// Returns an error if the namespace capacity is not enough
    pub async fn add_permissions(
        &self,
        permissions: Vec<String>,
    ) -> Result<Vec<Permission>, AddPermsError> {
        let mut set = PermissionSet::load_from_db(&self.state.service.db)
            .await
            .unwrap();
        let perms = set.add_new(permissions, &self.state.service.db).await?;

        Ok(perms)
    }
    pub fn config(&self, cfg: &mut ServiceConfig, namespace: &str) {
        cfg.service(
            web::scope(namespace)
                .app_data(self.state.clone())
                .service(list_permissions)
                .service(claim_admin)
                .service(admin_grant_permission)
                .service(admin_deny_permission)
                .service(
                    web::scope("admin")
                        .configure(|cfg| self.absolute_viewset.clone().configure(cfg, "absolutes"))
                        .configure(|cfg| self.perm_viewset.clone().configure(cfg, "perm")),
                ),
        );
    }
}
