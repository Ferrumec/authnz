use crate::authz::admin::AbsoluteViewSet;
use crate::authz::{handlers::*, models::AppState, services::Service};
use crate::models::User;
use actix_web::web::{self, ServiceConfig};
use actixutils::middleware::{PermissionSet, Permissions};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use viewset::ViewSet;

#[derive(Clone)]
pub struct AuthorizModule {
    state: web::Data<AppState>,
    absolute_viewset: Arc<AbsoluteViewSet>,
}

impl AuthorizModule {
    pub fn new(db: Pool<Postgres>) -> Self {
        Self {
            state: web::Data::new(AppState {
                service: Service {
                    db: db.clone(),
                    absolute_repo: Arc::new(db.clone().into()),
                },
            }),
            absolute_viewset: Arc::new(db.clone().into()),
        }
    }

    /// `claim_admin` stays outside the Permissions gate so any logged-in user
    /// can attempt it (and receive 404 / 406 when they are not the configured
    /// ADMIN). Grant / deny / grants viewset remain permission-checked.
    pub fn config_with_permissions(
        &self,
        cfg: &mut ServiceConfig,
        namespace: &str,
        permissions: PermissionSet,
    ) {
        cfg.service(
            web::scope(namespace)
                .app_data(self.state.clone())
                .service(claim_admin)
                .service(
                    web::scope("")
                        .wrap(Permissions::<User>::new(permissions))
                        .service(admin_grant_permission)
                        .service(admin_deny_permission)
                        .service(
                            web::scope("admin").configure(|cfg| {
                                self.absolute_viewset.clone().configure(cfg, "grants")
                            }),
                        ),
                ),
        );
    }
}
