use crate::authz::admin::AbsoluteViewSet;
use crate::authz::{handlers::*, models::AppState, services::Service};
use actix_web::web::{self, ServiceConfig};
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

    pub fn config(&self, cfg: &mut ServiceConfig, namespace: &str) {
        cfg.service(
            web::scope(namespace)
                .app_data(self.state.clone())
                .service(claim_admin)
                .service(admin_grant_permission)
                .service(admin_deny_permission)
                .service(
                    web::scope("admin")
                        .configure(|cfg| self.absolute_viewset.clone().configure(cfg, "grants")),
                ),
        );
    }
}
