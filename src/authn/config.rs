use crate::authn::admin::create_viewset;
#[cfg(feature = "passkey")]
use crate::authn::passkey;
use crate::authn::{auth2::AppState, handlers, passwdless::config, user_id::username2userid};
use crate::models::User as ActiveUser;
use crate::models::User;
use actix_web::web::{self, ServiceConfig};
use actixutils::Store;
use actixutils::middleware::{PermissionSet, Permissions, SessionMiddleware};
use sqlx::{Error, Pool, Postgres};
use std::{env::VarError, sync::Arc};
use uuid::Uuid;
use viewset::ViewSet;

#[derive(Clone)]
pub struct AuthModule {
    state: web::Data<AppState>,
    session_store: Arc<dyn Store<Uuid, ActiveUser>>,
    permissions: PermissionSet,
}

#[derive(Debug)]
pub enum SetupError {
    Db(Error),
    Var(VarError),
}

impl ToString for SetupError {
    fn to_string(&self) -> String {
        match self {
            SetupError::Db(error) => error.to_string(),
            SetupError::Var(var_error) => var_error.to_string(),
        }
    }
}

impl From<VarError> for SetupError {
    fn from(value: VarError) -> Self {
        SetupError::Var(value)
    }
}

impl From<Error> for SetupError {
    fn from(value: Error) -> Self {
        SetupError::Db(value)
    }
}

impl AuthModule {
    pub async fn new(
        pool: Pool<Postgres>,
        session_store: Arc<dyn Store<Uuid, ActiveUser>>,
        permissions: PermissionSet,
    ) -> Self {
        let app_state = AppState::new(pool.clone()).await;
        Self {
            state: web::Data::new(app_state),
            session_store,
            permissions,
        }
    }
    pub fn config(&self, cfg: &mut ServiceConfig, namespace: &str) {
        let session_middleware: SessionMiddleware<ActiveUser> =
            SessionMiddleware::required(self.session_store.clone());
        #[cfg_attr(not(feature = "passkey"), allow(unused_mut))]
        let mut scope =
            web::scope(namespace)
                // `username2userid` and the `/passwordless` handlers extract
                // `web::Data<AppState>` directly, so the shared state needs to
                // be registered here too, not just the `AuthService` slice of it.
                .app_data(self.state.clone())
                .service(username2userid)
                .service(
                    web::scope("/auth")
                        .route("/register", web::post().to(handlers::register))
                        .route("/login/email", web::post().to(handlers::login))
                        .route("/login/username", web::post().to(handlers::username_login))
                        .route(
                            "/request_password_reset",
                            web::post().to(handlers::request_password_reset),
                        )
                        .route(
                            "/confirm_password_reset",
                            web::post().to(handlers::confirm_password_reset),
                        ),
                )
                // 🔐 PROTECTED ROUTES
                .service(
                    web::scope("/me")
                        .wrap(session_middleware)
                        .route("/logout", web::post().to(handlers::logout))
                        .route("/account", web::get().to(handlers::protected))
                        .route(
                            "/change_password",
                            web::post().to(handlers::change_password),
                        )
                        .service(
                            web::scope("/admin")
                                .wrap(Permissions::<User>::new(self.permissions.clone()))
                                .configure(|cfg| {
                                    create_viewset(self.state.pool.clone()).configure(cfg, "users")
                                }),
                        ),
                )
                .service(web::scope("/passwordless").configure(config));

        #[cfg(feature = "passkey")]
        {
            // 🔐 register/list/remove are protected by the Auth<Identity>
            // extractor inside the handlers themselves; login/start and
            // login/finish are intentionally public (no session yet).
            scope = scope.service(passkey::routes("/passkey"));
        }

        cfg.service(scope);
    }
}
