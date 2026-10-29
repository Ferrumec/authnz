use super::SessionMiddleware;
use crate::SessionRepo;
use crate::SessionService;
use crate::authn::admin::admin_session_viewset;
use crate::authn::admin::{UserRepository, UserViewSet, create_viewset};
use crate::authn::domain::JwtService;
use crate::authn::domain::user::UserService;
#[cfg(feature = "passkey")]
use crate::authn::passkey;
use crate::authn::{auth2::AppState, handlers, passwdless::config, user_id::username2userid};
use actix_web::web::{self, ServiceConfig};
use actixutils::HS256Signer;
use actixutils::middleware::ResponseEqualizer;
use actixutils::{Identity, Sign};
use ferrumec::{Infra, Module};
use std::sync::Arc;
use std::time::Duration;
use viewset::ViewSet;

#[derive(Clone)]
pub struct AuthModule {
    state: web::Data<AppState>,
    middleware: Arc<SessionMiddleware>,
    session_store: Arc<SessionRepo>,
    jwt: web::Data<JwtService>,
    session_service: web::Data<SessionService>,
    user_service: web::Data<UserService>,
    user_viewset: Arc<UserViewSet>,
}

impl Module for AuthModule {
    async fn new(infra: impl Infra) -> Result<Self, Box<dyn std::error::Error>> {
        // Built once and shared (cache included) across the domain
        // `UserService`, `JwtService`, and the `/admin/users` viewset, so
        // all three see a consistent, cached view of the `users` table —
        // mirroring how the groups service shares one repository per
        // entity across its handlers and admin viewsets.
        let pool = infra.database();
        let cache_factory = infra.cache_factory();
        let outbox =
            Arc::new(ferrumec::event::Outbox::new(pool.clone(), infra.event_stream()).await?);
        let session_store = Arc::new(SessionRepo::new(pool.clone(), cache_factory.clone()));
        let session_service = web::Data::new(SessionService::new((*session_store).clone()));

        let user_repo = Arc::new(UserRepository::new(pool.clone(), cache_factory.clone()));
        let app_state = AppState::new(
            pool.clone(),
            user_repo.clone(),
            outbox.clone(),
            cache_factory.clone(),
        )
        .await;
        let user_service =
            web::Data::new(UserService::new(pool.clone(), user_repo.clone(), outbox));
        let secret = std::env::var("signer.secret").expect("signer.secret not set");
        let aud = std::env::var("signer.aud").expect("signer.aud not set");
        let signer: Arc<dyn Sign<Identity>> = Arc::new(HS256Signer::new(aud, secret));
        let jwt = web::Data::new(JwtService::new(pool.clone(), signer, user_repo.clone()));
        let user_viewset = create_viewset(user_repo);
        let middleware = Arc::new(SessionMiddleware::new(cache_factory));
        Ok(Self {
            state: web::Data::new(app_state),
            middleware,
            session_store,
            session_service,
            jwt,
            user_service,
            user_viewset,
        })
    }
    fn configure(self: Arc<Self>, cfg: &mut ServiceConfig, namespace: &str) {
        #[cfg_attr(not(feature = "passkey"), allow(unused_mut))]
        let mut scope = web::scope(namespace)
            // `username2userid` and the `/passwordless` handlers extract
            // `web::Data<AppState>` directly, so the shared state needs to
            // be registered here too, not just the `AuthService` slice of it.
            .app_data(self.state.clone())
            .app_data(self.jwt.clone())
            .app_data(self.user_service.clone())
            .app_data(self.session_service.clone())
            .app_data(web::Data::new(self.session_store.clone()))
            .service(username2userid)
            .service(
                web::scope("/jwt")
                    .route("/logout", web::post().to(handlers::jwt_logout))
                    .route("/refresh", web::post().to(handlers::refresh)),
            )
            .service(
                web::scope("/auth")
                    .wrap(ResponseEqualizer::new(Duration::from_millis(200)))
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
                    //.app_data(self.session_store.clone())
                    .wrap(self.middleware.clone())
                    .route("/jwt", web::post().to(handlers::jwt))
                    .route("/logout", web::post().to(handlers::logout))
                    .route("/account", web::get().to(handlers::protected))
                    .route(
                        "/change_password",
                        web::post().to(handlers::change_password),
                    )
                    .route("/sessions", web::get().to(handlers::get_sessions))
                    .route(
                        "/delete_session/{id}",
                        web::delete().to(handlers::delete_session),
                    )
                    .service(
                        web::scope("/admin")
                            .configure(|cfg| self.user_viewset.clone().configure(cfg, "users"))
                            .configure(|cfg| {
                                admin_session_viewset(self.session_store.clone())
                                    .configure(cfg, "sessions")
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
