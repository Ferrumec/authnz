use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;
use viewset::{ApiError, DefaultRepo, DefaultViewSet, Entity, Service};

#[derive(Entity, FromRow, Clone, Serialize, Deserialize)]
#[entity(update = "UpdateUser")]
pub struct User {
    #[entity(skip_update)]
    pub id: Uuid,
    #[entity(searchable, sortable, filterable)]
    pub username: String,
    #[entity(sortable, filterable, skip_update)]
    pub email: String,
    #[entity(sortable, skip_update)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[entity(skip_update)]
    pub password_hash: String,
    #[entity(skip_update)]
    pub updated_at: DateTime<Utc>,
    pub email_confirmed: bool,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub email_confirmed: Option<bool>,
}

pub use viewset::web::{SessionRepo,Session,NewSession};

pub struct SessionService {
    repo: Arc<SessionRepo>,
}

impl SessionService {
    fn new(repo: Arc<SessionRepo>) -> Self {
        Self { repo }
    }
}

#[async_trait::async_trait]
impl Service for SessionService {
    type Repository = SessionRepo;

    fn repository(&self) -> &Self::Repository {
        &self.repo
    }

    // Only override the one hook we actually need.
    async fn before_create(
        &self,
        _tx: &mut Transaction<'_, Postgres>,
        _dto: NewSession,
    ) -> Result<NewSession, ApiError> {
        return Err(ApiError::Validation(
            "manual create not allowed, use login endpoint".into(),
        ));
    }
}

pub type AdminSessionViewSet = DefaultViewSet<SessionService>;

pub fn admin_session_viewset(db: Arc<SessionRepo>) -> Arc<AdminSessionViewSet> {
    let service = SessionService::new(db.clone());
    Arc::new(service.into())
}

/// Data access for [`User`], plus its item/list caches.
///
/// Mirrors the pattern used by the groups service's repositories (e.g.
/// `groups::community::CommunityRepository`): caches are built from a
/// [`CacheFactory`] instead of relying on `viewset::DefaultRepo`'s built-in
/// (uncached) behavior. Built once by [`crate::authn::config::AuthModule::new`]
/// and shared between the `/admin/users` viewset, the domain
/// [`crate::authn::domain::user::UserService`], and [`crate::authn::domain::JwtService`]

pub type UserRepository = DefaultRepo<User>;

pub struct UserService {
    repo: Arc<UserRepository>,
}

impl UserService {
    fn new(repo: Arc<UserRepository>) -> Self {
        Self { repo }
    }
}

#[async_trait::async_trait]
impl Service for UserService {
    type Repository = UserRepository;

    fn repository(&self) -> &Self::Repository {
        &self.repo
    }

    // Only override the one hook we actually need.
    async fn before_create(
        &self,
        _tx: &mut Transaction<'_, Postgres>,
        _dto: User,
    ) -> Result<User, ApiError> {
        return Err(ApiError::Validation(
            "manual create not allowed, use registration endpoint".into(),
        ));
    }
}

pub type UserViewSet = DefaultViewSet<UserService>;

/// Builds the generic admin CRUD viewset over users, mounted at
/// `/me/admin/users` by [`crate::authn::config::AuthModule::config`].
pub fn create_viewset(repo: Arc<UserRepository>) -> Arc<UserViewSet> {
    let service = UserService::new(repo);
    Arc::new(service.into())
}
