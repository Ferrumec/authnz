use crate::CacheFactory;
use crate::models::User as ActiveUser;
use actixutils::Store;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use std::time::Duration;
use std::{net::IpAddr, sync::Arc};
use uuid::Uuid;
use viewset::{ApiError, DefaultViewSet, Entity, Repository, Service};

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

#[derive(Entity, FromRow, Serialize, Clone, Deserialize)]
#[entity(table = "sessions", create = "NewSession")]
pub struct Session {
    #[entity(skip_create)]
    pub id: Uuid,
    #[entity(sortable)]
    #[entity(skip_create)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub sub: Uuid,
    pub username: String,
    pub email: String,
    pub role: Uuid,
    pub expires_at: DateTime<Utc>,
    pub ip_address: IpNetwork,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NewSession {
    pub sub: Uuid,
    pub username: String,
    pub email: String,
    pub role: Uuid,
    pub expires_at: DateTime<Utc>,
    pub ip_address: IpNetwork,
}

impl NewSession {
    pub fn new(value: ActiveUser, ip_address: IpAddr) -> Self {
        let ActiveUser {
            sub,
            username,
            email,
            role,
            expires_at,
        } = value;
        Self {
            sub,
            username,
            email,
            expires_at,
            ip_address: ip_address.into(),
            role: Uuid::from_u128(role),
        }
    }
}

#[derive(Clone)]
pub struct SessionRepo {
    pool: PgPool,
    cache: Arc<dyn Store<Uuid, Session>>,
}

impl SessionRepo {
    pub fn new(pool: PgPool, cache: Arc<dyn Store<Uuid, Session>>) -> Self {
        Self { pool, cache }
    }

    /// IDs of every session row belonging to `sub`, straight from the
    /// database (bypassing the entity cache, which is keyed by session
    /// id and has no per-user index). Used to bulk-revoke a user's
    /// sessions via the normal cache-invalidating `Repository::delete`.
    pub async fn session_ids_for_user(&self, sub: &Uuid) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar!("SELECT id FROM sessions WHERE sub = $1", sub)
            .fetch_all(&self.pool)
            .await
    }
}

impl Repository for SessionRepo {
    type Entity = Session;
    fn database(&self) -> &PgPool {
        &self.pool
    }

    fn cache(&self) -> Arc<dyn Store<Uuid, Session> + Send + Sync> {
        self.cache.clone()
    }
}

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
/// so all three see a consistent, cached view of the `users` table.
pub struct UserRepository {
    pub pool: PgPool,
    pub item_cache: Arc<dyn Store<Uuid, User>>,
    pub list_cache: Arc<dyn Store<u64, (Vec<User>, i64)>>,
}

impl UserRepository {
    /// Builds a new repository, creating its caches via `cf`.
    pub fn new<Cf: CacheFactory + 'static>(pool: PgPool, cf: Cf) -> Self {
        Self {
            pool,
            item_cache: cf.new_cache("user_items", Duration::from_mins(60)),
            list_cache: cf.new_cache("user_lists", Duration::from_mins(30)),
        }
    }
}

impl Repository for UserRepository {
    type Entity = User;
    fn list_cache(&self) -> Arc<dyn Store<u64, (Vec<User>, i64)> + Send + Sync> {
        self.list_cache.clone()
    }
    fn cache(&self) -> Arc<dyn Store<Uuid, User> + Send + Sync> {
        self.item_cache.clone()
    }

    fn database(&self) -> &PgPool {
        &self.pool
    }
}

pub struct UserService {
    repo: Arc<UserRepository>,
}

impl UserService {
    pub fn new(repo: Arc<UserRepository>) -> Self {
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
