use crate::models::User as ActiveUser;
use actixutils::Store;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use std::{net::IpAddr, sync::Arc};
use uuid::Uuid;
use viewset::{ApiError, DefaultRepo, DefaultViewSet, Entity, Repository, Service};

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

pub type UserRepository = DefaultRepo<User>;

pub struct UserService {
    repo: UserRepository,
}

impl UserService {
    fn new(db: PgPool) -> Self {
        let repo: UserRepository = db.into();
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

pub fn create_viewset(db: PgPool) -> Arc<UserViewSet> {
    let service = UserService::new(db);
    Arc::new(service.into())
}
