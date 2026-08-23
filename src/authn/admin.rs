use actixutils::Store;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;
use viewset::{ApiError, DefaultRepo, DefaultViewSet, Entity, Repository, Service};

#[derive(Entity, FromRow, Serialize, Clone)]
#[entity(
    create = "CreateUser",
    update = "UpdateUser",
    response = "UserDto"
)]
pub struct User {
    pub id: Uuid,
    #[entity(searchable, sortable, filterable)]
    pub username: String,
    #[entity(sortable, filterable)]
    pub email: String,
    #[entity(sortable)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub password_hash: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateUser {
    name: String,
    email: Decimal,
}

// `skip_serializing_if` is what makes PATCH semantics work: an omitted
// field in the request body stays absent from the serialized JSON, so the
// default `update_columns` (see Repository) never touches that column.
// Without it, `None` would serialize to `null` and the field would be
// wiped on every PATCH.
#[derive(Serialize, Deserialize)]
pub struct UpdateUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

#[derive(Serialize)]
pub struct UserDto {
    id: Uuid,
    username: String,
    email: String,
}

impl From<User> for UserDto {
    fn from(p: User) -> Self {
        Self {
            id: p.id,
            username: p.username,
            email: p.email,
        }
    }
}

#[derive(Entity, FromRow, Serialize, Clone, Deserialize)]
pub struct Session {
    id: Uuid,
    #[entity(sortable)]
    created_at: chrono::DateTime<chrono::Utc>,
    pub sub: Uuid,
    pub username: String,
    pub email: String,
    pub role: String,
}

pub struct SessionRepo {
    pool: PgPool,
    cache: Arc<dyn Store<Uuid, Session>>,
}

impl SessionRepo {
    pub fn new(pool: PgPool, cache: Arc<dyn Store<Uuid, Session>>) -> Self {
        Self { pool, cache }
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
        _dto: CreateUser,
    ) -> Result<CreateUser, ApiError> {
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
