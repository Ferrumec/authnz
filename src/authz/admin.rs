use crate::authz::models::PermissionReq;
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;
use viewset::{DefaultRepo, DefaultService, DefaultViewSet, Entity};

#[derive(FromRow, Deserialize, Serialize, Clone, Entity)]
#[entity(
    table = "absolutes",
    create = "PermissionReq",
    update = "PermissionReq"
)]
pub struct Absolute {
    #[entity(pk)]
    pub to_id: Uuid,
    /// Represent u128 permission bit map, represented as str since some db do not support u128
    pub role: String,
}

#[derive(FromRow, Deserialize, Serialize, Clone, Entity)]
#[entity(table = "permissions")]
pub struct Perm {
    #[entity(pk)]
    pub name: String,

    /// The index of this permission in the permissions bit string.
    /// It's a value between 0 and 128.
    pub value: i64,
}

pub type PermRepo = DefaultRepo<Perm>;
pub type PermService = DefaultService<PermRepo>;
pub type PermViewSet = DefaultViewSet<PermService>;
pub type AbsoluteRepo = DefaultRepo<Absolute>;
pub type AbsoluteService = DefaultService<AbsoluteRepo>;
pub type AbsoluteViewSet = DefaultViewSet<AbsoluteService>;
