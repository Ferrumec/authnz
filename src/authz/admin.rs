use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;
use viewset::{DefaultRepo, DefaultService, DefaultViewSet, Entity};

#[derive(FromRow, Deserialize, Serialize, Clone, Entity)]
#[entity(table = "grants")]
pub struct Absolute {
    #[entity(pk)]
    pub to_id: Uuid,
    /// Represent u128 permission bit map, represented as str since some db do not support u128
    pub role: Uuid,
}

pub type AbsoluteRepo = DefaultRepo<Absolute>;
pub type AbsoluteService = DefaultService<AbsoluteRepo>;
pub type AbsoluteViewSet = DefaultViewSet<AbsoluteService>;
