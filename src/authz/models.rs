use crate::authz::services::Service;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct Permission {
    pub value: u128,
    name: String,
}

#[derive(Deserialize, Serialize)]
pub struct PermissionReq {
    pub permission: u8,
    pub target: Uuid,
}

#[derive(Clone)]
pub struct AppState {
    pub service: Service,
}
