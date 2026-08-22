use std::sync::Arc;

use actixutils::{Authority, Sign};
use uuid::Uuid;

pub struct NewClaim {
    pub user: Uuid,
    pub tenant: Uuid,
    pub aud: String,
    pub role: u128,
}

pub fn create_token(claim: NewClaim, signer: Arc<dyn Sign<Authority>>) -> String {
    let mut claims = Authority::new(claim.tenant, claim.role, claim.user, vec![claim.aud]);
    claims.role = claim.role;

    signer.sign(&claims).unwrap()
}
