//! Cookie-based session data handle.
//!
//! [`Session<T>`] is the extractor handlers use to read and mutate the
//! current request's session value once
//! [`SessionMiddleware`](crate::middleware::SessionMiddleware) has populated
//! it into the request extensions.

use actix_web::{Error, FromRequest, HttpRequest, dev::Payload};
use std::{
    future::{Ready, ready},
    net::{IpAddr, Ipv4Addr},
};

pub struct SessionParams {
    pub ip_address: IpAddr,
    pub user_agent: String,
}

impl FromRequest for SessionParams {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let ip_address = req
            .peer_addr()
            .map(|a| a.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        ready(Ok(Self {
            ip_address,
            user_agent,
        }))
    }
}
