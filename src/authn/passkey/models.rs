use serde::Deserialize;

/// Body for `POST /passkey/login/start` — the only place we still need a
/// bare username, since the caller has no session yet at that point.
#[derive(Deserialize)]
pub struct UsernameRequest {
    pub username: String,
}

/// Optional query string for `POST /passkey/register/finish`, letting the
/// client label the credential being created (e.g. "MacBook Touch ID",
/// "YubiKey 5C"). Purely cosmetic — shown back via the list endpoint.
/// e.g. `POST /passkey/register/finish?label=MacBook%20Touch%20ID`
#[derive(Deserialize, Default)]
pub struct LabelQuery {
    #[serde(default)]
    pub label: Option<String>,
}
