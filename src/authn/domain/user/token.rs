//! Refresh-token helpers.
//!
//! Design contract:
//!   • Raw tokens are 32 cryptographically-random bytes, base64url-encoded.
//!   • Only `SHA-256(raw_token)` is ever written to the database.
//!   • The raw token is returned to the caller exactly once and never stored.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Generate a cryptographically secure random token.
///
/// Returns a 43-character URL-safe base64 string (256 bits of entropy).
/// This value is returned to the client and **must not** be persisted.
pub fn generate_raw_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token for storage using SHA-256.
///
/// Returns a lowercase hex string.  This is what goes into the database.
pub fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::authn::*;

    #[test]
    fn raw_token_has_expected_length() {
        // 32 bytes → 43 base64url chars (no padding)
        let token = generate_raw_token();
        assert_eq!(token.len(), 43, "unexpected token length: {}", token.len());
    }

    #[test]
    fn raw_tokens_are_unique() {
        let a = generate_raw_token();
        let b = generate_raw_token();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_is_deterministic() {
        let raw = "some-raw-token";
        assert_eq!(hash_token(raw), hash_token(raw));
    }

    #[test]
    fn different_tokens_produce_different_hashes() {
        assert_ne!(hash_token("token-a"), hash_token("token-b"));
    }

    #[test]
    fn hash_output_is_hex() {
        let h = hash_token("test");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h.len(), 64); // SHA-256 → 32 bytes → 64 hex chars
    }
}
