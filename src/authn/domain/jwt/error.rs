use thiserror::Error;

/// All errors that can surface from the authentication domain layer.
/// HTTP handlers map these to appropriate status codes; they must NOT
/// appear in handler logic directly.
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Refresh token is required")]
    MissingRefreshToken,

    // ── Auth failures ─────────────────────────────────────────────────
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Refresh token not found or revoked")]
    RefreshTokenNotFound,

    #[error("Refresh token expired")]
    RefreshTokenExpired,

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("Password hashing failed")]
    Bcrypt(#[from] bcrypt::BcryptError),

    #[error("Token signing failed: {0}")]
    TokenSigning(String),
    #[error("User not found")]
    UserNotFound,

    // ── Conflict ──────────────────────────────────────────────────────
    #[error("Username already exists")]
    UserAlreadyExists,

    // ── Infrastructure ────────────────────────────────────────────────
    #[error("Database error")]
    Database(#[from] sqlx::Error),
}
