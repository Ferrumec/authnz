use thiserror::Error;

/// All errors that can surface from the authentication domain layer.
/// HTTP handlers map these to appropriate status codes; they must NOT
/// appear in handler logic directly.
#[derive(Debug, Error)]
pub enum AuthError {
    // ── Input errors ──────────────────────────────────────────────────
    #[error("Username and password are required")]
    MissingCredentials,

    #[error("Password must be at least 6 characters")]
    PasswordTooShort,

    // ── Auth failures ─────────────────────────────────────────────────
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("User not found")]
    UserNotFound,

    // ── Conflict ──────────────────────────────────────────────────────
    #[error("Username already exists")]
    UserAlreadyExists,

    // ── Infrastructure ────────────────────────────────────────────────
    #[error("Database error")]
    Database(#[from] sqlx::Error),

    #[error("Password hashing failed")]
    Bcrypt(#[from] bcrypt::BcryptError),

    #[error("Cache failed")]
    Cache,
}
