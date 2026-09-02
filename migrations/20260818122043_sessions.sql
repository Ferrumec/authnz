CREATE TABLE IF NOT EXISTS sessions
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sub UUID NOT NULL,

    -- Denormalized user fields for session (match application session model)
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    role UUID NOT NULL,

    -- Device / request info
    ip_address INET,

    -- Lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT fk_user FOREIGN KEY (sub) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(sub);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
