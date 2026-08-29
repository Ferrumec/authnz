-- Up
CREATE TYPE session_status AS ENUM
('active', 'revoked', 'expired');

CREATE TABLE sessions
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sub UUID NOT NULL,

    -- Device info
    device_name TEXT NOT NULL,
    -- "Chrome on Windows", "iPhone App"
    user_agent TEXT,
    ip_address INET,

    -- Auth data
    data JSONB NOT NULL DEFAULT '{}',
    -- store roles, csrf, etc

    -- Lifecycle
    status session_status NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT fk_user FOREIGN KEY (sub) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_sessions_user_id ON sessions(sub);
CREATE INDEX idx_sessions_status ON sessions(status);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at) WHERE status = 'active';
CREATE INDEX idx_sessions_last_seen ON sessions(last_seen_at DESC);

-- Auto update last_seen_at
CREATE OR REPLACE FUNCTION touch_last_seen
()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_seen_at = NOW
();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_touch_last_seen
BEFORE
UPDATE ON sessions
FOR EACH ROW
EXECUTE FUNCTION touch_last_seen
();

