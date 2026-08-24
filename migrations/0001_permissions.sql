CREATE TABLE IF NOT EXISTS permissions (
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    value INTEGER NOT NULL,
    UNIQUE(namespace, name)
);

CREATE TABLE IF NOT EXISTS absolutes (
    to_id UUID NOT NULL,
    aud TEXT NOT NULL,
    role TEXT NOT NULL,
    UNIQUE(to_id, aud)
);

CREATE TABLE IF NOT EXISTS grants (
    from_id UUID NOT NULL,
    to_id UUID NOT NULL,
    aud TEXT NOT NULL,
    role TEXT NOT NULL,
    UNIQUE(from_id, to_id, aud)
);

