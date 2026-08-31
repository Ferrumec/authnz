CREATE TABLE IF NOT EXISTS permissions (
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    value INTEGER NOT NULL,
    UNIQUE(namespace, name)
);

CREATE TABLE IF NOT EXISTS absolutes (
    to_id UUID NOT NULL PRIMARY KEY,
    role UUID NOT NULL
);
