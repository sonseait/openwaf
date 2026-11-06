CREATE TABLE certificate_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    zone_id TEXT NOT NULL CHECK (zone_id ~ '^[0-9a-fA-F]{32}$'),
    zone_name TEXT NOT NULL,
    environment TEXT NOT NULL CHECK (environment IN ('production','staging')),
    credential BYTEA NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
