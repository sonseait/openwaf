CREATE TABLE applications (
    id TEXT PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    domain TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL CHECK (mode IN ('static', 'spa')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE application_releases (
    id TEXT PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    application_id TEXT NOT NULL REFERENCES applications(id),
    checksum TEXT NOT NULL,
    bytes BIGINT NOT NULL CHECK (bytes >= 0),
    file_count INTEGER NOT NULL CHECK (file_count > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by BIGINT NOT NULL REFERENCES admin_users(id)
);
CREATE INDEX application_releases_app_time ON application_releases(application_id, created_at DESC);
CREATE TABLE application_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    preview_base_domain TEXT
);
INSERT INTO application_settings (singleton) VALUES (true);
CREATE TABLE application_certificates (
    hostname TEXT PRIMARY KEY,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','running','current','degraded')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
