-- Public certificate observations only. No private keys, paths or credentials.
CREATE TABLE statistics_certificates (
    hostname TEXT PRIMARY KEY CHECK (length(hostname) BETWEEN 1 AND 253),
    metadata JSONB NOT NULL CHECK (octet_length(metadata::text) <= 8192),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE statistics_changes (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL CHECK (length(action) <= 64),
    target TEXT NOT NULL CHECK (length(target) <= 253),
    config_version BIGINT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX statistics_changes_time ON statistics_changes(observed_at);
