-- Separate from legacy provider-catalog import, and retained after provider deletion.
CREATE TABLE bootstrap_certificate_import (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    hostname TEXT NOT NULL,
    zone_id TEXT NOT NULL,
    zone_name TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE bootstrap_certificate_ownership (
    hostname TEXT PRIMARY KEY,
    owner TEXT NOT NULL CHECK (owner = 'admin-bootstrap')
);
