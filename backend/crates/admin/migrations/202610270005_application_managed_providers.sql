-- Preserve imported renewal identity; credentials remain separately encrypted.
ALTER TABLE certificate_providers ADD COLUMN acme_profile JSONB;
CREATE TABLE certificate_provider_runtime (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    state_root TEXT NOT NULL,
    worker_binary TEXT NOT NULL,
    master_key_file TEXT NOT NULL
);
