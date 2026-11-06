CREATE TABLE config_versions (
    version BIGINT PRIMARY KEY CHECK (version >= 0),
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    diff JSONB NOT NULL,
    rollback_from BIGINT REFERENCES config_versions(version),
    created_by BIGINT REFERENCES admin_users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO config_versions (version, document, diff) VALUES (0, '{}', '{}');
CREATE TABLE config_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    draft_revision BIGINT NOT NULL CHECK (draft_revision >= 0),
    draft JSONB NOT NULL CHECK (jsonb_typeof(draft) = 'object'),
    committed_version BIGINT NOT NULL REFERENCES config_versions(version)
);
INSERT INTO config_state (draft_revision, draft, committed_version) VALUES (0, '{}', 0);
