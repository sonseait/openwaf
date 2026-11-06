-- Configuration storage only; traffic history belongs to ClickHouse.
CREATE TABLE admin_users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 64),
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE admin_sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id BIGINT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX admin_sessions_user ON admin_sessions(user_id, created_at);
CREATE INDEX admin_sessions_expiry ON admin_sessions(expires_at);
CREATE TABLE admin_audit (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id BIGINT REFERENCES admin_users(id),
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    source_ip INET
);
CREATE TABLE secret_key_check (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    envelope BYTEA NOT NULL
);
CREATE TABLE credentials (
    name TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 64),
    envelope BYTEA NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
