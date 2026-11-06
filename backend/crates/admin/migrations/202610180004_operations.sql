CREATE TABLE endpoint_operations (
 endpoint_key TEXT PRIMARY KEY CHECK (length(endpoint_key) <= 1024),
 mode TEXT NOT NULL CHECK(mode IN ('active','drain','maintenance')),
 revision BIGINT NOT NULL CHECK(revision > 0),
 reason TEXT NOT NULL CHECK(length(reason) <= 256),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE endpoint_checks (
 observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 endpoint_key TEXT NOT NULL,
 diagnostic JSONB NOT NULL
);
CREATE INDEX endpoint_checks_time ON endpoint_checks(observed_at);
CREATE TABLE telegram_settings (
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK(singleton),
 revision BIGINT NOT NULL DEFAULT 0,
 enabled BOOLEAN NOT NULL DEFAULT false,
 chat_id TEXT NOT NULL DEFAULT '',
 topic_id BIGINT,
 token BYTEA,
 silence_until_unix_ms BIGINT NOT NULL DEFAULT 0
);
INSERT INTO telegram_settings(singleton) VALUES(true);
CREATE TABLE telegram_outbox (
 id BIGSERIAL PRIMARY KEY,
 group_key TEXT NOT NULL,
 message TEXT NOT NULL CHECK(length(message)<=2048),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT now()+interval '24 hours',
 next_try TIMESTAMPTZ NOT NULL DEFAULT now(),
 attempts INTEGER NOT NULL DEFAULT 0,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','sent','failed','expired')),
 last_error TEXT
);
CREATE INDEX telegram_pending ON telegram_outbox(next_try) WHERE state='pending';
