CREATE TABLE abuse_incidents (
    id BIGSERIAL PRIMARY KEY,
    group_key TEXT NOT NULL UNIQUE CHECK (length(group_key)<=256),
    detector TEXT NOT NULL CHECK (detector IN ('endpoint_probing','route_flood')),
    scope TEXT NOT NULL CHECK (length(scope)<=128),
    route_id TEXT NOT NULL CHECK (length(route_id)<=64),
    window_start_ms BIGINT NOT NULL,
    window_end_ms BIGINT NOT NULL,
    first_ms BIGINT NOT NULL,
    last_ms BIGINT NOT NULL,
    config_version BIGINT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','ack','resolved')),
    quality TEXT NOT NULL,
    evidence JSONB NOT NULL CHECK (octet_length(evidence::text)<=8192),
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX abuse_incidents_scope ON abuse_incidents(detector,scope,state);
