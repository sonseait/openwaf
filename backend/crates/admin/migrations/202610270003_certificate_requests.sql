CREATE TABLE certificate_requests (
    hostname TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    provider_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','running','current','covered','degraded')),
    covered_by_hostname TEXT,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    last_error_code TEXT,
    next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    requested_by BIGINT NOT NULL REFERENCES admin_users(id),
    terms_accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((state = 'covered') = (covered_by_hostname IS NOT NULL))
);
