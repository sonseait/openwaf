-- Sample active-snapshot eligibility independently of traffic history.
CREATE TABLE uptime_samples (
    id bigserial PRIMARY KEY,
    observed_at_unix_ms bigint NOT NULL CHECK (observed_at_unix_ms >= 0),
    epoch text NOT NULL CHECK (length(epoch) <= 64),
    config_version bigint NOT NULL,
    available integer NOT NULL CHECK (available >= 0),
    unavailable integer NOT NULL CHECK (unavailable >= 0),
    unknown integer NOT NULL CHECK (unknown >= 0),
    CHECK (available + unavailable + unknown <= 1024)
);
CREATE INDEX uptime_samples_observed ON uptime_samples (observed_at_unix_ms);
