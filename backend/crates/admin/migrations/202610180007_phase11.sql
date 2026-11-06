-- Informational maintenance deadline; never authorizes force-disconnect.
ALTER TABLE endpoint_operations ADD COLUMN deadline_unix_ms BIGINT
    CHECK (deadline_unix_ms IS NULL OR deadline_unix_ms BETWEEN 1 AND 253402300799999);
