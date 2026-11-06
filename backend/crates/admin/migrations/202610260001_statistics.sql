-- One managed gateway is already enforced by the configuration lease.
CREATE TABLE openwaf_statistics (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    checkpoint JSONB NOT NULL CHECK (octet_length(checkpoint::text) <= 131072)
);
