ALTER TABLE openwaf_statistics DROP CONSTRAINT openwaf_statistics_checkpoint_check;
ALTER TABLE openwaf_statistics ADD CONSTRAINT openwaf_statistics_checkpoint_check
    CHECK (octet_length(checkpoint::text) <= 4194304);
