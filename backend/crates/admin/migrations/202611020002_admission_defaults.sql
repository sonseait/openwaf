-- Startup validates/prepares and versions the data migration before marking it done.
ALTER TABLE config_state
    ADD COLUMN admission_defaults_upgraded BOOLEAN NOT NULL DEFAULT false;
