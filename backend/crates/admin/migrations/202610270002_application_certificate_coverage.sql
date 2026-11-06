ALTER TABLE application_certificates
    DROP CONSTRAINT application_certificates_state_check,
    ADD COLUMN covered_by_hostname TEXT,
    ADD CONSTRAINT application_certificates_state_check
        CHECK (state IN ('pending','running','current','degraded','covered')),
    ADD CONSTRAINT application_certificates_coverage_check
        CHECK ((state = 'covered') = (covered_by_hostname IS NOT NULL));
