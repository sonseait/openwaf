-- Public preview identifiers, independent from artifact IDs/checksums. UUID v4
-- supplies CSPRNG entropy; base64 remapping keeps the hostname alphanumeric.
ALTER TABLE application_releases ADD COLUMN preview_label TEXT NOT NULL
    DEFAULT substr(translate(encode(uuid_send(gen_random_uuid()), 'base64'), '+/', 'AZ'), 1, 12)
    CHECK (preview_label ~ '^[a-zA-Z0-9]{12}$');
-- DNS labels are case-insensitive. Refuse collisions rather than shadowing a route.
CREATE UNIQUE INDEX application_releases_preview_label ON application_releases(lower(preview_label));
