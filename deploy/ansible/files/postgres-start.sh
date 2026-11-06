#!/bin/bash
# PGAIO's outer entrypoint needs password values before Bitnami reads *_FILE.
# Read only the private generated file; no secret in Compose environment or argv.
set -eu
if [[ "${OPENWAF_POSTGRES_CREATE:-1}" != 1 ]]; then
    echo 'PostgreSQL creation is disabled; do not start this service explicitly.' >&2
    exit 1
fi
POSTGRESQL_PASSWORD="$(cat /run/secrets/postgres/password)"
if [[ ! "$POSTGRESQL_PASSWORD" =~ ^[0-9a-f]{64}$ ]]; then
    echo 'Invalid managed PostgreSQL password file.' >&2
    exit 1
fi
export POSTGRESQL_USERNAME=postgres
export POSTGRESQL_PASSWORD
export POSTGRESQL_POSTGRES_PASSWORD="$POSTGRESQL_PASSWORD"
exec /docker-entrypoint.sh
