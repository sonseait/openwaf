# Cloudflare providers and DNS management

Open **Certificates → DNS providers → Add provider**. Choose **API Token**
(recommended) or **Global API Key + email**, enter credentials, and select
**Connect and load zones**. Select the authoritative zone and a Let's Encrypt
Production/Staging environment, name the provider and save. The provider is
available immediately for certificate requests, without a gateway restart.

An API Token needs **Zone Read**, **DNS Read** and **DNS Edit** for its selected
zones. Global keys use `X-Auth-Key` and `X-Auth-Email`; tokens use bearer auth.
The server always verifies HTTPS to `api.cloudflare.com`, with no redirects,
proxy inheritance, arbitrary API origin or caller-supplied executable/file paths.
Zone discovery is paginated (50/page), and save checks the selected zone against
Cloudflare. A saved provider is permanently bound to its zone and CA environment.
Create another provider to change either. Names and credentials can be updated.

**Test** verifies zone and DNS-read access only; it does not create a record or
claim DNS-write access. Missing edit permission becomes visible on a real DNS or
ACME operation. A token scoped to a parent zone can request certificates for
subdomains: e.g. the `example.com` provider can request `*.sub.example.com`.
Accept CA terms separately when requesting a certificate; saving a provider does
not accept those terms or request a certificate.

## DNS records

Choose **DNS records** on a dashboard-managed provider. The dialog reads directly
from Cloudflare, with timestamps, bounded pagination, optional exact-name filtering,
refresh/loading/error/empty states and the page's pause control. Supported manual
edits are **A, AAAA, CNAME, TXT, MX and NS**. Other types remain view-only so their
structured fields are not lost. Record type stays fixed during edit.

Names accept `@`, a relative owner or a full owner in the selected zone. Relative
names are always qualified under that zone. Proxying is available only for
A/AAAA/CNAME and uses automatic TTL. DNS-only TTL accepts 1 (automatic) or
60–86400 seconds. MX requires a priority. TXT content is limited to 2048 bytes.
Cloudflare still validates provider-specific restrictions, conflicts and plan
limits. DNS propagation and public reachability are not inferred from API success.

Names containing an `_acme-challenge` label and records carrying OpenWAF's ACME
ownership comment cannot be created, edited or deleted through the manual editor.
The ACME worker continues to own its TXT challenge creation and cleanup.

Updates/deletes require a provider revision and the record version observed by
the user. Before writing, OpenWAF re-reads that record in the saved zone and rejects
stale versions. PATCH preserves fields outside the editor, including comments,
tags and settings. Local writes are serialized with explicit certificate jobs.
Cloudflare does not provide an atomic compare-and-swap contract for this editor:
an independent writer can still race between the read and the write. Refresh and
coordinate edits when using multiple tools.

Every write first commits an audit of the attempt; failure prevents dispatch.
Acknowledged/unacknowledged outcomes are audited separately. Audit entries contain
IDs and action names, never credentials or DNS content. A lost response, malformed
success, provider 5xx or failure to commit the outcome audit returns
`cloudflare_outcome_unknown`. **Reload DNS records before retrying**: the external
change may already have completed. Writes are never retried automatically, and
there is no distributed transaction between PostgreSQL and Cloudflare. An attempt
without a completion audit also requires reconciliation after cancellation/crash.

## Secrets, ownership and persistence

Dashboard credentials are AES-256-GCM encrypted in PostgreSQL with the existing
external Admin master key and provider-ID authenticated binding. API responses
never return tokens, global keys or account email. Input credentials are transient
form state, not query/mutation variables or browser storage; saved credentials
cannot be revealed. Omitting replacement (`credentials: null`) preserves the existing credential.

Before a certificate child starts, its provider credential is decrypted in the
control plane and atomically published as a private `OWCC1` file encrypted with
the external ACME key. The real ACME worker understands token and global-key
credentials while retaining compatibility with legacy `OWCF1` token inputs.
The bridge file uses the same stable path on credential rotation, preserving
immutable per-host config, account state, request fingerprint and renewal owner.
Only encrypted data is written to these credential files. They are generated worker
inputs; PostgreSQL is the provider source of truth.

There are at most 16 application-managed providers total. Each row represents a
zone and a CA environment, not a different DNS vendor. The previous homelab catalog
had four Cloudflare connections: `sonlc.dev` and `0xh4ck3d.dev`, each with production
and staging. Import preserves those four rows; staging and production have separate
issuance identities and are not silently merged. Unused rows can be deleted in UI.
A provider referenced by any certificate request cannot be deleted.
Provider changes, new requests and DNS writes return conflict while an explicit
certificate operation holds the shared mutation gate. Loaded certificates continue
to serve traffic.

On the first upgraded startup, an existing private catalog is imported in one
PostgreSQL transaction, including credentials re-encrypted with the Admin key and
an audit per provider. Failure rolls back all rows and the import marker; certificate
requests report unavailable while traffic keeps its loaded certificates. Existing
IDs, profile fingerprints, per-host state and account ownership are preserved.
Imported jobs keep their original immutable `request.json`; a derived private
`managed-request.json` points the child at the database-backed encrypted credential
bridge while using the same state/account directory. No old token file is read by
renewal after import. Imported providers support the same edit, credential rotation,
test and DNS actions as new providers.

Once the durable runtime/import marker exists, catalog/template/token files are
never consulted again: changing them cannot override edits or resurrect a deleted
provider. Fresh VPS bootstrap seeds one Production provider through its separate one-time
transaction and `bootstrap_certificate_import` marker; homelab/standalone installs
continue to add providers explicitly. File changes cannot override either import marker. Master keys and generated
ACME state remain private filesystem inputs, outside the database.

Include `bootstrap_certificate_import`, `bootstrap_certificate_ownership`,
`certificate_provider_runtime` and the `certificate_providers` table in administrative database backups.
Retain both external master keys separately, the certificate-request state and
live TLS manifest/PEMs; a database backup alone cannot restore certificate accounts.
Startup validates every dashboard credential against the Admin key. No new
backup/restore endpoint or clean-instance recovery result is claimed here.

## Deployment

On a fresh [VPS deployment](../deploy/ansible/docs/runtime.md#quản-lý-tlsacme-trong-admin),
the existing Admin module is enabled by default: private request-state and a
separate certificate key are provisioned offline, then mounted into the gateway
with writable live TLS. Add additional providers in the UI; no catalog or per-domain JSON
is needed. Its bootstrap zone/token is imported automatically as one Production
provider, or an existing Production provider for that zone is reused unchanged.
The Admin-key-encrypted handoff has its own private `bootstrap-provider` volume.
Import/audit/reservations commit before DNS writes. Restart neither reimports
credentials nor resurrects a deleted provider. Admin DNS/TLS bootstrap remains
a separate renewal owner with its own token/key; changing provider credentials
in the dashboard does not rotate that bootstrap token.
See [VPS certificate runtime](certificates.md#vps-compose).

For homelab upgrades, the Certificates opt-in Compose override sets:

- `OPENWAF_CERTIFICATES_ROOT=/var/lib/openwaf/certificate-requests`.
- `OPENWAF_CERTIFICATES_MASTER_KEY_FILE=/run/secrets/openwaf-acme-master.key`.
- `OPENWAF_CERTIFICATES_CONFIG=/etc/openwaf-certificates/catalog.json` only as a
  one-time upgrade import location, ignored after a successful import.

Enable `OPENWAF_CERTIFICATES_ENABLED=true`, provision the existing 32-byte ACME key,
and deploy updated unified gateway/ACME image and the override. The deployment
helper prepares private directories. Fresh installs add providers directly in UI.
Existing installs keep the catalog/templates/encrypted token available for the
first import, then verify all expected rows and the import audit. Keep the existing
state, runtime root and keys; do not recreate accounts. After successful import,
the legacy config mount (if it contains no other runtime inputs such as CA trust PEMs)
and `OPENWAF_CERTIFICATES_CONFIG` can be removed while
retaining `OPENWAF_CERTIFICATES_ROOT` and key mounts. Metadata/credentials change
immediately in UI without restarting the gateway.

The gateway retains its read-only container root and no Docker socket. Only the
signing/TLS/state mounts gain the capabilities described in
[Certificates](certificates.md#homelab-compose). Provider management requires a
managed gateway with TLS, a private writable request root and the key mount;
standalone Admin reports it unavailable.

Outbound operations are limited to four concurrent requests and 120 admissions
per minute for the service. Each HTTP operation has a two-second connection and
three-second total timeout; response bodies are bounded to 512 KiB. There are no
unowned background tasks or additions to the proxy/TLS hot path.

## API

All paths below are relative to `/api/v1`. Reads require an Admin session;
POST/PUT/DELETE also require exact Origin and CSRF. Invalid input/unknown fields
are rejected without quoting input. Credentials have `{ auth_type, secret, email }`;
`auth_type` is `api_token` (email null) or `global_api_key` (email required).

| Method/path | Body/result |
| --- | --- |
| `GET /certificate-providers` | Safe metadata, source (`dashboard`, including imported providers), revisions, usage count, availability and timestamp |
| `POST /certificate-providers/discover` | `{ credentials, page }` → bounded `{ zones, page, has_more, observed_at_unix_ms }` |
| `POST /certificate-providers` | `{ name, zone_id, zone_name, environment, credentials }` → `{ id, revision }` |
| `PUT /certificate-providers/{id}` | `{ name, expected_revision, credentials }`; null credentials preserve the saved value; `204` |
| `DELETE /certificate-providers/{id}` | `{ expected_revision }`; `204` only when unused |
| `POST /certificate-providers/{id}/test` | Zone/DNS-read result and timestamp; `dns_write: "not_tested"` |
| `GET /certificate-providers/{id}/dns?page=1&name=...` | Records with versions/editability, page metadata, provider revision, source and timestamp |
| `POST /certificate-providers/{id}/dns` | `{ record, expected_provider_revision, expected_record: null }` |
| `PUT /certificate-providers/{id}/dns/{record_id}` | `{ record, expected_provider_revision, expected_record }` |
| `DELETE /certificate-providers/{id}/dns/{record_id}` | `{ expected_provider_revision, expected_record }`; `204` after acknowledgement |

`record` is `{ type, name, content, ttl, proxied, priority }`; priority is null
except for MX. DNS writes return safe record metadata and observation timestamp.
Provider operations expose finite Cloudflare error codes for permission denial,
rate limit, unavailable/incomplete reads and unknown write outcomes; raw provider
messages are discarded. `404` denotes missing dashboard provider/record, `409`
stale state/in-use/busy/protected records, and `422` invalid input/provider rejection.
