# Certificate requests from the dashboard

## Safe ACME diagnostics

For an Admin UI certificate job, inspect gateway logs around its attempt:

```sh
docker logs --since 30m <gateway-container> 2>&1 | grep -E 'certificate (DNS )?diagnostic:'
```

Only finite allowlisted stage/status values are forwarded from the ACME child. Other child stderr is discarded; credentials, provider responses, TXT values, challenge data, and raw errors are not logged. `worker_failed` without a stage line can mean input preparation or child startup failed before ACME diagnostic emission. Rebuild the gateway image with matching `openwaf-admin` and `openwaf-acme` binaries to receive diagnostics; this change does not deploy an image.

If `dns_present` succeeds but `dns_propagation` never reaches `ok`, TXT creation
was acknowledged but visibility through the worker's resolver was not confirmed.
Successful `dns_cleanup` afterward does not mean issuance succeeded; it removes
the challenge record, so finding no TXT after the attempt is expected. New workers
emit `certificate DNS diagnostic: reason=...` on the propagation deadline:

| Reason | Check |
| --- | --- |
| `nxdomain` / `no_records` | Public zone delegation, exact challenge name, and negative DNS cache; a recursive resolver can retain an earlier missing-record answer beyond the 60-second propagation window. |
| `txt_mismatch` | Resolver still sees an old or unrelated TXT answer; check delegation, cache and any challenge CNAME. |
| `servfail` | Delegation/DNSSEC and recursive resolver health. |
| `timeout` / `network` | Outbound UDP/TCP 53 from the gateway container and the configured resolver's reachability. |
| `protocol` | Resolver response/protocol failure; inspect DNS independently. |

The reason describes the last lookup observation, not a definitive root cause.
Check from the **gateway** network namespace, where dashboard ACME children run.
In the Ansible deployment, `openwaf_acme_dns_resolver` (for example `1.1.1.1:53`,
only if reachable there) renders `OPENWAF_ACME_DNS_RESOLVER` for both bootstrap
and gateway. An empty value uses the request's configured resolver, then system
DNS. For an existing installation, pass this variable in the gateway service's
environment and recreate that service before retrying; editing Compose `.env`
alone does not update a running container. Keep encrypted account state, master
keys and cleanup journals intact. Do not skip propagation or TLS verification.

Open **Certificates → Request certificate**, enter an ASCII/punycode domain such
as `*.sub.example.com`, choose a saved Cloudflare DNS-01 provider, accept the CA
terms, and queue the request. Provider credentials can be configured in **DNS providers → Add provider**.
See [Cloudflare providers and DNS management](cloudflare-providers.md) for API
Token/Global API Key setup, zone selection and DNS records. Executable paths,
state paths and PEM keys remain server-controlled.

`*.sub.example.com` covers `app.sub.example.com`; it does not cover
`sub.example.com` or `a.b.sub.example.com`. A separate exact request is needed for
the base domain. Dashboard requests have one exact or wildcard identifier. The VPS bootstrap
separately issues one two-SAN certificate containing the zone apex and wildcard.
DNS records directing application traffic to the gateway remain an operator task.

## Status and ownership

- **Pending / running:** waiting for the owner or processing an ACME operation.
- **Worker check complete** (`current`): `renew-once` finished successfully; it
  may have issued a certificate or skipped one outside its renewal window.
- **Using existing wildcard** (`covered`): the live gateway selects a valid
  wildcard, so no separate child/config is created for the concrete hostname.
- **Degraded:** a finite, redacted error code explains the next step. **Retry**
  resets that request's failure budget with authenticated CSRF protection and audit.
- **Loaded / not loaded:** independently reports the valid certificate actually
  selected by the live TLS store. It does not prove public DNS/firewall reachability
  or browser trust in a custom CA. Staging results remain outside the live store.

A request with an already loaded exact manifest entry is rejected to preserve its
existing renewal owner. An existing Applications job that may own issuance also
blocks an explicit request. After acceptance, the explicit queue owns that hostname;
Applications excludes it from its own queue. The single supervisor runs the two
queues sequentially, with a shared transaction lock around ownership handoff.
Do not configure a separate `watch`/`watch-many` process for the same hostname.
Existing externally managed certificates continue to appear in the listener table.
There is no UI takeover, deletion or cancellation of certificate requests.
Dashboard provider credentials can be rotated without changing renewal ownership.

There are at most 16 application-managed providers total,
128 request rows and 256 retained per-host state
directories. Worker success schedules a renewal-window check after 12 hours. Failed
operations retry after five minutes, with at most five attempts before an explicit
retry. A process interrupted before acknowledgement retains a ten-minute running
lease. A 30-second reconciliation tick and coalesced notifications drive requests;
there is one child process at a time, with a 210-second operation deadline and
SIGTERM/25-second cleanup before forced termination on shutdown/deadline.

Existing wildcard coverage is rechecked on every tick. Removal/expiry returns a
covered concrete hostname to pending with a fresh budget. An explicitly requested
wildcard with a generated per-host config retains its renewal checks while valid.
No CA/provider request or database access is added to the TLS/proxy hot path.

## Server configuration

Set `OPENWAF_CERTIFICATES_ROOT` to the absolute private writable request-state
directory and `OPENWAF_CERTIFICATES_MASTER_KEY_FILE` to the external 32-byte ACME
key. The managed gateway must have a TLS listener (`OPENWAF_TLS_MANIFEST`).
Standalone Admin reports certificate requests unavailable. Add Cloudflare zones,
names, CA environments and credentials in **Certificates → DNS providers**.
PostgreSQL stores provider metadata and encrypted credentials; no provider catalog
or template file is needed for a fresh installation.

For an upgrade with `OPENWAF_CERTIFICATES_CONFIG`, startup imports the old catalog
once in an audited database transaction. Invalid/unreadable inputs or credentials
roll back the whole import and disable new requests without stopping existing
traffic. After success, file edits/removal have no effect on provider inventory;
all imported providers are editable in the application. See the
[migration and persistence contract](cloudflare-providers.md#secrets-ownership-and-persistence).
The two zones and two CA environments in the previous homelab catalog produce four
Cloudflare connections; these are retained rather than automatically merged.

State/TLS publication directories remain private (`0700`) and generated files use
`0600`. Keep external master keys and certificate/account state through upgrades.
Staging profiles publish outside the live TLS store and are not publicly trusted.

The template fingerprint is pinned in each request, and per-host configs are
immutable. A changed/missing provider degrades affected jobs with `provider_changed`
and stops issuance. Restore the original database profile before retrying;
retry does not silently migrate accounts, secrets, CA or state. Retain state through
upgrades and keep it separate from Applications artifacts. Crash/forced kill can
leave ACME writer locks or encrypted DNS cleanup journals: inspect the owner and
follow the [ACME cleanup procedure](../deploy/ansible/docs/runtime.md#restart-lỗi-và-dữ-liệu-bền-vững)
before deliberately clearing anything. Retry never deletes locks/journals.

## VPS Compose

The [VPS stack](../deploy/ansible/docs/runtime.md#quản-lý-tlsacme-trong-admin) enables this
existing Admin module by default. Offline dependency init creates the private
`certificate-requests` state volume and a separate 32-byte key in `certificate-key`.
Gateway receives `OPENWAF_CERTIFICATES_ROOT` and
`OPENWAF_CERTIFICATES_MASTER_KEY_FILE`, the key as read-only, and write access to
the live TLS volume. Root filesystem remains read-only; no Docker socket is mounted.
No `OPENWAF_CERTIFICATES_CONFIG`, per-domain JSON, provider template or independent
watch process is required. VPS bootstrap seeds one Production provider for its
zone; add other providers and certificate requests in the UI.

`admin-bootstrap` retains its separate token/key/state and owns the zone apex,
wildcard and admin hostname. A one-shot `bootstrap-provider` preflight checks
queue conflicts, reserves these identifiers and imports a Production provider in
an audited transaction before public DNS writes. It reuses an existing Production
provider for the same zone without replacing its credentials. The encrypted seed
uses the Admin key; gateway never receives the bootstrap ACME master key.
Restart does not overwrite or resurrect an edited/deleted provider. UI provider
rotation and bootstrap token-file rotation remain independent. Reserved identifiers
return `409` on explicit certificate requests, even before TLS loads; Applications
cannot claim them. See [migration](../deploy/ansible/docs/runtime.md#nâng-cấp-instance-đã-có-cert-exact).
The private files generated for UI jobs are internal runtime state derived from
PostgreSQL providers, not operator-managed configuration. Retain both sets of
keys/state through upgrades; never assign two workers the same hostname.

## Homelab Compose

The default gateway has no ACME signing key or TLS write mount. The opt-in
[Compose override](../deploy/homelab/compose.certificates.yaml) adds these exact
capabilities while keeping the container root read-only and Docker socket absent.
A one-time upgrade import can read the existing encrypted token mount; subsequent jobs use generated database-backed credential inputs.
The signing key is mounted at `/run/secrets/openwaf-acme-master.key`, outside
the read-only `/etc/openwaf` bind; provider templates must use this container path.

On the server, prepare directories with the existing deployment env file:

```sh
sudo python3 deploy/homelab/prepare.py certificates \
  --env-file deploy/homelab/.env
```

Deploy the updated images/override, then add providers in UI. The override supplies
the private state root and `OPENWAF_CERTIFICATES_MASTER_KEY_FILE`. Existing catalogs
and templates are used only for the first transactional import. The helper preserves
configuration/state so this upgrade can complete without losing renewal ownership.
Confirm the ACME master key/encrypted token have already been provisioned. Then
set `OPENWAF_CERTIFICATES_ENABLED=true` in the deployment `.env` and use the normal
image build/push/deploy workflow. `manage.py` includes the override when enabled;
`server.py deploy` prepares its directories before recreating the gateway group.
The feature code and deployment files must both be included in the deployed version.
No deployment or public issuance is performed by repository tests.

## API

All paths below are under `/api/v1`. GET requires a session. POST additionally
requires exact Origin and CSRF; mutations and consent are audited transactionally.

| Endpoint | Contract |
| --- | --- |
| `GET /certificates` | `enabled`, safe unavailable reason, provider ID/name/zone/environment, bounded requests, live selected certificate metadata, worker state and timestamps |
| `POST /certificates` | `{ "hostname": "*.sub.example.com", "provider_id": "cloudflare-example", "terms_of_service_agreed": true }`; `202` after durable queue/audit commit |
| `POST /certificates/retry` | `{ "hostname": "*.sub.example.com" }`; `204` after resetting a degraded job and committing audit |

Live certificate metadata includes `dns_names`, the actual leaf DNS SANs, alongside
SNI `hostname` and validity timestamps; neither field implies public CA trust.

Requests expose hostname/provider ID/state/attempts, `covered_by_hostname`,
`last_error_code`, `updated_at`, `next_attempt` and `loaded_certificate` metadata.
Raw templates, filesystem paths, provider tokens, account/key material and child
stdout/stderr never enter API responses. Error codes are `worker_failed`,
`interrupted`, and `provider_changed`; no unbounded provider error text is stored.
Validation/out-of-zone/consent failure returns `422`, duplicate/ownership/capacity
conflicts return `409`, unknown retry target `404`, unavailable configuration `503`.
