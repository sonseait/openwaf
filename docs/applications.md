# Frontend Applications

Applications serves prebuilt static HTML and SPA releases directly from the Rust gateway. It does not build source, execute scripts on the server, run Node/SSR, deploy containers, or manage DNS records. Each app uses `/` on its own domain. Proxy routes remain available for API backends.

## Use

1. Enable persistent artifact storage with `OPENWAF_APPLICATIONS_ROOT=/var/lib/openwaf/applications`; the directory must be absolute and writable by the gateway user. In Docker this is the container volume destination, not the host source directory. Recreate the container after changing mounts/environment. The homelab deploy helper prepares storage for UID 10001 before recreation; see [homelab storage setup](../deploy/homelab/README.md#frontend-applications). Database migrations run through the existing admin startup path.
2. Open **Applications**. The bordered **Application library** lists apps, domains, deployment and loaded TLS status; **Domains & HTTPS** holds preview and certificate setup, and **Storage limits** shows upload/retention budgets. **Create app** opens a modal for the name, production domain and **Static HTML** or **SPA** mode. The admin hostname and its children are rejected. Point the production domain's A/AAAA records to the gateway; omit AAAA if IPv6 does not reach it. HTTPS uses the gateway listener's public port.
3. Click the application name or **Manage** to open the release manager modal (also opened after creating an app). Upload a ZIP of the build output, for example `dist/`, rather than the source repository. `index.html` must appear at the ZIP root or under one common enclosing directory. Uploading does not publish content.
4. Optionally configure a dedicated preview base domain such as `preview.example.com`. Point `*.preview.example.com` to the gateway and provision wildcard TLS. **Create preview** prepares and applies a separate route to `<random-label>.preview.example.com` (for example `aB3xY7kL9mQ2.preview.example.com`). Each release receives a persistent 12-character `a-zA-Z0-9` label generated from PostgreSQL cryptographic UUID randomness, independently from its artifact ID/checksum. Review and apply use the same saved label. DNS matching and uniqueness are case-insensitive; the displayed URL keeps the saved letter case. Existing long preview URLs remain active across upgrade/review/restart until disabled; creating a new preview afterwards uses the saved short label. Preview is public, expires after seven days, and sends `X-Robots-Tag: noindex, nofollow, noarchive` and `Cache-Control: no-store`. These headers are not access control. Do not upload private content to a public preview.
5. Review **Deploy**, then confirm. Review shows the route diff, preserved more specific routes, selected release and loaded TLS status. An unrelated draft must be applied or discarded first. If another mutation changes the version, reload and review again.
6. Use **Rollback** for an earlier release, **Disable** to remove production routing, or disable an individual preview. An active/preview release cannot be deleted. Use **Edit** to open the metadata modal; to change app name/domain/mode, disable production and all previews first. More specific API routes are preserved when an app is disabled.

A valid certificate must be loaded for the SNI before HTTPS works. Domain DNS reachability and public firewall reachability are not tested by this UI. An unavailable certificate badge never means HTTPS is ready; a provisioning job marked `current` also does not establish gateway reload or public reachability.

## Routing and serving contract

The optional route field is:

```json
{
  "application": {
    "application_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "release_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "mode": "spa",
    "preview_expires_at_unix_ms": 1790000000000
  }
}
```

Production omits the expiry. The target cannot coexist with upstream/redirect, wildcard hostname, a non-root path or a methods filter. Applications owns target, ID and domain. Configuration still edits route protection, security headers, middleware and maintenance. Manual draft APIs cannot inject/remove/change an application target. Config rollback revalidates database ownership and artifact availability; a deleted release makes historical rollback fail before publication.

Deploy uses the same configuration writer, expected draft revision and expected active version as ordinary apply. Metadata/audit/config version commit together before infallible snapshot publication. Pending unrelated drafts are never implicitly applied. Root routes that overlap the app hostname are rejected rather than shadowed. Longer routes such as `/api` keep precedence and appear in review. Route limits remain 128 for the entire gateway; previews consume routes too.

Every request captures an immutable snapshot holding its release resource. Security, WAF, password sessions, ForwardAuth, maintenance and response headers use the existing path. New application routes use CRS `DetectionOnly`, paranoia level 1. Change protection explicitly in Configuration when ready for blocking. Local requests have application/release metadata and do not falsely report upstream forwarding.

The server supports GET/HEAD, MIME types, ETag/If-None-Match, a single byte range and If-Range with an exact ETag. Other methods return 405 after security checks. Static mode serves existing files and directory index files; directory URLs redirect to a trailing slash. There is no directory listing. SPA fallback requires HTML navigation and an extensionless final path segment; missing JS/CSS/images and non-HTML fetches return 404. Default cache policy is `no-cache` (revalidate), with no CDN cache or filename-based immutable heuristic. The gateway streams 64 KiB chunks with backpressure and existing request/write deadlines, with at most 64 concurrent artifact I/O leases. Disk failures return 503 before headers or abort an already-started response.

Existing browser tabs can request old asset URLs after a deploy; keeping a release for rollback does not expose its assets through the new production route. Reopen/reload the page if assets from an old tab are missing. No promise is made that every browser session survives a release switch.

## Upload, persistence and limits

| Resource | Default |
| --- | --- |
| Compressed ZIP | 100 MiB |
| Expanded files per release | 500 MiB |
| Files per release | 10,000 |
| Materialized directories per release, including implicit parents | 10,000 |
| ZIP entries including directories | 20,000 |
| Serialized release manifest | 4 MiB |
| Artifact storage, including staging | 5 GiB |
| Concurrent upload/extraction | 1 |
| Recent releases retained per app | 5, plus active/preview releases |
| Application records | 64 |
| Release records per app | At most 64; reject further uploads when all remain protected |

Override byte budgets with `OPENWAF_APPLICATIONS_ZIP_BYTES`, `OPENWAF_APPLICATIONS_EXPANDED_BYTES`, `OPENWAF_APPLICATIONS_TOTAL_BYTES`. ZIP is bounded to 1 GiB, expanded content to 4 GiB. Before each upload, available module capacity must cover the configured maximum ZIP and expanded content, 4 MiB manifest, and 8 KiB per allowed file for allocation/directory overhead (about 78 MiB by default). Storage accounting includes directories and the greater of logical length or allocated filesystem blocks, including abandoned staging. A final quota check runs before publication; unusual filesystem allocation can still reject extraction. File count/retention defaults are fixed in this version. These are module budgets, not a filesystem or host-wide quota.

Raw central-directory inspection happens before the ZIP library builds a filename map, so duplicate names cannot disappear silently. Encrypted, ZIP64, split/multi-disk, malformed, absolute/traversing paths, links, special files and duplicate normalized names are rejected. Names must be UTF-8; backslashes, controls, colons and dot segments are rejected. The entry/byte/time limits are checked during extraction, not just against declared sizes.

Upload streams to staging, then a bounded worker extracts outside the proxy runtime with a 60-second extraction deadline. Final files and directories are synchronized before an atomic rename to `releases/<release-id>`. The database records archive SHA-256, expanded size, file count and upload time. Only the release's `public/` directory is served; manifests, staging and ACME state are outside it. Files are immutable through the API. Local administrators must not edit artifacts in place.

The admin supervisor owns cleanup and certificate workers. Staging older than one hour is collected. Metadata deletion commits before artifact reclamation; active snapshots and transfers retain leases until retirement. An upload interrupted after artifact publication can leave an unreferenced artifact for the janitor. Quota reservations include abandoned staging, so retries cannot accumulate unlimited partial ZIPs. Cleanup failures are reported and retried, and never remove production routes. Artifacts require their own persistent volume; database-only backup is insufficient. This feature does not implement backup/restore.

## Automatic TLS

The **Domains & HTTPS** block links to **Certificates**. Without an Applications ACME template, it reads `GET /api/v1/certificates` to report certificate service availability, missing provider setup or worker degradation. A missing template alone is not a TLS warning: Certificates-managed requests renew separately, and Applications reuse loaded certificates. Creating an app does not automatically request a certificate through that separate service; request the domain or preview wildcard in Certificates. Failed status reads show partial availability and a retry action; they do not imply that loaded TLS is absent. Per-app/preview badges continue to use the Applications inventory's live gateway state. **Refresh** refreshes both inventories.

The optional Applications certificate queue reuses `openwaf-acme renew-once CONFIG.json`, which checks the renewal window before issuing. It has one child process at a time, a 210-second operation deadline, five attempts per failure budget, a five-minute retry delay and a twelve-hour check interval after success. **Retry failed certificates** resets degraded jobs explicitly. Worker stdout/stderr and provider errors do not enter the API or traffic logs. Gateway TLS status comes from the live certificate store, with timestamped job status shown separately. Obsolete job rows are removed as domains change. Generated host-state directories remain for DNS cleanup/recovery and are capped at 128; inspect obsolete state before deliberately reclaiming it.

The queue reuses a currently valid wildcard selected by the gateway for a production hostname. For example, a loaded `*.example.com` serves `shop.example.com` without another certificate request, worker process or generated per-host config. The job reports `state: "covered"` and `covered_by_hostname: "*.example.com"`; the UI shows **Using wildcard**. Matching uses the same exact-first, single-label selection as TLS handshakes and the live TLS badge. An exact certificate retains precedence, including rejection after its expiry; an unrelated wildcard cannot mask it. `*.example.com` covers neither `example.com` nor `shop.preview.example.com`.

Coverage is re-evaluated every 30 seconds, independently of issuance retry budgets. A wildcard hot reload can recover an exhausted job without manual retry. Removal or expiry returns a covered job to pending with a fresh retry budget; HTTPS remains unavailable until a valid replacement is loaded. Existing wildcard renewal remains the responsibility of its current certificate manager. For previews, the exact `*.preview-base-domain` manifest entry can also be reused if this queue has no generated config for that wildcard. Once the queue has generated a config, it conservatively retains ownership of renewal checks, even while its wildcard is valid. Keep generated state during upgrades so owned wildcard renewal is not mistaken for externally managed coverage. Exact certificates continue through `renew-once` and its renewal-window checks.

Set these on the managed gateway:

```text
OPENWAF_APPLICATIONS_ACME_TEMPLATE=/etc/openwaf-applications/acme-template.json
OPENWAF_APPLICATIONS_ACME_ROOT=/var/lib/openwaf-applications-acme
OPENWAF_APPLICATIONS_ACME_BINARY=/usr/local/bin/openwaf-acme
```

The template must be an owner-only JSON file following the existing ACME config schema, with `cloudflare` DNS-01 configuration, `directory_url`, `master_key_file`, `tls_manifest`, and explicitly accepted terms. Do not include `challenge_listen`. The controller supplies `hostname` and a separate per-host `state_dir`; preview provisioning uses `*.preview-base-domain`. A single template covers one configured Cloudflare zone. Other zones require manually managed certificates in this version. Do not put credentials into ZIPs, UI fields, source or example fixtures.

Provide the ACME master key and encrypted token as separate private files. The process needs a writable ACME state volume and TLS manifest/publication directory. Keep them outside the artifact volume; the master key must be outside the ACME state directory. The existing homelab profile intentionally does not mount ACME signing credentials into the gateway, so automatic provisioning requires an explicit local deployment override for those files/volumes. Manual certificate provisioning and the existing isolated ACME service remain valid alternatives.

Generated per-host configs are immutable. After changing the provider template, stop issuance, inspect pending DNS leases/locks, and deliberately replace the generated config; the worker refuses an implicit rewrite. Normal shutdown sends SIGTERM and allows bounded DNS cleanup. Crash/forced kill may leave ACME writer locks or cleanup journals; inspect process state and follow the existing ACME recovery runbook before clearing locks. Retry does not blindly delete a lock. Use Let's Encrypt staging before production. Public DNS-01, CA issuance, renewal and hot reload still require deployment-specific validation; repository fixtures do not certify public TLS readiness.

## API

All paths below are under `/api/v1`; mutations require the existing session, exact Origin and CSRF token.

| Method/path | Behavior |
| --- | --- |
| `GET /applications` | Bounded app/release inventory, active release/domain, preview expiry, live TLS status, certificate jobs, limits and preview settings |
| `POST /applications` | Create `{name, domain, mode}` |
| `PUT /applications/{id}` | Update metadata while production/previews are disabled |
| `PUT /applications/settings` | Set `{preview_base_domain}` or clear with null; disable previews first |
| `POST /applications/{id}/releases` | Multipart upload with one `file` field; returns immutable release metadata |
| `DELETE /applications/{id}/releases/{release}` | Delete an inactive release; existing request leases delay physical reclamation |
| `POST /applications/{id}/review` | Prepare and return diff, selected targets/TLS and preserved routes, without publication |
| `POST /applications/{id}/actions` | Durable validate/apply and audit |
| `POST /applications/certificates/retry` | Reset degraded certificate jobs, with audit |

Review/action input: `{kind, release_id?, expected_active_version, expected_draft_revision}`. Kinds: `deploy`, `rollback`, `preview`, `disable_preview`, `disable`. A release is required except for `disable`. Version conflicts return 409; missing app/release returns 404; malformed ZIP/config returns 422; oversized streamed ZIP returns 413; unavailable storage/preparation returns 503. Errors do not echo ZIP contents, filesystem paths or provider secrets. A missing upload acknowledgement is an unknown outcome: reload release history before retrying.

Pingora forwards dashboard traffic directly to Axum. The existing authenticated multipart handler retains its size limit and 180-second upload deadline; static dashboard serving does not consume or buffer upload bodies. Application content is served by Rust/Pingora, without a per-app webserver.

## Application dialog polish (2026-10-27)

The routing review dialog groups application/action context, added/updated/removed
route counts, destinations and TLS status, with expandable route details and
explicit Cancel/Confirm actions. Technical JSON is no longer shown as the primary
review content. The release Preview column shows the URL and expiry/TLS status. Create preview
and Disable preview sit in Actions alongside Deploy/Rollback and Delete. The table scrolls horizontally on
small screens without compressing cells or expanding the modal. The native ZIP
picker keeps its label/keyboard behavior and uses theme-aware button, focus,
hover and disabled styling.
