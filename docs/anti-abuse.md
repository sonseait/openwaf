# Anti-abuse AB-1–AB-6

## Operator workflow

New controls are opt-in per route under Configuration → middleware. They use the existing saved draft → validate → apply/version/rollback path. No detector automatically bans a client.

- `identity_rate_limit`: requires ForwardAuth and an explicitly approved `identity_headers` field. Quotas run after successful auth and before forwarding. Raw identity never enters retained quota state; process-keyed HMAC namespaces it by route, auth upstream/path and header. Missing identity follows `require_identity`; optional identity requires an existing IP/global rate policy. Malformed/oversized returned identity fails unavailable rather than using the missing-identity fallback. Existing IP/global protection remains in effect.
- `detectors`: observe-only endpoint probing and route flood. Evidence distinguishes upstream 404, gateway 404, denials, errors and capacity failures. These are completed-request observations, not an exact count of incoming starts or business/fraud outcomes. Request/path evidence is bounded and hashed; no raw body, token or principal is retained.
- `api_schema`: bounded JSON structural validation, default `observe`, explicit operator-selected `block`. The editor can import one selected required application/json request body from OpenAPI 3.0/3.1. This is not full OpenAPI validation. Import returns an unapplied policy; review and save/apply it through Configuration. Parameters, responses, references, formats and composition are not validated. Unknown schema keywords are rejected. Configure full body inspection and an application/json content contract. JSON bytes are not rewritten; duplicate object keys are rejected.

Abuse incidents opens detector diagnostics and persisted evidence with request/config-version links. Polling can be paused. Open/ack/resolved changes are authenticated, CSRF-protected, optimistic-revision checked and audited. PostgreSQL persistence runs outside proxy executors. Persistence failure does not stop forwarding. Gap/restart-unknown evidence must not silently resolve incidents. Existing Telegram outbox handles notification coalescing/silence; integration tests do not enable or send Telegram messages.

Security simulator is separate from routing Playground. Select active, saved draft or compare; exact active version and draft revision are submitted. It evaluates routing, IP ACL, content/schema and native WAF in independent policy workers. It never forwards a request, calls ForwardAuth, or consumes live identity quota. Stateful quotas, GeoIP, CrowdSec, challenge, sessions, detectors, incidents, DNS/TLS health and response/frame inspection are explicitly not simulated. Inputs/results stay local to the form and can be cleared. It is not proof a production request will have the same outcome in unmodeled layers.

## Bounds and lifecycle

### Client correlation and recent behavior

Routes with detectors now correlate endpoint-probing windows using a successful
ForwardAuth identity when exactly one approved `identity_headers` field is
configured and present. Multiple approved fields are intentionally ambiguous:
no first-field guess is made. Identity is HMAC-derived with route and auth
namespace; raw identity is not retained. Otherwise HTTPS uses a signed random
`__Host-openwaf-client` cookie (Secure, HttpOnly, SameSite=Lax, 30-minute fixed
expiry), and HTTP falls back to the trusted client IP. Cookies are stripped
before WAF/auth/upstream. Detector-route responses are private/no-store.

Cookie possession is correlation, not authentication: deleting, sharing or
copying cookies changes/merges sessions; first concurrent visits can split until
a cookie is established. Identity and anonymous windows are not retroactively
merged. Restart invalidates cookies and process-local correlation hashes.
There is no TLS/HTTP fingerprint, automatic ban or cross-route identity graph.

Each detector window retains at most 32 metadata-only recent completed requests,
sorted by request start and completion time: timestamps, status, upstream flag
and process-local path hash (query excluded). `correlation_source` distinguishes
verified identity, gateway cookie, IP fallback and route aggregate;
`sequence_truncated` discloses eviction. Parallel request ordering is not proof
of causality. Window duration/TTL, key caps and observation-loss quality retain
the existing detector bounds. Diagnostics and persisted incident evidence expose
the sequence; the UI expands recent events. This supplies bounded sequence
evidence, not a new semantic attack-sequence classifier.

- Security signals: 16 entries, metadata only; request details retain the existing 16 KiB transport cap. Native rule action is report-wide, not proof that each finding independently caused the final outcome.
- Identity quota: 4,096 process keys, 128 per route, identity at most 1,024 bytes. Changed rate/burst/auth namespace gets separate bounded state; unchanged configuration does not reset depleted quotas. Restart resets quota state. Expiry exceeds refill time. Lock contention and capacity return unavailable, not bypass.
- Detectors: 1,024 windows, 64 path hashes per window, 256 pending incident events; bounded TTL cleanup and evidence references. Process-keyed hashes reset on restart. Diagnostics expose warmup/stale/gap and drops.
- Incidents: 1,000 persisted records; resolved history expires after seven days during persistence. Open/ACK records are not evicted merely to admit new incidents; saturation is degraded pending/drop behavior rather than pretending complete history.
- Schema: 64 KiB body, 256 schema nodes, schema depth 8, input depth 16 and 8,192 input nodes, bounded property/array/string limits. Exceeding inspection capacity returns 503. No multipart/streaming expansion, response validation or body normalization is added.
- Simulator: two request slots; independently bounded native policy compiler/worker capacity. Body 64 KiB, 64 headers/16 KiB, URI 8 KiB. Native transaction capacity remains held by its job after caller cancellation. Additional state/native allowances are included in resource accounting, not claimed as measured peak RSS.

## Verification and remaining gates

See [local acceptance evidence](evidence/anti-abuse/acceptance.md). The local integration test uses a disposable PostgreSQL container, synthetic credentials, real native WAF rules and upstream/auth spies. Browser tests intercept explicitly synthetic API fixtures: they verify rendering and interaction, not a browser-to-live-backend deployment.

Remaining production acceptance: release workload/overhead benchmarks; sustained high-cardinality and slow-client load; real CRS distribution rather than only native fixture rules; ClickHouse/SSE overflow/reconnect end-to-end; Telegram delivery; Linux deployment/restart/load verification. The identity limiter currently performs a bounded full retained-state cleanup scan per check; its latency at the maximum key count has not been benchmarked. Schema parsing is bounded but runs synchronously in request processing; executor latency under adversarial concurrency remains a required performance gate. Do not interpret passing functional tests as a capacity/SLA claim.
