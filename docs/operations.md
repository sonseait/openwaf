# Request safety and operational controls

The route editor exposes body handling, retry authorization and replay storage as separate controls. Existing configurations default to one attempt, replay `none`, full inspection and a 64 KiB request body limit. New explicit WAF policies default to DetectionOnly / paranoia level 1.

Linux/systemd and Compose deployment, private HTTPS admin hosting, SIGTERM ordering,
incident handling and rollback are covered in the [deployment runbook](deployment-runbook.md).

Per-route redirects with path/query preservation, path rewrite, custom headers,
CORS and ForwardAuth are configured under **Configuration → Routes → Request middleware**
(redirect controls are under **Redirect requests**). See the
[middleware contract](route-middleware.md) for execution order, trust boundaries,
limits and provider compatibility.

Gateway error HTML is configured globally or per route under **Error pages**.
See the [error page contract](error-pages.md) for precedence, validation,
JSON/HEAD behavior, browser preview and CSP restrictions.

## Upstream DNS after container redeployment

Configure upstreams with stable service names or unique network aliases on a shared
Docker network, not container IPs. The background health scheduler resolves names
and publishes validated, healthy socket addresses for proxy selection; request
routing does not perform a separate DNS lookup on the hot path.

The runtime resolver caps positive DNS cache TTL at five seconds and negative
cache TTL at one second, without extending shorter authoritative TTLs. These are
cache bounds, not an outage/recovery SLA: probe deadlines, health thresholds,
bounded job capacity and failure backoff (up to 30 seconds) also affect recovery.

In managed mode, the scheduler reads the private collector's Docker inventory
every two seconds. A change in fresh inventory clears the runtime DNS cache and
reschedules hostname checks, resetting their recovery backoff. This is a global,
coalesced hint, not a per-service subscription: all configured hostname endpoints
are rechecked through the existing bounded worker pool. Results from probes that
started before the hint are discarded and retried. The collector still owns Docker
events and periodic reconciliation; gateway never receives the Docker socket.

Collector outage/stale inventory does not clear upstream configuration or disable
ordinary DNS refresh. Discovery never writes container IPs into configuration or
auto-selects new services. DNS results still undergo loop validation, health checks
and normal HTTP Host/TLS SNI/verification handling. No API payload changes are
required. This mechanism does not migrate an established connection to a new IP.

## Retry contract

| Mode | Before sending upstream headers | After starting upstream headers |
| --- | --- | --- |
| `disabled` | Never | Never |
| `connect-only` | Transport failures only | Never |
| `safe` | Configured safe methods only | Configured safe methods, with complete replay for nonempty bodies |
| `idempotent` | Valid Idempotency-Key required | Valid key, backend deduplication contract, complete replay for nonempty bodies |

Safe defaults are GET, HEAD and OPTIONS. Explicit PUT/DELETE opt-in requires backend semantics that make repetition safe. POST/PATCH use idempotent mode. An absent, repeated, empty, non-printable or longer-than-255-byte Idempotency-Key forwards once. Endpoint scope pins retries after starting the first request; pool scope is an operator assertion that backend deduplication is shared across endpoints.

`max_attempts` includes the first attempt and is bounded to 1–5. Retry causes are transport errors: `connect_failure`, `connect_timeout`, `connection_reset`, `request_write_timeout`, `response_header_timeout`, `per_try_timeout`. HTTP statuses do not trigger retries. TLS verification failures, downstream errors, final upstream headers, 101 upgrades, committed responses, cancellation, force disconnect and shutdown prohibit retry.

`per_try_timeout_ms` covers connection establishment, body transmission and waiting for final upstream headers. It ends at those headers. `total_timeout_ms` covers admission, WAF, client body, attempts, jitter and response streaming without reset. On expiry the request/stream is closed, including stalled downstream writes. A per-attempt timeout can produce a reference-bearing 504 before a response starts. A total deadline may terminate a connection without an HTTP error page.

Backoff uses full jitter with a 100 ms base and 1 s cap by default. The default node budget admits at most 16 retrying logical requests. Uploads also consume their configured class, route and client quotas (four uploads per route by default). If retry capacity cannot be reserved, the gateway returns 503 instead of sending another attempt.

Example route fragments use the API's canonical milliseconds and bytes:

```json
[
  {"retry":{"mode":"safe","max_attempts":3,"per_try_timeout_ms":3000,"total_timeout_ms":8000,"retry_on":["connect_failure","connection_reset"]}},
  {"body":{"inspection":"headers-query-only","max_body_bytes":536870912},"retry":{"mode":"connect-only","max_attempts":2,"replay":{"mode":"none"},"total_timeout_ms":1800000}},
  {"retry":{"mode":"disabled"}},
  {"body":{"inspection":"headers-query-only","max_body_bytes":536870912},"retry":{"mode":"idempotent","max_attempts":2,"replay":{"mode":"disk","max_body_size_bytes":536870912}}}
]
```

Body storage never grants retry permission. Memory replay defaults to 64 KiB, at most 1 MiB/request, with a 64 MiB aggregate reservation budget. Disk replay defaults to 512 MiB, at most 2 GiB/request, with 2 GiB aggregate reservations, four retained disk captures, four positional reads and four 64 KiB chunks queued per writer. Anonymous temporary files have private permissions and no directory entry to leave behind after a crash. Disk I/O runs on bounded blocking workers; replay reads have independent offsets. Disk capture tees the first upstream stream. Failure before capture completes prevents replay; the gateway does not drain a failed client's body to manufacture a replay source. Capture cap/quota/queue/write failure disables replay and continues forwarding the original body once. The independent request-body limit still rejects oversize bodies with 413.

All syntactically valid `multipart/*` requests skip native body parsing, including on ordinary routes. Headers, query and other security layers remain active. Multipart streams and explicit `headers-query-only` routes do not prebuffer the request. Large non-multipart bodies require that explicit inspection setting. Full inspection remains bounded to 64 KiB and completes before upstream transmission. A header/query block never reaches upstream; a stream crossing its body limit may already have sent its earlier bytes.

## Request reference and false positives

Every admitted HTTP request receives a random 64-character `X-Request-ID` drawn uniformly from `A-Z`, `a-z`, `0-9` and `_` (about 383 bits of entropy). Generation uses OpenSSL’s CSPRNG with bounded rejection sampling. Lookup accepts exactly 64 characters from the same alphabet, or legacy 32-character IDs (including lowercase hexadecimal IDs). Existing stored references remain searchable; no storage migration is required. Incoming IDs and upstream response IDs are overwritten. The same ID reaches backend headers, client response and available traffic records. This provides correlation; it is not a distributed tracing implementation.

Gateway error responses select HTML or JSON using Accept, contain a generic explanation and request ID, use no-store, and disclose no rules or matched values. Request details use schema version 8 (bounded body/query capture markers, retaining schema 6 timing and at most 16 decision checkpoints): bounded client/IP/GeoIP/UA/TLS metadata, original request method/host/path, redacted headers, declared/observed body sizes, response metadata, pinned configuration/route, decision layer, inspection scope, up to 32 numeric native findings, bounded attempts and reasons retry/replay stopped. Native messages, body contents, credentials, query values and matched data are omitted from ordinary telemetry. Opt-in [body recording](body-recording.md) stores redacted request/response payloads and opt-in query strings separately and loads them only through the authenticated body endpoint. See the [request details contract](request-details.md) for field sources, redaction, partial records and budgets. Rules using `nolog` may omit findings. Native anomaly score is currently unavailable (`null`). Cancelled admitted requests produce partial status-0 records where telemetry capacity permits; they do not increment completed-request metrics.

The request detail dialog proposes a rule/target exclusion to the configuration draft. The default expiry is 24 hours; 0 hours deliberately selects permanent. Targets support exact names in ARGS, ARGS_GET, ARGS_POST, REQUEST_HEADERS or REQUEST_COOKIES. Rule IDs are checked against the installed ruleset. Expiry is evaluated per native transaction without requiring a reload. Review the existing diff and apply to activate; normal draft concurrency, validation and audit apply. Explicit route WAF configuration is required before proposing an exclusion.

## Shadow policy

One session/node samples 1–100% of real traffic, default 10% for 30 minutes. A separate compiler, native pools and four-job queue isolate candidate work. Sampling uses the random request ID, once per logical request; retries do not resample. Only the session's initial active configuration version is compared. The candidate receives the same body-inspection scope, so streamed bodies are omitted. Shadow work never sends upstream requests or changes enforcement. Sessions report sampled/completed/would-block/different/dropped totals and bounded rule counts. Sessions are ephemeral across gateway restart; dropped samples limit conclusions.

Route-specific scheduled maintenance renders a local 503 page, independently of
endpoint admission modes. Configure it in the route modal; see the
[route maintenance contract](route-maintenance.md) for precedence and save/apply semantics.
Discovery endpoint diagnostics use a searchable table with the existing controls modal.

## Endpoint controls and health

An opaque endpoint key identifies the canonical upstream ID, protocol, configured address and SNI. It survives reordering, DNS address changes and source refresh; changing these identity fields creates another endpoint identity. Drain and maintenance persist in PostgreSQL with an optimistic revision/reason/audit. Both exclude new endpoint admissions and retries. Existing leases continue, including requests pinned to retired routing snapshots. Force disconnect is a separate audited action; it cancels the request/HTTP/2 stream using the endpoint. It does not close unrelated multiplexed streams.

Gateway-origin diagnostics record DNS/TCP/TLS/HTTP status, latency, observation time and configuration version every 30 seconds, retain seven days and return at most 100 recent endpoint samples. Existing live health checks continue to decide eligibility; historical records do not control traffic.

`GET /api/v1/operations/endpoints?summary=true` is the dashboard polling view
(every five seconds while running). Each `endpoints[]` entry carries `health`:
`available`, `reason`, `phase`, `checked_at_ms`, remaining `valid_for_ms`, and
nullable `latency_ms`. Identity and health are joined by the server from one
retained active snapshot; `config_version`, `observed_at_unix_ms`, `source` and
`operations` remain present. Summary omits the top-level `diagnostics` array and
per-address/DNS check details. Without `summary=true`, the existing full response
is unchanged. Detailed recent checks remain available on demand through the
endpoint history API. Missing/expired health, pause or a failed poll is Unknown,
never a current healthy observation.

Endpoint tables and uptime monitors do not fetch `/config` to match health.
The frontend caches the single `config` query for 30 seconds of freshness and
60 seconds after its last observer unmounts. Local save/apply/rollback/application
mutations still invalidate it immediately; a changed active version observed by
endpoint polling also invalidates it (only mounted config consumers refetch).
Navigation within the freshness window reuses config; later mounts revalidate.
This is a bounded in-memory cache, cleared on logout/401, not HTTP caching or
cross-tab draft-change synchronization. Other protected queries keep their
existing retention policy.

After successful upstream 2xx headers with `Content-Type: text/event-stream`, a
read error, read timeout or closed connection terminates that request and remains
visible in its traffic log, but does not passively quarantine the shared endpoint.
Other API requests remain eligible; active health checks can still remove an
unhealthy endpoint. Connection/TLS failures, errors before final headers, ordinary
response failures and unsuccessful SSE responses keep their existing passive
failure behavior. This does not authorize retries or replace a started response.

Admin SSE bodies end cleanly two seconds before the accepted socket's 30-second
deadline. The deadline is measured from socket acceptance, including time spent
serving earlier requests on a pooled connection. HTTP/1 SSE responses close that
connection after the complete body, so the edge reconnects on a fresh socket.
The hard I/O deadline still bounds stalled readers; authenticated upload budgets
are unchanged. EventSource reconnects using the existing sync/gap protocol; there
is no event replay or payload change.

Active health probes and their scheduler share the validated `health_jobs` budget (1–16). Local probe admission `busy` defers the endpoint check by 100 ms without changing the previous observation, success/failure streaks or failure backoff. This never extends the original DNS/health expiry or clears passive failures: expired or failed peers remain unavailable. If an address already failed a real check before admission becomes busy, only the verified healthy subset is published. Resource diagnostics expose `health_capacity.deferred_total`, also shown as Deferred checks and exported as `openwaf_health_deferred_total`; this process counter resets on restart. Persistent scheduling overload can still exhaust health validity and must be addressed using backlog/delay/capacity diagnostics.

System health separates gateway heartbeat, protection components and monitoring loss. ClickHouse failure or collector loss does not imply traffic stopped. Loss counters remain visible after recovery. PostgreSQL failure can also prevent session authentication; the UI then labels observations stale. ACME supervisors atomically write `STATE_DIR/health.json` every five seconds. Configure `OPENWAF_ACME_HEALTH_FILES` as a comma-separated inventory of up to eight files readable by the admin process. Age over 20 seconds, stopped supervisors and renewal failures are degraded. No inventory is reported as not configured; loaded certificates alone do not prove renewal health.

## Telegram

Alerts use one encrypted bot token, one numeric chat ID and an optional topic. The worker is outbound-only: no polling or commands. Configure it in Alerts, then send a test notification. Token reads never return plaintext. Alert groups include upstreams, WAF workers, CrowdSec, history/monitoring, collector, ACME, expiring certificates and blocked-volume surges. Component transitions emit recovery events. Silence is bounded to seven days.

Outbox pending work is capped at 1,000; saturation is visible in the API/UI and test requests return 503 rather than acknowledging a discarded alert. Evaluated state transitions stay pending until accepted, while the owner continues draining existing work. Repeated groups coalesce for five minutes, entries expire after 24 hours and terminal history retains seven days. Delivery checks Telegram's acknowledgement, honors Retry-After / retry_after (capped at one hour), uses bounded exponential delays and stops after eight attempts. Unacknowledged deliveries can repeat; Telegram has no gateway-controlled deduplication contract. PostgreSQL outage prevents persisted alert delivery until the control plane recovers. No actual Telegram credentials or messages are used by repository tests.

### Safe admin operational logs

Admin diagnostics belong to control-plane lifecycle boundaries, not the proxy request
path. Config validate/prepare/commit/publication and rollback should report finite
operation/outcome/reason fields and numeric config versions/revisions; do not log
documents, diffs, arbitrary error chains, peer addresses, credentials or request data.
Certificate and Applications workers should record bounded preparation stages,
child exit/cancellation/deadline and queue degradation/recovery, without raw child
stderr, provider responses, hostnames or filesystem paths. Telegram delivery logs
should report sent/retry/rejected and bounded attempt/reason codes, never URLs,
tokens, chat content, response bodies or DB errors. Repeated background failures
must be transition-based or rate-limited (including scheduler cycles); success logs
must not be emitted on every poll. Existing diagnostics are partial: ACME has an
allowlisted child-stage protocol, while config, Applications and Telegram worker
boundaries have uneven coverage. Logs supplement durable audit, health observations
and outbox state; they are not a delivery or mutation ledger.

## Authenticated API additions

All mutations require the existing session and CSRF token.

| API | Purpose |
| --- | --- |
| `GET /api/v1/requests/{request-id}` | Lookup in the 1,000-entry live ring, then bounded seven-day ClickHouse history |
| `GET /api/v1/history/traffic?...&request_id=...` | Filter persisted records by validated reference |
| `GET/POST/DELETE /api/v1/security/shadow` | Session status/start/stop; start accepts route_id, policy, sampling_percent, duration_ms |
| `GET/PUT /api/v1/operations/endpoints` | Endpoint identity/diagnostics/leases; update accepts key, mode, expected_revision, reason |
| `POST /api/v1/operations/endpoints/history` | Recent diagnostics for `{key}` |
| `POST /api/v1/operations/endpoints/force-disconnect` | Cancel active endpoint requests for `{key}` |
| `GET /api/v1/health/system` | Serving, monitoring and dependency observations |
| `GET/PUT /api/v1/alerts/telegram` | Redacted settings; update uses expected_revision, enabled, chat_id, topic_id, optional token, silence_until_unix_ms |
| `POST /api/v1/alerts/telegram/test` | Queue a test notification |
| `GET /api/v1/alerts/telegram/outbox` | At most 100 recent delivery states |

### System health observations

`GET /api/v1/health/system` retains the authenticated, read-only component map.
`components.collector.sources.host_ports` and `.docker` each include `state`,
`observed_at_unix_ms`, `stale`, `error` and `reason`; successful inventory reads
also include `collector_available` and `docker_events_connected` (null for host
ports). Checks run concurrently with a three-second deadline per source. A
source failure preserves the other source's observation. Docker events being
disconnected degrades Docker health even when polling inventory is fresh.
Both sources unavailable makes the collector unavailable; one failed source
makes it degraded. These observations never change applied upstreams.

`components.acme.sources` reports `certificate_requests`, `applications` and
`schedules`. The first two reuse the existing supervisor observations; a fresh
`available` worker maps to healthy, starting/degraded workers map to degraded,
and missing/future/older-than-ten-minute heartbeats map to unavailable. This
freshness window allows the shared owner's two bounded children and cleanup.
Disabled sources are not configured and do not degrade configured sources.
Certificate runtime initialization failure remains degraded/unavailable.
Degraded jobs in each enabled queue degrade its source; a two-second database
deadline or read failure makes enabled queue observations unavailable.

`OPENWAF_ACME_HEALTH_FILES` remains optional for external `watch`/`watch-many`
schedules: one to eight comma-separated absolute health file paths, bounded to
4 KiB and 200 ms per read. Their freshness limit remains twenty seconds;
future timestamps are invalid. Explicitly configured missing/stale/failed
schedules degrade ACME even when the managed worker is healthy. The existing
top-level ACME `schedules` array is retained, with source details also under
`sources.schedules`. Managed Certificates needs no health-file variable.
No configured source produces `not_configured`, without an instruction to
enable an unrelated external worker.

Health shows worker/job observations, not proof of issuance, certificate loading,
public CA trust or public reachability. VPS `admin-bootstrap` remains monitored
separately by its Docker healthcheck/logs; its private state is not mounted into
gateway. Telegram uses the same ACME/collector aggregation as System health.
The page shows per-source states, timestamps, stale indicators, Docker event
connectivity and links to Certificates/Discovery.

The System health UI groups component cards into Traffic & protection,
Storage & telemetry and Discovery & TLS, with separate gateway heartbeat,
monitoring/log loss and component summaries. All / Needs attention / Not
configured filters apply to components; a source's unavailable, stale or unknown
state also puts its parent component in Needs attention. Not configured sources
remain neutral. TLS `observed` describes inventory, without asserting renewal
health. Each card names its purpose, shows available queue/backlog/certificate
counts and exposes per-source observations in an expandable section. Dropped,
written and failed-inspection values are counters, not rates.

Automatic refresh remains five seconds, with Pause/Resume and manual Refresh.
Paused observations are identified as a snapshot. A refresh failure keeps the
last snapshot with a stale warning and current health unknown; no successful
snapshot for fifteen seconds while refreshing also shows stale. Loading, no
observations and empty filters have separate states. No API payloads or health
aggregation rules change.


ClickHouse startup adds defaulted request_id/details columns to the existing table before inserting the new log shape. Old records remain readable with empty IDs/details.

## Implementation map

| Area | Main files |
| --- | --- |
| Retry/body contracts and admission | [retry schema](../backend/crates/config/src/retry.rs), [endpoint state](../backend/crates/config/src/operations.rs) |
| Proxy, replay and shadow evaluation | [gateway](../backend/crates/gateway/src/main.rs), [retry](../backend/crates/gateway/src/retry.rs), [capture](../backend/crates/gateway/src/replay.rs), [shadow](../backend/crates/gateway/src/shadow.rs), [Pingora extension](../backend/vendor/pingora-proxy/OPENWAF.md) |
| Admin and persistence | [endpoint operations](../backend/crates/admin/src/operations.rs), [Telegram](../backend/crates/admin/src/telegram.rs), [system health](../backend/crates/admin/src/health.rs), [migration](../backend/crates/admin/migrations/202610180004_operations.sql) |
| Native findings/exclusions | [adapter](../backend/crates/waf/src/native.cpp), [Rust ownership](../backend/crates/waf/src/native.rs) |
| Operator interface | [route editor](../frontend/src/configuration/RouteEditor.tsx), [request details](../frontend/src/RequestDetails.tsx), [operational controls](../frontend/src/OperationalControls.tsx), [system health](../frontend/src/SystemHealth.tsx) |

## Traffic profiles và content contracts (Phase 6)

Route cũ thiếu
`content` giữ semantics hiện có. Template chỉ là bản sao vào draft theo thao tác
người vận hành, không auto-expand/rewrite qua restart hoặc nâng version.
`profile.version` là metadata; `admission_class` chọn partition admission từ cấu hình
route. Phase 7 thêm quota và reserved capacity được mô tả bên dưới. Timeout override theo route áp dụng cả lifetime lẫn upstream peer.

Với contract strict, 415 nghĩa media type/encoding/JSON charset không được hỗ trợ;
400 nghĩa framing/header hoặc JSON/form syntax sai; 413 nghĩa body vượt cap;
503 ở waf_capacity/waf_unavailable nghĩa không thể inspect, không phải allow.
Kiểm tra Content-Type trước 100-continue/upstream. CRS vẫn có quyền chặn media
được allowlist cho phép: không tự thêm exclusion 920420 cho octet-stream. Nếu cần
bật On cho raw upload, người vận hành phải đánh giá exception và audit qua draft.
Multipart không parse body; cap muộn có thể để lại bytes tại backend. Không coi
413/504 là rollback nghiệp vụ hoặc kết quả giao dịch xác định.

Coverage API/Request details tách `full`, `headers_query_only`, `skipped_multipart`,
`off`, `not_inspected`. Native early header block không phải full. Counters
snapshot-local có mẫu số/version/profile, độc lập log drops và reset khi apply/
restart; không thay thế traffic history hoặc production workload acceptance.

## Resource budgets và fairness (Phase 7)

`routes[].admission`
nhận `{requests, streams, uploads, per_client}`, mặc định `{64, 8, 4, 32}`; thiếu
field dùng default, không thay route cũ thành template. Validate/save/apply và
rollback vẫn qua snapshot. Giảm quota chỉ từ chối request mới cho tới khi active
count xuống dưới cap; không hủy request đang giữ snapshot cũ. Thay class tạo
namespace admission khác; tổng node vẫn được giới hạn.

Public admin cũng dùng `{64, 8, 4, 32}` để JS/CSS/API còn slot khi
SSE mở; startup nâng đúng route admin mặc định cũ bằng config version có audit,
giữ draft edits. Quota admin không sửa qua route editor; không phải quota vô hạn
hoặc tăng login rate limit. Xem [admin bootstrap](admin-startup-bootstrap.md).

Từ bản nâng default 2026-11-02, route mới và form editor dùng 64 request/route,
32/IP; upload 4 và stream 8 giữ nguyên. Đây là giá trị mặc định, không phải mức
sàn validate: vẫn cho phép quota tùy chỉnh nhỏ hơn. Node/class budgets theo VPS
vẫn chặn trước quota route; `2c4g` chỉ có 32 slot API dùng chung.

Startup đọc các field bị lược bỏ trong DB theo defaults lịch sử, rồi nâng đúng
quota cũ `{32,8,4,8}` ở active/draft qua validate/prepare + transaction/version/
diff/audit `config.admission_defaults_upgrade` (có thể gộp cùng admin upgrade).
Quota tùy chỉnh khác bộ này giữ nguyên, gồm partial quota cũ. Migration có marker một lần trong DB; sau đó quota 32/8 được chọn lại hoặc
rollback vẫn giữ qua restart. Mỗi route mới lưu rõ đủ `admission`. Historical lookup/rollback
đọc field bị thiếu theo defaults cũ, không diễn giải lại history thành defaults
mới; rollback vẫn validate/apply. Xem [bằng chứng](evidence/website-default-quota.md).

`OPENWAF_RESOURCE_BUDGETS_FILE` trỏ JSON regular file private, tối đa 8 KiB,
được nạp khi startup; ví dụ [node budgets](../backend/resource-budgets.example.json).
Các field thiếu dùng default, field lạ bị từ chối. Không phải secret file và không
được lưu vào draft cấu hình hay backup cấu hình route. Kiểm tra tổng partition,
RAM estimate, FD estimate và process soft FD limit trước khi cấp native pools.
RAM estimate là accounting allowance cho transport/body/queues/native engines;
không phải giới hạn allocator native hoặc tự dò cgroup RAM. Đặt OS/cgroup memory
limit và FD limit phù hợp với workload, rồi đo trước deployment.

Giới hạn node hiện tại cho phép 1–16 WAF workers/pool, queue 1–16/worker và RAM
accounting tối đa 32 GiB; defaults Rust nhỏ vẫn giữ 2 workers/queue 4 và 2 GiB.
Runtime VPS chọn năm mức từ 2 core/4 GiB đến 16 core/64 GiB bằng
`OPENWAF_VPS_PROFILE` (mặc định `2c4g`), đồng bộ gateway budgets, PostgreSQL/ClickHouse
và CPU/RAM/PID limits của container. Worker/queue từ 2/4 đến 16/16; nâng/hạ
profile đã biết qua init theo [hướng dẫn VPS](../deploy/ansible/docs/runtime.md#resource-profiles-vps).
Profile homelab cho host 16 CPU/64 GiB dùng 16 workers/queue 16, 1.024 connections,
16 GiB RAM accounting; xem [cấu hình và quy trình cập nhật instance](../deploy/homelab/README.md#profile-máy-16-cpu--64-gib).
Offline CLI `openwaf-gateway check-resources` đọc JSON từ stdin tối đa 8 KiB,
validate bằng cùng `Budgets::validate` và RLIMIT_NOFILE, rồi thoát mà không khởi
động native pools, database hay listener. Deploy dùng image vừa pull để kiểm tra
trước khi thay runtime budgets/restart. Không bypass WAF hoặc tăng body limit.

Bốn partition `api/upload/stream/critical` không borrow và không xếp hàng đợi
capacity. `reserved_routes` giữ riêng số slot trong một class cho route ID xác định;
route khác chỉ dùng phần còn lại. Route reserved cũng bị giới hạn ở số slot đã
reserve. Tối đa 16 reservations. Không nhận class từ header client. H2 stream tính
một request, connection tính riêng suốt transport; pre-TLS handshakes và headers
được chặn trước khi spawn/route. Registry contention chỉ chờ tối đa 5 ms và được
giới hạn bởi header budget. Admission không bảo đảm SLO nếu CPU/native engines,
pre-routing capacity hoặc dependency đã cạn.

Per-client concurrency/rate depletion trả `429` + `Retry-After`; resource capacity
trả `503` với decision layer `admission_*`, `rate_limit_capacity`,
`retry_capacity` hoặc `waf_capacity`. NAT dùng chung client quota. Client identity
chỉ dùng trusted forwarded headers theo cấu hình. Rate keys dùng class + stable
route ID + exact rate/burst policy + normalized IP; unchanged apply/reorder/rollback
giữ state. Policy mới tạo bucket riêng, chuyển lại policy cũ dùng bucket chưa hết
TTL. Route/class identity đổi tạo namespace mới; restart xóa state volatile.
Tối đa 4.096 keys/node, 1.024/class, 128/route (gồm các policy generations).
TTL ít nhất 60 giây và dài hơn full-refill time; lazy cleanup khi có traffic,
không eviction depleted bucket để nhường slot. Một route không chiếm hết class;
nhiều route vẫn có thể lấp partition của class. Các class khác giữ state riêng.

Body full-inspection được thu tối đa 64 KiB trong request quota trước khi lấy WAF
ticket. Slow upload không giữ ticket native. Mỗi pool dành một admission ticket
cho critical class; đây không phải worker preemption. Caller timeout/cancellation
không giải phóng job đang chạy native. Compiler giữ pool retired tới khi hết
snapshot references và native work; registry refresh mỗi 100 ms.

Security dashboard hiển thị usage/cap/high-water/grants/rejections, upload/stream,
WAF registry, cancelled native work, health backlog/delay, rate keys và replay.
`GET /api/v1/telemetry/dependencies` thêm `admission` (schema 1, source/timestamp/
budgets/estimates), `waf_registry`, `rate_limit`, `health_capacity`, `replay`,
`retry_capacity`; `retry_slots` vẫn là active scalar tương thích. `/metrics` xuất
fixed resource/class/reason labels. Không xuất client/route/version labels;
route-series cap bằng 0 nên không tích lũy series qua reload. Gate grants có thể
tăng trước khi cấp sau từ chối; `admitted_total` chỉ tăng khi cả hierarchy thành
công. High-water/counters node reset khi restart; WAF registry phản ánh pools
còn được giữ. Health/WAF observations có thể trễ một chu kỳ, UI pause/error báo
paused/stale, không coi số cũ là current.

### Replay disk deployment

Đặt `OPENWAF_REPLAY_DIRECTORY` trên filesystem/volume riêng, directory thật mode
0700; symlink/public directory bị từ chối. Directory thiếu/read-only/unwritable
làm disk replay unavailable, gateway vẫn chạy. Không cấu hình sẽ dùng private
process temporary directory: tiện phát triển nhưng không cung cấp disk isolation.
Đặt quota filesystem/project/volume thực sự ở deployment, độc lập với byte
reservations trong gateway. `OPENWAF_REPLAY_MIN_FREE_BYTES` mặc định 64 MiB;
worker chỉ tạo capture nếu free space đủ toàn node disk quota cộng reserve.
External writers vẫn có thể làm đầy volume sau phép kiểm tra.

File anonymous mode 0600 không có directory entry, **không phải mã hóa**. Body
nhạy cảm cần encrypted volume và bảo vệ key ngoài database; không mount replay
volume vào collector hoặc frontend. Disk reservation và capture slot sống tới
khi capture/reader/worker cuối cùng kết thúc. Writer deadline tổng 10 giây,
read deadline 2 giây, mỗi read tối đa 64 KiB; blocked syscall giữ permit cho đến
khi kernel trả về. Không cưỡng bức free state đang dùng. Queue/cap/reserve/I/O
lỗi vô hiệu replay, giữ forward-once khi original stream còn hoạt động; upstream
reset sau body không được retry nếu capture chưa complete. Không bảo đảm replay
cho mọi burst upload.

Giới hạn container logs riêng (ví dụ logging driver `max-size=10m`, `max-file=3`),
ClickHouse history trên volume/quota riêng và retention hiện hành; PostgreSQL
trên volume riêng với capacity alert. TTL history không thay hard disk quota.
Không dùng chung replay reserve để suy ra DB/log còn chỗ. Full/read-only fixture
chỉ điền tmpfs 1 MiB của container test và không chạm filesystem của host.

## Phase 8: timeout và hợp đồng giao thức

`timeouts` ở route thay toàn bộ nhóm timeout upstream; các field thiếu trong
nhóm đó lấy defaults. Route không có nhóm này kế thừa upstream, rồi defaults.
Các field mới là optional để đọc được document cũ, không cần SQL migration:

| Field | Default / fallback | Phạm vi |
| --- | --- | --- |
| `connect_ms` | 3000 | TCP connect; không gồm TLS |
| `tls_ms` | `connect_ms` | Mỗi TLS handshake upstream, xác minh chain/SNI vẫn bật |
| `header_ms` | `read_ms` (10000) | Deadline tuyệt đối từ khi gửi upstream request headers đến final response headers, **gồm thời gian gửi upload**; informational headers/trickle không reset |
| `body.idle_timeout_ms` | 30000 | Chờ tiến triển body từ client, cả full inspection và streaming/H2; hết idle trả 408 nếu còn gửi được response |
| `response_idle_ms` | `read_ms` (10000) | Đọc upstream body/WS sau final headers, reset khi có dữ liệu; không nối lại response |
| `write_ms` | 10000 | Mỗi lần ghi upstream/downstream; absolute total vẫn chặn slow reader |
| `idle_ms` | 30000 | Connection pool keepalive, không phải lifetime request |
| `total_ms` | 30000 | Lifetime tuyệt đối sau route/admission, gồm body/WAF/retry/backoff/response/upgrade |
| `retry.total_timeout_ms` | Không có | Chỉ có thể **rút ngắn** total: lấy min với `timeouts.total_ms` |
| Node drain | 5000 | Sau grace 1 giây khi SIGTERM; không gia hạn theo heartbeat |

TCP/TLS giới hạn 1–30000 ms; header/total 1–86400000 ms; body/response idle,
read/write/pool idle 1–120000 ms. Full inspection vẫn tối đa 64 KiB. Trước đây
full-body reader còn hard cap 10 giây và read idle 5 giây; nay dùng body idle đã
khai báo và absolute total. HTTP/2 body idle nay có hiệu lực theo stream.
Upload template đặt header/total 30 phút; tăng body size không tự tăng các deadline.
SSE/WS/media templates đặt total 30 phút và response idle 30 giây; người vận hành
phải chỉnh theo workload. Editor hiển thị effective values của draft, request
details ghi values của snapshot thực sự phục vụ request.

WS HTTP/1.1 dùng idle riêng cho mỗi chiều: heartbeat cần có traffic hợp lệ cả hai
chiều trước idle tương ứng. Ping/Pong hoặc application heartbeat do client/backend
thực hiện. SSE backend nên gửi comment/event heartbeat ngắn hơn response idle;
client cần reconnect với jitter và Last-Event-ID theo khả năng backend. Upgrade
hoặc Accept không tự nới total. Không retry sau 101, final headers, response
commit, client cancellation hoặc replay source chưa hoàn chỉnh. H2 flow control
và RST_STREAM được cô lập theo stream, không đóng sibling streams.

Request details schema **5** giữ metadata schema **4**, thêm bounded `decision_trace` và giữ các trường schema **3**: `outcome`, `response_committed`,
`response_status_observed`, `effective_timeouts`. Schema 2/3 cũ vẫn đọc được; UI
hiển thị unknown cho field thiếu. `response_committed` nghĩa là final headers đã
vào transport, không chứng minh client nhận đủ bytes/ACK. Timeout trước commit
có thể trả 504; absolute total cũng có thể chỉ đóng connection/reset stream.
Sau commit chỉ đóng response dở, không gửi một final response khác. Partial/cancelled
record giữ status 0 khi không có completion; observed status riêng có thể là 200
hoặc 101. `absolute_timeout`, `force_disconnect`, request/response idle và lỗi
transport được phân biệt; cancellation không tăng completed-request counters.
Không diễn giải 200 headers hay 504 thành kết quả nghiệp vụ.

### Protocol matrix đã kiểm chứng

| Trường hợp | Hành vi |
| --- | --- |
| Upload fixed-length/chunked, download | Giữ raw body bytes; framing có thể đổi; giới hạn body vẫn áp dụng |
| HEAD, Range/206/416, If-Range/ETag, multiple ranges | Chuyển đến upstream và giữ semantics/bytes upstream; multiple ranges do upstream tạo, không tự tổng hợp/cache |
| Response Content-Encoding | Giữ encoded bytes, không tự decompress/recompress |
| Compressed request ở content profile | Identity-only; encoding khác bị 415 theo content contract |
| SSE | Incremental delivery, deadline hữu hạn, không cache/nối lại/replay response |
| WS | HTTP/1.1 handshake qua CRS, tunnel hai chiều; không inspect frames |
| Downstream H2 | TLS/ALPN, multiplex, upload/response flow control, cancellation; upstream của workload fixture là HTTP/1.1 |
| Request trailers | Header `Trailer`/`TE` bị 400 trước upstream. Trailers không khai báo cũng bị từ chối khi đọc thấy; route streaming có thể đã gửi một phần body trước lỗi |
| Response trailers | `Trailer` header bị 502 trước commit; unannounced HTTP/1 trailers làm response dở bị đóng. Không silently bỏ signature trailers |
| Expect | HTTP/1.1 `100-continue` được trả sau header/admission/security checks; strip Expect trước upstream. Expect khác, duplicate hoặc H2 Expect bị 417 |
| gRPC / extended CONNECT | Chưa hỗ trợ contract; không suy ra hỗ trợ từ HTTP/2 |

### Payment/webhook

Giữ profile mặc định retry **disabled**, DetectionOnly/PL1; chủ động bật On sau
đánh giá false positives. Webhook có route ACL/GeoIP/rate-limit riêng (MaxMind DB
phải khả dụng khi dùng GeoIP); ACL allow vẫn đi qua CRS. Đừng nới global policy để
cho callback đi qua. Backend kiểm tra HMAC trên raw bytes, timestamp, replay window
và quyền merchant; gateway giữ signature headers thông thường cùng body qua retry.
Signature nằm trong trailers không nằm trong protocol contract này.

Chỉ bật `idempotent` khi backend ghi dedup entry và business ledger nguyên tử,
phạm vi merchant + operation + key được xác định, cùng key khác payload trả conflict,
TTL dài hơn mọi retry/delivery/reconciliation window, và shared store giữa endpoints
khi dùng scope `pool`. Fixture dùng lock + ledger in-memory có TTL 1,5 giây để
chứng minh cả dedup và giới hạn sau expiry; không phải storage cho payment thật.
Mất ACK sau commit, client timeout hoặc response dở vẫn có thể là giao dịch thành
công. Tra cứu/reconcile bằng business key ở backend trước khi gửi lại. Request ID
chỉ dùng correlation; không thay idempotency key. Không ghi raw key, signature,
payload hoặc matched data vào diagnostics/artifacts.

Checkout CSP/frame policy phải cho đúng issuer/merchant origins và redirect
đích cố định đã validate. Chỉ thay policy tại route cần thiết. Chromium fixture
kiểm tra redirect 303, CSP `frame-src 'self'`, SAMEORIGIN iframe giả lập 3DS và
điều hướng hoàn tất. Issuer bên ngoài cần CSP `frame-src`/`frame-ancestors` phù hợp
và không được giữ X-Frame-Options DENY/SAMEORIGIN nếu workflow đòi cross-origin.
Public provider sandbox và CSP thực thuộc gate deployment riêng, không dùng
repository tests tạo giao dịch tiền thật.

### Recipes cho backend và deployment

- **Resumable upload/quarantine:** backend quản lý upload ID có auth, offset/checksum,
  quota/expiry và atomic finalization. Gateway dùng headers-query-only, body size,
  body/header/total deadline rõ và retry disabled hoặc connect-only. Backend lưu
  quarantine ngoài public path, scan bằng service riêng rồi publish sau clean verdict;
  scan lỗi/unknown giữ quarantine. Test chunk trùng/sai offset, disconnect, resume,
  checksum sai, scan timeout và cleanup. OpenWAF không scan antivirus.
- **WS/chat/game HTTP:** client reconnect với exponential backoff + full jitter hữu hạn,
  backend xác thực lại, nhận resume token/last sequence và replay hữu hạn hoặc báo gap.
  Không dựa connection cũ để giữ session/game state. Dùng heartbeat hai chiều, tổng
  lifetime và drain; reconnect burst phải qua admission/rate limits. Không hỗ trợ UDP,
  khôi phục game session hoặc frame inspection.
- **CDN/object storage:** backend phát signed upload/download URLs có expiry và scope,
  object storage/CDN chịu range, resumable protocol và cache. WAF bảo vệ HTTP origin;
  không tự cache/transcode/relay media transport. Tách auth routes khỏi public assets.
  Chỉ cấu hình trusted proxies cho CIDR egress thực sự được kiểm soát; strip/overwrite
  client-IP header ở proxy tin cậy. Tại firewall/security group của origin chỉ cho CDN
  egress hoặc private tunnel vào listener, giữ admin riêng. Route ACL dựa client IP
  không thay firewall kiểm tra peer nguồn.

Khi **bật CDN ở deployment**, bắt buộc chạy từ máy ngoài node: (1) qua CDN với
forged XFF/Forwarded/X-Real-IP vẫn phải thấy địa chỉ client đã xác minh, (2) truy cập
thẳng origin IP với Host/SNI hợp lệ và forged CDN/client headers phải bị chặn ở
firewall/tunnel, (3) client bị ACL/rate limit không vượt qua được bằng spoof header,
(4) Range/If-Range và callback signature qua CDN còn đúng, (5) cập nhật CIDR egress
không mở origin ra Internet. Ghi topology/observations và giữ unknown nếu probe
không chạy. Origin-bypass gate phải được đo trên cấu hình CDN thực của deployment.

## Phase 11 tuning, maintenance và cold start

Config draft/validate/apply/rollback hiện có nhận thêm:

```json
{
  "id": "app",
  "endpoints": [
    {"address": "service-a:8080", "protocol": "http", "weight": 1},
    {"address": "service-b:8080", "protocol": "http", "weight": 3}
  ],
  "balancing": {"algorithm": "weighted_round_robin", "slow_start_ms": 5000},
  "affinity": {"lifetime_seconds": 3600, "fallback": "rebalance"}
}
```

Đây là object upstream, không phải full config. Algorithms: `round_robin`
(default), `weighted_round_robin`, `least_active_requests`; weights 1–1000
(default1), slow start 0–300000ms (default0). Eligibility health/drain/maintenance
luôn ưu tiên; từng H2 stream giữ request lease riêng. Affinity optional, yêu cầu
HTTPS tại gateway và cookie ký lifetime1–86400s; fallback `rebalance` hoặc `reject`
503. `OPENWAF_AFFINITY_KEY_FILE` optional regular owner-only32-byte file;
không có thì key random/process. Không phục hồi backend state.

WAF exclusions thêm optional `owner` (1–128 ký tự khi có), reason hiện có, expiry
Unix ms phải >0 khi có; missing expiry vẫn là deliberate permanent exclusion.
Không auto renew/promotion/apply. API authenticated:

| API | Payload/semantics mới |
| --- | --- |
| `GET /api/v1/security/shadow` | active/config versions, config_changed, process_epoch; started/ends timestamps; sampled/completed/dropped/pending; comparison_denominator=completed; scope/completed_scopes, conclusion_limited và findings_untracked |
| `GET /api/v1/security/exclusions` | source, observed timestamp, active config_version, scope=`active_config_process_lifetime`, routes/mode/inspection_offers; rule/target/owner/reason/expiry/state/offered_while_active; matched_data_collected=false |
| `GET /api/v1/operations/endpoints` | config_version; per-endpoint eligible_alternatives/expected_downtime/single_endpoint/slow_start_ms; operation remaining_leases/drained/deadline_unix_ms/deadline_exceeded |
| `PUT /api/v1/operations/endpoints` | optional nullable deadline_unix_ms, future≤7 days, only drain/maintenance; expected_revision/mode/reason unchanged; audit + persistence before runtime publication |
| `GET /api/v1/telemetry/dependencies` | crowdsec.checkpoint_recovery (startup evidence), crowdsec.checkpoint_status (writer state), crowdsec.checkpoint_degraded (`write_failed`/`clock_rollback`), plus sync degraded/last-success age |

Exclusion usage là offers khi còn active, không phải matched-rule counts.
Shadow sample population chỉ gồm request đã qua contract checks và có primary
WAF result (hoặc Off); candidate On đối chiếu quyết định primary thực tế. Không
gộp versions/restart, không xem missing/drop như request an toàn. Maintenance
không còn alternative báo downtime; deadline không force disconnect. Force API
riêng vẫn yêu cầu authenticated admin + Origin/CSRF và audit, chỉ cancel leases
của endpoint đó.

CrowdSec config optional `checkpoint_file` trỏ file local trong directory0700;
master key hiện có bảo vệ HMAC-SHA256, file0600 ≤4MiB/10000 IDs. Dedicated worker
atomic write/fsync, error báo writer degraded (`write_failed`/`clock_rollback`)
không chặn gateway. Startup chỉ active bans chưa hết hạn, báo missing/invalid/
stale rõ ràng. Cùng boot dùng monotonic boot uptime để clock rollback không tăng
remaining; khác boot yêu cầu trusted wall clock, detected rollback từ chối load.
HMAC không chống privileged attacker restore một checkpoint cũ hợp lệ. Đây là
runtime security state, không backup/restore.

## Route tools và password-only access

Service Map, Route Playground chỉ đọc, Request decision flow và password-only
login theo route được mô tả trong [hợp đồng route tools](route-tools.md).
Password protection phải terminate HTTPS tại gateway; mọi apply/rollback/restart
thu hồi session cũ. Route con có policy độc lập, không tự kế thừa password từ prefix.
