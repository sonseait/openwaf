# OpenWAF — Baseline và kế hoạch vận hành

Cập nhật: 2026-11-02. OpenWAF là WAF + reverse proxy + realtime monitoring trên một node Linux, hiện do một người quản trị. Trọng tâm tiếp theo là giúp người vận hành trả lời: **Có chuyện gì? Vì sao? Cần làm gì tiếp theo?**

Tài liệu này gom baseline từ kế hoạch trước và toàn bộ 17 tài liệu trong `docs/`, gồm các bổ sung đến 2026-11-01 và thay đổi workspace hiện có. “Đã có” là implementation được tài liệu hiện hành ghi nhận, không phải kết luận audit source hoặc nghiệm thu lại trong lần tổng hợp này. Một số báo cáo, ảnh và harness lịch sử đã được dọn; không khôi phục chúng hoặc dùng dấu `[x]` cũ làm bằng chứng mới. Tài liệu hợp đồng có thể mô tả cả yêu cầu kiểm thử lẫn kết quả đã chạy: chỉ phần có kết quả/môi trường rõ mới là ghi nhận kiểm chứng lịch sử.

[Bảng trạng thái tại mục 4](#4-trạng-thái-hiện-hành) là nguồn trạng thái duy nhất. [Mục 5](#5-kế-hoạch-tiếp-theo-từ-bước-1) là lộ trình mới cho phần còn thiếu; không bắt đầu xây lại nền tảng. ID `P6`–`P13` chỉ còn là tham chiếu kế hoạch trước, không phải thứ tự triển khai hiện tại.

## 1. Mục tiêu, phạm vi và stack

Bảo vệ website/API, hỗ trợ upload, SSE/WebSocket, media HTTP và payment/webhook trong phạm vi đã nghiệm thu cho từng deployment. Gateway quản lý TLS tự động, khám phá backend Docker/host TCP ports và cung cấp UI vận hành. Discovery chỉ gợi ý; người vận hành chọn/test endpoint rồi validate/apply.

Một người quản trị dùng tài khoản nội bộ. **MFA và phân quyền/RBAC đang hoãn**, không phải gate hay phụ thuộc của roadmap hiện tại. Secure bootstrap, bảo vệ session và giới hạn truy cập admin vẫn cần hoàn thiện độc lập.

| Thành phần | Công nghệ và vai trò |
| --- | --- |
| Gateway | Rust + Pingora/OpenSSL; downstream HTTP/1.1 và HTTP/2, upstream HTTP/1.1 |
| Admin API và static dashboard | Axum + Tokio trong cùng gateway image; Pingora terminate HTTPS |
| WAF | libmodsecurity v3 + OWASP CRS qua adapter Rust/native |
| TLS/ACME | `instant-acme`; HTTP-01 và Cloudflare DNS-01 |
| Cấu hình/quản trị | PostgreSQL + SQLx; encrypted credentials, audit và statistics checkpoint |
| Traffic history | ClickHouse, raw traffic retention mặc định 7 ngày |
| Metrics | Prometheus exporter/history integration; không đồng nghĩa mọi deployment đã dựng Prometheus |
| Discovery | `bollard`, Docker Engine cùng host và Linux TCP listeners |
| Frontend | React + TypeScript + Vite + Mantine |
| Thư viện frontend | TanStack Query: server state; React Hook Form: form; React Router DOM: điều hướng; mantine-datatable: bảng; D3 scale/shape + Canvas: biểu đồ; Lucide: icon; Day.js: thời gian; react-hot-toast: thông báo |

Frontend Applications phục vụ ZIP static/SPA đã build là phạm vi hiện có. Không build source, chạy SSR/Node hoặc deploy container. Không dùng Caddy/Nginx riêng; không thêm thư viện trùng vai trò. Multi-node, multi-tenant, Docker từ xa, backend app runtime, HTTP/3 và CDN cache không thuộc MVP. Chi tiết hoãn/ngoài phạm vi ở mục 6.

## 2. Kiến trúc và các bất biến phải giữ

Bổ sung client correlation theo yêu cầu: detector opt-in dùng verified
ForwardAuth identity (một approved identity header), sau đó signed gateway cookie
trên HTTPS, cuối cùng trusted IP fallback. Mỗi window giữ tối đa 32 sự kiện đã
hoàn thành, sắp theo thời điểm bắt đầu, metadata-only và có truncation/gap.
Không thêm TLS fingerprint, không tự ban hoặc suy thứ tự thành quan hệ nhân quả.
Hợp đồng và giới hạn: [Anti-abuse](docs/anti-abuse.md#client-correlation-and-recent-behavior).

```text
Client → Pingora/OpenSSL → routing + security + WAF → upstream HTTP/HTTPS
                 │                              └→ static application release
                 ├── immutable snapshot ← validate/prepare/apply ← Admin API
                 ├── bounded counters/histograms → aggregator → SSE/dashboard
                 ├── bounded request/security events → live ring + ClickHouse writer
                 ├── optional body/query capture → redact worker → separate cache/storage
                 └── /metrics → external Prometheus

Dashboard → Axum/Admin API → PostgreSQL
                         ├── TLS/ACME/Cloudflare workers
                         ├── CrowdSec sync → local ban snapshot/checkpoint
                         └── discovery client → Unix socket → collector
                                                               ├── Docker socket
                                                               └── Linux host TCP listeners
```

- Tách proxy/config/WAF/TLS/admin/security/discovery/telemetry/storage/frontend. Collector riêng chạy trong host network namespace; chỉ collector có Docker socket. Gateway không mount socket; UI/storage/collector không điều khiển trực tiếp hot path.
- Hot path chỉ dùng snapshot bất biến/local state đã chuẩn bị và proxy I/O bất đồng bộ; không query DB, gọi Docker/collector/CrowdSec LAPI, ghi log đồng bộ hoặc chạy blocking FFI/filesystem I/O trên executor proxy.
- Draft → validate schema/precedence/loop/policy/cert → prepare → serialized durable commit với version/diff/audit → atomic publication. Phân biệt saved draft, committed active version và runtime observation. Optimistic revisions chống ghi đè; request đang chạy giữ snapshot ban đầu. Rollback cũng validate/prepare/apply, không sửa trực tiếp SQL/snapshot. Mất commit ACK là unknown outcome, phải đọc lại version/audit trước retry.
- Mọi task/child có owner, shutdown/cancellation/deadline; queue, retry, cache, state keys, export, native pools và bộ nhớ hữu hạn. Cancellation không được free native state hay trả permit khi công việc blocking còn dùng tài nguyên.
- Cô lập FFI/`unsafe` trong adapter nhỏ; safety contract bao gồm ownership, lifetime, allocator, thread affinity và cleanup. Một worker sở hữu transaction từ tạo đến hủy; không tự thêm `Send`/`Sync` để vượt compiler.
- Policy WAF mới mặc định `DetectionOnly`, PL1. Blocking full inspection hoàn tất trước upstream; body quá cap trả 413, thiếu capacity/không inspect được trả 503, không silently bypass. ACL allow, challenge hoặc authentication thành công không tự bỏ qua CRS.
- Chỉ tin forwarded client identity từ trusted proxies. Validate loop cho manual/discovery và DNS answers runtime. Upstream TLS verification mặc định bật; không có cert hợp lệ cho SNI phải từ chối handshake.
- Không đưa secrets vào source/log/error/fixtures/docs. Credentials mã hóa bằng master key ngoài DB; không tự sinh key thay thế khi key thiếu/sai. Body, cookie, authorization, query values và WAF matched data bị redact mặc định; recording là opt-in riêng với redaction trước storage.
- ClickHouse lỗi, collector mất, client SSE chậm hoặc log queue đầy không chặn proxy. Phải báo loss/gap/stale/backlog; không làm dữ liệu thiếu trông như đầy đủ. Audit mutation có yêu cầu bền vững khác traffic history best-effort.
- Metrics labels hữu hạn, không dùng IP, raw URL/query/reference. RPS theo request bắt đầu; status/latency theo request hoàn thành. Không cộng/average percentiles để tạo percentile tổng.
- Lỗi phân biệt validation/not found/conflict/unavailable, có ngữ cảnh nhưng không lộ dữ liệu nhạy cảm. SQLx transaction khi cần nguyên tử; kiểm tra rows affected, không báo thành công cho update/delete không tác động hàng nào. Không panic/`unwrap` trên dữ liệu ngoài hoặc nuốt lỗi.

## 3. Baseline hiện tại theo nhóm chức năng

Các mục dưới mô tả hành vi được tài liệu ghi nhận; trạng thái bằng chứng/deployment nằm ở mục 4. Tài liệu liên kết giữ chi tiết schema/API, budgets và hạn chế; không chép lại các schema đó thành hợp đồng thứ hai.

### 3.1. Routing, middleware và request safety

- Host exact trước wildcard, wildcard cụ thể hơn trước; path exact trước prefix, prefix dài hơn trước; method cụ thể trước mọi method. Tập match đồng hạng giao nhau dẫn đến nhiều route thắng bị từ chối, không phụ thuộc thứ tự nhập.
- HTTP/HTTPS upstream, pooling, active/passive health, DNS TTL refresh và loop validation, request/connection limits. Weighted round-robin, least-active-requests, slow start và signed-cookie affinity có fallback; health/drain/maintenance luôn quyết định eligibility trước. Health hỗ trợ HEAD mặc định hoặc GET, path/Host/status range/threshold/deadline; TLS SNI độc lập HTTP Host.
- Upstream HTTPS mặc định verify CA/hostname/SNI, có thể dùng CA tin cậy riêng. Ngoại lệ `tls_verify: false` đã có theo từng endpoint do operator chọn rõ; proxy/health/ForwardAuth/connection test dùng cùng giá trị. Đây là kết nối không xác minh danh tính upstream, không phải mặc định hoặc cách tự khắc phục lỗi certificate.
- Downstream TLS HTTP/2 có bounded streams, flow control/cancellation và isolation sibling streams; upstream hiện HTTP/1.1. SSE incremental và WS HTTP/1.1 tunnel có deadline/drain hữu hạn. Sau SSE 2xx headers, lỗi stream không tự passive-quarantine cả endpoint; active health vẫn áp dụng.
- Retry authorization `disabled`/`connect-only`/`safe`/`idempotent` độc lập replay `none`/`memory`/`disk`, mặc định một attempt, không retry. HTTP status không kích hoạt retry; không retry sau final headers/101/response commit/cancel. Disk I/O có worker/budget/reserve riêng; replay lỗi không cấp quyền retry, giữ forward-once khi stream gốc còn hoạt động.
- Connect/TLS/header, body idle, response idle, write, absolute total và drain là các timeout khác nhau; total không reset bởi trickle/heartbeat. Editor/request details có effective timeouts. Deadline sau commit có thể đóng stream, không gửi response lỗi thứ hai.
- Redirect tùy chọn giữ raw path/query, strip/add/replace path, custom request/response headers, CORS và bounded ForwardAuth. CORS preflight hợp lệ xử lý local sau security/WAF; ForwardAuth không thu response body, không retry, chỉ tin identity headers đã cấu hình và strip giá trị client giả. Không có arbitrary plugin chain.
- Trang lỗi mặc định có request reference/IP/quốc gia; custom HTML ưu tiên route → global → mặc định, có sandbox/CSP và giới hạn. Giữ JSON/HEAD/status/Retry-After và body lỗi HTTP từ upstream; không thay TLS handshake failure hay response đã bắt đầu.

Nguồn: [Operations](docs/operations.md), [Route middleware](docs/route-middleware.md), [Error pages](docs/error-pages.md).

### 3.2. WAF, profiles và protection coverage

- `Off`/`DetectionOnly`/`On`, policy theo route, CRS exclusions hẹp theo rule/field/route có reason/owner/expiry; proposal từ request vào draft, validate/diff/apply/audit. Exclusion usage là số offers khi active, không phải matched-rule count.
- Shadow policy có sampling, sampled/completed/would-block/different/dropped và mẫu số completed, scope/version/process epoch; pool/queue candidate tách khỏi primary. Không đổi enforcement, promote hoặc gia hạn exclusion tự động; mất mẫu/config đổi hạn chế kết luận.
- Profiles API/CRUD, upload, SSE, WebSocket, HLS/DASH/video và payment/webhook khởi tạo field tường minh. Template mới không tự sửa route active; config cũ giữ semantics. Methods/media types/encoding/body limits được validate; diagnostics có route ID, field/path và cách sửa.
- Coverage phân biệt `full`, `headers_query_only`, `skipped_multipart`, `off`, `not_inspected`, có mẫu số/version. **Full body inspection tối đa 64 KiB; mọi multipart hiện bỏ body parsing; WS chỉ kiểm tra handshake.** Early header block không phải full body inspection. Chưa inspect response body hoặc WS frames.
- Streaming vượt body cap muộn có thể đã gửi bytes tới backend; 413/504 không chứng minh rollback nghiệp vụ. Không cho nhãn WAF On ngụ ý mọi body đã được kiểm tra.

Nguồn: [Operations](docs/operations.md). Phần cần nối hoàn chỉnh thành workflow điều tra nằm ở bước 3.

### 3.3. Access, flood protection, challenge và tài nguyên

- Global/route ACL IP/CIDR, GeoIP allow/deny/unknown, per-IP rate limit; global không bị route vô hiệu, allow không bypass các lớp sau. GeoIP từ MMDB local; thiếu/lỗi database khác unknown country, có trạng thái unavailable rõ.
- HTTP flood budgets opt-in tổng mọi client ở global/route, độc lập per-IP quota và concurrent admission. Thiếu token 429/Retry-After; thiếu state/lock capacity 503; không có auto-ban/detector. Global bucket có thể bị bulk traffic tiêu thụ, không phải RPS reservation cho critical route.
- Browser JavaScript SHA-256 proof-of-work đã có, opt-in global/route; cần HTTPS tại gateway, cookie/Fetch Metadata, bounded issue/verify state và browser deadline. Clearance bind authority/IP/version/scope/expiry; không bypass ACL/CRS. Không chứng minh con người, không có risk scoring/auto-enable. Không bật cùng cách cho API-only, webhook/payment callback hoặc machine clients; request không có clearance có thể bị 403, không replay POST/upload/stream.
- Hierarchical admission global/class/route/client với partition API/upload/stream/critical, reserved routes, pre-routing connection/header/TLS budgets, bounded WAF/health/rate-key/retry/replay resources. Không borrow hoặc xếp queue capacity vô hạn. Local RAM limiter state giữ qua apply không đổi policy và reset theo hợp đồng khi restart.
- Security/resource UI có usage/cap/high-water/rejections, retired pools/native work sau cancel, health backlog/deferred checks, replay memory/disk. Runtime budgets kiểm tra RAM/FD accounting; CLI offline `check-resources` đã có, khác CLI config automation còn thiếu. Accounting estimate không thay OS/cgroup/disk quota hoặc capacity benchmark.
- CrowdSec service riêng, sync local ban snapshot; LAPI outage giữ đến expiry gốc. Integrity/version checkpoint và cold-start recovery có giới hạn/clock handling; không kéo dài ban vô hạn. VPS hiện dùng manual decisions, **chưa có traffic log acquisition/scenarios** để tự phát hiện abuse từ traffic OpenWAF.

Nguồn: [Global rules](docs/global-rules.md), [HTTP flood](docs/ddos-protection.md), [Browser challenge](docs/browser-challenge.md), [Operations](docs/operations.md).

### 3.4. Discovery, Service Map và endpoint operations

- Collector read-only dùng Docker events + reconcile và host refresh mỗi 10 giây, Unix socket giới hạn quyền; configurable rootful/rootless Docker socket. Host TCP listeners IPv4/IPv6 đọc trong host namespace, không scan network/port hoặc yêu cầu PID. Nguồn Docker/host ports có health riêng, timestamp/stale/degraded/unavailable và refresh thủ công.
- Picker manual/Docker/host ports, pagination tối đa 100/trang, network/alias/published port/source identity; không tự lấy network/port đầu tiên. Exposed port không chứng minh listener/HTTP. Không lưu `0.0.0.0`/`::` làm upstream hoặc đổi host-loopback thành container-loopback; ưu tiên DNS alias/Compose service trên network chung, không dùng container IP làm định danh bền vững.
- HTTP/HTTPS do người vận hành chọn; gateway connection test DNS/TCP/TLS/HTTP dùng network/resolver/trust context của chính gateway, finite timeout/concurrency/response, không follow redirect tùy ý. TLS mặc định verify CA/hostname/SNI. Collector outage không xóa upstream; stopped/missing/unreachable không tự thay endpoint.
- Service Map lấy active config, Traffic paths có Incoming routes → Upstream → Endpoints, route protection, ForwardAuth riêng, local redirect/application handlers và endpoint provenance. Discovery inventory phân trang riêng; không coi configured là healthy hoặc candidate chưa thấy là biến mất. Playground active/saved draft dùng matcher chung, không chạy WAF/rate/GeoIP/auth/DNS/TLS/health hoặc gọi upstream.
- Endpoint diagnostics/history và bảng maintenance có timestamp/config version, pause/refresh, leases/alternatives/downtime/deadline. Drain/maintenance persist bằng revision/reason/audit, loại admissions/retries mới; force disconnect riêng chỉ cancel lease/stream liên quan. Deadline không tự force disconnect.
- Route maintenance độc lập endpoint mode: local 503 HTML/JSON/HEAD, Retry-After, private/no-store; không gọi application/auth, không WAF-block/forwarded. Request/stream cũ giữ snapshot. Một endpoint hoặc hết alternatives phải hiện downtime, không hứa bảo trì không gián đoạn.

Nguồn: [Route tools](docs/route-tools.md), [Route maintenance](docs/route-maintenance.md), [Operations](docs/operations.md), [Frontend README](frontend/README.md).

### 3.5. Request details, recording và điều tra có sẵn

- Gateway reference mới 64 ký tự, tiếp tục lookup ID 32 ký tự cũ; overwrite client/upstream request ID. Lookup live ring rồi ClickHouse trong retention; ID chỉ correlation, không phải distributed tracing hoặc idempotency key.
- Live/history có chung các cột, host/country filters; history thêm literal path filter trên ClickHouse trước LIMIT. Path là gốc trước rewrite không query; route ID từ snapshot request, không resolve index bằng config hiện tại. Thiếu metadata/GeoIP có unavailable rõ.
- Request Details có Handling/Overview/Security/Upstream/Headers và Body & query; decision flow tối đa 16 checkpoint, timing riêng mỗi bước bằng monotonic clock, config/route version, security layer/rule IDs/attempts/forwarding. Không suy diễn bước chưa chạy, timing thiếu thành 0, hoặc cộng step timings thành tổng latency. Partial/cancelled/response committed khác completed/ACK nghiệp vụ.
- Details schema hiện hành **9**, giữ trace/timing/metadata/capture markers và thêm bounded CRS security signals theo [contract](docs/request-details.md); tối đa 16 KiB, headers allowlist và giới hạn riêng, redact trước telemetry queue. Bản ghi cũ thiếu trường phải unavailable/not collected, không backfill suy đoán. Schema 5/6/8 mô tả thời điểm cũ, không phải payload mới nhất.
- Recording request body, response body và query là ba cờ độc lập theo route, mặc định tắt, cùng snapshot/validate/apply/diff/rollback. Body chỉ JSON/form-urlencoded UTF-8 đầy đủ, không nén, tối đa 64 KiB mỗi chiều; query gốc cũng tối đa 64 KiB. Strict decode, che field mặc định + bổ sung theo route; invalid/partial/oversized bỏ toàn bộ, không lưu prefix. Không thu multipart/file/binary/SSE/WS, không drain body sau block.
- Recorder parse/redact ngoài proxy executor, raw buffers hữu hạn/zeroize, queue/cache/batch/shutdown hữu hạn, overload bỏ capture không đổi forwarding/WAF. ClickHouse bodies riêng TTL 7 ngày, live cache 32 records; chỉ endpoint authenticated/no-store tải nội dung riêng khi mở tab. SSE/traffic list chỉ có marker, không có body/query content; UI không giữ nội dung sau unmount. Báo pending/disabled/skipped/dropped/expired/unavailable và failed-or-uncertain, không hứa lưu đủ hoặc suy ra client đã nhận response.

Nguồn: [Request details](docs/request-details.md), [Body & query recording](docs/body-recording.md), [Route tools](docs/route-tools.md), [Operations](docs/operations.md).

### 3.6. Telemetry, statistics, health và alerts

- Aggregator mỗi giây, RPS incoming/forwarded/blocked, latency/status/bytes/active, queue/dependency/resource observations; authenticated SSE có heartbeat/epoch/sequence/reconnect/gap, bounded queue/drop accounting. Không replay vô hạn. UI giữ tối đa **1.000 logs và 900 samples/15 phút** kể cả reconnect; history qua Admin API, không browser nối DB trực tiếp.
- ClickHouse batch writer finite queue/deadline và TTL traffic 7 ngày, uncertain write/drop/degraded; không disk spool hoặc bảo đảm history đầy đủ qua crash/outage. Prometheus exporter có access guard và bounded range API.
- Statistics có Request volume/Response outcomes/GEO & user agents/Performance, D3/Canvas, accessibility tables, pause/gap/stale/history error. Host filter toàn trang dùng counters, tối đa 32 observed hosts, overflow không gán nhầm; host-filtered Prometheus history hiện chỉ hỗ trợ incoming series. GEO/UA/method là dimensions hữu hạn, UA heuristic không phải bot detector.
- Managed counters/histogram bins/status/bytes/dimensions và host totals checkpoint PostgreSQL mỗi 5 giây và cuối graceful drain, validate version/generation/bounds trước restore. Ghi lỗi không chặn proxy; crash mất phần sau last-success, có thể dài hơn 5 giây khi DB outage. Startup cần DB đọc checkpoint được. Không restore gauges/RPS/live charts hoặc tạo spike từ counters cũ. Totals là best-effort atomics, không phải ledger hoặc số bản ghi history.
- System health authenticated phân biệt heartbeat, protection, storage/monitoring loss và per-source collector/ACME observations với timestamp/unknown/not configured. UI nhóm Traffic & protection, Storage & telemetry, Discovery & TLS, Needs attention, refresh 5 giây/pause/stale. Không dùng cert loaded để chứng minh renewal khỏe; public bootstrap worker và gateway có nguồn giám sát khác nhau.
- Uptime history endpoint eligibility có retention/bounds/stale/gap; endpoint diagnostics lịch sử đã có, không phải external uptime. Health scheduler quá tải defer hữu hạn, không kéo dài health/DNS expiry hoặc biến peer lỗi thành healthy.
- Telegram outbound-only đã có encrypted token, outbox 1.000 pending, bounded retry/backoff, coalescing 5 phút, recovery, silence tối đa 7 ngày, expiry và delivery history. Missing ACK có thể duplicate; DB outage ngăn delivery persisted, channel lỗi không chặn proxy. Chưa đồng nghĩa generic webhook channels, incident workflow hoặc external monitor độc lập đã có.

Nguồn: [Request statistics](docs/request-statistics.md), [Request details](docs/request-details.md), [Operations](docs/operations.md).

### 3.7. TLS, Cloudflare và public admin bootstrap

- TLS tối thiểu 1.2, exact/wildcard SNI, valid-cert selection, certificate hot reload/restart; không fallback cert sai domain. HTTP-01/DNS-01, renewal window/ARI scheduling, encrypted account/private-key state và bounded retry/cleanup. Local Pebble/private-CA fixtures khác public Let's Encrypt/Cloudflare nghiệm thu.
- Certificates UI queue exact/wildcard requests, CA consent, retry/audit, bounded children/jobs/state và renewal ownership dùng chung với Applications. `current` là worker check complete; `covered` là live wildcard reuse; `loaded` là TLS store observation. Không trạng thái nào tự chứng minh public DNS/reachability/trust. Không có UI takeover/delete/cancel request.
- Cloudflare providers theo zone + CA environment, API Token hoặc Global API Key/email mã hóa; PostgreSQL là source of truth. Catalog cũ import một lần có transaction/audit, giữ account/state/ID; file không ghi đè UI hoặc resurrect provider đã xóa. Credential rotation giữ renewal owner. Provider test chỉ zone/DNS-read, không chứng minh DNS-write.
- DNS CRUD A/AAAA/CNAME/TXT/MX/NS có pagination, revisions, protected ACME records, audit attempt trước write và outcome riêng. Không external CAS/distributed transaction; unknown ACK phải reload/reconcile, không retry write mù. Không Cloudflare I/O trên proxy hot path.
- VPS bootstrap preflight import một Production provider, reserve apex/wildcard/admin trước DNS writes; cấu hình DNS một lần có journal/checkpoint, xin cert SAN apex + wildcard, staging trước production, atomic publication giữ cert/account cũ đến validate. Admin hostname chỉ apex hoặc một cấp dưới zone. Restart sau checkpoint không reconcile DNS thủ công hoặc overwrite provider credentials; bootstrap token rotation và provider UI rotation độc lập.
- Public admin Pingora → Axum loopback phục vụ API/static UI; protected route seed qua version/diff/audit, không mở quyền sửa route để tự khóa admin ngoài migration có review. Không tạo user/password sẵn: setup UI/API tạo admin đầu tiên bằng Argon2id/advisory lock/audit, DB lỗi unavailable, không coi là instance trắng. **Token setup một lần chưa có**, cần bước 1. Account/password giữ qua restart.
- Admin login có Argon2id, secure session có expiry/revocation, cookie HttpOnly/Secure/SameSite, exact Origin/CSRF cho mutation, login rate limit và audit. Production dùng static dashboard trong image, không dùng Vite dev/test server; session controls không bị hoãn cùng MFA/RBAC.

Nguồn: [Certificates](docs/certificates.md), [Cloudflare providers](docs/cloudflare-providers.md), [Admin startup bootstrap](docs/admin-startup-bootstrap.md).

### 3.8. Password gate, Applications và deployment

- Password-only protection theo route là visitor access gate, khác admin MFA/RBAC. Argon2id verifier sealed bằng external master key, HTTPS Origin/CSRF, login rate/capacity/hash workers hữu hạn; signed secure cookie bound host/route/policy/version. Apply/rollback/restart thu hồi session cũ cho request mới. Route con policy độc lập, không tự kế thừa prefix password; gate không thay authorization/CSRF nghiệp vụ hoặc firewall backend.
- Applications nhận ZIP static/SPA đã build, validate paths/duplicates/links/ZIP bombs và byte/file/time/storage budgets; artifact immutable, staging/cleanup/leases hữu hạn, persistent volume riêng. Production domain/root route và public preview 12 ký tự lưu bền vững, preview expiry/noindex/no-store không phải access control. Review/deploy/rollback qua config writer, giữ specific API routes; config rollback phải validate release còn tồn tại.
- Static handler GET/HEAD/ETag/single range, SPA fallback chỉ HTML navigation phù hợp, streaming backpressure/finite artifact I/O. Không directory listing, SSR, source build/container runtime; release switch không hứa mọi tab cũ còn asset. TLS queue riêng dùng chung ownership/certs với Certificates. DB-only backup không đủ khôi phục artifacts.
- UI có loading/error/empty, connected/stale/pause/gap/drop, dark/light, keyboard/focus/labels; form và server state dùng đúng stack. Service Map/endpoint tables/request modal đã có các cải tiến layout và mobile, không lập kế hoạch xây lại.
- Hai luồng deploy được duy trì: VPS startup Compose và homelab. Image dựng sẵn chứa Rust/frontend/runtime init; VPS pull/run, không build trên máy đích. Static dashboard do Axum trong gateway phục vụ; installer/template độc lập/systemd units cũ đã gỡ, không coi native systemd là profile hiện được cung cấp.
- VPS có new/existing PostgreSQL với private credentials/TLS/migration guards, managed/external Docker network; runtime UID/GID 10001, private secrets/volumes, no Docker socket trong gateway, quotas/readonly/capability limits. SIGTERM/drain/flush có deadline; recreate giữ project/volumes/keys và có downtime single-node. Không dùng `down -v`, đổi master key hoặc migration down để chữa lỗi.
- VPS Compose hiện có ClickHouse, CrowdSec manual LAPI và collector; **Prometheus chưa dựng sẵn**, GeoIP tùy chọn. Gateway private admin HTTP/metrics/DB không publish tùy ý; Cloudflare Full(strict), trusted proxies, cache bypass và origin firewall phải kiểm chứng trên deployment.

Deploy VPS mới dùng [Ansible](deploy/ansible/README.md) làm entry point; bind-mount state từ thư mục host vẫn là mặc định. Operator có thể chọn rõ `existing_volumes` để reattach named volumes Docker đã tồn tại, sau preflight metadata-only và recovery guard. Native bootstrap/renewal vẫn ở runtime image. Đây là tùy chọn layout/automation; không tự migrate/copy volumes, chứng nhận restore, đóng gate restore hoặc chứng minh public VPS/ACME đã đạt.

Nguồn: [Route tools](docs/route-tools.md), [Applications](docs/applications.md), [Deployment runbook](docs/deployment-runbook.md), [Fresh VPS](docs/fresh-deploy-vps.md), [VPS runtime](deploy/ansible/docs/runtime.md), [Homelab](deploy/homelab/README.md).

## 4. Trạng thái hiện hành

Bảng này tách **implementation / kiểm thử cục bộ / nghiệm thu deployment / hoãn**. “Ghi nhận lịch sử” không xác nhận lại kết quả hoặc artifact còn tồn tại. Không dùng bản tổng hợp này để đóng gate. Mỗi lần hoàn tất công việc phải cập nhật đúng hàng, kèm ngày, commit/version, môi trường, workload, kết quả, link bằng chứng và giới hạn; không duy trì bảng trạng thái song song theo phase cũ.

| Hạng mục | Implementation | Kiểm thử cục bộ | Nghiệm thu deployment | Công việc/giới hạn còn lại |
| --- | --- | --- | --- | --- |
| Proxy/config/discovery/WAF/profiles/quota/streaming baseline | Được ghi nhận đã có | Ghi nhận lịch sử phase 1–3, 6–8; Linux/native/DB/CRS/Docker fixtures và rootless lồng | Chưa nghiệm thu tổng thể | Bước 7; rootless native, cold-start health/reload và long soak không tự coi đạt |
| Middleware/error pages/password/Service Map/Playground/maintenance/balancing/CrowdSec recovery | Được ghi nhận đã có | Ghi nhận lịch sử, phạm vi từng contract; không xác nhận lại UI đang chỉnh | Chưa nghiệm thu tổng thể | Bước 3/7 chỉ mở rộng phần thiếu; Authelia/Authentik thật chưa chứng nhận |
| Live telemetry/history/statistics/host filters/checkpoint | Được ghi nhận đã có | History/SSE/storage có ghi nhận lịch sử; host/path tests 2026-11-01 có giới hạn macOS/browser/Prometheus | Chưa nghiệm thu tải/deployment | Bước 4/7; mất logs/checkpoint tail, không backfill; host history incoming-only |
| Body/query recording, request timings/layout mới | Workspace và contract ghi nhận đã có | Contract có test cases/harness; không coi mô tả kiểm thử là kết quả đã đạt | Chưa nghiệm thu | Xác minh theo contract ở bước 3/7; không là response WAF inspection |
| AB-1 — Security signals | Native report và security outcomes → bounded signals → details schema 9 → Security tab | Serialization/bounds/details tests và local native block → upstream non-delivery đã đạt | Đã kiểm chứng chức năng local | Chưa benchmark/ClickHouse-SSE tải; action native là quyết định cấp report |
| AB-2 — Verified identity quota | ForwardAuth approved identity → bounded HMAC quota → config/editor/diagnostics | Unit NAT/churn/TTL/reload/capacity; integration chống spoof, quota độc lập cùng IP và auth failure đạt | Đã kiểm chứng chức năng local | Restart reset; cleanup scan hữu hạn chưa benchmark maximum keys |
| AB-3 — Observe-only detectors | Endpoint probing và route flood, bounded state/evidence, quality/drop diagnostics và UI | Unit bounds/recovery/gap và integration traffic → incidents đạt | Đã kiểm chứng chức năng local | Dựa completed requests; không coi là exact incoming RPS hoặc fraud |
| AB-4 — Incident workflow | PostgreSQL bounded persistence, audited optimistic ACK/open/resolve, UI drilldown và existing Telegram outbox | Integration persistence/ACK conflict/audit, DB outage traffic continuity và restart-unknown đạt | Đã kiểm chứng chức năng local | Chưa thử Telegram delivery; production saturation/retention load chưa đo |
| AB-5 — Security simulator | API/UI active/saved draft/compare, independent native workers và explicit not_simulated layers | Native unit, integration không auth/upstream/quota mutation và offline Chromium interaction đạt | Đã kiểm chứng chức năng local | Không mô phỏng stateful protections/network/response; không production-equivalent |
| AB-6 — API structural validation | Bounded JSON subset, selected OpenAPI request-body import, observe/review/draft/apply/block UI | Unit structure/bounds/duplicates và integration observe/block/non-delivery/raw-byte preservation đạt | Đã kiểm chứng chức năng local | Không full OpenAPI; synchronous bounded parser cần executor/load benchmark |
| Global rules/HTTP flood/browser PoW | Được ghi nhận đã có | Không xác minh lại trong lần tổng hợp; đọc đúng phạm vi contract | Chưa nghiệm thu capacity/browser thực tế | Bước 7; không detector bot/DDoS mạng hoặc challenge API trong suốt |
| TLS/Certificates/Cloudflare/Applications | Được ghi nhận đã có | Ghi nhận local fixtures/Pebble/Chromium; bootstrap v2 2026-11-01 có smoke riêng | Public CA/provider/DNS và deployment còn mở | Bước 7; public gate đã bàn giao người vận hành, không thay bằng Pebble |
| Public admin UI, account setup, VPS/homelab packaging | Được ghi nhận đã có; VPS tự phát hiện Docker/Compose/origin và chọn sizing profiles 2c4g–16c64g theo CPU/RAM, WAF 2/4–16/16 và container CPU/RAM/PID caps | Ghi nhận Linux local smoke; bổ sung 2026-11-02, `6cae4c1` + working tree: 39 init tests, năm native resource validators/Compose renders và Linux smallest-profile dependency/gateway/PG restart smoke theo [bằng chứng VPS](docs/evidence/vps-resource-profiles.md); chưa kiểm chứng release mới/VPS thật; bổ sung [admin resource quota regression](docs/evidence/admin-resource-quota.md) với migration 8→32/IP và 12 SSE + tải resource song song; [default mọi website 64/32](docs/evidence/website-default-quota.md) có migration một lần, giữ quota tùy chỉnh/history | Chưa nghiệm thu tổng thể | Setup không tạo account sẵn; token một lần thiếu ở bước 1; quota route/IP vẫn cấu hình riêng |
| System health/Telegram/endpoint history | Được ghi nhận đã có | Ghi nhận local, không gửi Telegram thật trong tests | External monitor/channel thật chưa nghiệm thu | Bước 2/5/7, không làm lại outbox/coalescing/silence đã có |
| Bước 1 — secure setup | Có nền setup/session; token còn thiếu | Phần thiếu chưa có bằng chứng | Chưa nghiệm thu | P0, không phụ thuộc MFA/RBAC |
| Bước 2 — probes/external monitoring/failure taxonomy | System health/trace có một phần; probe độc lập còn mở | Phần còn lại chưa nghiệm thu | Chưa nghiệm thu | P0; ngoài node và không phụ thuộc DB session cho probe tối giản |
| Bước 3 — investigation | Đã triển khai route active/draft/request version, URL drill-down, config/audit diff, exclusion → shadow → review và liên kết setup/diagnosis | 2026-11-02, `6cae4c1` + working tree; macOS arm64, Docker PostgreSQL/ClickHouse, gateway/native WAF và Chrome: [bằng chứng OPS-3/4](docs/evidence/ops-3-4.md) | Chưa nghiệm thu deployment | Các tình huống nghiệm thu đầy đủ tại bước 3/7 còn mở; không thay missing record bằng cấu hình hiện tại |
| Bước 4 — statistics | Đã triển khai bốn góc nhìn, 128 route IDs/process, counter rollup 5 phút/30 ngày, comparison và observed change markers | Cùng [bằng chứng OPS-3/4](docs/evidence/ops-3-4.md); unit, DB/API/browser và bounded client-state regression đạt trong phạm vi ghi nhận | Chưa nghiệm thu tải/deployment | Route counters reset khi restart; host history vẫn incoming-only; rollup không backfill, có gộp config versions; SLO chỉ số đo, hoãn target/evaluation |
| Bước 5 — incidents | Có alerts/outbox baseline; incident workflow tổng hợp chưa triển khai | Phần mới chưa nghiệm thu | Chưa nghiệm thu | P1; incident khác alert group hiện có |
| Bước 6 — audit/export/retention | Audit cơ bản đã có; assurance/export độc lập còn mở | Phạm vi mở chưa nghiệm thu | Chưa nghiệm thu | P1, bắt buộc phần audit tương ứng trước công bố hỗ trợ payment quan trọng |
| Bước 7 — acceptance | Đã có runbook và harness cục bộ từng phần | Chưa đủ capacity/fault/profile acceptance | Còn mở theo workload | P0 nghiệm thu cho phạm vi production dự định hỗ trợ; soak dài vẫn hoãn |
| Bước 8 — API/abuse/automation | Hợp đồng API session `/api/v1` đã có; các mở rộng còn mở | Phần mới chưa nghiệm thu | Chưa nghiệm thu | P2; mTLS chỉ khi tích hợp yêu cầu |
| MFA/RBAC; backup/restore; patch/dependency/CRS workflow; advanced apply; long soak | Không coi đã hoàn tất | Không dùng bằng chứng baseline để đóng | Không coi được nghiệm thu | Đang hoãn theo mục 6; không tự đưa lại vào lịch |

**Đối chiếu tài liệu khi cập nhật:** `fresh-deploy-vps.md` và một đoạn runbook còn nói account tạo sẵn; contract bootstrap mới và `bootstrap.rs` ghi rõ không provisioning account, init/Compose không còn admin password mount. Dùng setup lần đầu làm baseline. Đoạn giới hạn bootstrap cũ nói thiếu ClickHouse đã bị Compose/deployment hiện tại vượt qua; giữ Prometheus chưa dựng sẵn và CrowdSec chưa acquisition. Các đoạn schema 5/6 là lịch sử; request-details/body-recording hiện dùng schema 8. Lần tổng hợp baseline chỉ chỉnh `plan.md`; lần triển khai OPS-3/4 cập nhật contract liên quan và thêm bằng chứng mới, không sửa kết quả lịch sử.

## 5. Kế hoạch tiếp theo từ bước 1

Mỗi checkbox dưới là **phạm vi còn thiếu hoặc cần xác minh**, không phải toàn bộ tính năng chưa có. Chỉ đổi `[ ]` thành `[x]` sau khi có bằng chứng cho toàn mục, đồng thời cập nhật mục 4. MUST là gate của phạm vi công bố tương ứng; SHOULD không tự trở thành gate mọi workload. Thứ tự là mặc định thực hiện, không cam kết thời gian: security/health P0 làm trước, tests đi cùng mỗi bước, acceptance production không chờ mọi mở rộng P1/P2 hoàn tất. Payload mới phải đồng bộ API/schema/UI/docs và migration/backward compatibility; lần viết lại kế hoạch này không đổi API hoặc tạo schema mới.

**Phạm vi triển khai đã chọn:** người dùng bỏ qua bước 1–2 và yêu cầu triển khai OPS-3.1–3.4, OPS-4.1–4.4. Các gate bước 1–2 vẫn mở; không tự coi đã đạt hoặc triển khai kèm. Contract/API mới ở [Investigation](docs/investigation.md); bằng chứng và phần chưa kiểm chứng ở [OPS-3/4](docs/evidence/ops-3-4.md). Checkbox bước 3–4 còn mở cho toàn bộ ma trận nghiệm thu, dù implementation và regression cục bộ đã có.

### Bước 1 — Secure bootstrap cho một người quản trị (P0)

Đã có setup transaction/race guard, Argon2id, session/Origin/CSRF, login rate limit và route bootstrap. Giữ các phần đó, không thêm MFA hoặc roles.

- [ ] **OPS-1.1 MUST — Setup một lần an toàn** (cũ P9-M1): token dùng một lần ngoài DB, mặc định file owner-only, expiry/consume rõ và không in secret. Bind setup transaction chống race/reuse/restart; DB unavailable không mở lại setup hoặc reset account. Không tạo account/password mặc định mới; không tạo remote recovery không xác thực.
- [ ] **OPS-1.2 MUST — Exposure và session:** hoàn thiện giới hạn firewall/VPN/Cloudflare Access theo lựa chọn deploy, bảo vệ setup trước lần tạo user, HTTPS production đúng Origin/cookie/CSP và session rotation/revocation. Public admin là opt-in được cấu hình; không tự đổi deployment hiện tại sang loopback hoặc khôi phục edge/systemd cũ.

**Nghiệm thu:** token missing/wrong/expired/reused, hai setup đồng thời chỉ một user/audit, restart trước/sau setup, DB outage, Origin/CSRF/session fixation/revocation, secret không lọt logs/API. Test gateway/admin thật trên DB cô lập; kiểm tra access boundary từ nguồn không được phép. Tài liệu và UI setup phải cùng một luồng.

### Bước 2 — Health, external monitoring và failure taxonomy (P0)

Đã có authenticated System health, dependency/resource observations và decision layers. Bổ sung probe/giám sát độc lập, không xây lại health dashboard.

- [ ] **OPS-2.1 MUST — Liveness/readiness** (cũ P10-M1): probe tối giản trên management listener giới hạn truy cập, không cần DB session. Liveness phản ánh process/event loop; readiness phản ánh snapshot hợp lệ/khả năng phục vụ cấu hình. DB mất lúc startup khác DB mất khi đang chạy; collector/ClickHouse/Telegram lỗi không gây restart loop hoặc tự hạ mọi traffic readiness.
- [ ] **OPS-2.2 MUST — External monitoring** (cũ P10-M2): cấu hình probe DNS/TCP/TLS/HTTP/cert expiry từ máy/dịch vụ khác, kênh cảnh báo không phụ thuộc gateway/DB cùng node. Tích hợp last-seen/stale nếu có, không tự xây monitoring platform. Nêu rõ Prometheus chưa dựng trong VPS và triển khai scrape/history khi cần.
- [ ] **OPS-2.3 MUST — Hoàn thiện failure taxonomy** (cũ P10-M3): inventory lớp đã có rồi bổ sung khoảng thiếu cho upstream/WAF/admission/rate-state/replay/policy/client cancel/idle/absolute timeout, partial/commit/attempts. UI/metrics/request details cùng reason/source/timestamp/version; recovery không xóa loss counters hoặc biến cancellation thành completed.
- [ ] **OPS-2.4 SHOULD — Synthetic journeys** (cũ P10-S1): login, sandbox checkout, Range, SSE/WS handshake/event ngoài node; credentials test quyền hẹp, deadlines/concurrency/cleanup hữu hạn. Probe thiếu là unknown/gap, không suy uptime từ HEAD hoặc response 200 đơn lẻ.

**Nghiệm thu:** process/node/DB/ClickHouse/collector/LAPI outages, DNS/TLS/firewall failure, stale ACME worker, clock skew và worker stall. Assert probe/health/UI nhất quán, external monitor phát hiện node tắt và không restart gateway chỉ do monitoring dependency.

### Bước 3 — Điều tra theo route và request (P1)

Tận dụng Service Map, decision flow/timing, Request Details, effective timeouts, editor diagnostics, exclusions và shadow đã có.

Implementation 2026-11-02: route detail phân biệt active/saved draft/historical version; request-reference page, exact history filters và liên kết diff/audit; narrow-exclusion proposal nối shadow/review hiện có; setup/diagnosis nối các công cụ hiện có. [Bằng chứng](docs/evidence/ops-3-4.md) ghi API/recorder/restart/outage và Chrome đã chạy; chưa đóng toàn bộ acceptance draft-conflict/exclusion-expiry/shadow-gap/onboarding trên deployment.

- [ ] **OPS-3.1 — Route detail và effective configuration:** một nơi xem cấu hình có hiệu lực, nguồn global/profile/route/default, traffic/security/health, coverage và thay đổi gần đây. Snapshot active/draft/request có nhãn riêng; không suy dữ liệu lịch sử bằng config hiện tại. Profile là template, không tạo inheritance runtime không tồn tại.
- [ ] **OPS-3.2 — Liên kết điều tra** (cũ P12-S2): metrics → requests → request reference/attempts → config/audit diff cùng thời gian/route/action/policy version; giữ bộ lọc khi drill-down/quay lại. Giải thích 403/429/503 bằng lớp tạo lỗi, upstream đã nhận hay chưa và tài nguyên liên quan. Phân biệt missing do loss/retention khi có bằng chứng; 404 lookup không đủ để kết luận request chưa từng tồn tại.
- [ ] **OPS-3.3 — False-positive workflow:** nối request → rule → narrow exclusion field/rule/route, reason/expiry → shadow → review/apply. Hiện sampled/completed/dropped/mẫu số, scope/version và ảnh hưởng; nhắc expiry. Không tự tắt WAF, promote, gia hạn hoặc apply. Chưa có phân loại mẫu thì dùng “nghi ngờ chặn nhầm”, không công bố false-positive rate.
- [ ] **OPS-3.4 — Luồng thao tác hoàn chỉnh:** thêm dịch vụ chọn backend → test → profile → domain/TLS → coverage → apply; chẩn đoán DNS → TLS → route → policy → upstream → telemetry. Dùng lại endpoint drain/route maintenance, single-endpoint downtime và slow start. Xác minh recorder/timing/Service Map mới theo hợp đồng, chỉ sửa khoảng thiếu.

**Nghiệm thu:** lịch sử config thay đổi sau request, no matching route, thiếu/lỗi metadata, recorder disabled/skipped/dropped/outage/expiry, filter handoff, thao tác draft conflict/rollback/exclusion expiry/shadow gap. Thử keyboard/mobile/theme và loading/error/empty; không dùng body/query capture mới để thay thế metadata an toàn hoặc yêu cầu thu toàn payload.

### Bước 4 — Thống kê trả lời câu hỏi vận hành (P1)

Dùng counters/SSE/checkpoint/host statistics đã có; không tái tính tổng gateway từ live logs.

Implementation 2026-11-02: bốn góc nhìn vận hành, bounded route counters/histograms, top records và comparison/change markers. Lựa chọn đã chốt: thu rollup **5 phút**, TTL **30 ngày**; client IP chỉ trong điều tra authenticated, không vào rollup/Prometheus labels. **Route SLO hiện chỉ số đo; hoãn cấu hình target và đánh giá đạt SLO.** [Bằng chứng](docs/evidence/ops-3-4.md) tách kiểm thử local/DB/browser khỏi nghiệm thu Prometheus, tải, outage và deployment còn mở.

- [ ] **OPS-4.1 — Bốn góc nhìn:** sức khỏe dịch vụ (RPS, errors theo nguồn, p95/p99, upstream availability, saturation, route SLO); bảo vệ (actual block/would-block/rule matches/coverage/challenge); điều tra (top route/rule/client, mẫu đã redact, version); năng lực (WAF queue/RAM/FD/streams/replay disk/health backlog/loss). Route grouping bằng stable ID hoặc template chuẩn hóa, không raw URL chứa ID; per-client phân tích có bounds/privacy, không thêm IP labels.
- [ ] **OPS-4.2 — So sánh và change markers:** trước/sau deploy, hôm nay/hôm qua, cùng giờ tuần trước khi có dữ liệu; mốc config/policy apply, cert renew, upstream down/recovered. Hiện route tăng 5xx, latency và rule mới nổi; correlation không khẳng định config là nguyên nhân. Không nội suy khoảng mất dữ liệu hoặc cộng percentiles.
- [ ] **OPS-4.3 — Chất lượng và nguồn dữ liệu:** tách gateway totals, PostgreSQL last checkpoint/cửa sổ có thể mất, records tra cứu được, coverage/source/time window, ingest lag/gap/drop. Block request khác rule match; block rate tăng không tự là tốt; IP không phải user, UA không phải bằng chứng bot. Bounded route series/retirement và histogram aggregation phải được thiết kế trước khi thêm metrics.
- [ ] **OPS-4.4 — History và rollup:** bổ sung các history slices còn thiếu theo nhu cầu, rollup giữ lâu hơn raw traffic 7 ngày với budget/TTL riêng. Không đổi host incoming-only thành “đã có mọi history”, không backfill phần chưa thu; báo unavailable khi thiếu Prometheus/ClickHouse.

**Nghiệm thu:** nhiều rule match một request, actual vs shadow block, received/completed/in-flight khác nhau, host overflow, counters restart/checkpoint gap, ClickHouse outage và request bị bỏ log. Giữ tối đa 1.000 logs/900 samples/15 phút, test reconnect/tab lâu và đúng mẫu số/version/timezone.

### Bước 5 — Incident, alert lifecycle và việc cần xử lý (P1)

Telegram đã có transition/recovery/coalescing/silence/retry/outbox. Incident là lớp điều tra mới, không đổi tên outbox thành detector hoặc làm lại delivery.

- [ ] **OPS-5.1 — Incident model và workflow:** phát hiện → gom sự kiện → giải thích → đề xuất → theo dõi kết quả; route/service scope, thời gian/config/policy versions, severity/impact, bằng chứng redacted, trạng thái mở/acknowledged/resolved và data-quality. Bounded incident/state/history, dedup/cooldown/recovery; thiếu dữ liệu không tự resolve thành an toàn.
- [ ] **OPS-5.2 — Tích hợp alerts** (cũ P10-S2): bổ sung signals quota/disk/deadline/external-check/audit health còn thiếu, routing và silence theo scope có expiry; giữ delivered/retrying/expired/unknown-ack. Generic webhook delivery còn mở, triển khai nếu cần ngoài Telegram bằng bounded outbox/retry, authenticated secrets và unknown-outcome semantics; không gửi thực trong repository tests.
- [ ] **OPS-5.3 — Bảng công việc:** cert/exclusion sắp hết hạn, CrowdSec/collector/monitor stale, lost logs, unhealthy endpoints, capacity và setup chưa an toàn; mỗi mục có ảnh hưởng, quan sát cuối và hành động cụ thể. Không thay bằng security score tổng khó kiểm chứng.
- [ ] **OPS-5.4 — Saved views và báo cáo:** URL/view lưu bộ lọc không chứa secrets/payload, chia sẻ vẫn cần session; ngày/tuần tổng hợp sự cố/coverage/exclusions/certs/degraded. Export dữ liệu đã redact theo controls bước 6, không biến report scheduler thành task/queue vô hạn.

**Nghiệm thu:** burst hàng trăm matches gom incident đúng scope/version, dedup/cooldown/recovery/reopen, telemetry mất, stale state, channel/DB outage, queue full, retry/unknown ACK duplicate, restart và expiry silence. Không khẳng định false positive/bot/business outcome khi chỉ có tín hiệu gián tiếp.

### Bước 6 — Audit độc lập và vòng đời dữ liệu (P1)

Audit cơ bản và transaction đã có. Bước này hoàn thiện assurance và export còn mở, không cần roles/RBAC để có hiệu lực với một admin.

- [ ] **OPS-6.1 MUST cho payment quan trọng — Durable admin audit** (cũ P12-M1): kiểm kê mutation rồi đóng khoảng thiếu actor/action/target/result/time/config/reference; audit cùng SQL transaction khi có thể, audit failure hủy mutation cần audit nhưng không chặn traffic. Tách DB runtime/migration/export privileges; không đưa migration vào hot path. External DNS write giữ attempt/outcome audit, không hứa distributed atomicity.
- [ ] **OPS-6.2 MUST cho payment quan trọng — Independent export** (cũ P12-M2): transactional outbox budget/expiry/owner/deadline/retry/shutdown, delivery IDs và receiver dedup/ACK, off-node append-only/retention controls. Hết khả năng lưu audit bắt buộc thì từ chối mutation tương ứng; unknown ACK không coi là chưa gửi. Không hứa tamper-proof khi host/DB bị chiếm hoặc chỉ có hash chain local.
- [ ] **OPS-6.3 SHOULD — Retention/export** (cũ P12-S1): tách audit/security/traffic/uptime/deliveries/rollup và recorded bodies; budgets/retention/export controls riêng, bounded pagination/jobs/download expiry/audit. Mặc định redact body/cookie/authorization/query/matched data, không tự đưa recorded content vào export thông thường. Không biến history thành ledger hay thêm backup trong bước này.

**Nghiệm thu:** audit insert failure rollback, rows-affected=0, crash/cancel/mất ACK/export duplicates, outbox full, receiver unavailable/restart, retention/download expiry và unauthorized access/privacy. Off-node sink thật là gate deployment riêng; local receiver fixture không đủ chứng nhận độc lập khi node hỏng.

### Bước 7 — Nghiệm thu deployment theo workload (P0 cho công bố production)

Runbook và nhiều harness cục bộ đã có; phần còn lại là thu bằng chứng và sửa lỗi được phát hiện trong phạm vi được chọn, không tuyên bố đủ production chỉ từ danh sách tính năng.

- [ ] **OPS-7.1 MUST — Capacity envelope** (cũ P13-M1): release build cùng topology/resources cho proxy thuần/DetectionOnly/On; benign/attack tách riêng, short APIs/WS/SSE/uploads/media/bandwidth, p50/p95/p99/status/errors theo lớp, CPU/RSS/FD/threads/queues/replay I/O/telemetry delay/loss. Load generator độc lập, offered load, warm-up/steady/burst/overload/recovery/repeat; không đổi tên WAF Off thành proxy thuần nếu vẫn có chi phí WAF pool.
- [ ] **OPS-7.2 MUST — Fault matrix** (cũ P13-M2): DB mất đang chạy/vừa restart; DNS/TLS/health/LAPI/collector/ClickHouse outage; disk full/read-only/I/O stall; native timeout/OOM/process kill/node/network outage; client chậm/H2 churn/reconnect storm; upstream reset sau commit; clock skew. Môi trường cô lập có owner/cleanup, đo detection/recovery và loss; không tự bật backup/fail-open hoặc chạy long soak đang hoãn.
- [ ] **OPS-7.3 MUST — Deployment/runbook thực tế** (cũ P13-M3): VPS/homelab profiles đang duy trì, release image pull/architecture, UID/permissions/volumes/network/rootful-rootless liên quan, admin isolation/metrics guard, resource/disk limits, external monitor và SIGTERM/restart/drain. Đối chiếu instructions tạo admin, HEAD/GET health, endpoint `tls_verify: false` opt-in nếu dùng: mặc định vẫn verify, ngoại lệ phải rõ trong UI/docs/probe/health. Không khôi phục systemd/template đã gỡ; Linux native cần scope mới nếu triển khai sau.
- [ ] **OPS-7.4 MUST theo tích hợp — Public TLS/CDN/provider:** theo dõi gate Let's Encrypt staging/Cloudflare thật đã bàn giao người vận hành; cấp/renew/restart/hot reload với cert public, DNS permissions/propagation/CAA/IPv6/firewall/Full(strict). Với CDN, kiểm tra trusted-IP spoofing và truy cập origin trực tiếp từ ngoài node phải bị firewall/tunnel chặn. Không tự gọi provider, gửi Telegram hoặc tạo thanh toán thật khi chỉ chạy repository tests.
- [ ] **OPS-7.5 MUST — Profile acceptance** (cũ P13-M4): website/API, flash sale/checkout, upload, HLS/DASH/seek, SSE/AI stream, WS control và payment/webhook sandbox theo nhu cầu deploy. SLO đặt trước đo, topology/resources/results/limitations công khai; missing log không kết luận giao dịch thất bại. Backend xác minh signature/raw bytes và dedup/ledger nguyên tử, gateway không cung cấp exactly-once hoặc authorization nghiệp vụ.
- [ ] **OPS-7.6 SHOULD — Evidence index** (cũ P13-S1): liên kết bằng chứng mới ngay tại checkbox và mục 4 với ngày/version/môi trường/schema/protocol/workload. Khi artifact không còn, ghi thiếu và chỉ tái kiểm chứng gate cần thiết bằng harness mới/hiện có; không phục dựng code/harness lịch sử ngoài nhiệm vụ.

**Giới hạn nghiệm thu:** stream dài cần gate long soak nhưng gate đó vẫn hoãn (cũ P13-M5); workload tương ứng chưa được công bố đạt production streaming. Single-node có downtime, restore/patch workflow chưa nghiệm thu; không công bố HA/DR/compliance/ngân hàng chỉ vì các bước trên đạt. Khi bật lại restore phải có instance sạch và evidence riêng, không dùng restart smoke thay thế.

### Bước 8 — Mở rộng bảo vệ API, abuse detection và automation (P2)

Chỉ thực hiện sau khi dữ liệu/điều tra đủ tin cậy. Không đưa AI hoặc remote detector vào quyết định mỗi request.

- [ ] **OPS-8.1 — Explainable behavioral detectors:** endpoint probing (distinct paths + 404 + rate), flood (RPS/concurrency/admission/WAF saturation), backend suy giảm (latency/5xx so với security blocks), nghi ngờ policy chặn nhầm sau apply. Brute force/login và callback bất thường cần tín hiệu nghiệp vụ đáng tin cậy từ ứng dụng; HTTP 200/401 không đủ. Không thu toàn response body để đoán login hoặc kết luận payment duplicate.
- [ ] **OPS-8.2 — Detector quality:** từng detector có window/min samples/threshold/scope/evidence, warm-up/unknown/stale/gap, baseline theo giờ/ngày khi đủ dữ liệu, bounded keys/incidents/TTL/dedup/cooldown/recovery. Tích hợp incident bước 5; quan sát và đề xuất trước, không tự ban/tắt WAF/apply. CrowdSec acquisition/scenarios cần luồng sự kiện redacted có hợp đồng riêng nếu chọn tích hợp, không suy từ LAPI sync là đã có detection.
- [ ] **OPS-8.3 — Identity rate limit** (cũ P9-S1): kết hợp IP + verified principal + route nghiệp vụ; key cache/keys/TTL/memory hữu hạn, trusted auth boundary, strip forged identity headers, không remote introspection mỗi request. Identity missing/invalid/expired keys có fallback rõ, không allow-all; không log raw token/subject. Đây là traffic identity, không admin RBAC.
- [ ] **OPS-8.4 — OpenAPI quan sát:** import để gợi ý route và schema checks required fields/types/array/string bounds trên nội dung thuộc inspection budget; người vận hành review/validate/apply, mặc định observe, không tự bật block. Parse/validation có CPU/body/state limits và coverage/unsupported rõ; không hứa schema giải quyết authorization/nghiệp vụ hoặc mở rộng multipart/64 KiB ngầm.
- [ ] **OPS-8.5 — Automation contract:** tái dùng `/api/v1` hiện có, làm rõ version/compatibility và lỗi, thêm machine credentials quyền hẹp/expiry/revocation/audit và CLI config validate/export/apply với optimistic versions. Machine scope tối thiểu không kéo admin RBAC vào roadmap. Contract/spec/tests phải được thiết kế cùng implementation; không tạo endpoint/token format/migration mới trong lần tổng hợp này.
- [ ] **OPS-8.6 MUST có điều kiện — mTLS** (cũ P9-M4): chỉ khi tích hợp yêu cầu client-cert downstream hoặc certificate upstream; chain/hostname/SNI/expiry/trust scope/rotation/removal và active-connection semantics có evidence. Không tin client-cert header tự khai, private key không trả qua API; không hứa immediate revocation chưa có cơ chế.

**Nghiệm thu:** traffic fixtures hợp lệ/attack/false alarm theo route/version, warm-up/insufficient samples/telemetry loss/state exhaustion, app signal spoof/replay và business outcomes unknown; identity header/JWT invalid/key rotation; OpenAPI malformed/unsupported/observe/no policy change/limits; machine scope/revocation/conflicts/audit; mTLS sai/hết hạn/rotation khi scope đó được bật. Quan sát/đề xuất không được thay traffic enforcement.

## 6. Đang hoãn và ngoài phạm vi

Các mục hoãn không là `[ ]` bắt buộc trong roadmap hiện tại và không tự chuyển sang lịch chạy. Rủi ro/giới hạn vẫn phải công khai; chỉ mở lại khi người dùng thay đổi quyết định.

| Nhóm | Quyết định và điều kiện xem lại |
| --- | --- |
| Admin MFA — cũ P9-M2 | Hoãn vì hiện một người quản trị; không giữ gate “public admin phải có MFA” trong roadmap này. Nếu bật lại: confirmed TOTP enrollment, encrypted secret, hashed one-time recovery, replay/rate/session/reauth/rotation/recovery audit; không tự viết crypto hoặc remote recovery không xác thực |
| Admin RBAC — cũ P9-M3 | Hoãn, xem lại trước nhiều quản trị viên. Khi mở lại cần API-enforced permission matrix, last-owner invariant, session/SSE revocation và audit; không chỉ ẩn nút UI, không tự thêm two-person approval |
| Backup/restore sạch | Giữ hoãn, gồm config/encrypted credentials/ACME/certs và Applications releases nếu dùng; master keys sao lưu riêng, không gộp traffic history. Khi mở lại: version/checksum/compatibility/decryption/references/validate/apply/rollback và instance sạch/restart/renew evidence. Manual DB snapshot hoặc CrowdSec checkpoint không chứng minh restore/DR |
| Dependency/CRS update, patch workflow, SBOM | Giữ hoãn chiến dịch nâng phiên bản/quy trình vá. Khi mở lại: running version/rule source/diff, compatibility/regressions và rollback. Có thể ghi metadata phiên bản trong inventory mà không coi quy trình cập nhật đã hoàn thành |
| Advanced review/apply | Hoãn approvals nhiều người, canary, automatic rollback và preflight/warm-up health trước publication. Giữ validator/version/diff/atomic apply/rollback/audit hiện có; cảnh báo editor không phải workflow approval mới. Cold-start/reload gaps chưa được giải quyết bằng quyết định hoãn |
| Long soak — cũ P13-M5 và phase 5 | Hoãn gate 2 giờ rồi 24 giờ mixed streaming/reload/drain/fault; soak 5 phút chỉ regression hữu hạn, từng ghi nhận 503 khi chuyển snapshot. Không hứa zero-downtime/new-request continuity hoặc production streaming khi chưa có evidence |
| Challenge nâng cao, tự xử lý, AI — P3 | Browser PoW cơ bản đã có; risk scoring/challenge nâng cao sau. Auto-remediation chỉ khi bật rõ, scope hẹp/TTL/impact cap/audit/nút dừng. AI chỉ tóm tắt incident/giải thích rule/gợi ý điều tra, không quyết định từng request |

Ngoài MVP: multi-node/HA, multi-tenant, remote Docker, backend deployment/runtime/SSR/Node/build source, HTTP/3, CDN cache/transcoding, native gRPC upstream/h2c/extended CONNECT, proxy UDP/RTMP/SRT/WebRTC media, antivirus/DLP, game-state recovery, response-body/WS-frame inspection và payment ledger/exactly-once. CDN/object storage/external monitor/backend identity/ledger là tích hợp deployment, không đưa remote control I/O vào hot path. CRS/schema/gateway access gate không thay quyền truy cập hoặc kiểm soát nghiệp vụ trong ứng dụng.

## 7. Tiêu chí nghiệm thu và báo cáo

### 7.1. Ma trận kiểm chứng theo thay đổi

| Nhóm | Tình huống bắt buộc khi thay đổi hành vi tương ứng |
| --- | --- |
| Config/routing | Precedence/ambiguous matches, proxy loops/IP interfaces/DNS, spoofed forwarded headers, concurrent apply/conflict/unknown ACK, immutable in-flight snapshot và validated rollback |
| WAF/FFI/coverage | Off/DetectionOnly/On, CRS benign/attack/exclusion/expiry/shadow, chunked/Expect/multipart/64 KiB, worker/queue/deadline/cancel/shutdown; upstream spy chứng minh block trước forwarding; ownership/sanitizer/fuzz phù hợp |
| Access/flood/challenge | Global + route precedence, rate/state exhaustion, HTTP budget độc lập IP quota, GeoIP unknown/unavailable, NAT/identity churn, PoW binding/replay/expiry/browser limits; API/webhook không bị challenge ngầm |
| Protocol/payment | Byte-exact upload/signature, retry vs replay, dedup/ledger sandbox commit-mất ACK/concurrent/conflict/TTL, HEAD/Range/encoding/trailers/Expect, SSE/WS/H2 cancellation/slow clients và timeout trước/sau commit |
| Discovery/operations | Bridge/host-network/rootful/rootless/IPv6/loopback, exposed vs listener, DNS alias TTL/loop, collector outage/stopped/recreate/source identity; probe từ gateway có verify, drain/maintenance/force disconnect/slow start/sticky fallback |
| TLS/provider | SNI invalid/exact/wildcard/SAN, restart/renew/hot reload, public staging/provider gate riêng, credential rotation/import ownership, DNS protected records/conflicts/unknown ACK/cleanup và bootstrap migration |
| Requests/recording | Schema cũ/partial/missing, redaction trước queue, capture flags/bounds/invalid/encoded fields/skip/no-drain, marker-only SSE/history list, auth/no-store/body query cache cleanup; không làm thay traffic/WAF/streaming |
| Telemetry/UI/statistics | Start vs completion, block vs match, counters vs history vs checkpoint loss, host/route cardinality/filters before LIMIT, reconnect/gap/pause/slow SSE/ClickHouse outage, client memory bounds, keyboard/mobile/light-dark |
| Incident/report/export | Grouping/dedup/window/baseline/warm-up/data loss/cooldown/recovery, filter/version correlation, bounded saved views/report jobs, delivery outage/unknown ACK, audit failure/receiver dedup/retention/privacy |
| Admin/deploy | Setup token/race/reuse/restart/DB outage, Origin/CSRF/session, exposure/firewall/metrics guard, volume/key preservation, resource budgets/disk faults/SIGTERM, release/topology checks; không thực hiện MFA/RBAC/restore/long soak đang hoãn |

Giữ số liệu công bố gắn với workload/tài nguyên/topology/version. Benchmark proxy thuần/DetectionOnly/On riêng, công bố concurrency/body/duration/offered load/RPS/latency/status/CPU/RSS/FD/queues/loss. Mục tiêu realtime event-to-display **≤2 giây chỉ là mục tiêu** cho tải nghiệm thu đặt trước, chưa phải kết quả của lần viết lại này. Historical local results, fixtures/Pebble và soak ngắn không thay public TLS, external monitoring, capacity/fault acceptance hoặc compliance.

### 7.2. Lệnh và phạm vi báo cáo

- Rust khi đổi code: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`; Linux/native dependencies và integration thực theo behavior. Môi trường không chạy được phải báo cụ thể, không tự bỏ test rồi tuyên bố toàn workspace đạt.
- Frontend khi đổi code: dùng package manager hiện có và scripts `lint`, `typecheck`, `build`, `format:check` trong `package.json`; browser tests phù hợp riêng, không giả định có script test khác. Không thêm thư viện trùng stack.
- Khi chỉ đổi tài liệu: rà nội dung và toàn bộ link nội bộ/Markdown, mapping baseline–công việc còn mở–mục hoãn, `git diff --check`; không cần build hoặc khôi phục ứng dụng/harness cũ.
- Báo file đã đổi, checks thực sự chạy, kết quả và giới hạn. Không đánh dấu deployment hoàn thành khi chỉ có local test hoặc tài liệu mô tả test. Với thay đổi mới, lưu bằng chứng phù hợp thay vì kế thừa trạng thái cũ; mọi API/schema/UI contract phải cùng semantics.
