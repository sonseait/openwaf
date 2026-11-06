# Điều tra route/request và thống kê vận hành

Bổ sung OPS-3 và OPS-4 trên baseline hiện có. Không thay đổi bootstrap, probes,
security enforcement, WAF inspection budget hoặc certificate lifecycle.

## Điều hướng và nguồn cấu hình

- `/routes/:id`: effective configuration, nguồn timeout route/upstream/default,
  global + route ACL, WAF policy, backend/health, exclusions/expiry, coverage và shadow.
  Profile là template đã sao chép; không thể khôi phục provenance từng field từ
  giá trị giống template. WAF không có override hiện `runtime_default_not_collected`.
- `?snapshot=draft` đọc saved draft; `?version=N` đọc document đã commit đúng version.
  Không prepare/apply document lịch sử. Health hiện tại chỉ có với lựa chọn active.
  Thiếu route/version trả 404; không thay bằng route/config hiện tại.
- `/requests/:reference`: lookup live ring rồi history như contract
  [Request Details](request-details.md), giữ reference 32/64 ký tự. 404 không chứng
  minh request chưa tồn tại: record có thể mất, hết retention hoặc chưa thu được.
- URL drill-down giữ time range, host/path/country, stable route ID, client IP,
  action, security layer, rule ID, status class và config version. Không chứa body,
  query values, cookies, authorization hoặc WAF matched data. IP chỉ là network
  identity; link điều tra có IP vẫn cần session và không nên công bố công khai.
- Request → narrow exclusion proposal → saved draft → route shadow → review/apply
  dùng workflow/revision/CSRF/audit hiện có. Expiry được nhắc trong route detail;
  không tự apply/promote/gia hạn. Thuật ngữ là “suspected false positive”, không
  đưa ra false-positive rate khi chưa có tập mẫu phân loại.

## API bổ sung tương thích

Tất cả endpoint dưới yêu cầu session, trả `Cache-Control: no-store`; mutations
vẫn dùng API hiện có với CSRF. Lỗi domain: invalid 422, not found 404, unavailable
503; malformed query bị Axum từ chối 400. Không trả lỗi SQL/native có dữ liệu riêng.

| GET `/api/v1` | Input | Kết quả |
| --- | --- | --- |
| `/routes/{id}` | `draft=true` hoặc `version=N`, không kết hợp | `source`, `config_version`, `active_version`, `observed_at_unix_ms`, route/global/upstream, `effective_timeouts`, `sources`, active-only `upstream_health`; không trả sealed password verifier |
| `/telemetry/routes` | Không | schema 1, epoch/source/timestamp, capacity/overflow/reset/retirement, coverage scopes và tối đa 128 route samples |
| `/history/traffic` | Input cũ + `route_id`, `client_ip`, `config_version`, `action`, `layer`, `rule_id`, `status_class` | Record list hiện có; lọc trước LIMIT, không resolve route index bằng active config |
| `/history/top` | Cùng input history, tối đa 24 giờ | Top 20 route/rule/client từ searchable records, source/time/health và completeness; rule count là recorded findings |
| `/history/statistics` | `start_ms`, `end_ms`, optional `route_id`; tối đa 30 ngày | Counter rollups, histogram-derived p95/p99, source/window/version scope/health/retention/completeness |
| `/history/changes` | `start_ms`, `end_ms`, optional `version`; tối đa 30 ngày | Tối đa 100 audit/health/certificate markers, timestamp/source, `may_have_more` và giới hạn observation slice |
| `/config/versions` | Optional `version=N` | Giữ response array cũ; lọc chính xác để lấy diff của version ngoài latest 100 |

Exact filters: route ID/security layer tối đa 128 bytes không control characters;
client IP phải parse được; config version không âm; action `blocked`/`forwarded`/
`local`; rule ID 900000–999999; status class 0–5. User text được hex-encode thành
SQL data; không nhận SQL/PromQL tùy ý. Top queries dùng shared semaphore 2, từng
ClickHouse request deadline 2 giây, execution 1 giây, memory 64 MiB, response tối đa
4 MiB; top handler deadline 7 giây. Resource accounting bổ sung 16 MiB cho route
windows/rollup/query buffers; đây là allowance, không thay OS/cgroup quotas. Time/record bounds cũ của history vẫn giữ nguyên.

Ví dụ: `/api/v1/history/traffic?start_ms=...&end_ms=...&limit=100&route_id=checkout&config_version=12&action=blocked&rule_id=941101`.
Các giá trị `...` trong ví dụ phải thay bằng Unix milliseconds hợp lệ.

## Counters, histogram và rollup

Route registry giữ tối đa 128 stable IDs/process, không eviction. Request giữ Arc
đến khi finish/drop; ID đã nghỉ vẫn chiếm slot tới restart. Overflow được đếm,
gateway totals vẫn thu độc lập. Route counters bắt đầu sau route selection; global
reject trước routing không được gán giả vào route. Các counter route mới không nằm
trong PostgreSQL checkpoint; API/UI ghi rõ reset khi process restart và không
phân bổ gateway totals đã restore vào route. Counter window đầu cần baseline;
RPS/p95/p99 theo window chưa có sẽ unavailable, không giả bằng 0.

Counters cập nhật bằng local atomics, độc lập log queue. Completed/status/histogram
khác started/in-flight/cancelled. Security coverage ghi lúc finalization; primary
WAF would-block khác actual security blocks và shadow would-block. Rule matches
đếm bounded findings đã có, không phải số request; truncated reports có counter
riêng. Shadow vẫn có sampled/completed/dropped và denominator riêng.

Một writer do admin runtime sở hữu đọc snapshots, ghi `openwaf_statistics_v1`
ClickHouse theo bucket 5 phút và flush cửa sổ cuối khi graceful shutdown. Một batch
≤129 rows/512 KiB, hai lần thử cùng serialized body, không queue/retry vô hạn.
`ReplacingMergeTree` dùng epoch/route/bucket/start làm key; query `FINAL` tránh đếm
đôi identical retry khi mất ACK. Thất bại cả hai lần được báo dropped/uncertain,
không backfill hoặc giữ proxy chờ storage. Deadline shutdown rollup 7 giây.

Rollup TTL 30 ngày độc lập traffic/body TTL 7 ngày. Tối đa khoảng 1,1 triệu windows
cho 128 routes + gateway chạy liên tục trong 30 ngày, chưa tính restart windows;
operator vẫn phải cấp disk quota/dung lượng ClickHouse theo deployment. Đây không
phải cam kết hard disk quota. Không lưu IP, raw URL, request reference hoặc payload
vào rollup/metrics labels. History ≤3 ngày nhóm 5 phút, dài hơn nhóm 1 giờ, tối đa
865 buckets do biên thời gian; không cắt âm thầm lựa chọn 30 ngày.

Rollup chỉ trả whole observed windows nằm trong lựa chọn, không prorate counts.
Histogram bins được cộng trước khi tính percentile; percentile là upper bound,
empty/+Inf là null. Gateway rollup chưa thu coverage tổng độc lập route:
`coverage_source=unavailable_use_route`, `security_source=unavailable_use_route`;
security fields của gateway rollup là null, dùng route scope cho coverage/WAF. Host scope
vẫn chỉ incoming Prometheus history như contract cũ; các filters khác ngoài route
chỉ áp dụng record investigation, UI cảnh báo điều này. Rollups gộp config versions
và ghi `version_scope=mixed_config_versions`, không suy version từ active config.

Trước/sau apply dùng time windows chọn rõ; hôm qua/cùng giờ tuần trước chỉ hiện
baseline nếu có records tương ứng. Missing/partial/gap không nội suy hoặc coi là
zero; aligned comparison không khẳng định causal impact. Route SLO targets và đánh
giá đạt SLO được hoãn theo lựa chọn người dùng; hiện chỉ có số đo.

## Change markers và giới hạn quan sát

- Audit markers dùng transaction/audit hiện có. Bounded health slice tối đa 1.000
  observations trong raw retention 7 ngày; chỉ ghi nhận down/recovered khi hai mẫu
  còn fresh, cùng config version và cách nhau ≤90 giây. Unknown/gap/version change
  không tự tạo recovery. Truncated slice được công khai; đây không phải uptime ledger.
- Sampler endpoint hiện có cũng quan sát public certificate metadata mỗi 30 giây.
  Migration `202611020001_statistics_changes.sql` lưu baseline để restart không
  tự tạo renewal; không thu private keys/PEM paths/credentials. Valid-from tăng tạo
  `certificate.renewal_observed`; thay metadata khác tạo `certificate.metadata_changed`.
  Đây không chứng minh public CA issuance/ACME staging hay cert lifecycle đã nghiệm thu.
- Certificate markers giữ 30 ngày, tối đa 10.000; baseline tối đa 256 hosts. Transaction
  deadline 2 giây; lỗi báo observation unavailable, không ảnh hưởng TLS/proxy.
  Marker có thể thiếu khi DB lỗi; không backfill từ cert hiện tại.
- Polling route có pause/stale; existing SSE/log bounds giữ nguyên 900 samples/15
  phút và 1.000 logs. History tối đa 865 counter buckets; top mỗi nhóm 20; query cache
  hủy khi unmount/đổi key. Browser script là regression hữu hạn, không long soak.

## Kiểm chứng

- Unit/integration tests nằm trong telemetry routes, storage rollup/filter,
  admin investigation và `backend/tests/body_recording.py`.
- ClickHouse tests cần instance cô lập, có TRUNCATE bảng test:
  `OPENWAF_TEST_CLICKHOUSE_URL=<isolated-origin> cargo test -p openwaf-storage clickhouse_ -- --ignored --test-threads=1`.
- Chạy `node --test backend/tests/investigation_state.mjs` từ root để kiểm tra
  URL privacy và bounds/reconnect với 12.000 events (Node ≥22.18).
- Chạy `python3 tests/statistics_storage.py` trong `backend/` để tạo/xóa các
  PostgreSQL/ClickHouse test containers và chạy bốn integration cases.
- Chạy `cargo build -p openwaf-gateway`, rồi `python3 tests/body_recording.py` trong
  `backend/`; harness chỉ tạo/xóa containers của mình, không gọi provider thật.
- Browser regression tùy chọn: build frontend, cài Playwright ở test environment
  riêng và chạy harness với `OPENWAF_RUN_BROWSER_CHECKS=1`,
  `OPENWAF_PLAYWRIGHT_MODULE=<absolute-path-to-playwright/index.js>`.
  Script dùng Chromium/Chrome local và session fixture trên loopback; không là
  nghiệm thu exposure/TLS/session trên deployment production.

Kết quả thực chạy và giới hạn được ghi trong [evidence OPS-3/4](evidence/ops-3-4.md).
