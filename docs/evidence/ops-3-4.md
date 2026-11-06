# Bằng chứng triển khai OPS-3/4

Ngày: 2026-11-02. Revision: `6cae4c1` + working tree của lần triển khai này,
chưa commit/deploy. Phạm vi được chọn: OPS-3.1–3.4 và OPS-4.1–4.4; bỏ qua bước
1–2. Contract hiện hành: [Investigation](../investigation.md); trạng thái duy
nhất ở [plan.md](../../plan.md#4-trạng-thái-hiện-hành).

## Môi trường và workload

- macOS 27.2, Darwin 27.2.0 arm64; Rust 1.97.1; Node 24.18.1.
- Docker Engine 29.8.2 Linux/arm64; PostgreSQL `17-bookworm`, ClickHouse `25.8`.
  Harness dùng containers cô lập, loopback ports ngẫu nhiên, credentials sinh
  lúc chạy và cleanup trong `finally`.
- Gateway debug build với native ModSecurity; upstream HTTP fixture và rules
  cục bộ. Không phải workload/benchmark CRS production.
- Google Chrome headless qua Playwright cài ngoài repository. Browser gọi
  gateway/static frontend thật; cookie session fixture trên loopback.
  Không xác minh secure-cookie/TLS/exposure của deployment bằng fixture đó.

## File và hành vi đã triển khai

| Phạm vi | File chính | Hành vi |
| --- | --- | --- |
| OPS-3.1 | `backend/crates/admin/src/investigation.rs`, `frontend/src/Investigation.tsx` | Route effective config/timeouts và nguồn, active/draft/historical version, active-only health, expiry/coverage/shadow; historical không resolve bằng active |
| OPS-3.2 | `backend/crates/storage/src/lib.rs`, `backend/crates/admin/src/config.rs`, `frontend/src/investigation-state.ts`, RequestDetails/Configuration/TrafficFeed/ServiceTopology/App | Exact filters trước LIMIT, reference page, giữ URL selection/back, request → route/version/audit diff |
| OPS-3.3–3.4 | RequestDetails/Investigation/TrafficProfiles/OperationalControls | Narrow exclusion proposal → draft → route shadow → review/apply; setup/diagnosis nối các công cụ đã có, không mutation tự động |
| OPS-4.1–4.3 | `backend/crates/telemetry/src/routes.rs`, telemetry/gateway hooks, `frontend/src/OperationsStatistics.tsx` | 128 stable IDs/process, counter/histogram độc lập logs; Service/Protection/Investigation/Capacity, top route/rule/client và source/loss/coverage |
| OPS-4.2–4.4 | `backend/crates/storage/src/rollup.rs`, gateway admin runtime, investigation handler, `202611020001_statistics_changes.sql` | Rollup 5 phút/30 ngày; retry dedup, cộng histogram trước percentile, observed health/cert markers, persisted cert baseline, bounded queries/writer/shutdown |
| Contract/resource budget | `docs/investigation.md`, `frontend/README.md`, config resources, `plan.md` | Sources/retention/reset/unavailable/privacy; allowance 16 MiB; SLO chỉ số đo, hoãn target/evaluation |
| Regression | `backend/tests/body_recording.py`, `statistics_storage.py`, `investigation_browser.cjs`, `investigation_state.mjs` và Rust tests cạnh implementation | Real API/DB/native gateway/browser cùng bounded state/URL tests |

## Kiểm tra đã chạy

Các lệnh Rust/Python bên dưới chạy trong `backend/`; npm trong `frontend/`;
Node test chạy từ repository root. Exit code 0 trừ dòng workspace không lọc.

| Lệnh | Kết quả và phạm vi bằng chứng |
| --- | --- |
| `cargo fmt --all -- --check` | Đạt |
| `cargo clippy --workspace --all-targets -- -D warnings` | Đạt |
| `cargo test -p openwaf-admin -p openwaf-storage -p openwaf-telemetry` | 61 passed, 6 ignored; integration cần DB chạy riêng bên dưới |
| `cargo build -p openwaf-gateway` | Đạt, debug binary dùng trong harness |
| `cargo test --workspace` | Exit 101: `probe::tests::dns_cache_expires_and_connection_uses_new_address` không bind được `127.0.0.2` trên macOS (`AddrNotAvailable`, OS code 49); không báo toàn workspace đạt |
| `cargo test --workspace -- --test-threads=1 --skip probe::tests::dns_cache_expires_and_connection_uses_new_address --skip checkpoint::tests::atomic_roundtrip_integrity_permissions_and_bounds` | 187 passed, 6 ignored, 2 filtered. Test checkpoint phụ thuộc `/proc/sys/kernel/random/boot_id`; giữ nguyên source, chưa kiểm chứng hai test này trên Linux trong lần này |
| `npm run lint`, `npm run typecheck`, `npm run build`, `npm run format:check` | Đạt; Vite còn cảnh báo chunk chính lớn hơn 500 KiB |
| `node --test backend/tests/investigation_state.mjs` | 2 passed: URL bỏ captured content/query values; 12.000 synthetic events, duplicate/reconnect/restart, 1.000 logs/900 samples/15 phút |
| `python3 tests/statistics_storage.py` | 4 DB integration cases đạt: ClickHouse exact filters/top trước LIMIT/malformed metadata; retry dedup/histogram/hourly grouping/TTL DDL; PostgreSQL cert baseline qua restart/rollback; checkpoint host statistics |
| `OPENWAF_RUN_BROWSER_CHECKS=1 OPENWAF_PLAYWRIGHT_MODULE=/tmp/openwaf-browser-check/node_modules/playwright/index.js python3 tests/body_recording.py` | Đạt: các assertions API/recorder/restart/outage và Chrome nêu dưới đây. Đường dẫn Playwright là dependency môi trường test, không dependency sản phẩm |
| `git diff --check`, Python/JavaScript syntax và rà local Markdown links của tài liệu đổi | Đạt |

Harness API/gateway kiểm chứng session/no-store, route missing/conflicting
selection, active/draft/historical version sau apply, exact-version diff lookup,
route counters, audit/health markers (không suy recovery qua config version),
filtered history/top, graceful shutdown flush và rollup history sau restart.
Recorder regression kiểm tra cờ độc lập, redaction, form/query decode lặp,
disabled/skipped/oversize/compressed/HEAD/chunked, rollback/restart, stalled reader,
ClickHouse outage giữ traffic và báo persistence lỗi. Upstream fixture xác nhận
request bị body/header WAF block không tới upstream; header block không drain body.

Chrome kiểm tra route active/draft/historical, giữ route/time filters khi
drill-down/back, bốn operational tabs, historical health unavailable, pause,
keyboard focus, 1440×1000 và 390×844, không document overflow trên mobile,
toggle light/dark thật và không `pageerror`. Đây là regression hữu hạn; synthetic
state test riêng xác nhận bounds, không phải browser heap profiling hoặc long soak.

## Giới hạn và nghiệm thu còn mở

- Không chạy public CA/provider, external monitoring/Prometheus scrape/history,
  production deploy, capacity benchmark, realtime event-to-display ≤2 giây hoặc
  long soak. Linux-specific workspace tests cần chạy trên Linux trước nghiệm thu
  tương ứng. Hai ignored bootstrap cases ngoài phạm vi không được chạy lại.
- Chưa chạy lại toàn ma trận onboarding Docker/rootless/domain/TLS/profile,
  draft conflict, shadow expiry/gap, challenge, mọi lớp 403/429/503, host overflow
  và restart/clock/fault combinations trên deployment. Workflow hiện nối các
  controls baseline; các checkbox nghiệm thu toàn mục vẫn mở trong plan.
- Rollups chỉ gồm whole observed windows; không backfill, prorate hoặc bảo đảm
  đủ dữ liệu qua crash/outage. Route counters process-local, reset khi restart;
  gateway/host checkpoint có semantics riêng. Không chứng minh hard disk quota
  hoặc actual TTL cleanup sau 30 ngày chỉ từ DDL test.
- Rollups scope gateway/route, gộp config versions; arbitrary record filters
  không áp dụng vào counters. Gateway rollup coverage/WAF fields unavailable;
  dùng route counters. Rule findings khác request blocks; shadow khác primary WAF.
- Health/certificate markers là bounded observations, có thể mất khi DB lỗi;
  metadata renewal không chứng minh ACME/public issuance. Client IP chỉ trong
  authenticated investigation; không thêm IP/URL/reference vào rollup hay labels.
- Route SLO target và evaluation được hoãn theo lựa chọn người dùng. Chưa công
  bố production acceptance hoặc đóng các gate bước 1–2/5–8.
