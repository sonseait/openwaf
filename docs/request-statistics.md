# Request statistics và biểu đồ vận hành

Bổ sung OPS-4 (2026-11-02): bốn góc nhìn, route counters, comparison/change
markers và counter rollup 5 phút/30 ngày theo [hợp đồng Investigation](investigation.md).
Nguồn, giới hạn và kết quả thực chạy ở [bằng chứng OPS-3/4](evidence/ops-3-4.md).
Bộ lọc Host của baseline áp dụng live statistics/Prometheus incoming history;
operational views mới dùng route scope riêng, không gán host filter vào rollup.

## Hợp đồng giao diện

Người dùng: quản trị viên vận hành một gateway. Tác vụ chính: xác định lưu lượng,
tỷ lệ bị chặn, nguồn theo quốc gia/nhóm client và các bất thường về HTTP/latency.
Trang `/statistics` có Request volume, Response outcomes, GEO & user agents và
Performance; Overview/Live traffic giữ biểu đồ realtime. Nguồn tham chiếu là
counters, SSE và Mantine/theme/layout hiện có trong workspace.

- Viewports kiểm tra: 1440x1000 và 390x844. Nội dung có loading/empty, stale,
  pause/resume, gap/drop, lỗi storage/history và retry tải history.
- Phân cấp: connection/observation/source → tổng counters → tabs biểu đồ →
  Prometheus history khi người dùng yêu cầu. Tổng và phân nhóm tích lũy qua restart
  trong managed mode; không nhầm với khoảng 15 phút của chuỗi realtime.
- D3 scale/shape + Canvas cập nhật qua requestAnimationFrame, không animation
  hoặc React node theo từng điểm. ResizeObserver và frame được hủy khi unmount.
  Các chart có tên truy cập được, legend có giá trị và bảng 10 quan sát gần nhất;
  biểu đồ chia nhóm có bảng số liệu và nhãn, không chỉ dùng màu.
- Client giữ tối đa 900 metrics/15 phút, 1.000 live logs. Chỉ latest snapshot giữ
  các counters chia nhóm; không nhân bản toàn bộ breakdown vào 900 mẫu biểu đồ.
  Trang Statistics chỉ mở stream metrics, không subscribe logs không dùng.
- Form numeric: tối đa 3 trường/hàng trên desktop, 2 trên màn hình trung bình,
  1 trên mobile. Timeout/quota/retry/WAF/health có mô tả đơn vị, kế thừa và hành vi.
  Các flow validate/save/review/apply giữ nguyên.

## API bổ sung tương thích

### Lọc theo host

`GET /api/v1/telemetry` và `GET /api/v1/events/metrics` nhận query `host`
tùy chọn: hostname chuẩn hóa, so khớp chính xác, không kèm scheme/port/path.
Bỏ query này để xem toàn gateway. Snapshot theo host có `host`, toàn bộ totals,
rate, latency, bandwidth và dimensions đều thuộc host đó; queue/resources vẫn là
health toàn gateway. Không suy ra thống kê từ live logs. Host chưa được thu thập
trả `404`, host không hợp lệ trả `422`.

`GET /api/v1/telemetry/hosts` trả `hosts`, `capacity`, `overflow_requests` và
`observed_at_unix_ms`. Tối đa 32 host đã quan sát được giữ ổn định, không eviction;
request vượt số host này vẫn nằm trong tổng gateway và traffic history, được báo
qua overflow thay vì gán nhầm vào host khác. Host được ghi sau validation authority,
trước routing/security; request bị từ chối trước validation chỉ nằm trong tổng.
Checkpoint khôi phục cả counters từng host; checkpoint cũ không có dữ liệu host
vẫn đọc được, không tự phân bổ lại totals cũ. `statistics_started_at_unix_ms` của
snapshot host cho biết thời điểm bắt đầu thu thập host đó. Giới hạn checkpoint
tăng lên 4 MiB để chứa tối đa 32 bộ dimensions có giới hạn.

UI đổi stream khi chọn host, tách cache theo host và hủy stream cũ; chỉ giữ 15 phút
metrics của lựa chọn hiện tại. Bộ lọc áp dụng tất cả tabs và incoming RPS history.
`GET /api/v1/history/metrics?...&series=incoming&host=app.example.test` dùng
counter `openwaf_host_incoming_total{host="app.example.test"}`; chỉ hỗ trợ series
incoming khi lọc host. Nhãn host có tối đa 32 giá trị, không export path/raw URL.
History không tự backfill dữ liệu trước khi counter theo host được triển khai.

`GET /api/v1/telemetry` và snapshot/data trong `/events/metrics` bổ sung
`dimensions` vào metrics schema 1 (additive). Không đổi logs/ClickHouse schema.

```json
{
  "dimensions": {
    "source": "gateway_counters",
    "countries": [{"label": "GB", "received": 100, "blocked": 4}],
    "user_agents": [{"label": "Firefox", "received": 80, "blocked": 2}],
    "methods": [{"label": "GET", "received": 90, "blocked": 3}]
  }
}
```

Timestamp/window/epoch dùng các field hiện có trên metrics. Received đếm request
bắt đầu; blocked đếm quyết định block đúng một lần, độc lập với completion, retry
và log queue. Snapshots đọc atomics best effort, không transaction giữa counters.
Trong managed mode, tổng và các nhóm được checkpoint vào PostgreSQL và khôi phục
trước khi mở gateway. Standalone không có PostgreSQL tiếp tục dùng counters theo process.
Checkpoint lưu mỗi 5 giây và lần cuối sau graceful drain, timeout mỗi lần ghi 2 giây;
không ghi database trên proxy hot path. Một hàng `openwaf_statistics` có schema version,
generation tăng dần và JSON tối đa 4 MiB (gồm counters từng host). Generation ngăn ghi cũ hoàn tất muộn đè
checkpoint mới. Nhãn và số nhóm được validate trước restore; checkpoint không hợp lệ
hoặc đọc database lỗi làm managed startup thất bại, không tự reset/ghi đè dữ liệu.

`persistence` bổ sung vào metrics/SSE schema 1:

```json
{"persistence":{"configured":true,"degraded":false,"last_success_unix_ms":1793012345000,"interval_ms":5000}}
```

UI hiển thị nguồn PostgreSQL, lần checkpoint thành công cuối và degraded khi ghi lỗi.
Proxy/live counters tiếp tục khi ghi thất bại; lần ghi sau lưu tổng mới nhất, không
phụ thuộc ClickHouse/log queue. SIGKILL/mất điện có thể mất phần thay đổi sau checkpoint
thành công cuối; nếu database lỗi kéo dài thì cửa sổ mất dữ liệu tăng theo outage,
không bảo đảm mất tối đa 5 giây. Restart cần database đọc được. Không khôi phục được
statistics đã mất trước khi bản sửa này được triển khai.

Chỉ counters tích lũy được khôi phục (gồm status bins, histogram bins/sum, bytes và
GEO/UA/method). Active requests/connections, queue, tài nguyên process, RPS/percentiles
theo cửa sổ và SSE epoch/sequence khởi tạo mới. Baseline rate lấy từ totals đã restore,
không biến lịch sử thành spike RPS. Request đang dở lúc crash không được tự suy diễn
là completed/cancelled. Đây vẫn là snapshot atomics best effort, không phải ledger.
Không persist chuỗi live 15 phút hay lịch sử GEO/UA theo thời gian; history vẫn qua
ClickHouse/Prometheus.

GEO: lookup MMDB đã nạp trong bộ nhớ (`OPENWAF_GEOIP_DB`) sau khi resolve client
qua trusted proxies, trước route lookup/security decision. Không I/O/query DB trên
hot path. Không có MMDB là `Unavailable`; không match country là `Unknown`;
lỗi lookup là `Lookup failed`; request bị từ chối trước khi resolve client hoặc
đang chờ classification là `Unattributed`. Không tin X-Forwarded-For từ peer chưa
trusted. Nhãn country chỉ nhận 2 chữ cái ASCII hoa (676 slots + 4 nhóm đặc biệt).
UI hiện 10 nhóm có received cao nhất và gộp phần còn lại, giữ đúng số tổng.

Nhóm `Unavailable`/`Lookup failed` là counters lịch sử tích lũy, không phải health
status hiện tại của GeoIP. Chúng vẫn còn sau khi cấu hình database hoặc sửa lỗi,
kể cả qua restart khi được restore từ PostgreSQL. UI giải thích dữ liệu đã ghi
nhận và hướng dẫn kiểm tra `client.geoip_status` trên request mới; không kết luận
database hiện đang unavailable chỉ vì lịch sử có request thuộc nhóm này. MMDB
chỉ được nạp lúc gateway khởi động; đổi file hoặc biến `OPENWAF_GEOIP_DB` cần
restart/recreate gateway để có hiệu lực.

User agent: classifier heuristic có tối đa 1.024 bytes và 9 nhóm cố định: Edge,
Opera, Chrome, Firefox, Safari, Bot / crawler, CLI / library, Other, Missing.
Giá trị quá dài/non-ASCII vào Other. Đây là khai báo có thể giả mạo, không phải
bot detection hoặc căn cứ security. Không giữ raw UA, IP hoặc header trong metrics.
Method có 10 nhóm cố định gồm OTHER. Không thêm labels Prometheus cardinality cao.

Blocked/received dùng tổng block chia tổng incoming; phần còn lại gồm local,
forwarded và in-flight. Không suy ra blocked từ status 4xx. Status/latency theo
request hoàn thành; không cộng/average percentiles giữa nhiều cửa sổ.
Count chart dùng delta counters giữa snapshot cùng epoch, sequence liên tiếp và
thời gian hợp lệ. Reconnect/gap/reset không nội suy hoặc biến thành zero.
Prometheus history tiếp tục qua Admin API, previous hour/step 15 giây; chưa có
history GEO/UA và không suy ra từ ring live logs.

Không coi thay thư viện vẽ là bằng chứng benchmark hoặc đạt mục tiêu realtime ≤2s.

## Kiểm chứng bộ lọc host/path — 2026-11-01

Các file của thay đổi này (giữ nguyên các chỉnh sửa giao diện có sẵn):

- Frontend: [Telemetry.tsx](../frontend/src/Telemetry.tsx),
  [RequestStatistics.tsx](../frontend/src/RequestStatistics.tsx),
  [TrafficFeed.tsx](../frontend/src/TrafficFeed.tsx),
  [telemetry-state.ts](../frontend/src/telemetry-state.ts).
- Backend: [telemetry API](../backend/crates/admin/src/telemetry.rs),
  [checkpoint writer/tests](../backend/crates/admin/src/statistics.rs),
  [gateway accounting hook](../backend/crates/gateway/src/main.rs),
  [history queries/tests](../backend/crates/storage/src/lib.rs),
  [telemetry counters](../backend/crates/telemetry/src/lib.rs),
  [host registry/tests](../backend/crates/telemetry/src/hosts.rs),
  [migration](../backend/crates/admin/migrations/202611010002_host_statistics.sql).
- Hợp đồng: tài liệu này và [request-details.md](request-details.md).

Đã chạy và đạt:

- `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo test -p openwaf-admin -p openwaf-storage -p openwaf-telemetry`:
  45 test đạt; các test integration yêu cầu dịch vụ được chạy riêng như bên dưới.
- Test ClickHouse local 25.8.33.6:
  `OPENWAF_TEST_CLICKHOUSE_URL=<isolated-local-url> cargo test -p openwaf-storage clickhouse_filters_host_and_literal_path_before_limit -- --ignored`.
  Xác minh host không phân biệt case, path phân biệt case, literal quote/backslash/
  `%`/`_`, metadata hỏng và kết quả match nằm ngoài 100 bản ghi mới nhất.
- Test PostgreSQL local 17:
  `OPENWAF_STATISTICS_TEST_DATABASE_URL=<isolated-local-url> cargo test -p openwaf-admin postgres_migrates_saves_and_restores_host_statistics -- --ignored`.
  Xác minh migrations, lưu/khôi phục host, không khôi phục gauges/RPS và từ chối
  checkpoint host trùng trước khi thay đổi counters. Containers test đã dừng/xóa.
- Frontend: `npm run lint`, `npm run typecheck`, `npm run build`; Prettier trên
  bốn file frontend đã sửa; `git diff --check`. Build có cảnh báo bundle >500 kB.

`cargo test --workspace` trên macOS không đạt hai test có sẵn:
`probe::tests::dns_cache_expires_and_connection_uses_new_address` không bind được
`127.0.0.2`, và `checkpoint::tests::atomic_roundtrip_integrity_permissions_and_bounds`
không đọc được Linux `/proc/sys/kernel/random/boot_id`. Chạy workspace với hai
`--skip` tương ứng đạt phần còn lại; không sửa/bỏ qua các test đó trong source.
Chưa kiểm chứng tương tác trình duyệt, Prometheus history với dữ liệu scrape thật,
deploy production hoặc benchmark hot path trong lần thay đổi này.
