# Hướng dẫn làm việc trong OpenWAF

## 1. Nguồn định hướng và phạm vi

- Đọc [plan.md](plan.md) trước khi thay đổi kiến trúc hoặc triển khai tính năng. Đây là định hướng mới: WAF + reverse proxy + realtime monitoring trên một node Linux, có Docker discovery và host TCP ports discovery trong MVP.
- `execution_plan.md`, tài liệu Go/game và tiến độ cũ chỉ mang tính lịch sử. Không dùng các dấu hoàn thành, benchmark hay stack cũ làm bằng chứng cho kiến trúc mới.
- Stack: Rust + Pingora/OpenSSL; Axum + Tokio; libmodsecurity v3 + OWASP CRS; `instant-acme`; PostgreSQL + SQLx; ClickHouse; Prometheus; Docker client `bollard`.
- Frontend: React + TypeScript + Vite + Mantine; Lucide, TanStack Query, Day.js, mantine-datatable, React Router DOM, D3 (scale/shape + Canvas), react-hot-toast và React Hook Form đúng vai trò trong kế hoạch. Không thêm thư viện trùng chức năng.
- Không dùng Caddy. Multi-node, multi-tenant, Docker từ xa, app deployment/runtime, HTTP/3 và CDN cache nằm ngoài MVP.
- Không tự khôi phục code đã bị xóa hoặc sửa tài liệu lịch sử. Bước cập nhật tài liệu ban đầu đã kết thúc; người dùng đã yêu cầu bắt đầu triển khai `plan.md`. Tạo implementation mới theo giai đoạn, không khôi phục code lịch sử. Tôn trọng thay đổi có sẵn của người dùng, không reset/revert ngoài nhiệm vụ.

## 2. Ranh giới kiến trúc

- Tách proxy/config/WAF/TLS/admin/security/discovery/telemetry/storage và frontend; tránh để UI, storage hoặc collector điều khiển trực tiếp hot path.
- Không blocking I/O, query database hoặc ghi log đồng bộ trên proxy hot path. Không gọi Docker, discovery collector hoặc CrowdSec LAPI trên mỗi request.
- Hot path đọc snapshot bất biến/local state đã chuẩn bị. Validate trước atomic apply; request đang chạy giữ snapshot ban đầu. Rollback cũng phải validate/apply, có version/diff và audit.
- Quy định routing precedence rõ và từ chối cấu hình mơ hồ. Validate proxy loop cho cả manual và discovery; chỉ tin forwarded headers từ trusted proxies.
- Không đưa secrets vào source, fixtures, log, lỗi hoặc tài liệu. Mã hóa credentials bằng master key ngoài database; sao lưu master key riêng.

## 3. Discovery chỉ đọc

- Collector riêng chạy trong host network namespace, đọc TCP listeners từ hệ điều hành và Docker Engine cùng host qua socket cấu hình được cho rootful/rootless. Không quét mạng/dải port; không bắt buộc process/PID metadata.
- Chỉ collector được cấp Docker socket; gateway không mount socket đó. API Unix socket giới hạn quyền, chỉ đọc discovery/refresh cache; không start/stop/exec, Docker passthrough, publish port hoặc sửa network.
- Docker events kết hợp reconcile và host refresh mỗi 10 giây; có refresh thủ công, timestamp, stale/degraded và lý do unavailable.
- Discovery chỉ gợi ý. Mọi thay đổi upstream đi qua validate/apply như manual; mất collector không xóa upstream hoặc dừng traffic.
- Không coi exposed port là listener hoặc HTTP. Không tự chọn network/port đầu tiên; ưu tiên DNS alias/Compose service trên network chung, không dùng container IP làm định danh bền vững.
- Không lưu `0.0.0.0`/`::` làm upstream. Không chuyển host loopback thành container loopback; phản ánh khả năng truy cập thực của bridge/host-network và host gateway alias.
- Người dùng chọn HTTP/HTTPS. Test từ chính gateway với timeout/concurrency hữu hạn, kiểm tra TCP/HTTP/TLS và xác minh cert/SNI. Endpoint mất/stopped/unreachable phải unavailable, không tự thay endpoint.
- Loại bỏ endpoint OpenWAF khi nhận diện được; kiểm tra loop lại khi apply. DNS re-resolve theo resolver TTL khi mở kết nối và health check phát hiện endpoint lỗi.

## 4. WAF, FFI và bảo mật

- Policy mới mặc định `DetectionOnly`, CRS paranoia level 1. Hỗ trợ `Off`/`DetectionOnly`/`On`, exclusions theo rule/route; ACL allow không tự bỏ qua CRS.
- Trong blocking mode, kiểm tra body trước upstream. Vượt giới hạn body trả `413`; hết năng lực kiểm tra trả `503`, không âm thầm bypass WAF.
- Cô lập mọi FFI/`unsafe` trong adapter nhỏ; ghi safety contract về ownership, lifetime, allocator, thread affinity và cleanup cho từng thao tác.
- Một worker sở hữu transaction từ tạo đến hủy. Không tự thêm `Send`/`Sync` để vượt compiler; chứng minh thread safety từ API native trước mọi thay đổi mô hình ownership.
- Worker pool/queue có giới hạn, không chạy FFI blocking trên Tokio executor. Cancellation không được giải phóng native state đang sử dụng. Chưa kiểm tra response body hoặc WebSocket frames.
- CrowdSec chạy riêng; đồng bộ ban vào local snapshot. LAPI lỗi giữ ban đến expiry gốc, báo degraded; không kéo dài vô hạn hoặc tắt các lớp bảo vệ khác.
- Không bỏ TLS verification mặc định. SNI không có cert hợp lệ phải bị từ chối; kiểm chứng hot reload và ACME staging trước khi tuyên bố certificate lifecycle hoạt động.
- Đăng nhập dùng Argon2id, secure session, CSRF protection, login rate limit và audit. Redact body, cookie, authorization và query values mặc định, gồm WAF matched data.

## 5. Concurrency, lỗi và dữ liệu

- Mọi task nền có owner, shutdown/cancellation và deadline; queue, retry, cache, số rate-limit keys và bộ nhớ đều hữu hạn. Không sinh task không có đường dừng.
- Client SSE chậm, ClickHouse lỗi hoặc log queue đầy không được chặn gateway. Báo queue depth/drop/gap/stale; không nuốt lỗi hoặc tạo cảm giác dữ liệu đầy đủ khi đã mất log.
- Metrics có cardinality hữu hạn; không dùng raw URL, IP, query hay request ID làm label không giới hạn. RPS theo request bắt đầu, latency/status theo request hoàn thành.
- Trả lỗi có ngữ cảnh và phân biệt not found/conflict/validation/unavailable; không `unwrap`/panic trên dữ liệu ngoài hoặc bỏ lỗi im lặng.
- Dùng SQLx và transaction khi cần tính nguyên tử. Kiểm tra rows affected cho update/delete/write cần xác nhận; 0 hàng phải ánh xạ lỗi domain hoặc rollback theo bất biến, không báo thành công giả.
- Backup có version/checksum, gồm cấu hình/credentials/ACME state, không gộp traffic history. Restore phải validate, kiểm tra giải mã và có bằng chứng phục hồi trên instance sạch.

## 6. Frontend và hợp đồng API

- TanStack Query quản lý server state; React Hook Form quản lý form; React Router DOM điều hướng; mantine-datatable cho bảng, D3 (scale/shape + Canvas) cho biểu đồ realtime/thống kê, Lucide cho icon, Day.js cho thời gian và react-hot-toast cho thông báo.
- Màn hình có loading/error/empty, realtime connected/stale, pause và loss/gap indicators. Hỗ trợ dark/light, keyboard navigation, focus và label truy cập được.
- Giữ tối đa 1.000 live logs và 15 phút biểu đồ ở client; reconnect không được làm bộ nhớ tăng vô hạn. Lấy history qua API từ ClickHouse/Prometheus.
- Đồng bộ tài liệu, schema/API và UI khi thay đổi kiến trúc hoặc payload; ghi rõ timestamp, source metadata, lỗi unavailable và kết quả từng bước test kết nối.

## 7. Kiểm chứng trước khi hoàn tất

Chọn kiểm tra theo phạm vi thay đổi. Khi workspace Rust/frontend đã được tạo, dùng các lệnh tương ứng với workspace và package manager đã chọn:

- Rust: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Frontend: chạy các script lint, typecheck và build đã khai báo trong `package.json`; không tự giả định tên script hoặc đổi package manager.
- Integration/E2E phù hợp: routing/loop/trusted headers, atomic reload/rollback; CRS body blocking và FFI ownership; CrowdSec ban/expiry/outage; TLS/ACME staging/restart/hot reload; discovery bridge/host-network/rootless/IPv6/loopback/outage; gateway connection test và DNS changes; realtime overflow/reconnect/ClickHouse outage; backup/restore.
- Chứng minh request bị WAF chặn không tới upstream. Kiểm tra slow client không chặn proxy và frontend memory hữu hạn. Benchmark riêng proxy thuần, detection và blocking với workload/tài nguyên công bố.
- Với thay đổi chỉ tài liệu: rà nội dung theo yêu cầu, link nội bộ, Markdown và `git diff --check`; không cần khôi phục code hoặc chạy build ứng dụng đã bị xóa.

Báo rõ file đã đổi, kiểm tra đã chạy, kết quả và giới hạn chưa kiểm chứng. Không đánh dấu hoàn thành khi chưa có bằng chứng, không trình bày mục tiêu realtime ≤2 giây hoặc hiệu năng dự kiến như kết quả đo. Nếu lệnh không chạy được do môi trường/dependency, ghi nhận cụ thể thay vì bỏ qua hoặc báo đạt.
