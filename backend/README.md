# OpenWAF backend

Workspace Rust cho gateway Pingora/OpenSSL, WAF libmodsecurity v3 + OWASP CRS,
Admin API Axum và các worker nền. Phạm vi và các gate còn mở nằm trong
[kế hoạch](../plan.md); triển khai Linux/Compose theo [runbook](../docs/deployment-runbook.md).

Production image chứa cả frontend React đã build. Axum phục vụ UI/API tại
loopback 9090; Pingora xử lý HTTPS. `backend/Dockerfile` dùng build context là root
repository; [build Compose](../build/README.md) tạo một gateway image cho cả VPS
và homelab. Source init cùng defaults đóng gói trong image nằm ở
[runtime/startup-init.py](runtime/startup-init.py) và
[runtime/resource-budgets.json](runtime/resource-budgets.json); unit tests ở
`runtime/tests/`. Deploy VPS dùng [Ansible](../deploy/ansible/README.md), render
Compose và quản lý bind-mounted state trên host. Integration harnesses nằm ở
[deploy/ansible/tests/integration](../deploy/ansible/tests/integration/README.md).
Chạy API ngoài Docker có thể đặt `OPENWAF_ADMIN_UI_ROOT` tới thư mục
`frontend/dist`; bỏ biến này để chạy API-only.

## Build và chạy

Native build cần Rust theo `Cargo.toml`, C/C++ compiler, CMake, pkg-config,
OpenSSL development files, libmodsecurity >= 3.0.9 và OWASP CRS. File
[runtime/modsecurity.conf](runtime/modsecurity.conf) dùng đường dẫn CRS của Debian;
distro khác cần điều chỉnh đường dẫn. [Dockerfile](Dockerfile) cung cấp build Linux
và runtime non-root với các dependency native.

Từ repository root:

```sh
make -C backend help
make -C backend build
make -C backend release
make -C backend check
```

`check` chạy fmt-check, Clippy và các unit test còn trong mã nguồn. Các bộ test
riêng, integration runner và báo cáo kiểm thử lịch sử đã được dọn khỏi repository.
Fixtures trong `crates/waf/tests/fixtures` và `crates/security/tests/fixtures` vẫn
được unit test trong mã nguồn sử dụng.

```sh
cp backend/.env.example backend/.env
chmod 600 backend/.env
make -C backend dev
```

Gateway, Admin và collector đọc `.env` trong working directory trước khi tạo
threads; biến môi trường đã export được ưu tiên. Không tìm file ở thư mục cha
hoặc thực thi nội dung dưới dạng shell. Qua Makefile, `ENV_FILE=/absolute/path`
chọn file riêng và `ENV_FILE=/dev/null` tắt nạp file. Khi chạy binary trực tiếp,
dùng `OPENWAF_ENV_FILE` tương ứng. Không commit secrets hoặc `.env`.

Mặc định gateway chạy standalone với upstream `127.0.0.1:8081`, WAF DetectionOnly.
Cần tự chạy upstream và có rules file hợp lệ. Managed mode cần
`OPENWAF_DATABASE_URL`, `OPENWAF_ADMIN_MASTER_KEY_FILE` và origin HTTPS chính xác
trong `OPENWAF_ADMIN_ORIGIN`; xem [mẫu môi trường](.env.example). Master key là
32 raw random bytes trong private file ngoài repository, giữ nguyên khi dùng lại
database. `OPENWAF_REQUIRE_MANAGED=true` từ chối startup thiếu database URL.

`make -C backend admin` chạy Admin standalone; `make -C backend collector` chạy
collector riêng. Makefile không tạo database hoặc secrets.

## Thành phần và ranh giới

- `crates/gateway`: proxy, snapshot routing, health/DNS workers, admission,
  retry/replay, TLS reload và phục vụ static applications.
- `crates/config`: schema/validation, routing precedence, trusted headers,
  immutable snapshots, diff và atomic apply.
- `crates/waf`: adapter native và worker pool hữu hạn; mỗi worker sở hữu native
  transaction từ tạo đến hủy, cancellation không giải phóng state đang chạy.
- `crates/tls`, `crates/acme`: certificate validation/snapshots và ACME workers.
- `crates/admin`: SQLx/PostgreSQL, đăng nhập/session/CSRF, encrypted credentials,
  audit và luồng draft/validate/apply/rollback.
- `crates/discovery`: collector Linux listeners/Docker chỉ đọc qua Unix socket;
  gateway không được mount Docker socket.
- `crates/security`: ACL/GeoIP/rate limits và CrowdSec local snapshot/checkpoint.
- `crates/telemetry`, `crates/storage`: metrics, bounded event queues và history.
- `crates/applications`, `crates/cloudflare`, `crates/env`: static releases,
  provider client và nạp môi trường.

Hot path chỉ đọc snapshot/local state đã chuẩn bị; không query database, gọi
Docker/LAPI hoặc ghi log đồng bộ. Queue/cache/task nền có giới hạn và shutdown.

Worker ACME DNS-01 cho phép override resolver bằng environment
`OPENWAF_ACME_DNS_RESOLVER` (`IP:port`, IPv6: `[address]:port`). Giá trị không rỗng
ưu tiên hơn `cloudflare.resolver`; để trống/bỏ biến dùng config hoặc system DNS.
Áp dụng cho cả issuance child và renewal, không ghi lại immutable config/state.
Propagation logs chỉ chứa hostname/resolver/trạng thái, không chứa TXT challenge.
Xem [chẩn đoán trên VPS](../deploy/ansible/docs/runtime.md#restart-lỗi-và-dữ-liệu-bền-vững).
Các bản vá Pingora cục bộ có ghi chú tại
[pingora-core](vendor/pingora-core/OPENWAF.md) và
[pingora-proxy](vendor/pingora-proxy/OPENWAF.md).

## Hợp đồng vận hành

- [Retry, replay, profiles, resource budgets và giao thức](../docs/operations.md).
- [Route middleware](../docs/route-middleware.md), [route tools/password gate](../docs/route-tools.md),
  [maintenance](../docs/route-maintenance.md) và [error pages](../docs/error-pages.md).
- [Global security rules](../docs/global-rules.md), [HTTP flood protection](../docs/ddos-protection.md)
  và [browser challenge](../docs/browser-challenge.md).
- [Request details/redaction](../docs/request-details.md) và
  [statistics/history](../docs/request-statistics.md).
- [Applications](../docs/applications.md), [certificates](../docs/certificates.md)
  và [Cloudflare providers/DNS](../docs/cloudflare-providers.md).

Mở UI HTTPS để tạo admin đầu tiên qua `GET/POST /api/v1/auth/setup`, sau đó đăng
nhập. Không có tài khoản mặc định hoặc lệnh CLI tạo password. Cấu hình và secrets
cần được chuẩn bị trước khi public dashboard. ACME staging/public provider,
workload production và các gate chưa nghiệm thu vẫn phải được kiểm chứng tại nơi
triển khai; việc dọn repository không xác nhận các gate đó đã đạt.
