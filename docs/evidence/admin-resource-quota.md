# Admin resource 429 — kiểm chứng 2026-11-02

Phạm vi: quota route admin đóng gói quá thấp cho SSE và tải resource/API song
song. Source [bootstrap.rs](../../backend/crates/admin/src/bootstrap.rs),
[config.rs](../../backend/crates/admin/src/config.rs), regression
[admin_admission.py](../../backend/tests/admin_admission.py). Checkout `6cae4c1`
+ working tree, chưa publish image hoặc deploy.

## Hành vi

- Quota mặc định chung vẫn `{requests:32, streams:8, uploads:4, per_client:8}`.
  Public admin trước đây cũng dùng quota này, đồng thời route được reserved nên
  operator không thể sửa qua editor. SSE giữ request lease đến hết stream.
- Admin mới dùng `{64,8,4,32}`: JS/CSS/API có thêm slot khi nhiều tab/SSE mở.
  Node/class/connection budgets, WAF, access policies, auth/CSRF và login rate
  limit vẫn áp dụng. Không bảo đảm truy cập admin khi node hoặc global rate
  policy đã hết capacity.
- Startup nhận diện chính xác route admin đóng gói cũ, validate/prepare và ghi
  transaction/version/diff/audit cho active + draft. Giữ draft edits khác,
  immutable old versions và account/key; custom route/quota không tự ghi đè.
  Lặp startup không nâng version thêm. Audit `config.admin_admission_upgrade`,
  hoặc `config.admin_axum_upgrade` khi cùng nâng legacy upstream trong một lần.
- Cần release chứa Rust binary mới; thay VPS worker profile không tự thay route
  quota trong database. Không cần vào UI hoặc sửa SQL production để migration.

## Kiểm chứng local

macOS arm64, Rust 1.97.1, Python 3.9, native ModSecurity và PostgreSQL
`17-bookworm` trong Docker fixture có credentials ngẫu nhiên. Gateway thật chạy
HTTP trên loopback, static HTML/JS/CSS fixture và `2c4g` node budgets. Script dọn
container riêng; không dùng credentials/DB production hoặc gọi provider.

Chạy trong `backend/`:

| Lệnh | Kết quả |
| --- | --- |
| `cargo fmt --all -- --check` | Đạt |
| `cargo clippy --workspace --all-targets -- -D warnings` | Đạt |
| `cargo build -p openwaf-gateway` | Đạt |
| `cargo test -p openwaf-admin bootstrap::tests -- --nocapture` | 3 đạt, 2 ignored; test DB mục tiêu chạy riêng bên dưới |
| `python3 tests/admin_admission.py` | Đạt: real PostgreSQL upgrade edge+quota và quota-only; draft/version/audit/idempotence; 12 SSE cùng client đang mở + 24 HTML/JS/CSS/session fetches, concurrency 12, tất cả 200; unauthenticated session 401, mutation thiếu Origin 403 |
| `cargo test --workspace` | Dừng ở DNS fixture bind `127.0.0.2` trên macOS, `AddrNotAvailable` (OS code 49); không báo workspace đạt |
| `cargo test --workspace -- --test-threads=1 --skip probe::tests::dns_cache_expires_and_connection_uses_new_address --skip checkpoint::tests::atomic_roundtrip_integrity_permissions_and_bounds` | 188 đạt, 6 ignored, 2 filtered; checkpoint phụ thuộc `/proc/sys/kernel/random/boot_id`, chưa kiểm chứng Linux trong lần này |

Python syntax, local Markdown link targets và `git diff --check` đạt. Không sửa
frontend trong lần này, không chạy lại frontend build/browser suite.

## Incident production và giới hạn

Người dùng báo F12 thấy resource của `openwaf.swissy.shop` trả 429, UI không
khởi động. Read-only curl từ máy phát triển nhận 200 cho `/`, JS chính và
`/api/v1/auth/setup` (`setup_required=false`). Python urllib mặc định nhận 403
Cloudflare 1010, khác 429 người dùng báo. Không có SSH/production logs hoặc
request ID của request lỗi nên **chưa xác nhận lớp chặn của incident live**.
Bản sửa xử lý điểm nghẽn quota admin đã xác định trong source và kiểm chứng local;
không tuyên bố VPS đã khôi phục. Chưa kiểm tra qua Cloudflare/TLS production,
browser thật với session production, OOM/throughput hoặc mọi global rate policy.

Khôi phục tạm: đóng các tab OpenWAF, chờ khoảng 30 giây và hard refresh một tab
để tải lại resource lỗi. Nếu vẫn 429 cần request ID/lớp chặn; global rate policy
hoặc Cloudflare có thể cần xử lý riêng.
