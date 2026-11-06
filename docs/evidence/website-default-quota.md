# Website admission defaults — kiểm chứng 2026-11-02

Thay đổi tiếp theo sau [admin resource quota](admin-resource-quota.md): default
áp dụng cho mọi route mới là **64 request đồng thời/route, 32/IP**, stream 8,
upload 4. Không phải RPS hoặc mức sàn validation; quota tùy chỉnh nhỏ hơn vẫn
hợp lệ. Node/class/VPS budgets và WAF/rate/login protections vẫn áp dụng.

## Implementation và migration

- [resources.rs](../../backend/crates/config/src/resources.rs): default mới;
  reader riêng cho JSON persisted để field cũ bị lược bỏ vẫn có nghĩa lịch sử
  `{32,8,4,8}`; nâng đúng bộ default cũ, giữ quota khác và partial custom quotas.
- [Route serialization](../../backend/crates/config/src/lib.rs) luôn xuất đủ
  `admission`, gồm khi bằng default; API vẫn nhận field optional. Snapshot mới
  không bị đổi nghĩa khi defaults thay đổi về sau.
- [Config load](../../backend/crates/admin/src/config.rs) migrate active + draft
  một lần qua validation/preparation, transaction, version/diff/audit
  `config.admission_defaults_upgrade` (hoặc gộp với admin upgrade).
  [Schema marker](../../backend/crates/admin/migrations/202611020002_admission_defaults.sql)
  chỉ đánh dấu sau chuẩn bị/commit thành công. Không có semantic change thì chỉ
  đánh dấu, không tạo version giả. Draft edits và immutable old versions giữ nguyên.
- Sau migration, operator có thể đặt lại 32/8 hoặc rollback website; restart
  không tự nâng lại. Historical lookup/rollback dùng persisted reader để giữ
  đúng quota cũ. Admin reserved-route validation vẫn áp dụng.
- [RouteEditor](../../frontend/src/configuration/RouteEditor.tsx) dùng cùng
  defaults và mô tả node/class limits. Các bộ đọc stored draft/history ở Admin,
  Investigation và Applications dùng cùng persisted reader.

## Kiểm chứng

Checkout `6cae4c1` + working tree; macOS arm64, Rust 1.97.1, Python 3.9,
PostgreSQL `17-bookworm` và ClickHouse `25.8` trong Docker fixtures. Không gọi
provider/production. Lệnh backend chạy trong `backend/`, npm trong `frontend/`.

| Lệnh | Kết quả |
| --- | --- |
| `cargo fmt --all -- --check` | Đạt |
| `cargo clippy --workspace --all-targets -- -D warnings` | Đạt |
| `cargo build -p openwaf-gateway` | Đạt |
| `cargo test -p openwaf-config -p openwaf-admin` | 49 đạt, 4 ignored |
| `cargo test -p openwaf-gateway admission::tests` | 3 đạt: 32 request cùng IP được nhận, request 33 bị client quota chặn; 64 toàn route được nhận, request 65 bị route quota chặn; quota tùy chỉnh 4 vẫn được thi hành |
| `python3 tests/admin_admission.py` | Đạt: PostgreSQL thật, migration implicit/explicit old defaults, giữ custom/draft/history, diff đúng route, một audit, restart idempotent, chủ động đặt lại quota cũ được giữ; website thường tạo qua validate/save/apply nhận default 64/32; 12 SSE cùng client + 24 HTML/JS/CSS/session fetches (12 parallel) đều 200 trong `2c4g` node budgets; admin vẫn truy cập được; session/Origin guards còn hiệu lực |
| `python3 tests/body_recording.py` | Đạt: real native gateway/PG/ClickHouse; route details/history/diff, atomic apply/rollback/restart, redaction/body/query capture, WAF block không tới upstream, stalled reader và ClickHouse outage |
| `cargo test --workspace` | Dừng tại DNS fixture bind `127.0.0.2` trên macOS: `AddrNotAvailable`, OS code 49; không báo workspace đạt |
| `cargo test --workspace -- --test-threads=1 --skip probe::tests::dns_cache_expires_and_connection_uses_new_address --skip checkpoint::tests::atomic_roundtrip_integrity_permissions_and_bounds` | 190 đạt, 6 ignored, 2 filtered; test checkpoint cần `/proc/sys/kernel/random/boot_id` |
| `npm run lint`, `npm run typecheck`, `npm run build`, `npm run format:check` | Đạt; Vite vẫn cảnh báo chunk chính >500 kB |

Python syntax, local Markdown targets và `git diff --check` đạt. Không sửa node
budgets hoặc container limits trong lần này. Chưa build/push release image,
deploy VPS, benchmark throughput hoặc chạy browser/TLS/Cloudflare production.
Các ignored tests khác và hai test phụ thuộc môi trường chưa được xác minh ở
Linux trong lần này. Cần dùng release mới và khởi động lại gateway để migration
có hiệu lực; sửa riêng worker profile không thay quota route trong DB.
