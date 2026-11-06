# Kiểm chứng dọn deployment VPS — 2026-11-02

Deployment hiện hành là [Ansible](../../deploy/ansible/README.md).
`deploy/vps` đã được gỡ sau khi chuyển sáu Python integration harnesses sang
[tests/integration](../../deploy/ansible/tests/integration/README.md). Các test
Compose render trực tiếp templates/profiles hiện hành; không giữ manifest cũ
riêng cho tests. Runtime bootstrap vẫn đóng gói trong image.

Các báo cáo trước đây được giữ nguyên. Xem
[mapping đường dẫn](../../deploy/ansible/docs/legacy-paths.md) khi đọc lệnh cũ.
Một file environment local ngoài Git được giữ trong thư mục local bị ignore,
directory `0700`, file `0600`; không đọc hoặc đưa nội dung vào bằng chứng.

## Môi trường

- HEAD `550d4c700cf0ccbccbe7adba273bc3a5d877e9c5`, working tree có thay đổi.
- macOS arm64, Python 3.12.16, ansible-core 2.19.4,
  community.docker 4.8.1, Docker Engine 29.8.2, Compose 5.5.1.
- Image `openwaf-vps-tiers:local-check`, ID
  `sha256:e0c1b723437dbff9141abbee681900f96da88757935e6bd8f6b0961d5d04f110`,
  linux/amd64 qua emulation. Native HTTP tests dùng Rust 1.97.1 macOS;
  Postman CLI 1.82.0, Pebble 2.8.0.
- Dependency smoke dùng storage fixture riêng trên filesystem Linux của Engine
  làm bind sources để kiểm tra POSIX ownership. Đây không phải migration hoặc
  cấu hình named volumes cho production. Fixtures được dọn sau test.

## Kết quả

Chạy từ root repository với controller venv và collections đã cài. Các đường
dẫn lệnh bên dưới dùng `python`/`ansible-playbook` của venv đó.

| Lệnh / harness | Kết quả |
| --- | --- |
| `python -m unittest discover -s deploy/ansible/tests -v` | 11 tests đạt: render, guards, storage identity/permissions, named-volume rejection, fingerprint/retry |
| `python -m unittest discover -s backend/runtime/tests -v` | 39 tests đạt |
| `python deploy/ansible/scripts/generate-profiles.py --check` | Đạt, generated profiles khớp |
| `ansible-playbook playbook.yml --syntax-check` trong `deploy/ansible` | Đạt |
| `resource-profiles.py --image openwaf-vps-tiers:local-check` | Năm profiles đạt caps/headroom/fingerprint/native validator; từ chối profile không hợp lệ |
| `OPENWAF_TEST_IMAGE=openwaf-vps-tiers:local-check ... dependencies-smoke.py` | Native init, health, collector inventory/restart, loopback listeners, ClickHouse data và CrowdSec decisions/credentials qua restart đạt; caps 2c4g không OOM; thiếu bouncer key bị từ chối |
| `python deploy/ansible/tests/integration/provider-bootstrap.py` | PostgreSQL import atomic/idempotent/preserve-provider-changes đạt |
| `python deploy/ansible/tests/integration/dns-simulation.py --acme` | Hai native HTTP integration tests và Pebble lifecycle đạt, 279 Postman requests: apex/wildcard, TXT cleanup, restart, saved-account renewal và cancellation |
| Python compile, `startup-smoke.py --help` | Đạt; embedded Python probe của dependency smoke cũng được compile |
| Current Markdown links/anchors và whitespace | 207 local links/anchors đạt; tracked diff và 35 untracked files không có lỗi whitespace. Báo cáo lịch sử được giữ nguyên, không tính vào current-link audit |

Các tên harness rút gọn nằm trong
`deploy/ansible/tests/integration/`. Test DNS chạy với mock HTTPS và private CA;
[simulation context](../../postman/simulations/admin-dns.context.yaml) giữ
fingerprint và phạm vi bằng chứng. Không thao tác provider công cộng.

## Giới hạn

Full `startup-smoke.py` chưa chạy lại trên layout mới: harness đọc trực tiếp
private files từ host và cần filesystem Linux bảo toàn UID/chmod; Docker Desktop
shared filesystem trên máy này không đáp ứng bằng chứng ownership đó. Kiểm tra
PostgreSQL provider riêng không chứng minh full startup PostgreSQL/gateway.

Chưa kiểm chứng apt/SSH/sudo trên VPS thật, cài lại Docker thật, public
Cloudflare/Let's Encrypt, clean backup/restore, capacity hoặc realtime latency.
Không thay implementation Rust/frontend trong cleanup này nên không chạy lại
build/test toàn ứng dụng.
