# Ansible host autodetection — 2026-11-02

Revision: HEAD `550d4c700cf0ccbccbe7adba273bc3a5d877e9c5` + working tree.
Đây là kiểm chứng local cho [Ansible deployment](../../deploy/ansible/README.md),
không phải nghiệm thu cài đặt trên VPS thật.

## Thay đổi

- [Host settings](../../deploy/ansible/filter_plugins/host_settings.py) chọn
  profile lớn nhất vừa cả vCPU và MemTotal. Metadata
  [capacity](../../deploy/ansible/files/profile-capacity.json) được sinh từ
  sizing source hiện có, không thay container budgets/fingerprints.
- Cho phép usable RAM thấp hơn nominal tối đa 5% do kernel/firmware; không tính
  swap hoặc RAM trống. Thiếu CPU/RAM facts, không đủ mức nhỏ nhất hoặc override
  vượt tài nguyên đều bị từ chối. Override nhỏ hơn vẫn được giữ.
- Origin mặc định lấy địa chỉ global của interface có default route. Không dùng
  IP private/loopback/link-local, IP SSH, interface bất kỳ hoặc dịch vụ IP bên
  ngoài. NAT cần override; chuỗi rỗng tắt family tương ứng. Facts không chứng minh
  firewall/NAT/public reachability.
- Có URL file thì tự dùng PostgreSQL ngoài; không có thì dùng managed DB.
  Boolean override vẫn được validate nhất quán với URL file. Secrets không đọc
  trong detection, không đưa URL/token vào báo cáo settings.
- [Docker probes](../../deploy/ansible/tasks/docker-detect.yml) chạy chỉ đọc cả
  trong `--check`, dùng socket đã cấu hình và đọc GID của socket đích khi có symlink.
  [Installation plan](../../deploy/ansible/tasks/docker-plan.yml) dùng luôn
  Engine/Compose hợp lệ, kể cả Linux ngoài danh sách tự cài. Chỉ cài Engine khi
  thiếu cả CLI/socket, chỉ bổ sung Compose cho official `docker-ce` thiếu plugin.
  CLI hỏng, daemon unavailable, rootless, Compose cũ hoặc package Compose đã cài
  nhưng probe lỗi đều dừng, không cài đè/nâng cấp. Curl/CA thiếu được bổ sung trên
  các OS hỗ trợ. `openwaf_install_docker: false` chỉ là policy cấm cài package Docker.
- Inventory mẫu bỏ các giá trị đã tự phát hiện. Domain, image release, token,
  ACME/public-admin opt-ins và external network vẫn là lựa chọn tường minh.

## Kiểm tra

Controller: macOS arm64, Python 3.12.16, ansible-core 2.19.4,
community.docker 4.8.1, Docker Engine 29.8.2, Compose 5.5.1.
Commands dùng venv controller đã cài requirements/collections.

| Kiểm tra | Kết quả |
| --- | --- |
| `python -m unittest discover -s deploy/ansible/tests -v` | 23 tests đạt: 15 automation và 8 host-settings tests |
| `ansible-playbook -i inventory.example.yml playbook.yml --syntax-check` từ `deploy/ansible` | Đạt |
| `python deploy/ansible/scripts/generate-profiles.py --check` | Profiles và capacity metadata khớp sizing source |
| `python deploy/ansible/tests/integration/resource-profiles.py --image openwaf-vps-tiers:local-check` | Cả năm Compose renders/native validators đạt; profile lạ bị từ chối |
| Python compile, current Markdown links/anchors, whitespace | Đạt: 211 local links/anchors; `git diff --check` và whitespace của 42 untracked files không có lỗi. Báo cáo lịch sử không nằm trong current-link audit |

Unit/automation fixtures bao gồm: 6 vCPU/16 GiB → `4c8g`, 16 vCPU/8 GiB →
`4c8g`, 8 vCPU/32 GiB → `8c32g`, vượt tier cao nhất vẫn chọn tier cao nhất,
usable RAM tại/dưới ngưỡng, thiếu facts, override nhỏ/vượt mức, IPv4/IPv6-only,
NAT/link-local, disable IPv6 và tự chọn DB theo URL file.

Docker regression chạy tasks thật với fake CLI, socket Unix riêng và facts
Fedora giả lập trong cả check/normal mode: Engine hợp lệ không chạy apt/repository/
service tasks, socket symlink được nhận đúng. CLI trả exit 2 được coi là lỗi,
không bị nhầm thành chưa cài. Các plan tests giả lập Engine thiếu, plugin thiếu,
package khác, plugin đã cài nhưng lỗi, policy cấm cài, daemon down, socket mất,
rootless và Compose dưới 2.22. Các tests này không dùng Engine hoặc package
manager thật để chứng minh host provisioning.

Resource-validator smoke dùng image
`openwaf-vps-tiers:local-check`, ID
`sha256:e0c1b723437dbff9141abbee681900f96da88757935e6bd8f6b0961d5d04f110`,
linux/amd64 qua emulation trên host arm64. Đây là validator offline;
không start full stack hoặc gọi Cloudflare/ACME.

## Giới hạn

Chưa chạy SSH/apt/Docker installation thật trên Ubuntu/Debian hoặc kiểm chứng
facts trên VPS của nhà cung cấp. Chưa nghiệm thu Compose 2.22 tối thiểu,
public DNS/ACME, full startup, restore hoặc capacity/realtime latency. Không thay
implementation Rust/frontend/native init, không chạy lại toàn bộ application
tests. Bằng chứng integration trước thay đổi được giữ trong
[báo cáo cleanup](deploy-cleanup.md), không tự xem là rerun của lần này.
