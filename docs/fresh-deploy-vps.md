# Cài mới OpenWAF trên một VPS

**[Ansible](../deploy/ansible/README.md)** là entry point deploy VPS được duy trì.
Controller kết nối SSH để cài Docker, render Compose, chuẩn bị bind mounts và
chạy startup. Domain/token khai báo trong inventory, IP/profile tự phát hiện;
VPS chỉ pull/run image
đã phát hành, không build Rust/frontend.

## Chuẩn bị

- VPS Linux mới với Python 3 và root/sudo qua SSH. Tự cài Docker trên Ubuntu
  22.04/24.04 và Debian 12/13; Linux khác cần Docker rootful/Compose >=2.22,
  curl và CA bundle có sẵn. Docker/Compose hoạt động được dùng luôn.
- Controller Linux/macOS (Windows qua WSL), Python 3.11+ và checkout cùng release
  với image amd64/arm64. Profile tự chọn theo CPU/RAM thực, không coi caps là
  capacity đã benchmark.
- Domain dùng zone Cloudflare active, IP origin public thực, token đúng zone có
  Zone Read và DNS Read/Edit. Cloudflare Full (strict), edge cert active và cache
  bypass admin. Bootstrap chuẩn hóa DNS apex/wildcard/admin theo
  [runtime contract](../deploy/ansible/docs/runtime.md#startup-tự-làm-gì).
- Chuẩn bị Cloudflare Access cho hostname admin và firewall origin trước khi
  startup: setup chưa có one-time token, người truy cập đầu có thể tạo admin.
  Chỉ nhận 443 từ nguồn đã chọn; SSH giới hạn IP quản trị, không publish DB/9090.
  Cho phép outbound HTTPS/DNS, DNS-01 không cần inbound 80.

## Cấu hình và chạy từ controller

```sh
python3.12 -m venv deploy/ansible/.venv
deploy/ansible/.venv/bin/pip install -r deploy/ansible/requirements.txt
deploy/ansible/.venv/bin/ansible-galaxy collection install -r deploy/ansible/requirements.yml
cp deploy/ansible/inventory.example.yml deploy/ansible/inventory.yml
```

Sửa [inventory](../deploy/ansible/inventory.example.yml): SSH host/user/key/port,
`openwaf_image` bằng tag/digest cụ thể, hostname và file token private trên
controller. Chỉ override IP origin khi sau NAT/interface khác hoặc profile khi
muốn dành tài nguyên cho app khác. File token nằm ngoài checkout, mode 0600/0400; không
đưa nội dung vào inventory, `.env`, command line hoặc shell history. Chấp nhận
điều khoản ACME và bật public-admin opt-in theo README sau khi bảo vệ setup.
Nếu registry private, chuẩn bị quyền pull bằng Docker login root trên VPS.

```sh
cd deploy/ansible
.venv/bin/ansible-playbook playbook.yml --syntax-check
.venv/bin/ansible-playbook playbook.yml --check --limit edge
.venv/bin/ansible-playbook playbook.yml --limit edge
```

`--check` hiển thị profile/IP/DB mode, kiểm tra Docker/Compose và dependencies
thiếu cùng inputs/private files; không mô phỏng toàn bộ install/deploy.
Chạy thật mặc định đặt Compose/env ở `/opt/openwaf`, input secrets
ở `/etc/openwaf-secrets`, state ở `/srv/openwaf/data`. Ansible giữ permissions của
state đã có, native init kiểm tra keys/identity; không tự sinh key thay thế khi
state đã khởi tạo bị thiếu. Readiness gồm Compose health và verified origin
TLS/SNI, không thay kiểm chứng Cloudflare/Access từ bên ngoài.

## Trước khi nhận traffic

Mở hostname admin qua Cloudflare Access, tạo admin lần đầu; không có tài khoản/
mật khẩu mặc định. Cấu hình trusted Cloudflare CIDRs qua validate/apply, thêm
upstream/route, chọn HTTP/HTTPS và probe từ gateway trước khi apply. WAF mới mặc
định DetectionOnly/PL1, bật blocking sau khi đánh giá false positives.

PostgreSQL managed hoặc existing, external Docker network, discovery và GeoIP
được chọn bằng inventory theo [runtime contract](../deploy/ansible/docs/runtime.md).
Collector duy nhất có Engine socket; ClickHouse/CrowdSec loopback dùng namespace
của gateway. ACME bootstrap và Certificates/provider giữ keys/state qua recreate.
Prometheus chưa dựng, CrowdSec chỉ local manual decisions trong profile này.

Giữ inventory, project và cả ba thư mục host khi cài lại Docker. Backup database
nhất quán và master keys riêng; bind mounts không bảo vệ khi mất ổ đĩa. Instance
cũ có named volumes bị chặn để tránh chuyển sang state trắng; xem
[storage/migration](../deploy/ansible/README.md#instance-cũ-dùng-named-volumes).
Không xóa data, keys, marker hoặc dùng `down -v` để restart.

Xem [runbook](deployment-runbook.md). Public Cloudflare/Let's Encrypt, clean
restore và VPS provisioning thực cần nghiệm thu riêng; không suy diễn từ tests
local. Không trộn project/data VPS với [homelab](../deploy/homelab/README.md).
