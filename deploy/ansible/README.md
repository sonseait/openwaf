# Deploy VPS bằng Ansible

Đây là luồng deploy VPS được duy trì, qua SSH cho VPS của bất kỳ nhà cung cấp
nào. Ansible phát hiện Docker/Compose, tự cài phần thiếu, render [Compose](templates/compose.yaml.j2) và environment,
chuẩn bị bind-mounted storage mặc định (hoặc named-volume recovery khi chọn rõ), pull image rồi chờ bootstrap/readiness
và kiểm tra HTTPS origin với CA/SNI hợp lệ. Không build trên VPS.

Sau khi apply, playbook kiểm tra gateway, ClickHouse và CrowdSec có cùng Linux
network namespace. Nếu sidecar còn gắn namespace của gateway cũ, playbook recreate
ClickHouse/CrowdSec (không restart gateway, không xóa volume), rồi kiểm tra lại và
gọi ClickHouse `/ping` từ namespace gateway. Kiểm tra thất bại sẽ dừng deploy trước
khi ghi `.ansible-applied`; container healthy riêng lẻ không đủ để đạt readiness.
VPS cần `nsenter` (util-linux), Python 3 và `curl`. Kiểm tra này không chứng minh
rollup writer đã ghi thành công hoặc phục hồi dữ liệu đã dropped.

Toàn bộ templates, integration files, profiles và deployment tasks nằm trong thư
mục này. Python/native bootstrap đặc thù vẫn được đóng
gói trong image từ `backend/runtime/`. Xem [hợp đồng runtime](docs/runtime.md)
về DB/network, DNS/ACME, discovery và resource profiles.

## Phạm vi và điều kiện

- Controller: Linux/macOS, Python **3.11+** (khuyến nghị 3.12), SSH và checkout
  release phù hợp image. Windows dùng WSL. VPS: Python 3, SSH và root/sudo.
- Docker rootful/Compose có sẵn được kiểm tra và dùng luôn, không cấu hình lại
  apt repository hoặc service. Tự cài phần thiếu trên **Ubuntu 22.04/24.04,
  Debian 12/13**, amd64/arm64. Linux khác cần Docker Engine/Compose **>=2.22**,
  `curl` và CA bundle có sẵn; không cần bật/tắt biến cài đặt. Không hỗ trợ Docker
  từ xa/rootless trong automation này. Profile tự chọn theo CPU/RAM thực trong
  [runtime](docs/runtime.md#resource-profiles-vps).
- Image đã publish đúng kiến trúc, cùng release với runtime files/profile trong
  checkout. Cần tag cụ thể hoặc digest; playbook từ chối `latest`. VPS không cần
  Git/Rust/Node.js. Private registry: đăng nhập bằng `sudo docker login` trên VPS
  trước khi chạy (bao gồm registry của PostgreSQL nếu cần). Credential được
  Docker quản lý riêng, không ghi trong inventory hay task arguments.
- Domain/zone active tại Cloudflare; token **Zone Read + DNS Read/Edit** đúng
  zone. Host admin là apex hoặc con trực tiếp của zone. Origin tự lấy từ public
  IP của interface mặc định; VPS sau NAT cần khai báo public IP origin thực,
  không phải IP Cloudflare. Bootstrap chuẩn hóa DNS apex/wildcard/admin theo
  [hợp đồng runtime](docs/runtime.md#startup-tự-làm-gì), kể cả record đang tồn tại tại các tên đó.
- Cloudflare **Full (strict)**, edge certificate active, bypass cache admin.
  Mở inbound TCP 443 từ nguồn đã chọn, SSH từ IP quản trị; outbound HTTPS/DNS.
  DNS-01 không cần cổng 80. Port 443 còn trống nếu chưa có gateway của project.
- **Bảo vệ hostname admin bằng Cloudflare Access trước khi chạy** và chặn truy
  cập thẳng origin bằng firewall của VPS/provider. Luồng setup hiện chưa có
  token một lần; người truy cập đầu tiên có thể tạo admin. Playbook yêu cầu
  `openwaf_public_admin_enabled: true` để thể hiện lựa chọn public HTTPS, nhưng
  không cấu hình/kiểm chứng Cloudflare Access hoặc firewall thay bạn. Docker
  published ports có thể vượt rule UFW thông thường; kiểm tra cả IPv4/IPv6.
  Đây là giới hạn của bootstrap hiện tại, không phải bảo đảm exposure đã an toàn.

## Cấu hình một lần trên controller

Từ root repository:

```sh
python3.12 -m venv deploy/ansible/.venv
deploy/ansible/.venv/bin/pip install -r deploy/ansible/requirements.txt
deploy/ansible/.venv/bin/ansible-galaxy collection install -r deploy/ansible/requirements.yml
cp deploy/ansible/inventory.example.yml deploy/ansible/inventory.yml
```

Sửa `inventory.yml`: `ansible_host`, SSH user (key/port nếu khác mặc định),
`openwaf_image`, `openwaf_init_image`, hostname và đường dẫn file private trên **controller**. Hai image references phải khai báo riêng cho cùng release; không có fallback init.
Docker, profile và origin mặc định được phát hiện tự động. Sau khi đọc
[điều khoản Let's Encrypt](https://letsencrypt.org/repository/) và chuẩn bị giới
hạn truy cập admin, đặt `openwaf_acme_accept_terms` và
`openwaf_public_admin_enabled` thành boolean `true`. Không đặt token/password/URL
database trực tiếp trong inventory hoặc `-e`. Tạo file token bằng editor/secret
manager ngoài checkout, không đưa nội dung vào shell history:

```sh
chmod 600 /absolute/private/path/cloudflare-token
ssh ubuntu@203.0.113.10
# Kiểm tra SSH host key qua kênh tin cậy khi kết nối lần đầu, rồi thoát.
```

Private inputs phải là file thường, không rỗng, quyền `0400`/`0600`, tối đa 1 MiB.
Playbook copy qua SSH về `/etc/openwaf-secrets/` (directory `0700`, file `0600`,
root sở hữu) với `no_log` và không xuất diff. Inventory local và các thư mục
`host_vars`/`group_vars` đã được gitignore. Source secret vẫn phải ở ngoài repo.
Master keys/database credentials do startup init sinh trong host data directories, không nằm
trong inventory và không được phát ra terminal. Sao lưu master keys riêng.

## Chạy

```sh
cd deploy/ansible
.venv/bin/ansible-playbook playbook.yml --syntax-check
.venv/bin/ansible-playbook playbook.yml --check --limit edge
.venv/bin/ansible-playbook playbook.yml --limit edge
# Thêm --ask-become-pass nếu sudo yêu cầu mật khẩu.
```

Chạy từ thư mục này để Ansible nạp `ansible.cfg` và inventory mặc định. Hoặc chỉ
định `ANSIBLE_CONFIG`, `-i` cùng đường dẫn playbook đầy đủ. Không tắt SSH host key
checking. Thêm host dưới group `openwaf` và dùng `--limit` để chọn VPS; mỗi host
là một instance độc lập, không phải cluster. Playbook triển khai tuần tự.

`--syntax-check` chỉ kiểm tra cấu trúc. `--check` kết nối host để lấy facts,
hiển thị profile/IP/DB mode đã chọn, kiểm tra Docker/Compose và báo dependencies
cần cài cùng inputs/private files. Nó **không mô phỏng apt/copy/Compose**, không
gọi Cloudflare/ACME và không chứng minh image, registry hoặc DNS khả dụng. Lần
chạy thật mới thay đổi host.

Nếu chưa có Docker CLI/socket, playbook cài Engine và Compose. Engine đang hoạt
động nhưng thiếu Compose: chỉ tự cài plugin khi Engine thuộc package chính thức
`docker-ce`; không trộn package của distribution với Docker repository. Docker
có sẵn nhưng daemon/socket lỗi, rootless hoặc Compose quá cũ sẽ báo lỗi cụ thể,
không cài đè, tự nâng cấp hoặc khởi động lại daemon. Curl/CA bundle thiếu được
cài riêng trên các OS hỗ trợ. GID socket tự đọc từ host.

Mặc định runtime nằm ở `/opt/openwaf`, dữ liệu ở `/srv/openwaf/data`, project
cố định `openwaf-vps`. Collector
lấy GID socket từ host; gateway không được mount socket. Chỉ 443 được publish;
PostgreSQL, ClickHouse và CrowdSec giữ network isolation của Compose gốc.
Không thay daemon config, firewall, SSH config hoặc container của project khác.

Bootstrap có thể chờ gần 50 phút cho DNS/staging/production; thời gian chờ
playbook mặc định 3.600 giây, không phải một vòng retry issuance mới. Sau khi
Compose báo ready, `curl --resolve` trên VPS kiểm tra trực tiếp origin qua
loopback với hostname/SNI đúng và CA verification bật. **Không dùng `-k`**.
Kiểm tra này bỏ qua Cloudflare, không thay kiểm chứng public HTTPS/Access.

Sau khi playbook thành công, kiểm tra hostname từ bên ngoài qua Cloudflare
Access, tạo admin trên giao diện lần đầu, rồi cấu hình trusted proxies và
upstream/policy theo [runbook](../../docs/deployment-runbook.md). Không có tài
khoản/mật khẩu mặc định hoặc mật khẩu được in ra bởi automation.

## Tuỳ chọn

Các giá trị mặc định ở [defaults.yml](defaults.yml); ghi đè trong inventory:

| Biến | Mặc định / ý nghĩa |
| --- | --- |
| `openwaf_install_dir` | `/opt/openwaf`; runtime files trên VPS |
| `openwaf_image` | Required published gateway/runtime image tag or digest |
| `openwaf_init_image` | Required published one-shot init image tag or digest; no fallback |
| `openwaf_secrets_dir` | `/etc/openwaf-secrets`; input secrets tách khỏi runtime |
| `openwaf_data_dir` | `/srv/openwaf/data`; dữ liệu bền vững qua bind mounts |
| `openwaf_project_name` | `openwaf-vps`; giữ ổn định cùng data path |
| `openwaf_install_docker` | `true`: cho phép cài Docker/Compose còn thiếu; `false` cấm cài package Docker, vẫn kiểm tra/dùng Engine hiện có |
| `openwaf_vps_profile` | `auto`: mức lớn nhất vừa CPU và RAM; có thể ép profile nhỏ hơn từ `2c4g` đến `16c64g` |
| `openwaf_origin_ipv4`, `openwaf_origin_ipv6` | `auto`: địa chỉ global trên interface mặc định; override public IP cho NAT, `""` để tắt family đó |
| `openwaf_postgres_create` | `auto`: tạo DB nếu không có URL file; có URL file thì dùng DB ngoài. Boolean override vẫn được hỗ trợ |
| `openwaf_database_url_file` | File local chứa URL private; tự chọn DB ngoài khi được khai báo |
| `openwaf_database_ca_file` | File local CA PEM tùy chọn cho DB ngoài |
| `openwaf_docker_network_external` | `false`; `true` để nối bridge đã có |
| `openwaf_docker_network_name` | `openwaf-backends`; tên thật trong Docker Engine |
| `openwaf_docker_socket` | `/var/run/docker.sock`; Unix socket local rootful |
| `openwaf_acme_dns_resolver` | Rỗng; tùy chọn `IP:port` / `[IPv6]:port`, áp dụng cho cả bootstrap và worker Certificates trong gateway |
| `openwaf_geoip_file` | File local MMDB có license; rỗng = GEO unavailable |
| `openwaf_pull` | `missing`; `always` để pull lại, `never` nếu đã preload toàn bộ images |
| `openwaf_force_recreate` | `false`; ép recreate toàn stack khi đã xác định cần |
| `openwaf_wait_timeout` | `3600` giây; phạm vi 60–7200 |

DB ngoài cần database/role đúng quyền, network reachable và TLS CA/SNI hợp lệ;
không dùng gateway loopback làm host DB. Xem [yêu cầu PostgreSQL](docs/runtime.md#chọn-postgresql).
External network phải tồn tại, là user-defined bridge có outbound; playbook
không tự tạo hoặc sửa network/container ngoài stack.

Profile dựa vào vCPU và **MemTotal**, không lấy RAM trống/swap. RAM usable được
phép thấp hơn nominal tối đa 5% do kernel/firmware; máy dưới 2 vCPU hoặc 3.892 MiB
usable RAM bị từ chối. Ví dụ 6 vCPU/16 GiB chọn `4c8g`, 8 vCPU/32 GiB chọn
`8c32g`. Máy chạy chung ứng dụng khác nên chọn profile nhỏ hơn; tự phát hiện
không đo capacity hoặc đặt chỗ tài nguyên cho ứng dụng khác. Profile được tính
lại mỗi lần chạy, nên resize VPS có thể làm đổi profile và recreate stack.

Origin chỉ lấy địa chỉ global trên interface có default route, không lấy IP
private/loopback/link-local, IP SSH hoặc gọi dịch vụ dò IP bên ngoài. Không tìm
được địa chỉ public thì yêu cầu override; `--check` hiển thị kết quả để đối soát.
Phát hiện interface không chứng minh NAT/firewall/public reachability. Các lựa
chọn hostname, image release, token, ACME opt-ins và external network vẫn do
người vận hành quyết định; không tự chọn network của ứng dụng khác.

## Chạy lại, cập nhật và lỗi

Chạy **một playbook tại một thời điểm cho mỗi VPS**. Chạy lại cùng settings/file
không ép recreate services đang khớp. Khi runtime/env/profile/secret/MMDB hoặc
image pull thay đổi, recreate **toàn stack** để ClickHouse/CrowdSec dùng namespace
gateway mới. `.ansible-applied` chỉ ghi fingerprint sau khi readiness và HTTPS
đạt: deployment thất bại không được ghi nhận thành công, lần chạy sau vẫn nhận
ra cấu hình chưa apply đủ. Marker không phải backup hoặc release history.

Để nâng cấp: sao lưu state/keys theo quy trình riêng, checkout deployment release
và đổi `openwaf_image` và `openwaf_init_image` tương ứng, rồi chạy lại cùng inventory/project. Ưu tiên
digest để tránh tag bị thay nội dung; mặc định `pull: missing` giữ image đã có.
Có downtime khi recreate trên một node. Không đổi project/data directory để tạo
instance thay thế instance đang dùng. `.ansible-storage.json` lưu project/data
path và từ chối thay đổi; gateway mount metadata cũng được kiểm tra nếu có.

Không đổi hostname/origin, DB mode/URL/CA hoặc network trên instance hiện có bằng
cách sửa inventory rồi ép chạy: native init có identity guards, các thay đổi này
cần migration riêng. Rotate Cloudflare token bootstrap không đồng nghĩa provider
credential đã import trong Admin database được rotate; xem [runtime](docs/runtime.md#restart-lỗi-và-dữ-liệu-bền-vững).

Nếu thất bại, playbook dừng; giữ container/data/key, không tự rollback database,
xóa locks hoặc retry ACME. Xem trên terminal SSH riêng:

```sh
sudo docker compose --project-name openwaf-vps --env-file /opt/openwaf/.env -f /opt/openwaf/compose.yaml ps -a
sudo docker compose --project-name openwaf-vps --env-file /opt/openwaf/.env -f /opt/openwaf/compose.yaml logs --tail=80 startup-init admin-bootstrap gateway
```

Sửa nguyên nhân (registry/DNS/network/permissions/cert), đối soát worker và state
theo [runbook](../../docs/deployment-runbook.md), rồi mới chạy lại. Worker
`exhausted`/stale lock cần xử lý có chủ đích; nếu thực sự cần recreate một release
không đổi, dùng `-e '{"openwaf_force_recreate": true}'`. Giảm image về release cũ
chỉ hợp lệ khi schema/state tương thích và đã được kiểm chứng; không có auto
rollback. Không dùng `down -v`, không tự sinh lại master keys để vượt lỗi.

## Dữ liệu trên host và cài lại Docker

Ở bind mode mặc định, mọi state mount của OpenWAF dùng bind mount với
`create_host_path: false` để Docker không tự tạo thư mục khi đường dẫn sai.
Ansible tạo 19 leaf directories trước startup, chỉ tạo những thư mục chưa có và
không đổi owner/mode của leaf đã có. Native init đặt quyền theo UID 10001 hoặc
PostgreSQL UID 1001 như trước. Data root là root-only `0700`, phải nằm ngoài
Docker data-root trên filesystem Linux bảo toàn POSIX ownership/chmod; kiểm tra
bằng SSH/sudo trên VPS:

```text
/opt/openwaf/                  # Compose, .env, profiles, deployment markers
/etc/openwaf-secrets/          # Cloudflare token, DB URL/CA đầu vào
/srv/openwaf/data/
  gateway-config/             # Config, instance identity, Admin master key
  postgres-data18/            # PostgreSQL data khi dùng managed DB
  admin-bootstrap/           # DNS/ACME account, journals, renewal state
  live-tls/                  # Certificate/key/manifest đã publish
  acme-key/                  # Master key của bootstrap
  certificate-key/           # Master key của module Certificates
  certificate-requests/      # Certificate accounts/jobs/state
  security-key/              # Master key của CrowdSec credential
  crowdsec-config/           # LAPI config và persisted credentials
  crowdsec-data/             # LAPI database
  clickhouse-data/           # Traffic history
  ...                        # Xem files/storage-directories.yml
```

Gỡ/cài lại Docker phải giữ nguyên cả ba thư mục trên và đúng inventory/project,
không format ổ đĩa hoặc xóa data. Sau khi Docker hoạt động lại, chạy playbook để
recreate containers/network với đúng bind sources. Nếu initialized storage bị
thiếu thư mục, playbook dừng; nếu thiếu/sai master key, native init dừng. Không
xóa markers hoặc tạo key thay thế để vượt lỗi. Việc này không phải quy trình
restore khi mất ổ đĩa; bind mount vẫn cần backup ngoài VPS.

Backup PostgreSQL phải nhất quán (database backup hoặc snapshot sau khi dừng
writers), không copy database đang chạy. Giữ config, credentials, DNS/ACME state,
certificates và Applications releases nếu sử dụng; backup master keys riêng.
ClickHouse traffic history có retention/backup riêng. Chưa có workflow
backup/restore sạch được nghiệm thu trong automation này.

### Instance cũ dùng named volumes

Mặc định `openwaf_storage_mode: bind` vẫn tạo deployment bind-mount mới, bỏ qua
volumes cũ, không mount/copy/xóa chúng. Để phục hồi state từ named volumes cũ,
chọn rõ `existing_volumes` trong `inventory.yml`:

```yaml
openwaf_storage_mode: existing_volumes
# Optional: exact logical-leaf -> Docker volume name overrides.
# Defaults are <openwaf_project_name>_<logical-leaf>.
openwaf_existing_volume_names:
  gateway-config: oldproject_gateway-config
  postgres-data18: oldproject_postgres-data18
openwaf_storage_recovery: true
```

Set overrides for any legacy names that differ; do not guess volume identities.
Discover names using Docker volume metadata (`docker volume ls`), then map each
logical directory from `files/storage-directories.yml`. Before any state write,
Ansible verifies that every expected volume exists by name only. It does not
inspect volume contents, create missing volumes, copy data, or stop/remove
containers. A missing/renamed optional leaf volume therefore fails closed; map
it explicitly only after confirming the correct old volume. All OpenWAF state
mounts (including secrets, database, certificates, Applications, ClickHouse and
CrowdSec) use external volumes consistently; unrelated Docker socket/GeoIP binds
remain binds. Compose marks each storage volume `external: true`.

`openwaf_storage_recovery: true` is required to transition an existing bind
storage marker to `existing_volumes`; project name and data path must remain
unchanged and no project containers may be running. It does not authorize
bind-to-bind or volume-map changes on an initialized deployment. Review the
state/backup first, then stop the old stack yourself without deleting volumes:

```sh
docker compose --project-name openwaf-vps --env-file /opt/openwaf/.env \
  -f /opt/openwaf/compose.yaml down
```

Do not add `-v`. The playbook will accept a stopped/created old gateway with a
bind mount only for this explicit bind-marker recovery; Compose may replace it
when the new stack is applied. The playbook itself never stops/removes containers
or deletes volumes. Bind directory state remains in place.

This option only reattaches configured volumes. It is not proof that all data,
keys, databases or ACME state form a consistent backup or can be restored.
Keep a verified independent backup and validate the recovered instance before
traffic cutover; public DNS/ACME, database compatibility and runtime restore
acceptance remain separate. Don't use this mode to perform an unreviewed
migration. Deployment legacy harnesses are described in
[tests/integration](tests/integration/README.md) and [mapping history](docs/legacy-paths.md).

## Kiểm tra automation

Sau khi cài dependencies, chạy từ root repository:

```sh
deploy/ansible/.venv/bin/python -m unittest discover -s deploy/ansible/tests -v
python3 deploy/ansible/scripts/generate-profiles.py --check
```

Tests cần Docker Compose CLI để validate model, không tạo container và không gọi
Cloudflare/Let's Encrypt. Chúng kiểm tra host detection với facts/probes giả lập,
input guards, render năm profile với DB managed/existing, isolation và
fingerprint chạy lại/retry. Cần nghiệm thu
riêng trên VPS thật: apt/Docker installation, registry/architecture, SSH/sudo,
public DNS/ACME/restart/renewal, Cloudflare Access/firewall và initial setup.
Local tests không phải bằng chứng full deployment hoặc capacity production.

Kết quả local trước thay đổi named-volume option, ngày 2026-11-02 trên macOS arm64:
Python 3.12.16, ansible-core 2.19.4, community.docker 4.8.1, Docker Engine
29.8.2 và Compose 5.5.1; **23 tests đạt** (15 automation, 8 host settings).
Các tests storage/Docker detection dùng metadata/probes giả lập, không chạm project
thật. Xem [bằng chứng autodetection](../../docs/evidence/deploy-autodetection.md).
Sau bổ sung này, test suite còn giữ regression bind-default, thêm render named-volume,
missing-volume-before-write, storage identity và recovery/no-running-container cases;
chạy lệnh hiện hành ở trên cho kết quả mới.

Smoke native riêng dùng `openwaf-vps-tiers:local-check` (image ID
`e0c1b723437d`, linux/amd64 qua emulation trên host arm64), template/runtime
files render bằng Ansible và bind sources trên filesystem Linux trong Docker
VM. Các thư mục fixture được chuẩn bị riêng; chỉ chạy offline `startup-init` và
`dependencies-init`, không DB/ACME network workers. Năm key/password digests,
mode 0600 và khả năng đọc bằng runtime UID 10001/1001 giữ nguyên sau khi xóa rồi
tạo lại containers/network metadata. Bỏ ACME key khiến init fail, không sinh key
thay thế. Fixture containers/network/volume đã được dọn; đây không phải thao tác
cài lại Docker thật. Smoke trực tiếp trên shared filesystem macOS không đạt UID
(vẫn thấy UID 0 sau chown); không dùng filesystem đó làm bằng chứng POSIX cho VPS.

Sau khi gỡ deployment cũ, đã chạy lại integration harnesses với templates
Ansible: năm profiles, dependency persistence/collector, provider import trên
PostgreSQL và DNS/Pebble lifecycle đều đạt. Xem [bằng chứng cleanup](../../docs/evidence/deploy-cleanup.md)
và [lệnh chạy harnesses](tests/integration/README.md).

Chưa nghiệm thu apt/SSH/sudo trên VPS Ubuntu/Debian thật, Compose 2.22 tối thiểu,
full PostgreSQL/gateway startup trên layout mới, public Cloudflare/Let's
Encrypt hoặc clean backup/restore. Không thay implementation Rust/frontend
nên không chạy lại build/test toàn ứng dụng. Local checks không đóng các gate
production hoặc chứng minh capacity/realtime latency.
