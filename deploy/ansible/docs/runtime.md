# Hợp đồng runtime VPS

[Ansible](../README.md) là entry point deploy. Compose được render từ
[template](../templates/compose.yaml.j2), state bind-mounted từ host. Init/defaults
vẫn ở trong cùng release image; không cần compiler/Node.js hoặc source trên VPS.
Tài liệu này mô tả runtime hiện hành, không phải bằng chứng public deployment.
Kết quả bootstrap cũ được giữ trong [báo cáo lịch sử](../../../docs/admin-startup-bootstrap.md).

## Prometheus metrics history

Ansible triển khai Prometheus cùng VPS, chia sẻ network namespace của gateway.
Prometheus chỉ nghe `127.0.0.1:9091`, không publish port; gateway dùng
`OPENWAF_PROMETHEUS_URL` để phục vụ `/api/v1/history/metrics`.
Scrape mỗi 15 giây tới exporter `127.0.0.1:9090`, có Bearer token được tạo
một lần trong `{{ openwaf_install_dir }}/metrics/token`, không ghi token vào log.
Token và dữ liệu thuộc UID/GID `10001:10001`; token chỉ đọc bởi runtime.

Dữ liệu nằm trong `{{ openwaf_install_dir }}/prometheus-data`, được giữ qua
container recreate ở cả bind và existing-volumes mode. Retention 7 ngày/1 GB
TSDB blocks; giới hạn kích thước này không phải hard disk quota (WAL/head có
thể dùng thêm dung lượng). Service bị giới hạn 256 MiB RAM, 0,5 CPU, 128 PIDs,
4 query đồng thời và query timeout 2 giây. Đây là ceilings, không phải capacity
đã benchmark. Không chuyển install directory mà bỏ lại dữ liệu này.

Sau apply, Ansible kiểm tra namespace và readiness từ gateway, có repair
sidecars khi phát hiện namespace cũ. Readiness không chứng minh scrape thành
công; cần kiểm tra target `openwaf` và history API sau triển khai thực tế.
Prometheus chỉ thu thập từ khi bắt đầu scrape, không backfill lịch sử đã thiếu.

Kiểm thử cô lập: `python3 deploy/ansible/tests/integration/prometheus-smoke.py`
(cần Docker và local image `openwaf-init:anti-abuse-local-check`). Test dùng
exporter fixture có xác thực, query range và dữ liệu sau restart; không phải
bằng chứng đã triển khai hoặc scrape gateway thật trên VPS.

## Resource profiles VPS

Mặc định `openwaf_vps_profile: auto`: Ansible chọn mức lớn nhất phù hợp cả
vCPU và MemTotal của host (usable RAM ít nhất 95% nominal, không tính swap).
Không cần khai báo profile trong inventory; có thể chọn mức nhỏ hơn nếu chia sẻ
VPS với ứng dụng khác. Profile thủ công vượt CPU hoặc RAM bị từ chối. Máy dưới
2 vCPU/3.892 MiB usable RAM không có profile được hỗ trợ.

| Profile | CPU / RAM VPS | Gateway RAM cap | PostgreSQL RAM cap | ClickHouse RAM cap |
| --- | --- | --- | --- | --- |
| `2c4g` | 2 / 4 GiB | 1.280 MiB | 512 MiB | 768 MiB |
| `4c8g` | 4 / 8 GiB | 2.560 MiB | 1.024 MiB | 1.536 MiB |
| `8c16g` | 8 / 16 GiB | 5.120 MiB | 2.048 MiB | 3.072 MiB |
| `8c32g` | 8 / 32 GiB | 10.240 MiB | 6.144 MiB | 8.192 MiB |
| `16c64g` | 16 / 64 GiB | 20.480 MiB | 12.288 MiB | 16.384 MiB |

Nguồn sizing là [vps_profiles.py](../../../backend/runtime/vps_profiles.py).
Các fragments trong [files/profiles](../files/profiles/) và
[capacity metadata](../files/profile-capacity.json) được sinh bằng:

```sh
python3 deploy/ansible/scripts/generate-profiles.py
python3 deploy/ansible/scripts/generate-profiles.py --check
```

Ship image và fragments cùng release. Native init kiểm tra fingerprint trước
khi cài budgets. CPU/RAM là ceilings, không phải reservations hoặc capacity đã
benchmark; cần thêm ngân sách cho host/app khác, disk và retention. Không tăng
workers để tự sửa 429 từ policy/quota. Đổi profile qua inventory rồi chạy lại
Ansible cho toàn stack; theo dõi OOM, RSS, FD, queue/drop và latency thực tế.
Custom budgets có thể bị native init từ chối, không tự ghi đè để vượt validator.

## Chọn PostgreSQL

Mặc định `openwaf_postgres_create: auto`: không có URL file thì tạo DB với image
`ecr.swissy.shop/c/pgaio:18.6.0`, dữ liệu ở
`openwaf_data_dir/postgres-data18`, UID 1001. Init sinh password và tạo database/
role `openwaf` không superuser. Không publish PostgreSQL/PgBouncer/PGAIO UI.

DB có sẵn: chỉ cần `openwaf_database_url_file` trỏ file private trên controller,
Ansible tự tắt managed DB. Boolean `openwaf_postgres_create` vẫn được hỗ trợ để
override tường minh và được kiểm tra nhất quán với URL file. URL phải có scheme,
host, port, database, username/password percent-encoded. `sslmode=verify-full`
là mặc định; `openwaf_database_ca_file` thêm CA PEM riêng. Không dùng
`prefer`/`require` thay TLS verification. Plaintext `sslmode=disable` chỉ khi
operator chọn rõ trên mạng riêng tin cậy.

Không dùng `localhost`/`127.0.0.1` làm host DB: đó là loopback container gateway.
Dùng DNS alias trên network chung hoặc endpoint reachable. Database trên host
có thể dùng `host.openwaf.internal` nếu listener/firewall cho bridge truy cập.
Dùng PostgreSQL trực tiếp hoặc pool **session mode**, không transaction pooling
vì config dùng session advisory lock. Gateway chạy SQLx migrations bằng role
được cấp; không tự tạo DB/role ngoài hoặc fallback sang DB mới khi outage.

Chọn mode/URL/CA trước lần đầu. Native instance identity từ chối thay đổi chúng
bằng environment. PostgreSQL 17 không dùng thẳng data directory với PGAIO 18;
database migration/restore cần kiểm chứng riêng.

## Chọn Docker network

Mặc định `openwaf_docker_network_external: false`, Ansible/Compose tạo bridge
`openwaf-backends`. Để nối network có sẵn, đặt `true` và
`openwaf_docker_network_name` bằng **tên thực trong Engine** (ví dụ `apps_default`).
Network phải là user-defined bridge, có DNS alias và outbound HTTPS/DNS; không
dùng built-in `bridge`, `host`, `none` hoặc network internal làm shared backend.
Playbook không tự tạo external network hoặc sửa container/network của stack khác.

Managed DB ở bridge `database` internal riêng, alias `openwaf-managed-postgres`.
Gateway và ACME worker tham gia backend bridge; init không network; collector
ở host network namespace. Gateway không có Docker socket. Không dùng container
IP làm định danh bền vững hoặc host loopback làm container loopback. Chọn/test
upstream từ gateway rồi validate/apply. Đổi topology cần migration/recreate có
review, không attach/detach network trực tiếp lúc gateway đang chạy.

## Startup tự làm gì?

1. Ansible tạo host directories; init offline kiểm tra resources/instance identity,
   đặt permissions, tạo keys khi instance thực sự mới, chuẩn bị DB credentials
   nếu dùng managed DB và mã hóa token bằng native adapter. Dữ liệu đã có được
   kiểm tra; thiếu/sai key không được tự sinh lại.
2. `bootstrap-provider` kiểm tra DB, reserve renewal ownership và import provider
   Production có audit. Provider cùng zone đã có không bị restart ghi đè token.
3. `admin-bootstrap` tìm zone Cloudflare, chỉ nhận hostname apex hoặc con trực
   tiếp. Nó chuẩn hóa apex A/AAAA, wildcard/admin CNAME về origin, `proxied=true`,
   kể cả records bên ngoài OpenWAF tại đúng các tên đó. Giữ MX/TXT và subdomain
   khác. DNS intent/journal xử lý write mất ACK qua read-back, không POST mù.
4. Xin cert SAN apex + wildcard bằng DNS-01, staging trước production, rồi
   validate và publish manifest. Pending TXT có ownership riêng; checkpoint
   ngăn restart/renew sửa lại origin DNS mỗi lần. Không hứa hostname nhiều cấp
   được wildcard bao phủ.
5. Gateway seed admin route/config chỉ khi DB trắng qua validate/prepare,
   transaction/version/audit. Pingora terminate 443 (container 8443), Axum UI/API
   ở loopback 9090. Tạo admin qua giao diện lần đầu, không có default password;
   bảo vệ setup bằng Access/firewall trước khi chạy vì chưa có one-time token.
6. Native ACME worker tiếp tục renewal, gateway reload manifest hợp lệ. Queue,
   retry, deadlines và ownership giữ nguyên trong runtime. Không chuyển renewal
   thành cron Ansible; cert/key/state được giữ qua recreate/reinstall Docker.

Admin route DetectionOnly/PL1 chỉ inspect headers/query; body login/config/ZIP
do Admin API xử lý với auth/CSRF/limits riêng. Không suy diễn CRS inspect body
admin. Cấu hình trusted Cloudflare CIDRs qua validate/apply và bypass cache
hostname admin sau setup; proxy DNS không tự chặn truy cập thẳng origin.

## Các service đi kèm

ClickHouse history retention mặc định 7 ngày và CrowdSec local manual decisions
chỉ bind loopback trong gateway namespace, không publish ports. Outage không
tham gia gateway readiness lúc runtime; phải theo dõi degraded/loss/backlog.
CrowdSec chưa có log acquisition/CAPI trong profile này. Prometheus chưa được
dựng; metrics history phải phản ánh chưa cấu hình.

### Discovery mặc định

Collector là service duy nhất nhận local rootful Engine socket, GID lấy từ host.
API private Unix socket `0600` chỉ phục vụ inventory/refresh; không Docker
passthrough hoặc start/stop/exec. Host listeners/Docker events chỉ gợi ý; mất
collector không xóa upstream. Automation không hỗ trợ rootless/remote Engine.

### GeoIP Country database

Đặt `openwaf_geoip_file` bằng file Country MMDB có license trên controller;
Ansible copy vào `/opt/openwaf/geoip/GeoLite2-Country.mmdb` (theo install dir),
mount read-only và bật container path. File regular, tối đa 64 MiB, UID 10001
đọc được; không dùng City/ASN database hoặc commit payload/license key vào Git.
Không download/update tự động. Đổi file rồi chạy lại playbook để recreate toàn
stack; gateway nạp DB vào RAM khi startup, không gọi GeoIP ngoài mỗi request.
Rỗng = unavailable; country policy đã bật có thể trả 503 khi DB unavailable.
Chọn trusted proxies trước khi dùng country từ client đi qua Cloudflare.

### Quản lý TLS/ACME trong admin

Module Certificates/providers được bật sẵn: credentials ở PostgreSQL, state
`certificate-requests`, key riêng `certificate-key`, live TLS writable. Không
cần JSON per-domain. Apex/wildcard/admin đã reserve cho bootstrap; request trùng
trả conflict, không chiếm owner kể cả cert chưa load. Zone khác quản lý qua UI
theo [contract Certificates](../../../docs/certificates.md).

Bootstrap token seed được mã hóa bằng Admin key trong `bootstrap-provider`.
Gateway mount handoff read-only; DB là nguồn provider sau import. Rotate token
bootstrap và rotate provider trên UI là hai việc độc lập. Gateway không có key
bootstrap ACME hoặc Docker socket; không cho hai owners cấp cert song song.

## Restart, lỗi và dữ liệu bền vững

Giữ inventory, project, origin, data path và keys. Update bằng Ansible; đổi
runtime/profile/secret hoặc image khiến toàn stack recreate để ClickHouse/
CrowdSec theo namespace gateway mới. Single node có downtime, không cam kết HA.
Health của ACME dựa cert và heartbeat, không chứng minh public reachability.
Worker exhausted không tự restart-loop; chẩn đoán/sửa nguyên nhân trước recreate.

Locks còn sau SIGKILL cần xác minh worker/issuance child đã dừng, snapshot state
rồi mới dọn đúng stale lock. Không xóa journal, pending/account hoặc owner marker
để cấp cert lại. Mất DNS write ACK phải đối soát. Thiếu/sai master key phải phục
hồi đúng key, không tạo instance mới từ dữ liệu còn lại.

Bind mounts giúp giữ data khi cài lại Docker, không thay backup. Xem
[storage/migration](../README.md#dữ-liệu-trên-host-và-cài-lại-docker). Không có
workflow restore sạch được nghiệm thu; không dùng `down -v` hoặc xóa data để restart.

### Nâng cấp instance đã có cert exact

Đây là migration riêng của runtime cũ: giữ đúng keys/accounts/ownership, dừng
writers trước reserve và kiểm chứng staging/production, không chiếm request của
owner khác hoặc sửa SQL. Các kết quả cũ nằm trong
[báo cáo bootstrap](../../../docs/admin-startup-bootstrap.md). Nó không chứng
minh named-volume → bind-mount migration; cần nghiệm thu riêng trước cutover.
