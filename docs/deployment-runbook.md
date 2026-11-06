# Triển khai và runbook một node Linux

Các cấu hình còn được duy trì nằm trong [deploy](../deploy/README.md):

- **VPS mới:** [hướng dẫn cài mới](fresh-deploy-vps.md) và
  [hợp đồng runtime](../deploy/ansible/docs/runtime.md). PostgreSQL riêng, tự tạo DNS/cert
  cho admin, dashboard public HTTPS 443 qua Cloudflare. PostgreSQL có thể tạo
  mới bằng PGAIO 18 hoặc dùng instance ngoài qua file URL private. Có thể
  [deploy tự động bằng Ansible](../deploy/ansible/README.md) qua SSH.
- **Homelab đang dùng:** [quy trình homelab](../deploy/homelab/README.md), image
  đã build, external network và storage hiện có. Không trộn dữ liệu/project
  của hai môi trường.

Template gateway độc lập, installer tương tác và systemd units cũ đã được gỡ.
Hiện repository không cung cấp profile native systemd hoàn chỉnh. Không dùng
hướng dẫn/template cũ để khởi tạo hoặc chuyển đổi instance mới.

## Khởi động VPS

Dùng [Ansible](../deploy/ansible/README.md) trên controller với checkout phù hợp
release image. Chuẩn bị inventory/secret local, SSH/sudo và Cloudflare Access/
firewall trước startup. Playbook cài Docker trên distro hỗ trợ, render Compose
và bind-mount state từ `/srv/openwaf/data` (có thể cấu hình bằng inventory).
Không build trên VPS. Chạy từ controller:

```sh
cd deploy/ansible
.venv/bin/ansible-playbook playbook.yml --limit edge
```

Chẩn đoán trên VPS (điều chỉnh paths/project nếu inventory thay mặc định):

```sh
sudo docker compose --project-name openwaf-vps --env-file /opt/openwaf/.env -f /opt/openwaf/compose.yaml ps -a
sudo docker compose --project-name openwaf-vps --env-file /opt/openwaf/.env -f /opt/openwaf/compose.yaml logs --tail=80 admin-bootstrap gateway
```

Ansible tạo host directories; init service chuẩn bị secrets và runtime permissions. `OPENWAF_POSTGRES_CREATE=1` tạo PGAIO
18 và role không superuser; `=0` dùng URL private và không chạy database container.
Xem [lựa chọn PostgreSQL](../deploy/ansible/docs/runtime.md#chọn-postgresql).
Preflight import một provider Production và reserve ownership trong PostgreSQL.
Worker cấu hình DNS apex A/AAAA, wildcard/admin CNAME một lần, xin cert SAN apex
+ wildcard bằng staging trước production và tiếp tục renewal. Gateway
chờ cert readiness rồi seed route admin có version/audit.
Dashboard public tại `https://OPENWAF_ADMIN_HOST`; Axum phục vụ UI/API tại loopback
9090 trong gateway, frontend đã nằm sẵn trong image. Không tạo sẵn tài khoản;
tạo admin ở lần truy cập đầu theo [hướng dẫn setup](../deploy/ansible/docs/runtime.md#startup-tự-làm-gì).
Giới hạn truy cập dashboard đến khi tạo xong admin; setup chưa có token một lần.

Không dùng integration image để triển khai. Stack mặc định chạy ClickHouse,
CrowdSec local LAPI (manual decisions) và collector. ACME admin chạy trong
`admin-bootstrap` cho apex/wildcard/admin; các zone khác dùng module Certificates/provider trong admin,
đã bật sẵn key/state/TLS mounts theo [VPS README](../deploy/ansible/docs/runtime.md#quản-lý-tlsacme-trong-admin).
Không cần provider catalog hoặc JSON per-domain cho fresh install.
Prometheus chưa dựng; UI phải phản ánh history metrics chưa cấu hình. Public
Cloudflare/Let's Encrypt, restore sạch và streaming nhiều giờ vẫn là các gate riêng; xem [bằng chứng local](admin-startup-bootstrap.md).

## Network, quyền và tài nguyên

- Chỉ publish 443; SSH giới hạn IP quản trị. Không publish database, API HTTP
  hoặc metrics. Với Cloudflare, cấu hình trusted proxies qua
  validate/apply và firewall origin theo CIDR hiện hành; proxy DNS không tự chặn
  truy cập thẳng IP origin. Bypass cache cho hostname admin.
- Gateway không có Docker socket hoặc ACME master key của bootstrap. Token seed
  dùng Admin key, import một lần qua volume private; DB provider và token-file
  bootstrap có vòng đời rotation độc lập. Module Certificates
  có key riêng qua read-only mount, state/TLS writable và provider credentials mã
  hóa trong PostgreSQL; chỉ control plane sinh input cho native ACME child.
  Collector chạy mặc định và là service duy nhất có Engine socket; điền đúng
  socket/GID trước khi `up`. ClickHouse/LAPI chỉ bind loopback trong namespace
  gateway. Dù bind `:ro`, quyền Engine vẫn rất lớn. Không đổi socket sang `0666` hoặc bật Docker TCP passthrough.
- Docker tự cấp subnet/IP cho network mới. Để dùng network có sẵn, đặt
  `OPENWAF_DOCKER_NETWORK_EXTERNAL=true` và `OPENWAF_DOCKER_NETWORK_NAME` bằng tên
  thực trong Engine theo [hướng dẫn network](../deploy/ansible/docs/runtime.md#chọn-docker-network).
  External network không bị tạo/xóa bởi Compose; phải có outbound HTTPS/DNS cho
  ACME. Gateway tự gộp địa chỉ interface IPv4/IPv6 vào inventory chống loop khi
  startup. Recreate khi topology thay đổi; không attach/detach network lúc chạy.
  Đổi host/network trên instance đang dùng cần migration có review.
- Upstream ưu tiên DNS alias của service trên network chung. Không lưu container
  IP làm định danh bền vững hoặc dùng `0.0.0.0`/`::` làm endpoint. Alias
  `host.openwaf.internal` không làm backend host-loopback truy cập được từ bridge.
  Chọn HTTP/HTTPS, probe từ gateway rồi validate/save/apply.
- Runtime dùng UID/GID 10001, secrets `0600` và directories `0700`. Init chuẩn bị
  permissions cho host data directories; không copy secret vào image hoặc đổi master
  key khi instance đã có dữ liệu. Sao lưu keys riêng với database/ACME state.
- Resource profile ở [runtime budgets](../backend/runtime/vps_profiles.py) giới hạn
  admission/queue/RAM accounting/FD, không phải capacity đã đo hoặc filesystem
  quota. Cấp quota và theo dõi disk riêng cho replay, DB, logs và applications.
  Build/runtime base tags và apt packages chưa được khóa snapshot; không hứa
  rebuild byte-identical.

## Recreate, restart và shutdown

Giữ cùng inventory/project, runtime directory và host data path. Storage identity
guard từ chối đổi path/project hoặc chuyển project còn named volumes sang state
mới. Frontend/init/ACME/collector nằm trong cùng image. Để cập nhật, đổi
`openwaf_image` trong inventory sang release đã review rồi chạy lại Ansible để
pull và recreate toàn stack, giúp ClickHouse/CrowdSec theo namespace gateway mới. Module
Certificates/provider đã được bật trong manifest, không cần profile bổ sung:

```sh
cd deploy/ansible
.venv/bin/ansible-playbook playbook.yml --limit edge
```

Host state nằm ngoài Docker data-root; cài lại Docker phải giữ data/keys và
inventory. Bind mounts không thay backup. Instance cũ xem
[storage migration](../deploy/ansible/README.md#instance-cũ-dùng-named-volumes).

Single node có downtime; không dùng `down -v` để restart/rollback. Giữ image
ID/digest trước đó và ghi nhận schema migrations trước khi cập nhật. Không sửa
trực tiếp config snapshot/SQL hoặc tạo keys thay thế để vượt lỗi startup.

Gateway stop grace 60 giây bao gồm proxy drain và worker deadlines. SIGTERM
ngừng nhận kết nối rồi drain hữu hạn; client SSE/WS cần reconnect/backoff.
Queue/history có thể mất tail khi SIGKILL/OOM; theo dõi dropped/uncertain thay vì
suy diễn toàn bộ logs đã được lưu. Native work giữ ownership cho đến cleanup.
Writer lock còn lại sau crash phải được đối soát khi worker/child đã dừng,
không xóa journal/lease/account để thử lại mù quáng.

## Nghiệm thu trước khi nhận traffic

1. Kiểm tra process UID, readonly filesystem, core dumps off, resource/FD/disk
   quotas, firewall chỉ expose data plane cần thiết. Gateway không thấy Docker
   socket. Admin HTTP/metrics không truy cập được từ mạng không tin cậy.
2. Mở UI qua HTTPS, đăng nhập owner đã được startup tạo, kiểm tra cookie Secure/HttpOnly/SameSite,
   CSRF và origin. `GET /api/v1/auth/session` 401 chỉ chứng minh API reachable;
   không dùng nó làm readiness cho proxy hoặc bằng chứng tất cả dependencies khỏe.
3. Chọn/probe endpoint từ gateway; quan sát DNS/TCP/TLS/HTTP từng bước, validate
   loop/self-address rồi apply. Không dùng collector inventory để suy ra HTTP.
   DNS alias phải resolve lại theo TTL và outage không tự chọn candidate khác.
4. Test benign request và WAF body attack trên route On có upstream spy: benign
   tới backend, blocked 403 không tới backend; oversized 413/capacity 503 phải rõ.
   Default policy DetectionOnly/PL1, đánh giá false positives trước bật On.
5. Test SNI không biết bị từ chối, upstream CA/SNI verification, cert hot reload,
   restart và ACME staging/renewal. Trusted proxy CIDRs chỉ của proxy kiểm soát
   được; chạy spoof-header và origin-bypass probes nếu dùng CDN.
6. Dừng collector/ClickHouse/PostgreSQL/LAPI lần lượt, kiểm tra proxy đang dùng
   snapshot tiếp tục đúng policy, UI báo unavailable/stale/gap/drop. Auth/config
   phụ thuộc DB; snapshot traffic không cần DB mỗi request. LAPI mất kết nối giữ
   ban đến expiry gốc, không kéo dài; cold-start xem checkpoint health riêng.
7. SIGTERM khi có body dở/SSE/WS/H2 và dependency lỗi; ghi drain duration, active
   requests, cancellations, history dropped/uncertain. Không coi response headers
   200 hay timeout là bằng chứng nghiệp vụ đã rollback. Payment cần reconcile
   business key tại backend. Xem [protocol contract](operations.md).
8. Đo workload thực (body, tỷ lệ attack, TLS, concurrency, burst, slow clients,
   requests dài), CPU/RSS/FD/disk, rejection/loss và success percentiles. Chạy
   release benchmark để có baseline hữu hạn;
   không dùng nó thay gate production hoặc realtime ≤2 giây.

## Xử lý sự cố và quay lại

| Triệu chứng                 | Kiểm tra và hành động                                                                                                                                                                                                   |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tăng 503/429                | Xem admission class/resource, WAF queue/worker, rate keys, health/backlog; phân biệt capacity với upstream unhealthy. Giảm tải hoặc tăng đúng budget sau đo RAM/FD; không bypass WAF                                    |
| Mất history/ClickHouse lỗi  | Giữ traffic; quan sát dropped/backlog/last_success, khôi phục storage/disk quota. Không hứa backfill và không retry batch uncertain để tránh duplicates                                                                 |
| DB outage                   | Không apply mới; phục hồi DB rồi xác nhận committed active version. Nếu mất commit ACK, đọc version/audit trước retry; không tự sửa runtime snapshot                                                                    |
| Collector unavailable/stale | Kiểm tra UID/socket/namespace/Engine events; inventory không làm mất upstream đã apply. Dùng gateway probe/health, không tự đổi endpoint                                                                                |
| TLS/renewal lỗi             | Kiểm tra expiry/chain/SNI, key permissions, encrypted ACME state/master key, challenge routing/DNS cleanup; giữ certificate hợp lệ hiện tại. Không tắt verify hoặc cấp key thay thế                                     |
| Disk full/OOM               | Xem volume/quota của replay, DB/history/logs riêng; drop logs phải hiển thị. Không xóa DB/keys/replay đang mở để chữa nhanh; giảm tải, thu hồi đúng retention rồi restart có kiểm soát                                  |
| Shutdown chậm               | Tìm forced admin drain, history/DB/compiler/native deadline trong stderr; supervisor có 60s rồi kill. Thu diagnostic counts, không xuất env, raw URL/body/headers/secrets                                               |
| Config lỗi                  | Chọn committed version cũ qua UI rollback (validate/apply/audit); đọc active version và probe lại. Không chỉnh trực tiếp snapshot hoặc SQL                                                                              |
| Binary/image lỗi            | Giữ image trước và DB compatibility/migration record, stop bằng SIGTERM, redeploy image cũ nếu schema tương thích rồi smoke. Không tự chạy migration down; schema không tương thích cần phục hồi do operator kiểm chứng |

Backup/restore version/checksum, giải mã và phục hồi instance sạch vẫn hoãn; hiện
chưa có quy trình restore được nghiệm thu. Snapshot DB thủ công không chứng minh
phục hồi credentials/ACME/certificates; không tuyên bố DR/MVP production hoàn tất.

Upstream HTTPS mặc định xác minh CA, thời hạn và hostname. Với thiết bị nội bộ
không có CA (ví dụ ESXi), có thể đặt `tls_verify: false` trên **endpoint đó**
qua editor hoặc config validate/save/apply. Đây là ngoại lệ có nguy cơ giả mạo
upstream; TLS vẫn mã hóa và gửi `tls_server_name`. Proxy, health checks,
ForwardAuth và connection test đều dùng cùng giá trị. Các endpoint khác không
bị ảnh hưởng; nên cài CA hợp lệ và bật lại xác minh khi có thể.

Active health checks có `method: HEAD` mặc định hoặc `GET`. Với backend không
hỗ trợ HEAD như Hasura, dùng `health: {method: GET, path: /healthz}` và chỉ chấp
nhận trạng thái thành công phù hợp. Probe chỉ đọc headers và đóng kết nối;
không cấu hình chấp nhận HTTP 500 để che lỗi do method không hỗ trợ.
