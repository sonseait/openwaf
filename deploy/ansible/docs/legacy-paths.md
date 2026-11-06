# Tra cứu đường dẫn deployment cũ

Deploy VPS hiện dùng [Ansible](../README.md). Thư mục `deploy/vps` đã được gỡ
sau khi chuyển integration harnesses và thay nguồn cấu hình bằng templates/
profiles hiện hành. Không khôi phục manifest cũ để cài mới.

Các [báo cáo bootstrap](../../../docs/admin-startup-bootstrap.md) và
[sizing](../../../docs/evidence/vps-resource-profiles.md) được giữ nguyên nội
dung, gồm paths/commands theo revision tại thời điểm chạy. Đường dẫn cũ trong
các báo cáo đó không phải lệnh hiện hành. Dùng bảng dưới để tìm implementation
tương ứng; kết quả lịch sử không tự chứng minh harness/layout mới đã đạt.

| Đường dẫn cũ | Vị trí hiện hành |
| --- | --- |
| `deploy/vps/README.md`, `.env.example` | [Hướng dẫn Ansible](../README.md), [inventory](../inventory.example.yml), [runtime contract](runtime.md) |
| `deploy/vps/compose.yaml` | [Compose template](../templates/compose.yaml.j2), được render qua Ansible |
| `deploy/vps/profiles/`, `generate-profiles.py` | [Profiles](../files/profiles/), [generator](../scripts/generate-profiles.py) |
| `deploy/vps/postgres-start.sh`, `pgbouncer.ini` | [PostgreSQL wrapper](../files/postgres-start.sh), [PgBouncer config](../files/pgbouncer.ini) |
| `deploy/vps/geoip/` | `openwaf_geoip_file` trong inventory; xem [GeoIP](runtime.md#geoip-country-database) |
| `deploy/vps/tests/` | [Integration harnesses](../tests/integration/README.md), giữ tên script |

Native init source và ownership/identity guards vẫn ở `backend/runtime/`;
không chuyển logic bootstrap/renewal thành scripts trên controller. Dữ liệu
instance đang chạy không được tự di chuyển hoặc xóa khi dọn source repository.
Instance có named volumes cần [migration riêng](../README.md#instance-cũ-dùng-named-volumes).
