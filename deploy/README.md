# Triển khai OpenWAF

VPS mới dùng **[Ansible](ansible/README.md)** làm entry point duy nhất: khai báo
inventory và private file paths trên controller rồi chạy playbook qua SSH.
Ansible chuẩn bị Docker, render Compose/environment, tạo host bind-mount
storage và chờ bootstrap/HTTPS readiness. Không cần clone/build source trên VPS.

- Runtime files: `/opt/openwaf`.
- Private inputs: `/etc/openwaf-secrets`.
- Persistent state: `/srv/openwaf/data`; cài lại Docker phải giữ thư mục này và
  đúng project/inventory. Bind mounts không thay backup ngoài VPS.
- Native bootstrap tạo/kiểm tra keys, credentials, DB/config và DNS/ACME state;
  renewal tiếp tục trong runtime, không phụ thuộc controller chạy thường trực.

Xem [cài mới](../docs/fresh-deploy-vps.md), [runtime contract](ansible/docs/runtime.md)
và [runbook](../docs/deployment-runbook.md). Project còn named volumes bị từ chối
trước khi áp dụng; instance đang chạy cần migration riêng, không trỏ vào data
rỗng hoặc xóa volumes/keys để vượt kiểm tra. Integration harnesses nằm trong
[Ansible tests](ansible/tests/integration/README.md); deployment cũ đã được gỡ.
Xem [mapping đường dẫn lịch sử](ansible/docs/legacy-paths.md) khi đọc báo cáo cũ.

Stack [homelab](homelab/README.md) hiện có vẫn dùng `manage.py` qua SSH và giữ
project/network/data riêng. Không trộn với VPS mới. `docker-compose.yml` ở root
vẫn là stack ứng dụng homelab. Build/push image ở [build](../build/README.md),
độc lập deployment; một image release chứa gateway/UI và các runtime/init binaries.
