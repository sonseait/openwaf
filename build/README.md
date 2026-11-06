# Build và xuất bản image

Quy trình này chạy độc lập với deployment. Sửa trực tiếp tag image, build arg
`OPENWAF_RELEASE` và `platform` trong `build/compose.yaml` cho cả hai service
(mặc định `latest`, `linux/amd64`; có thể đổi sang `linux/arm64`).
Ví dụ từ root repository:

```sh
docker login ecr.swissy.shop
docker compose -f build/compose.yaml build
docker compose -f build/compose.yaml push
```

Registry nhận hai image cùng tag và release từ cùng checkout:

- `ecr.swissy.shop/c/openwaf-gateway:TAG` (service `openwaf`, target `gateway`):
  distroless, Rust binaries, React UI và CRS; dùng cho gateway/admin/collector/ACME.
- `ecr.swissy.shop/c/openwaf-init:TAG` (service `openwaf-init`, target `init`):
  Python, offline VPS initializer, defaults/resource budgets và native helpers
  để validate/mã hóa credentials. Đây là image one-shot, không phục vụ proxy.

Lệnh build/push không chỉ định service ở trên xử lý cả hai image. Giữ tag image
và build arg `OPENWAF_RELEASE` cùng giá trị cho cả hai; không trộn image từ
hai release. Chỉ build init: `docker compose -f build/compose.yaml build openwaf-init`.
Source init/defaults nằm trong `backend/runtime/`, unit tests initializer ở
`backend/runtime/tests/`; xem thêm [kiểm chứng split images](../backend/runtime/IMAGES.md).
Không lấy source từ deployment templates để build image.
Build context là root repository, Dockerfile ở `backend/Dockerfile`; không
cần build/push admin-edge image riêng.
Máy build khác kiến trúc target cần builder/QEMU phù hợp. Sau khi image đã được
push:

- Homelab: đặt tag đó trong `deploy/homelab/.env` rồi dùng
  [deployment qua SSH](../deploy/homelab/README.md).
- VPS: đặt `openwaf_image: ecr.swissy.shop/c/openwaf-gateway:TAG` và
  `openwaf_init_image: ecr.swissy.shop/c/openwaf-init:TAG` trong inventory
  rồi dùng [Ansible](../deploy/ansible/README.md). Có thể khóa từng image bằng
  digest tương ứng. Init image là bắt buộc, không fallback sang gateway.
  Build/push cả hai trước khi cập nhật manifest; gateway distroless không chứa
  `openwaf-startup-init` hoặc Python.

Deployment chỉ pull/run, không gọi build/push và không biên dịch Rust/frontend
trên VPS. Lệnh build/push ở trên chạy trên máy build hoặc CI; chọn tag phù hợp
và xuất bản trước khi dùng ở VPS. Không dùng `docker compose build` với manifest
Compose do Ansible render vì deployment không khai báo mục `build`.
