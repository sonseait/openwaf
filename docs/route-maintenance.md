# Bảo trì từng route và bảng endpoint

## Bật và tắt bảo trì route

Configuration → Routes → Edit → **Enable route maintenance**. Nhập thông báo
plain text và Retry-After, cập nhật local draft rồi **Validate & save draft →
Review apply → Apply saved draft**. Cancel modal không đổi draft; lưu draft chưa
đổi traffic. Tắt công tắc và apply để phục vụ lại. Retry-After là gợi ý cho client,
không phải lịch tự tắt bảo trì.

Route dùng trường tùy chọn sau trong config JSON hiện có, không cần migration DB:

```json
{
  "maintenance": {
    "message": "Hệ thống đang bảo trì. Vui lòng quay lại sau.",
    "retry_after_seconds": 300
  }
}
```

Bỏ trường hoặc đặt `null` để tắt. `{}` bật với thông báo mặc định và 300 giây.
Thông báo phải có nội dung sau trim, tối đa 512 UTF-8 bytes; cho phép xuống dòng,
cấm control characters khác. Retry là số nguyên 1–86.400 giây. Backend từ chối
trường lạ hoặc policy không hợp lệ trước khi apply. Route vẫn cần destination và
các tham chiếu hợp lệ để có thể phục vụ trở lại sau khi tắt bảo trì.

Policy đi qua snapshot/version/diff/audit/rollback hiện có. Request mới đọc
snapshot đã apply; request đang chạy giữ snapshot ban đầu, không bị ngắt bởi
việc bật bảo trì. Không sửa endpoint modes, không ảnh hưởng route khác cùng
upstream, không bật bảo trì toàn hệ thống.

## Response và thứ tự thực thi

Sau framing/routing, DDoS budget, admission, ACL/GeoIP/IP rate limit và CrowdSec,
route bật bảo trì trả local **503 Service Unavailable**. Các lớp này vẫn có thể
trả lỗi riêng trước khi đến trang bảo trì. Maintenance chạy trước browser
challenge, password login, CORS, ForwardAuth, WAF và application/redirect. Nó
không yêu cầu backend healthy và không gọi application hoặc auth service.

- Trình duyệt nhận HTML responsive dark/light, thông báo đã escape, không
  JavaScript hoặc tài nguyên ngoài, có nút **Try again**. Có **Request reference**
  trùng `X-Request-ID`, **Client IP** theo trusted proxies và **Approximate
  location** theo GeoIP, giống trang lỗi mặc định; không có dữ liệu GeoIP hiển thị
  Unknown cùng lý do unavailable/lookup failed tương ứng.
- Accept `application/json` khi không chứa `text/html`, hoặc có header Upgrade,
  nhận JSON `status`, `reason: route_maintenance`, `message`,
  `retry_after_seconds`, `request_id`.
- HEAD có headers/content length giống response tương ứng, không có body.
- POST/upload không được replay hoặc gửi body tới upstream. SSE/WebSocket mới
  nhận 503 thay vì mở stream; kết nối đã chạy không bị ngắt.
- Headers gồm `Retry-After`, `X-OpenWAF-Maintenance: route`,
  `Cache-Control: private, no-store`, request ID, nosniff và CSP không cho script,
  form, embedding. Template maintenance được ưu tiên hơn custom error page 503.

Decision trace thêm `route_maintenance: enabled/disabled`, outcome/layer là
`route_maintenance` khi bật. Đây là planned local completion, không tính là WAF
security block và không tính forwarded. Response 503 vẫn thuộc HTTP error totals.

## Endpoint diagnostics & maintenance

Discovery → **Endpoint diagnostics & maintenance** dùng bảng có search, endpoint /
pool / protocol, health và timestamp, admission mode / active requests / remaining
leases, ảnh hưởng bảo trì / deadline và **Inspect / maintain** mở modal hiện có.
Bảng có cuộn ngang nội bộ trên mobile, giữ refresh mỗi 5 giây và Pause/Resume.

Polling dùng `GET /api/v1/operations/endpoints?summary=true`; gateway ghép identity
và health trong cùng active snapshot rồi trả `health` trực tiếp trên endpoint.
Bảng không tải `/config` để ghép indices. Response giữ config version, timestamp,
TTL và operations; bỏ diagnostics/address details trùng lặp, chi tiết lấy qua
history khi cần. Thiếu timestamp/TTL, quá TTL, lỗi tải endpoints hoặc pause thì
health hiển thị Unknown. Không lấy vị trí từ draft hoặc dùng health cũ như hiện tại.
Số leases, lý do và ảnh hưởng bảo trì là lần quan sát gần nhất có timestamp.

Modal endpoint tiếp tục dùng revision, reason, deadline, drain/maintenance và
force disconnect riêng. Endpoint maintenance loại endpoint khỏi lựa chọn mới;
**route maintenance** chủ động render trang bảo trì cho route. Layout Uptime giữ
nguyên. [Hợp đồng endpoint](operations.md#endpoint-controls-and-health).
