# Trang lỗi của gateway

Trong **Configuration → Edit draft → Error pages**, thêm HTML cho từng mã lỗi.
Trong từng route, mở nhóm **Error pages** để ghi đè. Lưu draft rồi review/apply
như các thay đổi cấu hình khác; rollback cũng khôi phục trang lỗi của version
được chọn. Xóa trang tùy chỉnh để dùng lại trang kế thừa/mặc định.

Với cùng mã HTTP, thứ tự ưu tiên là **route → toàn cục → mặc định OpenWAF**.
Trang toàn cục cũng áp dụng khi không có route khớp (`404`) hoặc request bị từ
chối trước routing. Request đang xử lý giữ snapshot ban đầu khi apply/rollback.
Standalone không có managed configuration vẫn dùng trang mặc định.

Trang mặc định có bố cục responsive, tự chọn sáng/tối theo hệ điều hành, thông
báo theo mã lỗi và request reference 64 ký tự để tra cứu. Trang còn hiển thị
IP client đã xử lý theo trusted proxies và vị trí cấp quốc gia từ GeoIP (mã ISO
hai chữ, ví dụ `VN`, `GB`). ID 32 ký tự cũ vẫn tra cứu được. Không tải font, ảnh hoặc CSS từ
bên ngoài.

GeoIP dùng database Country nạp sẵn qua `OPENWAF_GEOIP_DB`, không gọi dịch vụ
định vị bên ngoài. Vị trí chỉ xấp xỉ cấp quốc gia, chưa có thành phố/toạ độ.
Thiếu database hiển thị `Unknown (GeoIP unavailable)`; không có bản ghi hiển thị
`Unknown`; lỗi lookup hiển thị `Unknown (GeoIP lookup failed)`. Không suy ra vị
trí từ header do client tự khai báo. Request bị từ chối trước khi xác minh IP
hiển thị IP `Unknown`. Trang lỗi hiển thị thông tin này trong HTML mặc định, không nội suy
vào custom HTML hoặc thay đổi payload JSON của lỗi. Metadata client trong
live/history logs được mô tả riêng ở [chi tiết request](request-details.md). `Cache-Control: no-store` vẫn
áp dụng cho response chứa IP.

## Schema và API

`error_pages` là danh sách tùy chọn ở document và mỗi route. Ví dụ document:

```json
{
  "error_pages": [
    {
      "status": 404,
      "html": "<!doctype html><html lang=\"vi\"><meta charset=\"utf-8\"><title>Không tìm thấy</title><h1>Không tìm thấy dịch vụ</h1></html>"
    }
  ],
  "routes": [
    {
      "id": "app",
      "hostname": "app.example.test",
      "path": "/",
      "path_match": "prefix",
      "upstream": "app",
      "error_pages": [
        {
          "status": 403,
          "html": "<!doctype html><html lang=\"vi\"><meta charset=\"utf-8\"><title>Truy cập bị chặn</title><h1>Liên hệ quản trị viên để được hỗ trợ</h1></html>"
        }
      ]
    }
  ],
  "upstreams": [
    {
      "id": "app",
      "endpoints": [{ "address": "app:8080", "protocol": "http" }]
    }
  ],
  "trusted_proxies": []
}
```

Dùng các API `/api/v1/config/validate`, `/draft`, `/apply`, `/rollback` hiện có,
giữ authentication, CSRF và revision checks. Validation trả `error_pages` khi
status ngoài `400..599`, trùng status trong cùng scope, HTML trống/chứa NUL,
trang vượt **16 KiB UTF-8** hoặc quá **16 trang/scope**. Tổng document vẫn tối
đa **64 KiB**; vượt giới hạn tổng trả `limit`. Không tự cắt nội dung.

Diff có thêm `error_pages_changed` cho cấu hình toàn cục; chỉnh trang của route
nằm trong `routes.changed`. Diff của version lịch sử có thể thiếu trường mới,
UI xem là không có thay đổi toàn cục được ghi nhận. Không cần migration database;
document cũ không có trường này tiếp tục dùng trang mặc định. Trang tùy chỉnh
được lưu cùng document và nạp lại khi restart.

## Phạm vi và bảo mật

- Chỉ thay body HTML của lỗi do gateway tạo trước khi gửi final headers, gồm
  routing, security/WAF, body limit, admission và lỗi transport upstream. Giữ
  nguyên status HTTP, `Retry-After` nếu có và `x-request-id`.
- `Accept` chứa `application/json` tiếp tục trả JSON với `status`, `message`,
  `request_id`. `HEAD` có headers/content length tương ứng nhưng không gửi body.
  Lỗi HTTP do ứng dụng upstream trả về được chuyển tiếp nguyên body/format.
- HTML là nội dung tĩnh, không nội suy hostname, URL, query, WAF findings hoặc
  template variables. Trang tùy chỉnh lấy reference qua header `x-request-id`;
  chỉ trang mặc định hiển thị reference trong body. Không đưa credentials vào HTML.
- Cho phép CSS inline và ảnh `data:`. CSP bắt buộc `default-src 'none'`,
  `style-src 'unsafe-inline'`, `img-src data:`, `base-uri 'none'`,
  `form-action 'none'`, `frame-ancestors 'none'`, `sandbox`. Script, form và
  tài nguyên ngoài bị chặn bởi trình duyệt; gateway không fetch HTML/tài nguyên.
  Các lỗi luôn có `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`; cấu hình headers của
  route không được ghi đè những ràng buộc này trên lỗi gateway.
- Preview dùng iframe sandbox không có quyền script/same-origin và CSP tương
  ứng. Link tương đối không có base URL của website trong preview; nên viết
  trang tự chứa. Đây là preview HTML, không phát request thử đến upstream.
- Không thay lỗi TLS handshake, lỗi parser xảy ra trước request filter, hoặc
  chèn trang thứ hai vào response/SSE/WebSocket đã bắt đầu. Total deadline có
  thể đóng kết nối thay vì gửi trang lỗi; xem [hợp đồng vận hành](operations.md).

Chưa đo benchmark riêng cho rendering và chưa kiểm chứng Safari/Firefox hoặc
nghiệm thu production. Các gate soak/backup/ACME vẫn cần kiểm chứng.

## Chiều cao trang mặc định

Bản cập nhật 2026-10-20 giảm status typography, padding và khoảng cách help/reference;
layout vẫn co theo nội dung, không dùng `overflow:hidden` để che thông tin.
Browser tests kiểm tra cả hai chiều scroll với IPv6 dài và reference 64 ký tự tại
1280×900, 1280×650, 390×844 và 360×640. Font phóng lớn, viewport nhỏ hơn hoặc custom
HTML vẫn có thể cần scroll để giữ nội dung truy cập được.
