# DDoS protection — HTTP flood

OpenWAF managed mode hỗ trợ token bucket **tổng cho mọi client** ở hai phạm vi:
`global_rules.ddos` dùng chung qua mọi hostname/route/admission class;
`routes[i].access.ddos` dùng chung trên một route. Cả hai độc lập với
`rate_limit` theo client IP và concurrent admission hiện có. Không có chính sách
mặc định tự bật; cấu hình cũ tiếp tục hoạt động như trước.

Trong Configuration → Global rules hoặc access policy của route, bật
**DDoS protection (HTTP flood)**, nhập **Total requests per second** và
**Total burst capacity**, lưu draft rồi review/apply. Security hiển thị
counters từ process hiện tại; dữ liệu thiếu hiện Unavailable. Toàn bộ config đi
qua session/CSRF, validate, version/diff, atomic apply, rollback và audit hiện có.
Không có endpoint tự áp dụng hay auto-ban.

Ví dụ phần bổ sung cho document:

```json
{
  "global_rules": {
    "ddos": {"per_second": 1000, "burst": 2000},
    "rate_limit": {"per_second": 20, "burst": 40}
  }
}
```

Route có thể thêm `"access": {"ddos": {"per_second": 100, "burst": 200}}`.
Mỗi rate/burst phải là số nguyên từ 1 đến 10.000. Bỏ hoặc đặt `ddos: null` để tắt
phạm vi tương ứng; route không thể tắt hạn mức global. Các con số trên là ví dụ
cấu hình, không phải năng lực đã benchmark hoặc ngưỡng khuyến nghị cho production.

## Hợp đồng xử lý

Sau framing/routing/client identity và trước request admission, access policy,
CrowdSec, WAF, ForwardAuth và upstream, gateway tiêu thụ một token global, sau đó
một token route nếu được cấu hình. Client mới, đổi IP/IPv4/IPv6, hostname, method,
path hoặc class không tạo thêm ngân sách global. Hạn mức route dùng stable route
ID và admission class; đổi class chủ động tạo phạm vi state khác. Health tracking
hiện có vẫn đăng ký trong routing; policy này không bảo vệ chi phí parse/routing.

Thiếu token trả `429` với `Retry-After` giây nguyên (tối thiểu 1), không xếp hàng
hoặc gọi WAF/upstream. Credits không hoàn lại khi request bị lớp sau chặn/hủy;
request thất bại vẫn là tải gửi vào gateway. Burst là sức chứa bucket, không phải
một ngưỡng RPS cố định theo giây. Refill theo thời gian monotonic. WAF Off hoặc
ACL allow không bỏ qua DDoS; đi qua DDoS không bỏ qua IP limits, ACL hoặc CRS.

Không lấy được lock hoặc hết state capacity trả `503`, không bypass. Chi tiết
request phân biệt `ddos_global`, `ddos_route`, `ddos_global_capacity` và
`ddos_route_capacity`; không ghi matched payload hoặc dùng IP/URL làm metric label.
Request có decision trace `ddos: passed/disabled` khi đi tiếp. Early rejection
không phải completed WAF inspection. `GET /api/v1/telemetry/dependencies` bổ sung:

```json
{
  "ddos": {
    "limited_total": 12,
    "unavailable_total": 0,
    "global": {"max_keys": 4096, "per_class": 1024, "per_route": 128},
    "routes": {"max_keys": 4096, "per_class": 1024, "per_route": 128}
  }
}
```

Ví dụ rút gọn: hai phần limiter còn có class key/peak/capacity counters và
`contention_total`; class có thể `null` khi đang được cập nhật. Đây là process
counters, không chứng minh hệ thống đang bị DDoS hay phát hiện nguồn tấn công.
Playground trả cấu hình effective `ddos`, nhưng không chạy rate counters.

State là local RAM, không I/O hoặc task nền trên hot path. Mỗi scope/policy dùng
một identity nội bộ cố định; số IP tấn công không làm tăng số key. Global và route
có limiter riêng, không va chạm ngay cả route tên `global`. Route state được chia
bốn admission class; mỗi class tối đa 1.024 keys, mỗi scope tối đa 128 policy
generations. Global dùng một class, tối đa 128 policy generations. Capacity lỗi
không evict bucket đã cạn. TTL tối thiểu 60 giây và không ngắn hơn thời gian refill;
cleanup chỉ chạy khi có request tiếp theo. Hai limiter có giới hạn tổng 4.096 keys
mỗi limiter (global sử dụng ít hơn giới hạn đó).

State sống qua apply/reorder/rollback nếu scope/class/rate/burst không đổi. Đổi
rate/burst tạo policy generation khác; quay lại tiếp tục bucket cũ nếu chưa hết
TTL. Request giữ snapshot đã chọn khi bắt đầu. Restart process xóa token state và
counters; persistence request statistics không persist DDoS buckets.

## Phạm vi và giới hạn

Đây là bảo vệ capacity HTTP trên một node. Request không match route vẫn trả 404;
ACME HTTP-01 và listener Admin giữ luồng riêng. Không chống SYN/UDP flood, TLS
handshake flood hoặc bão hòa đường truyền; không phân loại bot/challenge/CAPTCHA,
không bảo đảm công bằng giữa client hợp lệ và attacker. Global budget có thể được
traffic bulk tiêu thụ trước critical route; chọn hạn mức route và quota class phù
hợp, không coi critical class là phần RPS được bảo lưu trong global bucket.
WebSocket/SSE tiêu thụ token lúc request/handshake, không kiểm tra frames/events.

Browser proof-of-work là lớp opt-in độc lập tại global/route, không thay HTTP flood budgets; xem [hợp đồng challenge](browser-challenge.md).
