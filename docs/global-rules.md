# Global security rules

`Document.global_rules` là access policy chung của gateway managed, mặc định rỗng
để tương thích cấu hình cũ. UI ở Configuration → Global rules; Security có liên kết
trực tiếp. Form dùng cùng editor IP/GeoIP/rate limit với route. Không thêm WAF/CRS
policy chung trong thay đổi này.

```json
{
  "global_rules": {
    "allow": [],
    "deny": ["192.0.2.0/24", "2001:db8::/32"],
    "geo": {"allow": ["GB", "US"], "deny": [], "unknown": "deny"},
    "rate_limit": {"per_second": 100, "burst": 200}
  }
}
```

Ví dụ chỉ là phần bổ sung của document, không phải toàn bộ cấu hình. Bỏ `geo` hoặc
`rate_limit` để tắt lớp tương ứng. ACL: tối đa 128 CIDR mỗi list; deny thắng allow,
allow không rỗng giới hạn client vào các CIDR đó. IPv4-mapped IPv6 client được
normalize, mapped IPv6 CIDR mơ hồ bị từ chối. GEO: tối đa 249 mã hai chữ ASCII hoa,
unknown phải chọn allow/deny. Thiếu/lỗi MMDB trả 503 khi bật GeoIP, khác với lookup
thành công nhưng không có country (áp dụng `unknown`). Rate/burst từ 1 đến 10.000.

Gateway resolve client theo trusted proxies, chọn route và admission trước access
policy. Với mọi request đã chọn route: global IP → global GeoIP → global rate limit
→ route IP → route GeoIP → route rate limit → CrowdSec/WAF và các bước route tiếp
theo. Route không thể override rule chung. Global allow không bỏ qua route deny,
CrowdSec hoặc CRS; WAF Off cũng không tắt global access policy. Request không match
route vẫn trả 404; framing lỗi, protocol reject và ACME challenge chuyên dụng giữ
luồng xử lý trước đó. Admin API là listener quản trị riêng, không chịu traffic rules.

Rate limit chung là một token bucket theo client IP, chia sẻ qua hostname, route và
admission class. Đây không phải quota tổng cho tất cả clients. State riêng với rate
limiter route, kể cả route tên `global`. Tối đa 4.096 key chung tính cả policy generations,
không evict bucket đang depleted; hết key/lock contention trả 503. Bucket quá TTL
được dọn khi check tiếp theo; TTL tối thiểu 60 giây và không ngắn hơn thời gian refill.
429 giữ `Retry-After`. Rate state giữ qua apply/reorder của policy không đổi, nhưng
reset khi process restart; statistics persistence không persist rate limiter state.

Editor chỉ cảnh báo `missing_quota` khi cả `global_rules.rate_limit` và
`routes[i].access.rate_limit` đều chưa cấu hình. Global ACL/GeoIP hoặc concurrent
admission limits không thay thế rate quota. Route có thể bổ sung hạn mức riêng
ngay cả khi đã có rate limit chung; cả hai hạn mức tiếp tục được thực thi.

Schema/API dùng các endpoint `/api/v1/config` hiện có (session và CSRF cho mutation),
không có đường tắt tự áp dụng. `global_rules` được validate cả save/apply/rollback;
`diff.global_rules_changed` có trong review/version/audit theo pipeline config hiện có.
Request giữ snapshot ban đầu. Cấu hình rỗng không serialize `global_rules` để tránh
thay đổi document cũ. Playground hiển thị ACL tổng hợp và global policy; GeoIP và
rate counters vẫn ghi rõ chưa chạy. Request details có decision layers
`global_acl`, `global_geoip`, `global_rate_limit`, `global_rate_limit_capacity`.
Config diagnostics bổ sung `route_id` là tên định danh của route trong document
đã validate. UI hiển thị `storefront · access.rate_limit · missing_quota` thay cho
index. `path` dạng `routes.0.access.rate_limit` giữ nguyên cho API/form; khi nói
chuyện với backend cũ, UI chỉ resolve path bằng đúng document gửi trong query đó.
Diagnostics `/api/v1/telemetry/dependencies` có `global_rate_limit` với key/capacity
counters hữu hạn. Không query database hoặc gọi collector trên hot path.

HTTP flood có thêm `global_rules.ddos` và `routes[i].access.ddos`: đây là token
bucket tổng cho mọi client, chạy trước admission/access và độc lập với `rate_limit`
theo IP mô tả phía trên. Xem [hợp đồng DDoS protection](ddos-protection.md) về schema,
thứ tự xử lý, state capacity và phạm vi bảo vệ.

Global và route có thể bật browser proof-of-work qua `challenge`; global không bị route tắt. Cookie clearance yêu cầu HTTPS tại gateway, có scope/IP/version và hạn dùng; không bypass access/CRS. Xem [hợp đồng browser challenge](browser-challenge.md).
