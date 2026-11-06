# Ghi body và query string theo route

Trong **Configuration → Routes → Body & retries → Body & query recording**, bật riêng
**Record request body**, **Record response body** và **Record query string**.
Mặc định cả ba tắt. Lưu
draft, validate rồi apply để có hiệu lực; diff, audit và rollback dùng cơ chế
cấu hình hiện có. Request đang chạy giữ policy từ snapshot ban đầu. Tắt record
không xóa dữ liệu cũ; không thu hồi tố.

```json
{
  "record_body": {
    "request_enabled": true,
    "response_enabled": true,
    "query_enabled": true,
    "redact_fields": ["private", "payment_details"]
  }
}
```

`record_body` là trường tùy chọn trên route trong document của Config API.
Các cờ thiếu mặc định `false`, `redact_fields` thiếu mặc định `[]`. Policy toàn
mặc định được bỏ khi serialize. Danh sách thêm tối đa 64 tên, mỗi tên 1–128 byte
UTF-8, không chứa control characters. Cấu hình cũ không cần migration PostgreSQL.

## Điều kiện capture

- Chỉ `application/json`, `application/*+json` và
  `application/x-www-form-urlencoded`, UTF-8, không nén (`identity` được chấp nhận).
- Tối đa **65.536 byte mỗi chiều**; cả body thô và nội dung sau redaction phải
  nằm trong giới hạn. Không lưu prefix khi quá lớn hoặc chỉ đọc được một phần.
- Không capture multipart/file, binary, text tự do, SSE hay WebSocket frames.
  Không tự giải nén, đổi framing hoặc thay payload gửi tới upstream/client.
- Request capture đọc body gốc trước middleware rewrite, không đếm replay như
  payload mới. Không drain body để ghi log sau quyết định chặn. Các request chưa
  match route không có capture; endpoint password login nội bộ luôn bỏ request
  capture với lý do `internal_authentication`.
- Response capture ghi body cuối gateway chuẩn bị gửi downstream, gồm JSON lỗi
  local, maintenance và file JSON được phục vụ trực tiếp nếu đủ điều kiện.
  Không ghi response của attempt retry bị loại. HEAD, 204, 304 và upgrade không
  ghi nội dung. Không có bảo đảm client đã nhận/ACK dữ liệu đã chuẩn bị.
- Capture là chức năng quan sát, không phải response-body WAF inspection.

Query string được lấy từ URI gốc ngay sau khi match route, trước rewrite và
không ghi lại theo retry. Cờ `query_enabled` độc lập với hai cờ body: hỗ trợ
cả GET không có body, request bị WAF chặn và request có body không hỗ trợ capture.
Không thay đổi query gửi tới upstream. Query dùng cùng giới hạn **64 KiB** cho
cả chuỗi gốc lẫn kết quả đã che, cùng retention **7 ngày** và cùng ngân sách
worker/queue/buffer; giới hạn request target/header hiện có vẫn áp dụng.

Tham số phân tách bằng `&`, decode percent encoding và UTF-8 nghiêm ngặt trước
khi so khớp tên; `+` biểu diễn dấu cách. Che mọi tên nhạy cảm kể cả tên được
encode và tên lặp, dùng cùng danh sách mặc định và `redact_fields` của route.
Sau đó encode lại nên không bảo toàn cách viết percent encoding ban đầu;
giữ thứ tự và tham số lặp, tham số không có `=` được chuẩn hóa thành giá trị rỗng.
Không có query hoặc query rỗng báo `empty`. Encoding lỗi báo `invalid_query`,
quá giới hạn báo `query_too_large`/`redacted_query_too_large`, không lưu prefix.

JSON che giá trị của tên khóa ở mọi cấp, kể cả trong mảng. Form decode tên và
giá trị bằng UTF-8/percent encoding nghiêm ngặt, che mọi trường lặp có tên khớp,
rồi encode lại; form hiển thị có thể khác cách encode ban đầu. JSON được parse
và serialize lại, không bảo toàn whitespace hoặc khóa lặp. Body sai cú pháp,
UTF-8 lỗi, encoding lỗi hoặc JSON vượt recursion limit bị bỏ toàn bộ.

So sánh tên không phân biệt hoa/thường. Luôn che: `password`, `passwd`, `secret`,
`token`, `access_token`, `refresh_token`, `authorization`, `api_key`, `apikey`,
`cookie`, `csrf_token`; route chỉ bổ sung tên, không bỏ danh sách này. Cơ chế
không tự nhận diện secret trong giá trị tự do hoặc tên chưa được cấu hình.

## Storage, giới hạn và vòng đời

Raw buffers chỉ tồn tại tạm trong bộ nhớ capture và được zeroize khi giải phóng.
Một worker thread có owner riêng parse/redact ngoài Pingora/Tokio proxy executor,
chỉ chuyển bản đã che vào storage/live cache. Không có raw payload trong ordinary
telemetry, stderr, audit hoặc backup cấu hình.

Giới hạn cố định: 128 raw buffers × 64 KiB (**8 MiB**), queue **32** request jobs,
batch tối đa **16** jobs và live cache tối đa **32** request records. Mỗi record
chứa tối đa một body mỗi chiều và một query string. Startup RAM estimate dành thêm **64 MiB** cho
recorder, cache, worker và serialization batches; đây là allowance kế toán,
không phải kết quả đo RSS. Không đợi queue/cache lock trên hot path. Quá tải bỏ
capture và giữ nguyên traffic/WAF. Diagnostics tại
`GET /api/v1/telemetry/dependencies` có `body_recording.active_buffers`,
`buffer_limit`, `queue_depth`, `processed`, `dropped`; `dropped` đếm các sự kiện
mất capture do capacity/queue, mất ghi history hoặc không cấu hình history, dù
live copy có thể còn.

ClickHouse tạo bảng `openwaf_bodies_v1` riêng khi có capture đầu tiên, dùng
request ID, timestamp và payload JSON đã che, TTL **7 ngày**. Query lọc timestamp
để không lộ dữ liệu đã quá hạn trong lúc chờ TTL merge xóa vật lý. Giữ quyền
ClickHouse phù hợp để worker tạo bảng và ghi dữ liệu. Lỗi ghi không retry INSERT
vì ACK mất có thể vẫn đã commit. `failed_or_uncertain` phản ánh sự không chắc
chắn đó. Mất history không chặn proxy; live copy có giới hạn và mất khi restart
hoặc bị evict. Shutdown ngừng nhận capture mới, drain queue hữu hạn, network
deadline 2 giây/thao tác và kết thúc runtime worker có timeout.

## Admin API và UI

`GET /api/v1/requests/{id}/body` yêu cầu session quản trị; không có session trả
401, ID sai trả 400, request không tìm thấy trả 404, dependency không khả dụng
có thể trả 503. Mọi response đi qua Admin guard và có `Cache-Control: no-store`.
Tra live cache trước, sau đó ClickHouse; nếu payload thiếu thì dùng capture
marker trong traffic record để giải thích, không suy đoán nội dung.

```json
{
  "request_id": "<gateway request reference>",
  "observed_at_unix_ms": 1793491200000,
  "request": {
    "status": "recorded",
    "reason": null,
    "content_type": "application/json",
    "bytes": 20,
    "content": "{\"token\":\"[REDACTED]\"}"
  },
  "response": {
    "status": "disabled",
    "reason": null,
    "content_type": null,
    "bytes": 0,
    "content": null
  },
  "query": {
    "status": "recorded",
    "reason": null,
    "content_type": "application/x-www-form-urlencoded",
    "bytes": 11,
    "content": "token=%5BREDACTED%5D"
  },
  "persistence": "written"
}
```

Request body, response body và query có `status`: `disabled`, `pending`, `recorded`, `empty`, `skipped`,
`dropped`, `expired` hoặc `unavailable`. `reason` phân biệt unsupported type/
charset/encoding, body quá lớn, incomplete, invalid, hết capacity/queue và history
unavailable. `bytes` là số payload byte quan sát tại capture hooks; disabled/
empty không thu byte, không thay các counters transport trong request metadata.
Với query, `content_type` mô tả dạng encode của nội dung trả về, độc lập với
Content-Type của request. `content` chỉ có khi `recorded`. Bản ghi cũ không có marker trả cả ba phần
`unavailable/not_collected`, có thể thiếu metadata còn lại. ID đã mất cả traffic
history và capture trả 404; không thể phân biệt hết hạn với ID chưa từng tồn tại.

`persistence`: `pending`, `written`, `not_configured`, `failed_or_uncertain`,
`dropped`, `not_required`. Marker pending đã mất live copy và không có history
sau 30 giây được báo `dropped/capture_not_retained`; outage báo unavailable.
Schema `details` là **8**, thêm marker query và chỉ chứa metadata không có nội
dung đã ghi. `metadata.request.query` vẫn là null hoặc `[REDACTED]` kể cả khi
bật ghi query; SSE, traffic list và history list không chứa nội dung query.
Bản ghi schema 7/ClickHouse cũ thiếu `query` trả `unavailable/not_collected`;
không suy luận là đã tắt, không cần migration bảng ClickHouse. Giới hạn details
16 KiB, SSE/live logs 1.000 records và biểu đồ 15 phút giữ nguyên.

Tab **Request Details → Body & query** tải riêng khi mở, hiển thị Request/Response/Query cùng
trạng thái/lý do, có refresh và polling 2 giây khi pending. Nội dung được render
như text, JSON định dạng có giới hạn; không thực thi HTML. Query hủy khi tab
unmount, không lưu body vào localStorage hoặc giữ Query cache sau unmount.

## Kiểm thử

Unit tests trong config/storage/admin kiểm tra default, tên trường hữu hạn, JSON/form
redaction, query encode/tên lặp, boundary 64 KiB, partial/invalid/unsupported bodies, queue/capacity,
worker ownership, live expiry và marker hỏng không lộ nội dung. Test tích hợp
dùng gateway thật và container
PostgreSQL/ClickHouse riêng, không dùng dữ liệu vận hành:

```sh
cd backend
cargo build -p openwaf-gateway
python3 tests/body_recording.py
```

Harness dùng rules fixture để chứng minh request bị body-WAF chặn không tới
upstream spy; gồm chunked hai chiều, chặn header không drain body, độc lập flags,
rollback, client chậm và restart/outage. Không thay thế nghiệm thu OWASP CRS
đầy đủ, HTTP/2, tải kéo dài,
đo RSS/latency hoặc kiểm chứng TTL merge vật lý sau 7 ngày.
