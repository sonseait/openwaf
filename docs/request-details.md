# Chi tiết request

Liên kết route/config version, request-reference page và bộ lọc điều tra OPS-3
được bổ sung theo [hợp đồng Investigation](investigation.md); xem
[bằng chứng OPS-3/4](evidence/ops-3-4.md) cho phạm vi kiểm chứng mới.

Mở **Traffic → View request** hoặc tra request reference để xem client, request,
response, quyết định bảo vệ và từng lần thử upstream. Reference mới dài 64 ký tự;
reference 32 ký tự cũ vẫn tra được. Các tab Handling, Overview, Security, Upstream và Headers
hỗ trợ bàn phím, màn hình nhỏ và theme sáng/tối. Tab Handling mặc định chứa flow
xử lý; chỉ nội dung tab đang mở cuộn dọc. Header, thông tin request và thanh tab giữ
nguyên vị trí; cả modal không có thêm vùng cuộn bên ngoài.

Hai bảng **Live request feed** và **Traffic history** dùng chung cột và thứ tự:
**Time**, **Reference**, **Method**, **Origin**, **Path**, **Country (code)**,
**Body size**, **Status**, **Decision**, **Latency (ms)**, **Version**, **Route**.
Time hiển thị milliseconds, tooltip có ngày và timezone. Origin là `scheme://host`
quan sát tại gateway; Path là path gốc trước rewrite, không kèm query. Metadata
thiếu/hỏng hiển thị `Unavailable`, path bị gateway cắt có dấu `…`.
Country là mã GeoIP hai chữ cái từ `metadata.client.country_code`; không suy ra
quốc gia từ header client. Body size là `metadata.request.body_received_bytes`
(payload request thực nhận, đơn vị byte, không gồm HTTP framing), không phải
Content-Length hay kích thước response. `body_read_complete` chưa true hiển thị
`(partial)`; 0 byte khác dữ liệu chưa thu thập. Không đọc hoặc tải nội dung body
để hiển thị bảng. Route dùng `details.route_id` từ snapshot request, không tra
`route_index` trong cấu hình hiện tại. Request chưa match route hiển thị
`No matching route`; thiếu identity hiển thị `Unavailable`. Không cần migration.

Cả hai bảng có **Host contains** (không phân biệt hoa/thường), thu chiều rộng
70% trên desktop, và **Country code** (ví dụ `VN`, `US`; nhập thường được chuẩn hóa
thành hoa). Live lọc trên tối đa 1.000 logs đã giữ; reset xóa cả lọc quốc gia.
History có thêm **Path contains**, phân biệt hoa/thường và tìm literal trên path
gốc đã thu thập, không kèm query. Các tiêu chí kết hợp bằng AND; để trống nghĩa
là không lọc. History gửi `host`, `path`, `country` tùy chọn đến
`GET /api/v1/history/traffic`; lọc tại ClickHouse **trước LIMIT**, không chỉ lọc
100 kết quả trên client. `country` phải rỗng hoặc đúng hai chữ cái ASCII, so khớp
chính xác mã quốc gia đã lưu sau khi chuẩn hóa input thành hoa; sai định dạng trả
422 (`validation`). Metadata thiếu/hỏng hoặc không có mã quốc gia không khớp bộ lọc quốc gia.
Host tối đa 253 byte ASCII không có scheme, port hoặc path; path tối đa 2.048
byte UTF-8, không chứa control characters hay query/fragment. Giá trị bị cắt chỉ
tìm được trong phần path đã lưu. `%`, `_`, quote và backslash là literal.

`GET /api/v1/requests/{id}` yêu cầu session quản trị, tìm trong live ring tối đa
1.000 bản ghi rồi tra ClickHouse trong retention 7 ngày. SSE logs và traffic history
mang cùng `details` (chuỗi JSON); schema bên ngoài không đổi. Schema bên trong là
**9**, thêm `security_signals` cho CRS; giữ marker query của schema 8 trong `body_recording` không chứa nội dung body/query, `metadata` của schema 4 và `decision_trace` tối đa 16 checkpoint của
schema 5; mỗi bước thêm `duration_ms` (milliseconds, có phần thập phân).
Phần “Why was this request blocked?” hiển thị route/config version, bước đã qua,
lớp quyết định, rule IDs/phase và trạng thái đã forward upstream. Không suy luận
bước chưa chạy là đã đạt; bản ghi cũ thiếu trace hiển thị unavailable. Xem thêm
[hợp đồng công cụ route](route-tools.md). Không cần
migration mới vì ClickHouse đã có cột `details String`. Bản ghi cũ không được bổ
sung dữ liệu hồi tố; UI hiển thị not collected/unavailable cho trường thiếu hoặc
metadata hỏng. Mất log/ClickHouse unavailable vẫn hiển thị trạng thái riêng.

### Security signals (AB-1)

`security_signals` được tạo từ native WAF report và các gate outcomes đã quan sát;
việc ghi signal không tự thay enforcement. Envelope có `status` (`collected`/`not_collected`),
`observed_at_unix_ms` (thời điểm report hoặc outcome, null khi chưa thu thập), `coverage`,
`entries` và `truncated`. Route/config version và request reference dùng context
của bản ghi bao ngoài, không suy từ cấu hình hiện tại.

Entry native hiện dùng `source: crs`, `reason: rule_match`, `scope: request`, `rule_id`,
`phase`, `severity` và `action`: `observed`, `would_block` hoặc `enforced_block`.
Tên source này bao gồm native ModSecurity rules, không chứng nhận rule thuộc OWASP CRS.
Native block không có logged findings (ví dụ rule `nolog`) vẫn tạo entry
`source: waf`, `reason: native_decision`, action `would_block`/`enforced_block`;
rule_id/phase/severity bằng 0, không bịa metadata rule hoặc nguồn CRS.
Gate outcomes dùng source/reason riêng, có thể có `capacity_error`; các trường
rule_id/phase/severity bằng 0 là sentinel không áp dụng, không phải native finding.
Action là quyết định **của cả report**, không khẳng định từng finding độc lập gây
block hoặc severity là risk score. Enforced block ghi nhận quyết định từ chối của
gateway, không chứng minh client nhận được response. Tối đa 16 entries, không có
matched data, body, token hoặc cookie; native findings bị cắt cũng đánh dấu
`truncated`. Findings gốc vẫn giữ contract 32 entries; toàn details giữ cap 16 KiB.

Không có report và không có gate outcomes là `not_collected`, không phải kết quả sạch.
Có gate outcomes không chứng minh native WAF đã chạy: phải đọc coverage/report riêng.
Report không có findings cũng không chứng minh không có attack. Bản ghi schema cũ
thiếu field hiển thị Not collected; không backfill. Security tab hiển thị signals
cùng findings hiện có. Các tính năng identity quota, detectors observe-only,
incidents và simulator có [hợp đồng anti-abuse riêng](anti-abuse.md).

Kiểm chứng local trên macOS: fmt check, workspace Clippy `-D warnings`, toàn bộ
workspace tests (221 passed, 0 failed), gateway build và integration native WAF /
PostgreSQL / upstream spy đạt. Frontend lint/typecheck/build/format và Chromium
API-fixture interactions đạt; Vite vẫn cảnh báo chunk >500 kB. Các lỗi DNS bind và
replay deadline của lượt AB-1 trước đã được xử lý trong test fixtures; một lượt
test native exception expiry từng fail do timing và lượt cuối đạt, chưa coi là đã
loại bỏ mọi flaky test. Xem [bằng chứng và giới hạn](evidence/anti-abuse/acceptance.md).
Chưa benchmark overhead/full load, ClickHouse/SSE end-to-end hoặc chứng nhận CRS
distribution thực tế; native integration dùng bộ rules fixture.

Các checkpoint hiển thị trong lưới thẻ gọn, giữ thứ tự, tên bước, kết quả và thời
gian riêng. Icon và màu giúp đọc kết quả: xanh teal cho kết quả thành công đã ghi
nhận, đỏ cho chặn/từ chối/lỗi, cam cho yêu cầu thêm hoặc dừng/gián đoạn (kể cả
maintenance enabled), xanh dương cho thông tin/redirect, xám cho disabled và kết
quả chưa biết. Nhãn kết quả luôn hiển thị; không suy luận kết quả mới là thành công.
Lưới tự thu cột trên màn hình nhỏ, hỗ trợ theme sáng/tối.

“How was this request handled?” và các flow blocked/stopped hiển thị thời gian
ngay cạnh từng bước, ví dụ `routing · 3 ms`. Gateway dùng đồng hồ monotonic, đo
riêng từ đầu đến checkpoint của mỗi bước, gồm thời gian chờ trong bước đó
(admission, nhận body, WAF queue/worker, ForwardAuth). Không lấy thời gian cộng
dồn từ đầu request. Thời gian routing gồm chuẩn hóa host/path/client, chọn route
và chuẩn bị metadata/health registration liên quan. Thời gian application kết
thúc khi chuẩn bị response, trước khi gửi body. Đây không phải CPU time hay tổng
latency: không bao gồm toàn bộ TLS handshake, upstream/response transfer và các
khoảng giữa bước. Vì vậy không cộng các bước để suy ra tổng request latency.
Bước bị từ chối ghi `stopped` (WAF block ghi `blocked`); bước đang chạy bị hủy/lỗi
transport ghi `interrupted`, chỉ phản ánh thời gian đã quan sát, không báo passed.
Bước chưa chạy không xuất hiện. Log cũ/thiếu thời gian ghi `Timing not collected`;
không nội suy thời gian hoặc coi missing là 0 ms. Giá trị nhỏ hơn 0,001 ms được
hiển thị `<0.001 ms`. Giới hạn 16 bước/16 KiB và đường log bất đồng bộ giữ nguyên.

## Trường và nguồn dữ liệu

| Nhóm | Trường trong `metadata` | Nguồn / ý nghĩa |
| --- | --- | --- |
| Thời gian | `started_at_unix_ms`, `completed_at_unix_ms` | Đồng hồ gateway, milliseconds UTC. Trường kết thúc có thể null khi task bị hủy trước logging |
| Client | `client.ip`, `ip_source` | IP đã chuẩn hóa theo cùng chính sách trusted proxies dùng cho ACL/WAF; nguồn `socket`, `trusted_proxy` hoặc `unresolved` |
| Kết nối | `client.peer_ip`, `peer_port` | Peer socket thực tế; port thuộc peer, không suy ra port của client sau proxy |
| User agent | `client.user_agent`, `user_agent_truncated` | Header gốc, tối đa 512 byte UTF-8; không suy luận thiết bị/OS từ chuỗi chưa được xác minh |
| Vị trí | `client.country_code`, `geoip_status`, `geoip_source` | MaxMind Country nạp sẵn qua `OPENWAF_GEOIP_DB`, cùng kết quả local dùng cho thống kê/trang lỗi. Chỉ quốc gia ISO, không có thành phố/tọa độ |
| TLS | `client.tls_version`, `tls_cipher` | Phiên bản/cipher thực tế của kết nối tới gateway; null với HTTP hoặc khi digest chưa có. Không lấy từ forwarded headers |
| Request | `request.method`, `scheme`, `http_version`, `host` | Method/giao thức nhận ở gateway và host sau validation; host null nếu bị từ chối trước validation |
| URL | `request.path`, `path_truncated`, `query` | Path gốc trước rewrite, không có query; tối đa 2.048 byte UTF-8. Query chỉ null hoặc `[REDACTED]`, không lưu tên/giá trị |
| Headers | `request.headers`, `response.headers` | Snapshot request trước sửa headers và response cuối đã chuẩn bị cho downstream, kể cả lỗi local. Header response có thể null nếu chưa có final headers |
| Body request | `request.body_declared_bytes`, `body_received_bytes`, `body_read_complete` | Content-Length hợp lệ duy nhất hoặc null; số payload byte đã đọc thực tế; có quan sát hết body hay chưa, gồm H2 END_STREAM |
| Body response | `response.body_declared_bytes`, `body_sent_bytes` | Content-Length hoặc null; payload byte transport gateway đã ghi. Không chứng minh client nhận/ACK đủ dữ liệu |
| Upstream | `response.upstream_body_received_bytes`, `upstream_body_complete` | Số payload byte nhận qua hook upstream và trạng thái kết thúc; lỗi local không có upstream body |
| Hoàn tất | `response.completed` | Logging kết thúc không có lỗi transport và có final response. Không phải kết quả nghiệp vụ của ứng dụng |

GeoIP phân biệt `known`, `unknown`, `unavailable`, `lookup_failed`, `not_resolved`.
IP chưa xác minh để null. Không tin header location/country do client tự khai báo.
`scheme` mô tả kết nối tới gateway: proxy phía trước kết thúc TLS rồi chuyển HTTP
vào gateway sẽ có scheme HTTP tại đây.

Body không có Content-Length (chunked/H2) vẫn có số byte thực nhận. Request bị
chặn sớm có thể khai báo body lớn nhưng thực nhận 0; upload ngắt giữa chừng có
`body_read_complete=false`. Retry/replay không cộng lại byte client đã nhận.
Cancellation giữ số liệu đã quan sát qua hook; byte response chưa lấy được từ
session để null. Không suy diễn số byte chưa quan sát là đã truyền thành công.
Với upgraded connection, transport có thể đếm cả byte tunnel/WebSocket; không
lưu hoặc kiểm tra nội dung frame. Header-only response (ví dụ HEAD) có thể có
Content-Length khác số body byte thực ghi.

## Redaction và giới hạn

Không đưa nội dung body/query vào `details`, SSE hoặc traffic list. Thu body/query là tùy chọn
riêng theo route, theo [hợp đồng body recording](body-recording.md). Cookie, Set-Cookie, Authorization, proxy credentials,
API key, CSRF, forwarding, identity và header ứng dụng chưa nhận diện
đều giữ tên nhưng thay giá trị bằng `[REDACTED]` **trước khi vào queue**.
`Referer`, `Location`, `Origin`, `Access-Control-Allow-Origin` giữ URL HTTP(S)
hoặc đường dẫn bắt đầu bằng `/` sau khi bỏ userinfo, toàn bộ query và fragment.
URL sai định dạng, scheme khác HTTP(S), protocol-relative URL, backslash hoặc
whitespace bị che toàn bộ; origin `null`/`*` được giữ nguyên. Cờ `redacted=true`
cũng chỉ việc đã loại bỏ một phần URL, không nhất thiết toàn bộ giá trị bị che.

Chỉ giữ giá trị cho allowlist: `accept`, `accept-encoding`, `accept-language`,
`content-type`, `content-length`, `content-encoding`, `user-agent`, `range`,
`connection`, `upgrade`, `sec-websocket-version`, `cache-control`, `vary`,
`x-content-type-options`, `referrer-policy`, `host`, `sec-fetch-site`,
`sec-fetch-mode`, `sec-fetch-dest`, `sec-fetch-user`,
`access-control-request-method`, `access-control-request-headers`,
`access-control-allow-methods`, `access-control-allow-headers`,
`access-control-allow-credentials`, `access-control-max-age`,
`access-control-expose-headers`, `x-request-id`, `x-correlation-id`, `traceparent`,
`date`, `server`, `allow`, `retry-after`. Request/correlation ID và traceparent từ
header chỉ là metadata không đáng tin, không thay reference do gateway tạo,
không được dùng làm identity hoặc metric labels. Các giá trị này và path vẫn là dữ
liệu do client/ứng dụng cung cấp; không đặt credentials trong path hoặc UA.
Frontend render như text, không render HTML từ metadata.
Chính sách này áp dụng chung request/response headers cho dữ liệu mới; không
khôi phục giá trị đã che trong history. Không thêm cấu hình mở custom headers
hoặc chế độ tắt redaction toàn bộ.

Mỗi tập headers giữ tối đa **24 entries**, tổng tên/giá trị **2.048 byte**, tên
64 byte và giá trị 256 byte. `total`, `omitted`, `truncated` và cờ trên từng entry
cho biết giới hạn đã áp dụng; `total` tính cả header trùng tên. Chuỗi bị cắt trên
ranh giới UTF-8, thay control characters bằng khoảng trắng.

Toàn bộ `details` tối đa **16 KiB JSON**. Khi vượt, bỏ hai tập headers và đặt
`metadata_truncated=true`; nếu vẫn vượt, chỉ giữ marker schema/outcome với
`details_truncated=true`. UI báo rõ trường bị bỏ. History vẫn tối đa 100 bản ghi,
2 query đồng thời, timeout 2 giây và giới hạn response ClickHouse **4 MiB** để
chứa details đã JSON-escape; Prometheus giữ giới hạn response 512 KiB riêng.
Live ring/UI vẫn tối đa 1.000 logs và biểu đồ 15 phút. Không thêm IP, UA, path,
headers hay reference vào metrics labels. Capture không query DB, gọi dịch vụ
GeoIP ngoài hoặc ghi log đồng bộ trên proxy hot path.

HTTP flood protection bổ sung decision layers `ddos_global`/`ddos_route` (429)
và `ddos_global_capacity`/`ddos_route_capacity` (503), trước admission/WAF/upstream.
Trace `ddos: passed/disabled` chỉ phản ánh bước này; không chứng minh WAF đã chạy.
Xem [hợp đồng DDoS](ddos-protection.md).
