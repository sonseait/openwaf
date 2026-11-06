# Route tools và password-only protection

Route detail và luồng request → exclusion proposal → shadow → review/apply
OPS-3 được bổ sung tại [Investigation](investigation.md), cùng
[bằng chứng OPS-3/4](evidence/ops-3-4.md). Các controls nền bên dưới được tái sử dụng.

Cập nhật 2026-10-20. Các chức năng này mở rộng cấu hình/snapshot hiện có; không
thêm deployment manager, network scan hoặc workflow apply mới.

## Request decision flow

Mở Request Details trong Live Traffic hoặc history. Phần đầu giải thích lớp quyết
định, route ID, config version, WAF rule IDs/phase và đã forward upstream hay chưa.
`details.schema_version=6` giữ `decision_trace` của schema 5: tối đa 16 checkpoint
`{stage,result,duration_ms}` từ gateway thực tế: framing, routing, admission, access policy,
CrowdSec, content/body limits, WAF, password và ForwardAuth khi có chạy.

Trace ghi checkpoint đã hoàn tất, lớp disabled, bước stopped/blocked hoặc bước
interrupted, không dựng lại từ policy hiện tại. `duration_ms` đo riêng mỗi bước
bằng đồng hồ monotonic, gồm thời gian chờ trong bước; không phải tổng latency hoặc
CPU time. Bước chưa chạy không được thêm vào trace. Log cũ thiếu timing hiển thị
`Timing not collected`. Xem phạm vi đo tại [metadata](request-details.md).
`security_layer` và `outcome` thể hiện điểm dừng/lỗi; attempts giữ bằng
chứng forwarding. HTTP lỗi từ backend không bị gắn nhãn WAF block. Dữ liệu cũ thiếu
trace hiển thị unavailable. Payload vẫn tối đa 16 KiB; query values, body, cookies,
password/CSRF và matched data không được ghi nhận. API/history/SSE giữ cùng trường
`details String`, không cần migration SQL. Xem [metadata](request-details.md).

## Service Map

`/service-map` dùng `GET /api/v1/config` và các API discovery candidates hiện có,
cùng session quản trị. Giao diện lấy **active** config, không lấy draft làm
trạng thái đang bảo vệ. Thanh tổng quan đếm routes/upstreams/endpoints và ghi
active version; không dùng số configured làm trạng thái runtime healthy.

Tab **Traffic paths** có danh sách dịch vụ tìm theo upstream, route/hostname/path
và địa chỉ endpoint. Chọn dịch vụ để xem sơ đồ **Incoming routes → Upstream →
Backend endpoints**; chọn route để xem WAF mode, password/ForwardAuth, ACL,
GeoIP, rate limit, global access rules và body inspection một lần trong panel
**Route protection**. HTTP/TLS verification, SNI và provenance nằm ở endpoint;
**Endpoint details** mở source identity và timestamp. Upstream dùng cho ForwardAuth
được ghi riêng, không gộp authentication calls thành proxy forwarding.
**Local handlers** chứa route redirect và hosted application, hiển thị response
của route đang chọn. Upstream không được route tham chiếu vẫn hiện rõ.

Desktop dùng danh sách dịch vụ cạnh sơ đồ ba cột; màn hình hẹp chuyển danh sách
lên trên (ô chọn dịch vụ gọn trên mobile) và xếp luồng theo chiều dọc. Giữ
light/dark, keyboard focus và cuộn danh sách hữu hạn. Có loading skeleton,
empty/search-empty, lỗi kèm retry và cảnh báo
password override; đổi tab giữ lựa chọn dịch vụ/route. Thiếu config không ngăn
xem discovery. Tab **Discovery inventory** giữ nguồn Docker/host TCP listeners,
metadata và phân trang độc lập với traffic paths.
WAF thiếu policy hiển thị inherits startup mode; không giả định blocking.

Discovery lấy từng trang tối đa 100 candidates, giữ timestamp/stale/unavailable,
incomplete inventory và cursor conflict. Chỉ liên kết chắc chắn khi address và
source identity trùng, bỏ timestamp khi so identity. Cùng address nhưng provenance
khác yêu cầu xác minh; không tự đổi endpoint sau container recreate. Chưa thấy
candidate trên trang hiện tại không chứng minh endpoint biến mất.

Bind wildcard/loopback và exposed ports không phải bằng chứng Internet exposure,
HTTP, TLS handshake hoặc khả năng truy cập từ gateway. Frontend không probe tự
động và không quét port. Badge là cấu hình, không phải chứng nhận WAF coverage,
certificate availability hoặc auth của ứng dụng. Route cụ thể hơn thiếu password
có cảnh báo trong map và config diagnostics.

## Route Playground

`/playground` dùng `POST /api/v1/config/playground`, yêu cầu session + CSRF.
Input:

```json
{
  "source": "active",
  "request": {
    "scheme": "https",
    "hostname": "app.example.test:443",
    "path": "/api/items",
    "method": "POST",
    "client_ip": "192.0.2.5"
  }
}
```

`scheme` mặc định HTTPS; HTTP-only redirects được đánh giá theo scheme. `source`
chỉ nhận `active` (không document) hoặc `draft` (có document). UI gửi **saved draft**,
không gửi unsaved editor; response draft dùng config_version 0, UI gắn draft revision.
Draft đi qua pure Snapshot validation, không native compilation/publication.
Invalid/malformed input trả 422; tổng body vẫn theo config size limit.

Response schema 1 có normalized host/path, config version, candidates theo
precedence với host/path/method match, route thắng và effective rewrite/redirect,
IP ACL, WAF/password/ForwardAuth/rate/GeoIP configuration. Gateway và Playground
dùng chung `Route::matches`/`precedence`; không có selector mutation hay health I/O.
Path không nhận query, encoded separator/dot segments hoặc reserved password
endpoint `/.openwaf/password/`; công cụ này mô phỏng routing ứng dụng, không login.

`runtime_checks=not_run`: không chạy WAF payload, GeoIP lookup, CrowdSec, live rate
counters, auth/session, DNS, TLS, health hoặc gửi request upstream. Route thắng không
đồng nghĩa request được phép. Đổi input/reload loại bỏ kết quả trước đó trong UI.

## Password-only login theo route

Trong Configuration → route → Password protection, nhập và xác nhận password,
chọn Set password in draft, sau đó Validate & save draft → Review & apply.
Không yêu cầu username. Cần gateway thực sự terminate HTTPS; không tin
`X-Forwarded-Proto` để cấp cookie qua HTTP. HTTP route có HTTP-only HTTPS redirect
vẫn redirect local; HTTP route khác đang bật password trả 503.

Admin `POST /api/v1/config/password-verifier` nhận `{route_id,password}`, yêu cầu
session/CSRF, password 12–128 byte UTF-8. Hash Argon2id v19 (m=19456 KiB, t=2, p=1)
với salt ngẫu nhiên; chỉ trả `sealed_verifier` AES-256-GCM hex, bound route ID bằng
AAD và dùng admin master key ngoài DB. Plaintext/hash không xuất lại qua config,
history/diff/audit. UI xóa fields sau yêu cầu, không giữ password trong mutation
variables. Đổi route ID sau khi set password cần set lại để tạo binding mới.

Route lưu optional `password_protect` gồm `sealed_verifier` và `session_seconds`
(300–86400, mặc định 43200). Missing/null tắt gate. Load/validate/save/apply/rollback
phải decrypt và kiểm tra fixed hash cost trước native prepare/publication; key sai,
envelope hỏng hay copy verifier sang route khác bị từ chối. Không có SQL trên
request hot path; prepared verifier chỉ nằm trong snapshot và được zeroize khi
không còn reference.

Browser chưa có session nhận trang login HTML local HTTP 401 khi Accept có
`text/html`; client khác nhận lỗi 401 JSON/gateway error. Trang có password field,
hidden CSRF/return path và form POST tới `/.openwaf/password/{route_id}`. Namespace
này dành riêng cho local login, không tới upstream. Form contract riêng:
application/x-www-form-urlencoded, không compressed body, tối đa 8 KiB, deadline
đọc 3 giây. Không chạy application content contract/rewrite/ForwardAuth hoặc native
CRS body parsing trên password form; admission, route ACL/rate/GeoIP và CrowdSec
vẫn chạy. Các request ứng dụng vẫn qua WAF trước password gate; không bypass CRS.

Login cần HTTPS Origin khớp authority (gồm port), signed CSRF token bound return
path, và matching HttpOnly SameSite=Strict CSRF cookie 10 phút. Redirect thành công
303 chỉ tới canonical local path trong route; không replay POST/body/query gốc.
Password sai trả trang 401, CSRF sai 403, form sai 415/422, quá lớn 413, read timeout
408; login rate limit 429 + Retry-After 60, thiếu capacity 503. Tối đa 5 POST/client
IP/phút và 120 POST toàn node/phút, dùng IP đã xác minh theo trusted proxies; window
được reset sau restart. Hashing tối đa 2 jobs, không queue chờ; permit và password
thuộc blocking job đến khi xong dù caller bị hủy, deadline chờ 3 giây.

Trang login dùng `Referrer-Policy: same-origin`: giữ Origin khi browser submit
form cùng origin và không gửi Referer sang origin khác. Không dùng `no-referrer`
ở trang này vì browser có thể gửi `Origin: null`, khiến CSRF từ chối cả password
đúng. Origin thiếu/null/khác authority và CSRF cookie thiếu vẫn bị từ chối.

Session cookie `__Host-openwaf-pw-{route_id}` dùng Secure, HttpOnly, SameSite=Strict,
Path=/, không Domain. HMAC key ngẫu nhiên trong process, token bound host, route,
policy và config version; có issued/expiry tuyệt đối và nonce. **Mọi apply/rollback
và restart đều kết thúc session/CSRF cũ cho request mới**, kể cả rollback về password
trước đó. Request/stream đang chạy giữ snapshot cũ theo hợp đồng chung. Không có
session database, sliding refresh, username, MFA hoặc logout từng visitor trong
phạm vi này; đổi password/apply hoặc restart thu hồi toàn bộ session.

Gate/CSRF cookies được lọc trước khi chuyển tới application hoặc ForwardAuth, kể
cả route sibling không bật password. Authenticated responses luôn private/no-store.
Đây là access gate, không thay authorization hoặc CSRF nghiệp vụ của backend.

Để bảo vệ **toàn bộ endpoint của một app**, dùng hostname app + prefix `/` + tất cả
methods. Route con cụ thể hơn có policy độc lập và có thể thắng prefix: phải cấu
hình password cho các route đó nếu không muốn truy cập không cần password. Listener
backend truy cập trực tiếp cần firewall/network isolation riêng. Cross-origin
preflight không có session sẽ bị gate từ chối; không quảng bá public CORS API qua
password gate. Trình duyệt phải mở app và login trước khi dùng SSE/WS/API có cookie.

Chưa benchmark password flood, soak dài hoặc chứng nhận production; các gate
ACME staging/provider, capacity và fault còn mở vẫn được theo dõi trong [kế hoạch](../plan.md).
