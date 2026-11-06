# Browser challenge — JavaScript proof-of-work

Opt-in cho `global_rules.challenge` và `routes[i].access.challenge`. Mặc định tắt,
không cần nhà cung cấp CAPTCHA hoặc credentials. Đây là phép tính SHA-256 tăng
chi phí client tự động, **không phải** xác minh danh tính con người hoặc bảo vệ
SYN/UDP/TLS handshake/băng thông. Bot có thể chạy JavaScript hoặc tự giải proof.

Trong Configuration → Global rules hoặc route modal → WAF & access controls,
bật **Browser challenge (JavaScript proof-of-work)**, đặt difficulty và clearance
lifetime, Save draft → Review/apply. Không tự apply; dùng pipeline validation,
optimistic revision, diff, version, audit và rollback hiện có. Playground chỉ hiện
policy, không giải challenge hoặc kiểm tra cookie.

```json
{
  "global_rules": {
    "challenge": {"difficulty": 12, "clearance_seconds": 900}
  }
}
```

Route có thể bổ sung `"access":{"challenge":{"difficulty":14,
"clearance_seconds":300}}`. Difficulty là số nguyên **8–20** leading zero bits;
mỗi bit tăng gấp đôi số hash trung bình. Lifetime là **60–86.400 giây**. Bỏ hoặc đặt
`challenge: null` để tắt scope đó. Route không thể tắt challenge global. Khi cần cả
hai, một proof dùng difficulty lớn nhất và cấp hai clearance có lifetime riêng.
Khi edit, bỏ tick lưu rõ `challenge: null`, không lấy lại giá trị challenge cũ
trong form. Lưu draft rồi apply để thay đổi có hiệu lực; mở lại draft vẫn giữ tắt.
Các giá trị mặc định UI không phải kết quả benchmark hoặc capacity recommendation.

## Luồng trình duyệt

Gateway phải tự terminate HTTPS, hỗ trợ JavaScript/Web Crypto, cookies và Fetch
Metadata (`Sec-Fetch-Site`). Không tin `X-Forwarded-Proto` để cho phép Secure cookie.
HTTP-only redirects hiện có được phép đưa client tới TLS; route HTTP phục vụ ứng
dụng khi bật challenge trả `503` thay vì bỏ qua bảo vệ. Admin listener riêng không
chịu challenge; request không match route vẫn 404. Chưa có risk scoring/auto-enable.

Sau framing/routing, DDoS budget, admission, global/route ACL/GeoIP/rate limit và
CrowdSec, gateway trả trang 503 nếu [route maintenance](route-maintenance.md) được bật;
nếu không, gateway kiểm tra clearance trước WAF/application. Bodyless GET chấp nhận
HTML, hoặc có Accept thiếu / wildcard (`*/*`, `text/*`) mà không ưu tiên media type
cụ thể khác, nhận trang challenge **403**, CSP nonce, no-store và pending cookie.
Không còn yêu cầu header Accept phải chứa literal `text/html`: tab cũ hoặc lớp
navigation trung gian dùng wildcard vẫn có thể hiển thị challenge. Accept
`text/html;q=0` không được nhận challenge HTML. `Sec-Fetch-Dest` nếu có phải là
`document` hoặc `empty`; script/style/image/worker/iframe vẫn bị từ chối thông thường.
`Vary` gồm Cookie, Accept, Sec-Fetch-Dest và X-OpenWAF-Challenge.
JavaScript tìm `SHA256(token + "." + decimal_counter)` có đủ zero bits rồi gửi
GET cùng URL với header `X-OpenWAF-Challenge: {"token":"…","counter":…}`. Proof
hợp lệ trả **204**, cookie clearance và xóa pending cookie; trang reload URL ban đầu,
giữ path/query. Không đưa path/query vào HTML, token hoặc proof vào URL/log.

API có Accept JSON hoặc media type cụ thể khác, HEAD/POST/upload/WS/SSE chưa có
clearance nhận **403**, không tự replay body,
không chuyển challenge HTML vào stream. Client phải mở GET URL thuộc route trước.
Route chỉ hỗ trợ POST không tự cấp được route clearance; không bật route challenge
cho API-only/webhook/machine clients. Global-only clearance có thể lấy từ một GET
route khác cùng authority. CORS preflight chưa có clearance cũng bị chặn: đây là
chế độ browser navigation, không phải challenge trong suốt cho cross-origin APIs.
`X-OpenWAF-Challenge` response header phân biệt required/invalid/rate/capacity/HTTPS.

Vượt challenge vẫn qua WAF, password/ForwardAuth và upstream; không bỏ qua ACL,
rate limit, CrowdSec hoặc CRS. Local issue/verify không gọi WAF/application; request
reload đã xác nhận mới được xử lý tiếp. Cookie/header challenge bị strip trước
WAF/ForwardAuth/upstream, ngay cả khi tắt policy; header được reserved trong middleware.
Mọi response của route có challenge là private/no-store để tránh cache chia sẻ bỏ
qua clearance; CDN/reverse proxy bên ngoài phải tôn trọng response cache policy.

## Token, state và giới hạn

HMAC-SHA256 dùng key ngẫu nhiên trong RAM của process; không lưu vào config/DB.
Clearance ký authority (hostname và port), normalized trusted client IP, config
version, scope, policy và thời hạn. Global cookie chỉ dùng lại trên cùng authority;
route cookie thêm route ID. Cookie `__Host-openwaf-challenge-global` và
`__Host-openwaf-challenge-route-<id>` có Path=/, Secure, HttpOnly, SameSite=Strict,
không Domain. Đổi IP, apply/rollback version hoặc restart process yêu cầu giải lại.
Expiry dùng timestamp, từ chối token phát hành trong tương lai.

Proof có nonce ngẫu nhiên, lifetime **120 giây**, bind route, cả hai policy và đúng
request target (kể cả query); pending HttpOnly cookie phải trùng token. Verify chỉ
chấp nhận một proof header ≤1.024 byte, schema chặt, counter 0–4.194.303,
`Sec-Fetch-Site: same-origin` và Origin cùng HTTPS authority nếu có. Proof/cookies
được redact bởi metadata allowlist hiện có. Proof không phải one-time ledger:
có thể replay trong cửa sổ proof khi có pending cookie và cùng binding, nhưng
clearance luôn tính từ lúc proof **phát hành**, không gia hạn từ lúc replay.

Không lưu hàng đợi/pending proof/session theo client. Gate dùng token bucket tổng
**200/s, burst 400** và theo IP **2/s, burst 12**, dùng chung issue/verify qua mọi
route/host. IP state tối đa 4.096 keys, TTL ít nhất 60 giây, dọn khi có request;
không evict state đang depleted. Lock contention/hết state trả 503; hết tokens trả
429 và Retry-After. Các lớp rate/DDoS được cấu hình vẫn áp dụng trước gate.
HMAC và một SHA-256 cho mỗi verify; không PoW search trên server, không query DB,
network I/O hoặc task nền trên hot path. Health registration/admission trước
challenge vẫn có chi phí; đây không phải tường chống toàn bộ request flood.

Browser search dừng sau 20 giây hoặc 4.194.304 attempts, fetch verify deadline
5 giây. Cookie/storage bị chặn hoặc máy chậm hiện retry thủ công; chống auto-reload
liên tục bằng một record sessionStorage hữu hạn theo context. Record cũ hỏng hoặc
không hợp lệ được bỏ qua; không dùng nó làm bằng chứng xác nhận client. Khi browser
không cho lưu sessionStorage, proof hợp lệ hiện nút **Continue** để người dùng tải
trang lại, thay vì tự reload mà không có loop guard. Cookie bảo vệ vẫn bắt buộc.
Difficulty cao có
thể không giải được trong deadline trên máy yếu. Nhiều tab có thể ghi đè pending
cookie cùng host; tab cũ cần retry. Không đo pin/CPU/mobile capacity trong thay đổi này.

Decision trace có `challenge: disabled/required/cleared/solved`, security layer
`challenge`, failure markers required/invalid/rate_limit/capacity/requires_https.
Challenge bị từ chối/issued được tính blocked; verify 204 thành công là local
completion, không forwarded hoặc blocked. Không dùng token/IP/URL làm metric label.
