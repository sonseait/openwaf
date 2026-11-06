# OpenWAF Admin UI

React + TypeScript + Vite + Mantine. TanStack Query quản lý server state,
React Hook Form quản lý form, React Router DOM điều hướng, mantine-datatable
hiển thị bảng và D3 scale/shape + Canvas vẽ biểu đồ. Icon dùng Lucide, thời gian
Day.js và thông báo react-hot-toast. Dependency lock dùng npm.

## Development

Node 24 + npm. Chuẩn bị certificate được browser tin cậy với SAN khớp hostname,
lưu tại `frontend/.dev/cert.pem` và private key tại `frontend/.dev/key.pem`;
thư mục này đã được Git ignore.

```sh
cd frontend
npm ci
npm run dev
```

Script dev dùng hai file TLS trên. Vite chỉ bind loopback, từ chối serve khi thiếu
TLS và chuyển `/api` tới `http://127.0.0.1:9090`; có thể đổi đích bằng
`OPENWAF_ADMIN_TARGET` sang địa chỉ HTTP loopback khác. Admin cần
`OPENWAF_ADMIN_ORIGIN` khớp origin HTTPS của UI, ví dụ `https://localhost:5173`.
Để rà frontend local với gateway đã deploy, đặt target HTTPS rõ ràng:

```sh
OPENWAF_ADMIN_TARGET=https://openwaf.swissy.shop npm run dev
```

Mở `https://localhost:5173` và đăng nhập tại đó; cookie của domain deploy không
được browser chia sẻ sang localhost. Dev proxy xác minh certificate của target,
đổi Host/Origin theo origin HTTPS đích sau khi kiểm tra Origin của UI local.
Không dùng HTTP tới máy từ xa, URL chứa credentials hoặc tắt TLS verification.
Các thao tác trên UI local sử dụng gateway đích thật, kể cả save/apply.

Session dùng cookie Secure/HttpOnly/SameSite Strict, giữ Origin/Host/cookie qua
proxy cùng origin. Không commit private key, credentials hoặc `.env`.

```sh
npm run lint
npm run typecheck
npm run format:check
npm run build
```

Build tạo `dist/`. [Gateway Dockerfile](../backend/Dockerfile) đóng gói frontend
vào cùng image với Rust. Axum phục vụ static UI với SPA fallback và Admin API/SSE
tại `127.0.0.1:9090`; Pingora xử lý HTTPS. Không cần Nginx/Caddy. Chạy Rust ngoài
Docker có thể đặt `OPENWAF_ADMIN_UI_ROOT` tới thư mục `dist` đã build; khi không
đặt, Axum chạy API-only. Xem [deployment runbook](../docs/deployment-runbook.md). Không dùng Vite dev server để deploy.
Các bộ browser test, Playwright và ảnh chụp lịch sử đã được dọn khỏi repository.

## Luồng quản trị

Database chưa có user hiển thị **Create your administrator**; tạo xong chuyển về
login. Setup status có loading/error/retry; không suy diễn lỗi thành database rỗng.
Session/CSRF không lưu web storage; logout/401 xóa protected query/mutation cache.
Mutation không tự retry; conflict hoặc kết quả write không rõ cần reload đối chiếu.

Query `config` dùng cache trong bộ nhớ: fresh 30 giây, xóa sau 60 giây không có
observer; logout/401 vẫn xóa ngay. Save/apply/rollback và application mutations
invalidate cache. Endpoint polling nhận thấy active version khác cũng invalidate
config, chỉ refetch khi có consumer đang mount. Không đồng bộ draft giữa các tab.
Endpoint diagnostics/Uptime poll summary mỗi 5 giây, nhận health gắn trực tiếp
với endpoint từ cùng snapshot nên không tải toàn bộ `/config` để ghép health.
DNS/TCP/TLS/HTTP details lấy qua history khi cần; pause/lỗi/hết TTL là Unknown.

Configuration dùng **Draft editor / Review & apply / Version history**. Form
chỉnh local draft; save không tự apply. Review/apply dùng saved draft trên server.
Thêm/sửa route/upstream mở modal trên bản sao; Cancel/Escape bỏ thay đổi trong
modal. Các modal nhiều nội dung dùng Mantine Tabs: Route chia Routing/Middleware/
Access & auth/WAF/Responses/Traffic & capacity/Timeouts/Body & retries; Upstream
chia Endpoints/Balancing & sessions/Timeouts/Health checks. Panels của form luôn
mounted để giữ giá trị và kiểm tra các trường ở tab khác; khi submit lỗi, mở tab
chứa trường lỗi rồi focus vào trường đó. Chiều cao khả dụng do Mantine Modal cung cấp; header, thanh tab và thao tác
lưu/hủy nằm ngoài vùng cuộn. Chỉ panel đang mở cuộn dọc, không lồng thêm
ScrollArea cho cả modal. Thanh tab cuộn ngang trên màn hình hẹp. Request details tách
Handling khỏi Overview/Security/Upstream/Headers. Các modal quản lý/review
application, WAF policy, endpoint controls và apply saved draft cũng chia tab theo
nhóm nội dung. Configuration warnings hiển thị một lần trong Draft editor, thu gọn mặc
định và có số cảnh báo. Mục này kiểm tra toàn bộ local draft; thay đổi trong modal
được kiểm tra sau khi thêm vào draft. Các cảnh báo chỉ mang tính hướng dẫn, save
vẫn chạy đầy đủ validator. Discovery chỉ gợi ý endpoint; người dùng chọn HTTP/HTTPS, gateway kiểm tra
DNS/TCP/TLS/HTTP và server validate trước save/apply. Metadata source và cấu hình
ngoài phần đang chỉnh được giữ nguyên.
Trong **Discovered candidates**, endpoint không thể chọn được ẩn mặc định;
tick **Show unavailable** để xem lại cùng lý do. Bộ lọc áp dụng trên trang hiện
tại, có số dòng bị ẩn và vẫn chuyển trang được khi tất cả dòng đều bị ẩn.

Overview hiển thị bộ đếm realtime request starts 15 phút, lọc host và literal path prefix (không gồm query); xem [hợp đồng và giới hạn bộ đếm](../docs/request-window-counts.md). Bộ đếm local reset khi gateway restart và báo partial khi đầy registry.

Realtime có connected/stale/pause và gap/drop indicators. Client giữ tối đa
1.000 live logs và 900 samples trong 15 phút; reconnect không tích lũy vô hạn.
History lấy qua API. Có loading/error/empty, dark/light, labels/focus/keyboard và
bảng giá trị truy cập được cho biểu đồ. Font IBM Plex được phục vụ cục bộ trong
`public/fonts` kèm OFL license.

## Quy ước giao diện compact

Theme tập trung tại [src/theme.ts](src/theme.ts), Mantine scale mặc định `1`.
Compact bằng component size và spacing; không thu nhỏ toàn app để giảm khoảng trống.

- Body/Text dùng `sm` (13 tại scale 1), metadata `xs` (12); input/button dùng `xs`
  (cao 30). Heading h1/h2/h3 tương ứng 20/16/14, tất cả khai báo bằng rem.
- Spacing xs/sm/md/lg/xl tương ứng 8/10/12/16/20 tại scale 1.
- Nhóm nhỏ dùng gap `xs`, nhóm thao tác `sm`, giữa section `md`. Card/modal padding
  `md`, nội dung lồng nhau `sm`; trang `md` trên desktop và `sm` trên mobile.
- Dùng size/spacing/radius tokens trước; kích thước riêng và icon Lucide dùng
  `rem()` từ Mantine. CSS dùng theme variables hoặc `calc(...rem * var(--mantine-scale))`.
  Không nhân scale lần nữa trên kết quả `rem()`.
- AppShell header desktop `rem(44)`, mobile `rem(48)`, navbar `rem(224)`, collapse ở `sm`. NavLink, surface,
  border và active/hover dùng Mantine theo light/dark; giữ font IBM Plex/palette app.
- Bảng dùng chữ `sm`, horizontal spacing `sm`, vertical spacing `rem(6)`; bảng rộng
  scroll bên trong. Mobile/touch giữ vùng bấm dễ thao tác, focus và nhãn truy cập được.
- Canvas nhận chiều cao, font và màu từ CSS/theme; chỉ backing buffer và phép vẽ
  dùng pixel/device pixel ratio. SVG giữ tọa độ viewBox, viewport dùng rem.
- Pixel dành cho border/focus hairline; breakpoint dùng em theo Mantine. Khi sửa
  layout, kiểm tra light/dark, mobile, scale `1`/`1.25` và browser zoom 200%.

## Hướng dẫn tính năng và API

- [Statistics](../docs/request-statistics.md), [request details](../docs/request-details.md)
  và [operational controls](../docs/operations.md).
- [Middleware](../docs/route-middleware.md), [route tools/password protection](../docs/route-tools.md),
  [maintenance](../docs/route-maintenance.md) và [error pages](../docs/error-pages.md).
- [Global rules](../docs/global-rules.md), [HTTP flood protection](../docs/ddos-protection.md)
  và [browser challenge](../docs/browser-challenge.md).
- [Applications](../docs/applications.md), [certificates](../docs/certificates.md)
  và [Cloudflare providers/DNS](../docs/cloudflare-providers.md).

System health hiển thị tổng quan heartbeat, monitoring/mất dữ liệu và các nhóm
thành phần. Có bộ lọc All/Needs attention/Not configured, chi tiết từng nguồn
thu gọn, số liệu hiện có từ API và trạng thái paused/stale rõ ràng. Màn hình này
không suy luận upstream reachable từ heartbeat hoặc renewal healthy từ TLS
inventory. API health giữ nguyên; phần hiển thị nằm ở `src/SystemHealth.tsx` và
phân loại trạng thái ở `src/system-health.ts`.

Route editor có ba tùy chọn Record request body, response body và query string độc lập tại Body & retries.
Request Details → Body & query tải payload đã che qua API riêng khi mở tab, không đưa body
vào live logs hoặc query cache sau unmount. Giới hạn/định dạng/lưu giữ và hợp đồng
API tại [body recording](../docs/body-recording.md).

## Điều tra và thống kê OPS-3/4

Route detail `/routes/:id` nối Service Map, request config version, exclusions,
expiry, coverage và shadow. `/requests/:reference` có link trực tiếp có session;
`/traffic` giữ bộ lọc điều tra trong URL. `/statistics` thêm Service health,
Protection, Investigation và Capacity, counter rollup 30 ngày và comparison.
Bộ lọc host áp dụng live statistics và Prometheus incoming history; operational
views dùng route scope riêng. Rollup chỉ
hỗ trợ gateway/route và ghi rõ các filter khác không áp dụng vào counter totals.

Hợp đồng API, nguồn dữ liệu, bounds và giới hạn: [Investigation](../docs/investigation.md).
SLO targets vẫn hoãn; không suy false-positive rate hoặc business outcome từ HTTP
status hay dữ liệu logs có thể thiếu.

Admission defaults: route editor và backend dùng 64 request đồng thời/route,
32/IP, stream 8 và upload 4. Node/class budgets vẫn áp dụng; quota tùy chỉnh nhỏ
hơn vẫn hợp lệ. Config API trả `admission` rõ trên mỗi route để giữ semantics
qua thay đổi defaults. [Migration và kiểm chứng](../docs/evidence/website-default-quota.md).

Commit diff lịch sử có thể là `{}` (version bootstrap ban đầu). Component diff
hiển thị `unavailable` khi thiếu dữ liệu; chỉ list rỗng đã ghi nhận mới là `none`,
chỉ boolean `false` mới là `unchanged`. Regression render component thật:
`node --test backend/tests/difference_render.cjs` từ repository root, dùng các
dependencies frontend đã cài, không cần database hoặc browser.
