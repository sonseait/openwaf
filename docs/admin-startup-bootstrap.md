# Bootstrap admin public khi startup

Cập nhật 2026-11-01. Cách vận hành và cấu hình:
[deploy/vps/README.md](../deploy/vps/README.md),
[Compose startup](../deploy/vps/compose.yaml),
[env example](../deploy/vps/.env.example).

## Hợp đồng vận hành

- `OPENWAF_ADMIN_HOST` là DNS ASCII/punycode exact; admin public dùng HTTPS 443.
  `OPENWAF_ORIGIN_IPV4`/`OPENWAF_ORIGIN_IPV6` là IP public origin, ít nhất một
  family. `OPENWAF_ACME_ACCEPT_TERMS=true` là lựa chọn chấp nhận điều khoản rõ ràng.
- `OPENWAF_CLOUDFLARE_API_TOKEN_FILE` trỏ file private ngoài checkout, có Zone
  Read + DNS Read + DNS Edit. Hostname phải bằng zone hoặc một subdomain trực tiếp;
  reject hostname sâu hơn trước khi sửa DNS.
- Init không có network/socket. Token bootstrap mã hóa bằng ACME key riêng; một
  bản seed mã hóa bằng Admin key được bàn giao qua volume `bootstrap-provider`.
  Service preflight cùng tên có DB/Admin key, kiểm tra queue conflict, import một
  provider Production và reserve apex/wildcard/admin trong một transaction có audit.
  Provider Production cùng zone có sẵn được dùng lại, giữ nguyên credentials/name.
  Gateway đọc handoff read-only và không nhận bootstrap ACME key.
- DB import marker riêng với catalog import; restart không ghi đè provider đã sửa
  hoặc tạo lại provider đã xóa. Provider UI và token file bootstrap rotate độc lập.
  Bootstrap giữ renewal ownership; explicit request trùng identifier trả `409`,
  Applications không tạo owner mới. Job/cert bên ngoài chặn migration, không bị chiếm.
- Worker tự thay A/AAAA/CNAME tại apex/wildcard/admin, kể cả record của bên ngoài:
  apex về origin, wildcard/admin CNAME về apex, proxied/TTL auto. Giữ các subdomain
  khác và MX/TXT. Delegation hoặc record khác ngăn CNAME làm bootstrap dừng. Có
  checkpoint v2; sau đó restart/renew không sửa DNS thủ công của operator.
- Journal durable trước POST/PATCH/DELETE, GET đối soát mất ACK, không gửi lại write
  chưa rõ kết quả. Không có transaction xuyên Cloudflare và PostgreSQL hoặc public
  DNS; migration có thể dừng ở trạng thái một phần và phải hiển thị degraded.
- Native ACME xin một cert với SAN `[zone, *.zone]`: staging trước production,
  hai TXT cùng owner có journal hữu hạn và cleanup theo ownership. Atomic publish
  hai manifest entry dùng chung PEM; admin exact cũ chỉ được retire sau validate.
  Config v2 dùng lại ACME account/state, không sửa immutable config v1. Cert không
  bao phủ subdomain nhiều cấp; DNS wildcard không tự tạo proxy route.
- VPS pull/run cùng `OPENWAF_IMAGE` cho gateway, bootstrap/provider, collector/init;
  không build Rust/frontend trên VPS. Code/Compose cùng phiên bản. Khi nâng cấp lần
  đầu, dừng gateway/worker cũ trước reserve; giữ project, volumes, keys và `.env`.
  [Hướng dẫn migration](../deploy/vps/README.md#nâng-cấp-instance-đã-có-cert-exact).
- Gateway chỉ mở public TLS sau cert readiness; không tạo sẵn user hoặc mật khẩu
  admin. DB chưa có user: `GET /api/v1/auth/setup` trả `setup_required=true`, UI
  nhận username/password do người vận hành chọn và `POST` tạo admin đầu tiên
  (`201`). Hash Argon2id, audit `admin.bootstrap` và advisory lock nằm trong luồng
  setup; request tạo tiếp theo trả `409`, status chuyển `false`. Restart giữ user
  và mật khẩu, database lỗi trả unavailable, không coi như instance trắng.
  Payload API/UI không đổi. Chưa có token setup một lần; giới hạn truy cập bằng
  firewall/VPN/Cloudflare Access đến khi đã tạo admin.
- Init không sinh/mount file mật khẩu admin. Nâng cấp cấu hình VPS tự bỏ đúng
  biến password-file cũ nếu toàn bộ cấu hình còn lại khớp; không xóa secret file
  cũ hoặc user trong DB. Các thay đổi cấu hình khác vẫn cần migration rõ ràng.
- Với DB/config trắng, route `openwaf-admin` và upstream `openwaf-admin-edge`
  được seed bằng validate/prepare, transaction, diff, version 1 và audit
  `config.admin_bootstrap`; account chỉ được tạo qua setup UI/API.
  Restart không seed lại. Draft đã sửa/config đang dùng không bị ghi đè.
- Khi `OPENWAF_ADMIN_PUBLIC=true`, API validate/save/apply/rollback từ chối
  document xóa/sửa route hoặc upstream admin, hoặc thêm exact-host route che
  admin (kể cả khác case/trailing dot). Các payload API không thêm field mới.
  Tắt chế độ public hoặc đổi hostname trên instance cũ cần migration có review.
- Pingora TLS → Axum loopback 9090 phục vụ cả API/static UI. Cookie vẫn
  `__Host-*; Secure; HttpOnly; SameSite=Strict`, Origin chính xác và CSRF cho
  mutations. Policy admin DetectionOnly/PL1, body inspection headers/query-only.
- Route admin có concurrent admission riêng `{requests:64, streams:8, uploads:4,
  per_client:32}`. SSE giữ slot trong thời gian stream mở; quota mặc định cũ
  8/IP có thể trả 429 cho JS/CSS/API khi mở nhiều tab hoặc tải song song, khiến
  UI không khởi động. Node/class/connection limits vẫn áp dụng; đây không phải
  RPS limit hoặc bỏ login rate limit. Route admin vẫn được bảo vệ khỏi sửa qua UI.
- Startup nhận diện **đúng route đóng gói cũ** và nâng quota trong committed
  config và draft qua validate/prepare + transaction, version/diff/audit
  `config.admin_admission_upgrade`; giữ các chỉnh sửa draft khác. Nếu đồng thời
  nâng upstream cũ, dùng chung một version/audit `config.admin_axum_upgrade`.
  Restart không tạo thêm version; custom route/quota không tự bị ghi đè. Cần
  image mới có bản sửa; chỉ đổi VPS worker profile không thay quota trong DB.
- Cert đang hợp lệ cho phép startup khi Cloudflare không truy cập được.
  Native renewal có retry/deadline/shutdown; mất renewal không xóa cert hiện
  tại. Health API có nguồn bootstrap riêng, phase DNS/TLS/provider và timestamp;
  certificate metadata thêm `dns_names` từ SAN thực. Readiness không phải bằng
  chứng renewal thành công; worker logs
  và health state phải được giám sát. Không có cert hợp lệ thì không mở TLS.

## Kiểm chứng bỏ tạo sẵn user (2026-11-01)

Các file thay đổi trong lần này:

- Backend: [bootstrap.rs](../backend/crates/admin/src/bootstrap.rs),
  [lib.rs](../backend/crates/admin/src/lib.rs),
  [startup-init.py](../backend/runtime/startup-init.py),
  [test_startup_init.py](../backend/runtime/tests/test_startup_init.py).
- VPS: [compose.yaml](../deploy/vps/compose.yaml),
  [startup-smoke.py](../deploy/vps/tests/startup-smoke.py),
  [README.md](../deploy/vps/README.md).
- Homelab: [prepare.py](../deploy/homelab/prepare.py),
  [README.md](../deploy/homelab/README.md).
- Tài liệu: file này, [deployment-runbook.md](deployment-runbook.md) và
  [plan.md](../plan.md).

Kết quả:

- `python3 -m unittest discover -s backend/runtime/tests -v`: 31 tests đạt, gồm
  không sinh password admin, giữ keys/DB credentials, nâng cấp cấu hình password
  cũ khi file đã mất hoặc còn tồn tại, và từ chối thay đổi cấu hình ngoài phạm vi.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`
  và `cargo test --workspace`: đạt trong Linux container có native dependencies
  (165 tests đạt, 2 integration tests ignored). macOS fmt/Clippy đạt; workspace
  test dừng ở DNS fixture bind `127.0.0.2` với `AddrNotAvailable`, nên kiểm tra lại
  toàn bộ trong Linux thay vì coi lần macOS là đạt.
- `postgres_startup_leaves_first_admin_to_setup -- --ignored`: đạt với PostgreSQL
  17 thật trong container cô lập, gọi router setup thật. Xác nhận startup/restart
  trước setup không có user; hai POST đồng thời trả một `201` và một `409`, chỉ
  một user/audit; hash Argon2id đúng, setup đóng sau tạo user và DB lỗi trả `503`.
  Test còn kiểm tra route seed/version/audit và giữ draft khi upgrade endpoint.
- Compose config hợp lệ, không còn volume/mount `admin-access`; Python compile
  cho smoke và homelab prepare đạt. `git diff --check` đạt.
- `startup-smoke.py --database new`: đạt với image kiểm thử local ghép gateway/admin
  Linux vừa build và init mới lên bundle runtime đã có. HTTPS xác minh CA/SNI qua
  Pingora → Axum; không có user tạo sẵn, Origin sai không tạo được user, setup
  thành công rồi đóng, login/session/CSRF/SSE hoạt động, restart PostgreSQL/gateway
  giữ user/password/config version. Không build/push release hoặc deploy VPS thật
  trong lần này; không dùng kết quả này để nghiệm thu Cloudflare/ACME public.

## Lựa chọn PostgreSQL trên VPS

`OPENWAF_POSTGRES_CREATE=1` tạo instance bằng `ecr.swissy.shop/c/pgaio:18.6.0`,
UID 1001, volume `postgres-data18` tại `/bitnami/postgresql`. Init chuẩn bị private
password/SQL tạo database và role OpenWAF không superuser. Wrapper đọc password
file trước outer entrypoint của PGAIO; password không nằm trong Compose env/argv.
Gateway dùng port PostgreSQL trực tiếp 5432; pooler loopback dùng session mode,
UI PGAIO không publish cổng.

`OPENWAF_POSTGRES_CREATE=0` đặt scale database service về 0, dependency health của
gateway là optional. Init chỉ đọc `OPENWAF_DATABASE_URL_FILE`, không sinh DB
credentials hoặc SQL tạo role/database. SQLx vẫn tự áp dụng schema migrations
vào database được cấp. URL mặc định `sslmode=verify-full`; CA riêng qua
`OPENWAF_DATABASE_CA_FILE` được copy private vào config. Plaintext cần chọn rõ
`sslmode=disable` trên network riêng. Không tự tạo DB dự phòng khi endpoint lỗi.

Instance marker schema 2 giữ mode/image hoặc hash URL/CA, ngăn đổi database bằng
cách sửa env/secret rồi restart. Marker PostgreSQL 17 cũ bị từ chối, không gắn
volume 17 vào image 18 hoặc tự tạo database trắng thay dữ liệu đang dùng. Migration
engine/credentials cần quy trình backup/restore riêng; không tự nghiệm thu restore.

## Dashboard HTTP và nâng cấp

- Root, static assets và GET/HEAD navigation có Accept `text/html` được Axum phục
  vụ từ thư mục image; route SPA không có phần mở rộng fallback sang `index.html`.
  Asset thiếu, `/api` không tồn tại, file ẩn và path traversal không fallback HTML.
- HTML có CSP cho bundle cùng origin, style inline của Mantine và fonts local;
  API vẫn dùng CSP `default-src 'none'`. Response dùng `no-store`, `nosniff`,
  `Referrer-Policy: no-referrer` và chống nhúng frame.
- `/metrics` yêu cầu Host loopback và session hoặc scrape token; public admin
  Host nhận 404. Static serving không thay auth/Origin/CSRF, multipart limits,
  deadlines, SSE slots hoặc connection budgets của Admin API.
- Axum là upstream đích, không forward request; context chống proxy loop chỉ
  liệt kê listener Pingora. Discovery vẫn loại listener Axum khỏi gợi ý.
- Startup chỉ nâng cấp endpoint edge cũ đã biết và được đúng một route admin
  cùng hostname dùng. Committed config/draft được validate; transaction lưu
  version/diff, tăng draft revision và audit `config.admin_axum_upgrade`, không
  ghi đè thay đổi draft khác. Restart không tạo thêm version. Endpoint tùy chỉnh
  cần kiểm tra riêng trước khi gỡ edge. Giữ ID upstream cũ để bảo toàn references.

## Kiểm chứng local

Môi trường: macOS arm64, Docker Linux arm64; Rust 1.99.1 trong integration image,
Smoke hai mode ngày 2026-11-01 dùng `ecr.swissy.shop/c/pgaio:18.6.0`. Các
Owner integration check ở lần Axum trước dùng PostgreSQL 17. Lần bổ sung external
network chạy lại Rust fmt/Clippy/workspace tests, 14 init tests và hai smoke dùng
PGAIO 18; không chạy lại ignored owner integration riêng. Gateway image build cả
React (lint/typecheck/build) và
Rust, đóng gói `dist` tại `/usr/share/openwaf/admin`, đặt `OPENWAF_ADMIN_UI_ROOT`.
Không có Nginx/Caddy hoặc admin-edge image riêng.

| Kiểm tra                                                   | Kết quả và phạm vi                                                                                                                                                                                                                                                                        |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cargo fmt --all -- --check`                               | Đạt                                                                                                                                                                                                                                                                                       |
| `cargo clippy --workspace --all-targets -- -D warnings`    | Đạt trong Linux với native dependencies, chạy lại khi bổ sung interface inventory                                                                                                                                                                                                         |
| `cargo test --workspace`                                   | 155 tests đạt, 1 ignored; test PostgreSQL có `ignore` được chạy riêng ở lần Axum trước                                                                                                                                                                                                    |
| `python3 -m unittest discover -s backend/runtime/tests -v` | 14 tests init đạt: keys/restart/token/permissions, lựa chọn DB/network, URL/TLS/CA, percent-encoding và chặn retarget/legacy engine                                                                                                                                                       |
| Compose config + image build qua `build/compose.yaml`      | Đạt; một image gồm Rust + frontend + Python/offline init/budgets. Deploy chỉ tham chiếu `OPENWAF_IMAGE`, không có named build context hoặc init image riêng                                                                                                                               |
| PostgreSQL owner integration (lịch sử, trước khi bỏ tạo sẵn user)              | Đạt: hai owner bootstrap đồng thời tạo một account/audit; verify Argon2; restart giữ owner; route bootstrap một lần; upgrade endpoint cũ có version/audit một lần và giữ draft khác; từ chối remove admin                                                                                 |
| `python3 deploy/vps/tests/startup-smoke.py --database new` | Đạt: native seal trong init `network:none`; private state giữ nguyên khi rerun; worker dùng cert hợp lệ khi offline (cả owner ngoài và native-owned với renewal child); không chiếm owner cert bên ngoài                                                                                  |
| HTTPS trong smoke                                          | Đạt: CA/SNI verified qua Pingora → Axum; UI/assets/HEAD/SPA, CSP, API/path traversal boundaries, login/session/CSRF/Origin/SSE, metrics public 404 và setup đóng; gateway graceful stop/start không đổi owner/password/version; SIGTERM dọn cả bootstrap/renewal locks sau khi child dừng |
| `python3 deploy/vps/tests/dns-simulation.py`               | Đã đạt ở lần bootstrap trước (không chạy lại khi chuyển static UI sang Axum): native DNS caller qua TLS đến local Postman simulation, 33 request events; create/current, 403, record conflict, unknown ACK đã/chưa ghi; không POST trùng                                                  |

Simulation artifact và giới hạn ở
[Postman context](../postman/simulations/admin-dns.context.yaml). Không publish
mock hoặc gửi token đến Postman/cloud. Relay local không chuyển authorization
header cho mock log. Trên macOS có thể cần
`OPENSSL_DIR=/opt/homebrew/opt/openssl@3` trước lệnh simulation.

Chạy PostgreSQL test trên **DB trắng cô lập**; cung cấp các environment sau cho
process `cargo test`, không sửa env trong test threads:

```sh
# Values below refer only to a fresh disposable test database/private temp file.
OPENWAF_ADMIN_PUBLIC=true \
OPENWAF_ADMIN_HOST=admin.example.com \
OPENWAF_ADMIN_ORIGIN=https://admin.example.com \
OPENWAF_BOOTSTRAP_TEST_DATABASE_URL=postgres://postgres@postgres:5432/openwaf_bootstrap_test \
cargo test -p openwaf-admin postgres_startup_leaves_first_admin_to_setup -- --ignored
```

Test không cần file mật khẩu ban đầu. Test kiểm tra startup/restart trước setup
không tạo user, hai setup đồng thời chỉ tạo một user/audit, hash Argon2id, setup
đóng sau tạo user và DB unavailable không báo cần setup. Test sử dụng migrations
thật, không chạy vào DB có dữ liệu quản trị. Smoke tạo resources với
prefix ngẫu nhiên rồi dọn đúng resources của nó, không xóa volumes của instance.

Kiểm chứng bổ sung cho database option ngày 2026-11-01:

- `startup-smoke.py --database new`: native init + PGAIO mới + SQLx migrations,
  login/CSRF/SSE, restart cả PostgreSQL và gateway giữ owner/config version.
- `startup-smoke.py --database existing`: PGAIO có sẵn với role/database được
  fixture provision trước, TLS `verify-full` và CA riêng; native init không tạo
  DB credentials/SQL. SQLx từ chối hostname sai và CA không được tin cậy. HTTPS UI,
  auth, SSE, PostgreSQL/gateway restart và shutdown đều đạt.
- Runtime Compose check dùng cấu hình init/PostgreSQL thật, project/volumes/network
  cô lập, gateway thay bằng consumer không publish port: `CREATE=1` chạy đúng một
  database container và đợi healthy; `CREATE=0` chạy đúng không database container,
  vẫn mount optional secrets và thỏa dependency. Tất cả resources test được dọn.
- Python syntax, shell syntax (`bash -n postgres-start.sh`), Compose config cho
  cả hai mode cùng discovery, link tài liệu và `git diff --check` đạt. Không chạy
  vào PostgreSQL/VPS thực của người dùng hoặc gọi public Cloudflare/ACME.

Kiểm chứng bổ sung cho external network ngày 2026-11-01:

- `.env` chọn `OPENWAF_DOCKER_NETWORK_EXTERNAL=true` và tên network thực bằng
  `OPENWAF_DOCKER_NETWORK_NAME`. Compose không còn IPAM/IP tĩnh; network mặc định
  dùng subnet do Docker cấp. Gateway đọc interface IPv4/IPv6 lúc startup bằng
  API an toàn của `nix`, gộp inventory khai báo, tối đa 128 địa chỉ. Không đọc
  interface/Docker trên proxy hot path và không tự thay membership khi chạy.
- `startup-smoke.py --database existing --external-network --ipv6-network` đạt:
  PGAIO có sẵn trên network dual-stack cô lập, URL `verify-full`/CA riêng; gateway
  dùng service/networks từ Compose thật (thay dependency bằng cert fixture, bind
  volumes test và host port ngẫu nhiên). Gateway nối đúng external + private DB
  network, probe HTTP qua DNS alias thành công; validate từ chối mọi IP IPv4/IPv6
  của chính nó và probe từ chối DNS alias tự trỏ. Network thiếu làm `up` lỗi và
  không bị tạo thay thế; `down` xóa network riêng, giữ external network/fixture.
- Smoke trên vẫn kiểm tra HTTPS UI/auth/CSRF/SSE, TLS DB sai hostname/CA, restart
  PostgreSQL/gateway giữ owner/config version và SIGTERM dọn worker locks.
  `startup-smoke.py --database new` cũng đạt với alias managed DB mới
  `openwaf-managed-postgres`, tránh trùng service `postgres` ở shared network.
- Compose config đạt cho bốn tổ hợp managed/external network × new/existing DB,
  có profile discovery. Init tests kiểm tra tên network được đưa vào discovery,
  không còn IP Docker cố định, giữ state khi restart và từ chối đổi topology bằng
  `.env` trên instance đã khởi tạo. Rust tests kiểm tra interface inventory,
  chống loop, manual mode và giới hạn địa chỉ. Build gateway/init, Python syntax,
  links Markdown và `git diff --check` đạt.

Đây là Docker Linux arm64 trong môi trường local, không phải thay đổi network hay
database của stack người dùng. Collector discovery thật không được chạy lại ở
lần này; metadata network đã kiểm tra bằng init tests, các projection tests thuộc
Rust workspace. Chưa nghiệm thu rootless/overlay hoặc topology nhiều shared networks.

Kiểm chứng bổ sung cho deploy bằng image ngày 2026-11-01:

- Build local bằng `build/compose.yaml`, tag `vps-prebuilt-check`, platform
  `linux/arm64`; không build bằng manifest deploy và không push registry. Image
  chứa runtime Python, init executable và budgets, giữ default user gateway
  10001; service init đổi user 0 cùng capability tối thiểu và `network:none`.
- Với `OPENWAF_TEST_IMAGE=ecr.swissy.shop/c/openwaf-gateway:vps-prebuilt-check`,
  hai lệnh smoke `startup-smoke.py --database new` và
  `startup-smoke.py --database existing --external-network --ipv6-network` đạt.
  Native seal/init chạy từ chính image release dưới read-only/cap-drop/network
  isolation; không dùng init image riêng. Auth/HTTPS UI/SSE, DB TLS, chống loop,
  restart/state và cleanup external network vẫn đạt.
- Compose config được kiểm tra với chỉ runtime deployment files, bốn tổ hợp
  database/network và profile discovery: không service nào có `build`, tất cả
  service OpenWAF dùng cùng image; PostgreSQL vẫn cố định PGAIO 18.6.0. Không
  khai báo `OPENWAF_IMAGE` thì config thất bại thay vì tự build/fallback image.
  14 unit tests init, Python syntax, links Markdown và `git diff --check` đạt.
- Không sửa Rust/frontend source trong thay đổi đóng gói này nên không chạy
  lại workspace tests/lint; dùng kết quả lần external network ở trên. Bước build
  image dùng lại cached layers Rust/frontend đã kiểm tra, bổ sung runtime/init.

Tag trên chỉ là artifact local kiểm thử. Cần xuất bản release chứa init trước
khi dùng trên VPS; chưa xác minh pull registry, multi-arch manifest hoặc deploy
trên VPS thật. Tag cũ không được coi như đã có thành phần mới chỉ vì cùng repository.

Sau khi chuyển init/defaults/unit tests sang `backend/runtime/`, 14 unit tests,
image build và smoke `--database new` được chạy lại và đạt; giữ nguyên nội dung
script/budgets, executable path trong image và giao diện deploy. Không chạy lại
Rust/frontend checks vì chỉ đổi vị trí source và đường dẫn đóng gói/tài liệu.

## Kiểm chứng wildcard DNS ngày 2026-11-01

- Đây là bằng chứng lịch sử của v1, được thay thế bằng bundle v2 bên dưới.
  Mã lúc kiểm chứng: [bootstrap DNS](../backend/crates/acme/src/admin.rs) và
  `backend/crates/acme/src/admin/wildcard.rs` (đã được gỡ ở v2).
  Contract vận hành ở file này và [runbook VPS](../deploy/vps/README.md).
  Không đổi schema Admin API, database hoặc frontend.
- [Postman mock](../postman/mocks/cloudflare-admin/default.js),
  [simulation context](../postman/simulations/admin-dns.context.yaml) và
  [runner](../deploy/vps/tests/dns-simulation.py) được mở rộng. Native caller chạy
  qua verified local HTTPS đến Postman simulation: 184 request events, hai test
  integration đạt. Có 22 case wildcard/precedence/failure và năm case create/
  denied/conflict/unknown ACK trước đó. Wildcard hợp lệ và rerun có zero writes;
  exact/parent TXT phải tạo record riêng, pending unknown không được bỏ qua.
- Docker Linux arm64: fmt, workspace Clippy warnings denied, ACME Clippy với
  `integration-test-provider` và workspace tests đạt: 160 passed, 1 ignored
  PostgreSQL integration. ACME local có 18 unit tests đạt; hai test HTTP simulation
  ignored được chạy riêng bằng runner. Node syntax, Python AST, links nội bộ và
  `git diff --check` đạt. Không chạy frontend build vì không sửa UI.
- Chỉ kiểm chứng caller với fixture local, không thay DNS Cloudflare thật hoặc
  build/push image. Đối chiếu wildcard precedence với
  [tài liệu Cloudflare](https://developers.cloudflare.com/dns/manage-dns-records/reference/wildcard-dns-records/).
  Empty non-terminal trên Advanced nameservers (Enterprise opt-in) khác Standard
  nameservers và chưa được nghiệm thu; chain qua zone khác cần đối soát thủ công.

## Chẩn đoán và giới hạn còn lại

### Chẩn đoán DNS-01 bổ sung ngày 2026-11-01

- Tách propagation checker vào
  [propagation.rs](../backend/crates/acme/src/propagation.rs). Timeout ghi tên
  challenge, resolver, số lần thử và kết quả cuối: timeout, DNS response code/
  negative TTL hoặc TXT chưa chứa challenge hiện tại. Không ghi TXT values hoặc
  raw resolver error payload. Parent ghi staging/production, mode và exit status.
- `OPENWAF_ACME_DNS_RESOLVER` chọn một `IP:port` (IPv6: `[address]:port`), ưu tiên
  hơn config resolver; rỗng/bỏ biến giữ config/system DNS. VPS Compose chỉ truyền
  biến này vào `admin-bootstrap`, child kế thừa qua environment. Không sửa config
  bất biến nên không làm instance cũ lỗi migration khi recreate worker.
  [Hướng dẫn xử lý](../deploy/vps/README.md#restart-lỗi-và-dữ-liệu-bền-vững).
- macOS: ACME unit tests và package Clippy đạt. Docker Linux arm64/native
  dependencies: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings` và
  `cargo test --workspace --locked` đạt: 158 passed, 1 ignored PostgreSQL test.
  DNS fixture dùng UDP thật trên loopback, kiểm tra NXDOMAIN rồi TXT split đúng,
  TXT cũ, SERVFAIL, resolver không trả lời, deadline và redaction. Compose config
  xác nhận override chỉ vào worker. `git diff --check` đạt.
- Chỉ thay phần DNS lookup/chẩn đoán, không thay HTTP payload Cloudflare hoặc
  Admin API/UI. Không chạy lại HTTP simulation hay frontend build. Chưa build/
  publish image mới, áp dụng override lên VPS hoặc nghiệm thu public issuance;
  TXT thấy qua resolver công khai không chứng minh khớp challenge worker hiện tại.

### Các gate public và vận hành chưa kiểm chứng

- Cloudflare public token permissions/zone/proxy, DNS propagation thực, CAA,
  edge certificate, Full(strict), firewall origin, IPv6 và target VPS.
- Lần xin/gia hạn cert public qua staging/production, restart giữa từng ACME
  bước và hot reload cert mới của profile startup trên Internet. Smoke dùng CA
  private có verify, không thay bằng chứng Let's Encrypt staging công cộng.
- PATCH/DELETE HTTP đã được mô phỏng cho v2 trong báo cáo bên dưới; chưa kiểm
  chứng các thao tác này với Cloudflare thật. Crash/power-loss tại mọi filesystem boundary chưa có
  fault injection; writer lock/journal recovery cần operator đối soát.
- Profile startup chưa có MFA/RBAC/backup-restore nghiệm thu, HA, ClickHouse hoặc
  Prometheus tích hợp sẵn; không thay các gate còn mở của `plan.md`.

Build frontend trước đó có npm audit báo 12 moderate vulnerabilities và Vite
chunk warning; không sửa dependencies trong thay đổi bootstrap này. Không
quảng bá capacity hoặc production acceptance từ các kiểm tra local ở trên.

## Kiểm chứng bundle apex/wildcard và provider v2 ngày 2026-11-01

Thay đổi hiện tại gồm [đối soát DNS một lần](../backend/crates/acme/src/admin/provision_dns.rs),
[bootstrap ACME](../backend/crates/acme/src/admin.rs),
[publish bundle](../backend/crates/acme/src/publish.rs),
[provider preflight](../backend/crates/admin/src/certificate_bootstrap.rs) và
[migration database](../backend/crates/admin/migrations/202611010001_bootstrap_certificates.sql).
Runtime init, Compose, Certificates/Operations/Health UI và các tài liệu contract
đã được đồng bộ. Các bằng chứng wildcard read-only v1 ở trên chỉ giữ làm lịch sử.

- Linux arm64 với native dependencies: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` và `cargo build --workspace --locked` đạt.
  Workspace có 165 tests đạt, hai PostgreSQL tests ignored; test import mới được
  chạy riêng bên dưới. Test publication kiểm tra SAN thiếu không thay manifest cũ,
  retire cert exact sau validate và hai entry dùng chung generation PEM.
- Frontend: `npm run lint`, `npm run typecheck`, `npm run build` và
  `npm run format:check` đạt. Vite còn cảnh báo chunk lớn hơn 500 kB.
  Runtime init có 28 unit tests đạt, gồm seed mã hóa riêng, private permissions,
  restart và không ghi đè credential seed sau khi operator rotate bootstrap token.
- `python3 deploy/vps/tests/dns-simulation.py --acme` đạt: hai Rust HTTP
  integration tests qua verified local HTTPS và Postman simulation, tổng 279
  request events. Các case gồm IPv6-only/dual-stack, admin=apex, reject admin
  nhiều cấp, giữ MX/TXT/subdomain khác, POST/PATCH/DELETE mất ACK và giữ chỉnh sửa
  thủ công sau checkpoint. Mock không thay DNS thật.
- [ACME harness](../deploy/vps/tests/acme_simulation.py) dùng Pebble 2.8.0 với
  CA private và UDP TXT server: order/CSR/PEM có đủ apex + wildcard SAN, hai TXT
  cùng owner tồn tại đồng thời rồi được cleanup, restart skip cert current,
  forced renewal dùng account cũ. SIGTERM trong propagation dọn TXT, không publish
  bundle dở dang. Kết quả này không thay thế Let's Encrypt staging công cộng.
- `python3 deploy/vps/tests/provider-bootstrap.py` đạt với PostgreSQL 17 riêng:
  queue conflict/capacity/audit failure rollback nguyên tử; credential mã hóa
  lại theo provider ID; rerun không ghi đè provider đã sửa hoặc tạo lại provider
  đã xóa; identity mismatch bị từ chối; dùng lại Production provider cùng zone.
- Image kiểm thử riêng `openwaf-bundle:local-check` chứa native Linux arm64 debug
  binaries từ source cuối cùng cùng frontend/runtime hiện tại. Lệnh
  `OPENWAF_TEST_IMAGE=openwaf-bundle:local-check python3 deploy/vps/tests/startup-smoke.py --external-network`
  đạt với gateway Pingora/Axum HTTPS thật và PostgreSQL: tự import Production
  provider; reserve apex/wildcard/admin trả `409`; telemetry trả hai SAN thực;
  Health phân biệt DNS/TLS/provider/renewal và không lộ private paths/credentials.
  Auth/CSRF/SSE, existing Docker network, gateway connection test/chống loop,
  restart giữ owner/password/config và SIGTERM giải phóng cả hai worker locks đạt.
  Test Health đơn vị riêng kiểm tra renewal degraded/stale dù cert vẫn còn loaded.
- Python AST, Postman context YAML và `git diff --check` đạt. Các container,
  network và database do các harness tạo đã được dọn; không tác động stack khác.

Chưa build/push release image, triển khai lên VPS, thay DNS Cloudflare public hoặc
xin/gia hạn cert Let's Encrypt staging/production công cộng. Smoke emulates
persisted v2 bootstrap với cert fixture; Pebble harness kiểm tra issuance riêng.
Chưa có fault injection power-loss tại mọi filesystem boundary hoặc kiểm chứng
hot reload public cert trên VPS. Khi nâng cấp dùng image mới cùng Compose mới và
theo [hướng dẫn migration](../deploy/vps/README.md#nâng-cấp-instance-đã-có-cert-exact).
