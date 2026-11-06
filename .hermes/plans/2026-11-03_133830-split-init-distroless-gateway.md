# Tách init image và distroless runtime cho OpenWAF

## Goal

Publish hai image cùng release: init có Python cho chuẩn bị filesystem/offline, và gateway dựa trên distroless cho Rust runtime; giữ nguyên dữ liệu, bảo mật và ownership.

## Context và assumptions

- Root workspace: `/Users/eric/Codes/openwaf`. Đọc `AGENTS.md`, `plan.md` và skill `openwaf-deployment` trước implementation.
- `backend/Dockerfile` hiện build dashboard và toàn bộ Rust workspace; final Debian bookworm-slim chứa Python, libmodsecurity3, CRS, OpenSSL, năm Rust binaries và startup-init Python.
- `deploy/ansible/templates/compose.yaml.j2` dùng một image cho startup-init, dependencies-init, crowdsec-seal, gateway, collector, admin-bootstrap và bootstrap-provider.
- Chỉ ba service startup-init/dependencies-init/crowdsec-seal cần chuyển sang init image. Admin bootstrap là tiến trình ACME dài hạn, không phải init filesystem; bootstrap-provider chạy Rust Admin. Giữ chúng trên runtime image.
- Gateway gọi native ACME child: runtime phải còn `openwaf-acme`; không cắt chỉ còn binary gateway.
- Không dùng scratch/static hay musl: Pingora/OpenSSL/libmodsecurity động cần glibc và thư viện native tương thích Debian 12.
- Dùng `gcr.io/distroless/cc-debian12:nonroot` làm base đề xuất; xác minh tag, architecture và pin multi-arch digest trước khi viết Dockerfile. Tiếp tục UID/GID 10001:10001 để khớp storage hiện có, không đổi thành UID 65532 của base.
- Không mặc định rollout VPS. Deliverable implementation là build artifacts + kiểm thử; deploy production cần người dùng yêu cầu riêng.
- Workspace có thay đổi dependency image chưa commit: ClickHouse 26.8.36.3-distroless, Prometheus v3.15.1-distroless và CrowdSec v1.8.2. Giữ nguyên các thay đổi đó. Recheck git status trước sửa.

## Architecture / proposed approach

Giữ một multi-stage `backend/Dockerfile` để build Rust/frontend một lần, expose target `init` và `gateway` (gateway là final/default target). Init dùng Debian slim + Python + defaults cần initializer; gateway dùng distroless cc-debian12 + Rust executables, dashboard, CRS/config và native shared-library closure. Mỗi release khai báo rõ hai image references độc lập, cùng release ID để ngăn ghép nhầm init/runtime; không tự suy ra init tag từ gateway digest.

## Implementation tasks

### 1. Chốt inventory phụ thuộc và test command (3–5 phút)

Read-only:

```sh
git status --short
```

Dùng read_file/search_files (không dùng sed) đọc các file sau:
- `backend/Dockerfile`
- `backend/runtime/startup-init.py`, `backend/runtime/vps_profiles.py`
- `backend/runtime/modsecurity.conf`
- `deploy/ansible/templates/compose.yaml.j2`, `deploy/ansible/templates/vps.env.j2`
- `deploy/ansible/defaults.yml`, `deploy/ansible/tasks/validate.yml`, `deploy/ansible/tasks/runtime.yml`
- `deploy/ansible/playbook.yml` (cơ chế load defaults)
- `deploy/ansible/tests/integration/compose_fixture.py`, `startup-smoke.py`, `dependencies-smoke.py`, `resource-profiles.py`
- `deploy/homelab/server.py`, `prepare.py`, `compose.openwaf.yaml`, `compose.security.yaml`

Tìm usages `OPENWAF_IMAGE`, `openwaf_image`, `openwaf-startup-init`, `python3`, `wget`, `Command::new`, `docker build`, image build/push scripts trong toàn repo, không đọc secrets/inventory private. Ghi trong PR các runtime paths được mở bằng code: CRS includes, CA certificates, shared libs, ACME binary và UI root.

Acceptance: xác định chính xác ba filesystem-init service, toàn bộ nơi build/render image và tests đang phụ thuộc Python trong runtime. Không tự thêm service Prometheus vào Ansible.

### 2. RED: thêm contract test image split (3–5 phút)

Tạo `deploy/ansible/tests/test_image_split.py`, dùng unittest + YAML/Jinja/Compose harness sẵn trong `test_automation.py` thay vì một renderer mới. Mở rộng fixtures settings bằng `openwaf_init_image: registry.invalid/openwaf-init:release-test`.

Assert render model:
- startup-init/dependencies-init/crowdsec-seal dùng init reference.
- gateway/collector/admin-bootstrap/bootstrap-provider dùng runtime reference.
- init services giữ entrypoint/command/user/mounts/dependency conditions.
- gateway vẫn có namespace readiness gate và TLS kiểm tra hiện có.
- thiếu/blank init image fail validation trước sửa container.
- hai refs digest và tagged refs hợp lệ; reject malformed references theo cùng rule hiện hành của gateway, không tự đổi chính sách latest trong task này.

Run:

```sh
deploy/ansible/.venv/bin/python -m unittest discover -s deploy/ansible/tests -p test_image_split.py -v
```

Expected RED: các assert service routing hoặc validation fail vì chưa có init setting. Không coi missing imports/test syntax là regression RED hợp lệ.

### 3. GREEN: thêm init image contract vào Ansible (3–5 phút)

Edit:
- `deploy/ansible/defaults.yml`: thêm `openwaf_init_image: ""`, bắt buộc explicit.
- `deploy/ansible/templates/vps.env.j2`: thêm `OPENWAF_INIT_IMAGE={{ openwaf_init_image }}`.
- `deploy/ansible/tasks/validate.yml`: validate init reference cùng gateway; không đọc credentials.
- `deploy/ansible/templates/compose.yaml.j2`: startup-init anchor riêng `${OPENWAF_INIT_IMAGE:?set published OpenWAF init image tag or digest}`, dependencies-init/crowdsec-seal alias init; runtime anchor riêng cho bốn Rust services. Không vô tình để anchor gateway trên startup-init.
- `deploy/ansible/tasks/runtime.yml`: bảo đảm fingerprint chứa cả hai refs; init image đổi phải kích hoạt release recreation.
- `deploy/ansible/inventory.example.yml`: document field init cạnh gateway; không sửa inventory thực chứa private values.

Rerun task 2: all green. Run syntax-check ở task 9. Review chỉ field image thay đổi, mounts/ownership không đổi.

### 4. RED/GREEN: tách target init (3–5 phút)

Edit `backend/Dockerfile`: preserve dashboard/build stages. Thêm target `init` dựa trên Debian bookworm-slim, Python 3 + CA (chỉ package cần từ dependency inventory), copy startup-init.py, vps_profiles.py, defaults dưới paths cũ. Init ENTRYPOINT là `/usr/local/bin/openwaf-startup-init`; explicit USER 10001:10001, service root override hiện có tiếp tục hoạt động.

Build và verify:

```sh
docker build --target init -f backend/Dockerfile -t openwaf-init:split-test .
docker run --rm --entrypoint python3 openwaf-init:split-test -c 'import pathlib; assert pathlib.Path("/usr/local/bin/openwaf-startup-init").is_file(); assert pathlib.Path("/defaults/resource-budgets.json").is_file(); print("init-files-ok")'
```

Expected `init-files-ok`. Add assertions trong image contract tests rằng init không chứa gateway binary, frontend/CRS hay compiler. Verify startup-init commands trên scratch volumes bằng integration harness, không gọi trên host filesystem production.

### 5. Build native closure donor (3–5 phút)

Trong `backend/Dockerfile`, thêm Debian bookworm dependency donor stage cài CA/libmodsecurity3/modsecurity-crs/libssl3 (không Python). Build container kiểm tra bằng `ldd` tất cả năm Rust executables và libmodsecurity. Tạo deterministic closure script `backend/runtime/collect-runtime-libs.py` chạy chỉ trong donor/build stage, không copy Python vào final.

Script contract: accept executable input paths và output root; dùng ldd trên binaries tin cậy; reject `not found`, nonabsolute libs, collision khác bytes, và lỗi command; copy lib symlinks cùng resolved file giữ absolute layout, include ELF interpreter, audit libraries dlopen nếu có. Không copy toàn bộ `/usr/lib` hoặc `/lib`; không tự claim minimal closure khi chưa test libmodsecurity initialization.

RED/GREEN unit tests tại `backend/runtime/tests/test_runtime_libs.py`: fixture ldd parser (normal/loader/vdso/missing), symlink preservation, collision failure. Run `python3 -m unittest discover -s backend/runtime/tests -p test_runtime_libs.py -v`; expected all cases pass. Check runtime GLIBC requirements phù hợp Debian12 trước task 6.

### 6. Distroless gateway target (3–5 phút)

Verify base with `docker buildx imagetools inspect gcr.io/distroless/cc-debian12:nonroot`; pin returned index digest, không đoán digest.

Final `gateway` stage copies verified library closure, five executables, dashboard, modsecurity.conf, CRS tree và CA paths inventory xác nhận. Giữ ENV OpenWAF paths, USER 10001:10001, WORKDIR /tmp, STOPSIGNAL SIGTERM và exec-form gateway ENTRYPOINT. Không copy defaults initializer hay Python; không thêm shell/package manager/curl vào final. Base filesystem files như passwd/nss phải khớp UID/DNS resolution; test numeric user thay vì đổi quyền bind mounts.

```sh
docker build --target gateway -f backend/Dockerfile -t openwaf-gateway:split-test .
```

Expected success, không missing ELF/shared libraries. Add archive inspection test bằng Docker export/tar từ stopped disposable container: reject `/bin/sh`, Python executables, apt/dpkg, compiler; require gateway/acme/admin/discovery/security, UI và CRS. Không chạy `sh -c` trong distroless. Healthchecks hiện có exec binary ACME giữ nguyên.

### 7. Adapt integration harness, không đưa Python trở lại runtime (mỗi file 3–5 phút)

- `deploy/ansible/tests/integration/compose_fixture.py`: accept independent init image input.
- `startup-smoke.py`, `dependencies-smoke.py`, `resource-profiles.py`: add explicit `--init-image`; supply `openwaf_init_image` to rendering. Read argparse hiện tại trước chọn commands.
- `dependencies-smoke.py`: remove `execute(gateway, python3, ...)` introduced by old smoke. Probe/query HTTP bằng test helper container chia sẻ namespace gateway hoặc host nsenter; helper image chỉ trong test, không cấp Docker socket/gateway volume secrets. Bounded timeout, cleanup finally.
- Các test cần sửa file init dùng init image hoặc existing fixture holder, không shell trong gateway.
- Add regression recreate gateway while leave sidecars stale on disposable project, run playbook namespace repair tasks, verify namespace equality và HTTP query afterwards. Không phá production namespace để diễn tập.

Acceptance: init repeat-run idempotent, data/key retained; thiếu key đúng là fail; startup, WAF transaction/CRS load, routing/DNS/TLS native ACME child launch hoạt động; request bị WAF chặn không tới upstream. Test runtime stop/cancel reaps child như hiện có; không giảm protection chỉ để green.

### 8. Homelab và release docs (3–5 phút/file)

- `deploy/homelab/server.py`, `prepare.py`: trace exact initializer invocation trước sửa, đưa filesystem init sang explicit init reference; runtime service images vẫn gateway. Không đổi CrowdSec image vừa pin.
- `deploy/homelab/compose.openwaf.yaml`: chỉ thay image references nếu cần theo launcher, giữ storage/network.
- `deploy/ansible/README.md`, `deploy/ansible/docs/runtime.md`, root build/release docs tìm từ task 1: hai build/push commands và hai refs cùng release, one-shot image không chạy lâu dài, distroless debug qua host namespace/helper thay vì docker exec shell.
- Tag `openwaf-init:<release>` và `openwaf-gateway:<release>` build cùng commit; publisher push cả hai rồi mới cập nhật inventory. Nếu runtime có release marker, assert same release ID; nếu chưa có, thêm nonsecret build label dùng shared build ARG và ghi kiểm tra same-release vào preflight/test, không tự suy ra từ digest string.

Chỉ commit khi người dùng cho phép. Chia local commits đề xuất: image-contract, Docker split, smoke/docs. Không push/commit trong plan turn.

## Tests / validation và delivery gate

Chạy các command chắc chắn tồn tại:

```sh
deploy/ansible/.venv/bin/python -m unittest discover -s deploy/ansible/tests -p 'test_*.py'
ANSIBLE_CONFIG=deploy/ansible/ansible.cfg deploy/ansible/.venv/bin/ansible-playbook -i 'openwaf,' deploy/ansible/playbook.yml --syntax-check
OPENWAF_DISCOVERY_EXCLUDE=127.0.0.1:8123 OPENWAF_DOCKER_GID=0 docker compose -f deploy/homelab/compose.openwaf.yaml -f deploy/homelab/compose.security.yaml config --quiet
git diff --check
```

Expected tests green, syntax/config successful, diff check silent. Existing full suite previously had assertions about openwaf_pull/ latest inconsistent with defaults: reproduce baseline and distinguish them; do not silently loosen tests or claim complete green. Run integration script `--help` to use real flags; after task 7 expose and document exact runnable build/init/runtime commands with expected PASS lines. Test amd64 và arm64 images hoặc explicitly report unverified architecture; inspect manifest alone không chứng minh runtime works.

Production acceptance khi được yêu cầu: backup/config/master-key policy hiện có trước upgrade; deploy một VPS trước; init completes, gateway ready, namespace gate passes, `/api/v1/history/statistics` authenticated returns 200; writer health recovers after five-minute write; không hứa restore dropped history. Không bypass TLS/ownership/security guards.

## Risks / tradeoffs / open questions

- Hai image tăng release coordination và cần explicit init reference. Không fallback init sang distroless gateway.
- Shared-library closure và native CRS runtime data là rủi ro chính; `--version` đơn lẻ không đủ chứng minh WAF/ACME/TLS.
- Distroless giảm tools/attack surface, không đảm bảo vulnerability-free; generate SBOM/scan cả native libs và base.
- Gateway vẫn chứa admin/discovery/security/acme binaries để giữ hai-image scope. Tách collector/admin thành nhiều image là ngoài yêu cầu.
- Init mặc định Debian slim để giữ Python; init chỉ chạy offline one-shot với mounts/quyền tối thiểu. Nếu user bắt buộc init cũng distroless, đó là scope riêng: python3-debian12 hoặc rewrite initializer Rust cần tests/review độc lập.
- Không hot migrate dữ liệu ClickHouse hay đổi dependency images ngoài các edits đã có.
- Không đảm bảo zero downtime: recreate gateway vẫn gián đoạn single-node, sidecar repair không restart gateway nhưng tạo khoảng dependency outage hữu hạn.
