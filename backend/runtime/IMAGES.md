# Split OpenWAF images

Build from the repository root. Publish both targets from the same checkout and use the same release tag; do not combine initializer defaults and gateway binaries from different releases.

```sh
docker build --build-arg OPENWAF_RELEASE=split-test --target init -f backend/Dockerfile -t openwaf-init:split-test .
docker build --build-arg OPENWAF_RELEASE=split-test --target gateway -f backend/Dockerfile -t openwaf-gateway:split-test .
OPENWAF_TEST_SPLIT_IMAGES=1 python3 -m unittest discover -s backend/runtime -p test_split_images.py
python3 -m unittest discover -s backend/runtime -p test_runtime_libs.py
python3 backend/runtime/smoke-distroless.py
```

`init` contains Python, the offline filesystem initializer and `/defaults`, plus the gateway resource validator and native ACME/security credential-sealing helpers. It has no dashboard and does not run the proxy: its entrypoint remains the one-shot initializer. Keeping these helpers preserves native encryption and resource validation rather than bypassing them. Existing service-specific users and mounts remain authoritative.

`gateway` is the default final target and uses digest-pinned distroless cc-debian12. It retains all five Rust executables because Admin owns native ACME children, bootstrap uses the Rust Admin/ACME binaries and the collector shares the release. It includes dashboard, CRS, native shared-library dependencies and CA certificates; it has no Python, shell, package manager or initializer. UID/GID remains 10001:10001. Native dependencies are collected only from trusted release binaries in a Debian12 donor stage; Python and ldd are not copied to the final image.

Debug from the host/container network namespace or a disposable helper, not `docker exec ... sh`. Do not mount the Docker socket into gateway. A healthy ClickHouse container is not proof of gateway connectivity: retain the deployment namespace and gateway-origin ping gates.

The smoke test uses disposable network/containers, read-only non-root gateway and bounded tmpfs. It verifies clean forwarding, real CRS SQLi blocking without upstream delivery, and graceful SIGTERM. It is not an ACME staging lifecycle, managed database migration or backup/restore acceptance test. Test both architectures before publishing a multi-arch release; a manifest listing alone is insufficient.
