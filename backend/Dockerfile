# Build from repository root; publish --target init and --target gateway together.
FROM node:22-bookworm-slim AS dashboard
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run lint && npm run typecheck && npm run build

FROM rust:1.99.1-bookworm@sha256:e12566d5abc17a0da741628782cdb504b68b8961f5bfcf677936bf3e8b32de29 AS build
RUN apt-get update && apt-get install -y --no-install-recommends libmodsecurity-dev libssl-dev pkg-config clang cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/crates ./crates
COPY backend/vendor ./vendor
RUN cargo build --workspace --release --locked -j 4

FROM debian:bookworm-slim AS init
ARG OPENWAF_RELEASE=development
LABEL org.opencontainers.image.version=$OPENWAF_RELEASE io.openwaf.role=init
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates python3 libmodsecurity3 libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/openwaf-gateway /build/target/release/openwaf-acme /build/target/release/openwaf-security /usr/local/bin/
COPY --chmod=0555 backend/runtime/startup-init.py /usr/local/bin/openwaf-startup-init
COPY backend/runtime/vps_profiles.py /usr/local/bin/vps_profiles.py
COPY backend/runtime/resource-budgets.json backend/runtime/clickhouse.xml backend/runtime/crowdsec.json backend/runtime/crowdsec-bootstrap.sh /defaults/
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/openwaf-startup-init"]

FROM debian:bookworm-slim AS native-runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libmodsecurity3 modsecurity-crs libssl3 python3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/openwaf-gateway /build/target/release/openwaf-admin /build/target/release/openwaf-discovery /build/target/release/openwaf-acme /build/target/release/openwaf-security /usr/local/bin/
COPY backend/runtime/collect-runtime-libs.py /build-tools/collect-runtime-libs.py
RUN python3 /build-tools/collect-runtime-libs.py /native-root /usr/local/bin/openwaf-* \
    && mkdir -p /native-root/usr/local/bin /native-root/etc/modsecurity /native-root/usr/share/modsecurity-crs \
    && cp /usr/local/bin/openwaf-* /native-root/usr/local/bin/ \
    && cp -aL /etc/modsecurity/. /native-root/etc/modsecurity/ \
    && cp -aL /usr/share/modsecurity-crs/. /native-root/usr/share/modsecurity-crs/

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS gateway
ARG OPENWAF_RELEASE=development
LABEL org.opencontainers.image.version=$OPENWAF_RELEASE io.openwaf.role=gateway
COPY --from=native-runtime /native-root/ /
COPY --from=dashboard /frontend/dist /usr/share/openwaf/admin
COPY backend/runtime/modsecurity.conf /usr/share/openwaf/modsecurity.conf
ENV OPENWAF_ENV_FILE=/etc/openwaf/gateway.env OPENWAF_RULES=/usr/share/openwaf/modsecurity.conf OPENWAF_ADMIN_UI_ROOT=/usr/share/openwaf/admin
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/etc/ssl/certs
USER 10001:10001
WORKDIR /tmp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/openwaf-gateway"]
