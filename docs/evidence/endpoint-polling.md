# Endpoint polling and configuration cache — 2026-11-02

## Changed behavior and files

- [Admin endpoint API](../../backend/crates/admin/src/operations.rs): optional
  `summary=true` projects health onto endpoint identities from one retained active
  snapshot; the default full response remains compatible. Reuses one health
  observation for diagnostics and maintenance alternatives, with eligibility
  counted once per pool rather than rescanning all endpoints for each endpoint.
- [Endpoint controls](../../frontend/src/OperationalControls.tsx),
  [table](../../frontend/src/EndpointTable.tsx),
  [Uptime monitors](../../frontend/src/UptimeMonitors.tsx) and
  [health state/types](../../frontend/src/uptime-state.ts): poll summary every five
  seconds, without a config-index join or health-driven `/config` fetch. Missing,
  pending, paused, failed and expired observations remain Unknown.
- [Config cache](../../frontend/src/config-cache.ts) and
  [API client](../../frontend/src/api.ts): only the `config` query is fresh for
  30 seconds and retained for 60 seconds after unmount. Existing local mutation
  invalidation remains; an observed different active version invalidates cached
  config. Inactive queries do not refetch until mounted. Logout/401 cleanup and
  other protected queries' zero-retention policy are unchanged.
- Contracts/documentation: [operations](../operations.md),
  [endpoint table](../route-maintenance.md), [frontend](../../frontend/README.md).
- Regressions: Rust tests in the API module;
  [Node state/cache tests](../../backend/tests/endpoint_polling.mjs);
  [isolated API fixture](../../backend/tests/endpoint_polling.py) and
  [Chromium checks](../../backend/tests/endpoint_polling_browser.cjs).

## Checks run

macOS host, native Rust/OpenSSL/libmodsecurity, Docker PostgreSQL 17 and installed
Chrome through Playwright outside the product dependency tree. API/browser
fixture uses a fresh temporary database, random session/master credentials,
loopback listeners and built `frontend/dist`; it removes its gateway/container
after execution. No production instance or provider API was used.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Failed at existing DNS test binding `127.0.0.2` (`AddrNotAvailable`) |
| Workspace tests excluding that DNS test | Reached existing checkpoint test; failed reading Linux `/proc` files on macOS |
| Workspace tests excluding both platform-dependent tests | 192 passed, 6 ignored, 2 filtered; exit 0 |
| `node --test backend/tests/endpoint_polling.mjs` | 3 passed; exit 0 |
| Frontend `npm run lint`, `npm run typecheck`, `npm run build`, `npm run format:check` | Passed; Vite retains its existing >500 kB chunk warning |
| `cargo build -p openwaf-gateway` | Passed |
| Isolated `python3 tests/endpoint_polling.py` with `OPENWAF_PLAYWRIGHT_MODULE` | API + Chromium checks passed; exit 0 |
| `git diff --check` | Passed |

The compatible workspace command, from `backend/`, was:

```sh
cargo test --workspace -- \
  --skip probe::tests::dns_cache_expires_and_connection_uses_new_address \
  --skip checkpoint::tests::atomic_roundtrip_integrity_permissions_and_bounds
```

The new native tests cover identical addresses in different pools, fresh/pending
health, response projection, unchanged full diagnostics, maintenance eligibility,
and retained snapshot identity across configuration publication/reordering.
Node tests cover TTL boundaries, missing observation fields, pause/error,
config reuse after unmount, stale revalidation and version/mutation invalidation.

Chromium observed at least three Uptime polls over 10.5 seconds, then Discovery
polling over 5.5 seconds: all endpoint reads used summary and there were **zero
`/config` requests** in these health views. Pause stopped polling for another
5.5 seconds. Playground fetched config once; navigation to Service Map reused it.
A real apply incremented the version; Discovery invalidated the inactive cache
without fetching config, and returning to Playground fetched the new config.
There were no browser page errors. API checks also verified authentication,
invalid query rejection and unchanged default full response shape.

In the one-admin-endpoint local fixture, the uncompressed JSON response body was
**994 bytes full / 654 bytes summary** (340 bytes less, about 34%). This is a
fixture observation, not a production bandwidth or latency benchmark. Config
payload size, endpoint count and address diagnostics vary by deployment.

## Remaining limits

No production deploy, multi-endpoint browser load benchmark or long soak was run.
The unfiltered workspace suite is not green on this macOS environment; the two
Linux-dependent tests were not modified. Six opt-in integration tests remained
ignored by the workspace command. Config freshness is bounded reuse on navigation,
not a background configuration watcher or cross-tab draft synchronization. Full
status and detailed history APIs remain available and can still have large
payloads; the polling summary omits their per-address detail.
