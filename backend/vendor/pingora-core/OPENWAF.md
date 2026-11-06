# OpenWAF listener extension

Based on pingora-core 0.9.0 (Apache-2.0, upstream LICENSE retained).
Expose `Listeners::build` and `Listeners::cleanup` so the gateway can own its
accept loop, acquire connection/handshake permits before spawning tasks, track
all tasks in a JoinSet and apply finite handshake/shutdown deadlines. Transport
parsing, TLS, HTTP/2 and socket construction remain upstream implementations.

Pin the existing resolved zstd 0.14.3 dependency to avoid an unrelated downgrade
when changing the core package from a registry dependency to a local patch.

Omit upstream runnable examples and their public sample private keys; remove the
corresponding manifest example targets. The gateway uses only the core library.

Phase 8 adds optional, default-preserving peer TLS/header/response-idle timeout
options, opt-in rejection of nonempty HTTP/1 trailers, and per-stream H2 request
body idle timeout/trailer rejection. All changes are safe Rust. H2 idle deadline
survives cancellation of an in-progress body-read future. TLS verification is
unchanged; a configured independent TLS deadline has a distinct error type.
