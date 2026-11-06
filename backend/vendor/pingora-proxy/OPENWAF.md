# OpenWAF transport extension

Based on pingora-proxy 0.9.0 (Apache-2.0, upstream LICENSE retained).
Adds explicit request replay sources, no implicit retry buffering when disabled,
and an attempt wrapper hook for absolute per-attempt deadlines. OpenWAF owns
retry authorization; this transport does not infer permission from a body copy.

Phase 8 bounds the final-header wait with a fixed timer, then switches upstream
reads to response idle. Final-header observations are shared with the request
context through a drop guard, including cancellation during downstream writes.
An observation means entered transport, not remote receipt. HTTP/1 request and
response trailers are rejected only when the gateway opts into this contract.
