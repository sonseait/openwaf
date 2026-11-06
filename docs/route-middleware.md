# Route middleware

Route policies are configured in **Configuration → Routes → Request middleware**.
Save, review/apply and rollback use the existing authenticated configuration API.
No new configuration endpoint or database migration is required: route documents
remain versioned JSON in PostgreSQL. Old documents omit `middleware`; the default
is no rewrite, custom headers, CORS or external authentication. Existing redirects
remain fixed unless preservation is explicitly enabled.

## Request order

1. Capture one immutable snapshot and route using the original hostname/path/method.
2. Reject conflicting framing and identity headers; enforce admission, ACL, rate limit
   and CrowdSec. Remove client-supplied configured ForwardAuth identity headers.
3. Validate CORS, content and body limits, then run the existing WAF inspection scope.
4. Answer an allowed CORS preflight locally. Otherwise prepare a rewritten path and
   call ForwardAuth if enabled. Authentication uses the original URL and method.
5. Produce a configured redirect, or send the application request with its rewritten
   path, custom request headers and verified identity headers. Routing is not rerun.
6. Apply custom response headers, typed security headers and CORS. Typed security
   headers take precedence. ForwardAuth routes always send `Cache-Control: private,
   no-store`; do not configure a CDN to override this protection.

Neither ACL allow, successful authentication nor CORS bypasses WAF. With full body
inspection, WAF completes before either the auth service or application is contacted.
The existing explicit streaming inspection scope remains headers/query only.
Middleware is opt-in per route; it is not an arbitrary ordered plugin chain.

## Redirects

```json
{
  "id": "http-to-https",
  "hostname": "app.example.org",
  "path": "/",
  "path_match": "prefix",
  "upstream": "app",
  "redirect": {
    "url": "https://app.example.org/",
    "status": 308,
    "http_only": true,
    "preserve_path": true,
    "preserve_query": true
  }
}
```

`http://app.example.org/deep/path?x=%2B&x=2` redirects to
`https://app.example.org/deep/path?x=%2B&x=2`. Preservation copies the raw path/query;
query values are not parsed, decoded or logged. The target authority is fixed and
validated; the client's Host never becomes an interpolated redirect target.
`preserve_path` requires a root target path, and `preserve_query` requires a target
without a query. Either flag defaults to false. Statuses are 301/302/303/307/308;
prefer 307/308 when the client must preserve the method/body.

`http_only` requires an upstream for HTTPS fallback. The gateway needs a separately
configured HTTP listener/deployment to receive HTTP requests; adding a redirect
policy does not open port 80 or add another listener to the Compose template.

## Path rewrite and custom headers

The following is the `middleware` object on a route:

```json
{
  "rewrite": {"strip_prefix": "/grafana", "add_prefix": "/internal"},
  "request_headers": {
    "set": [{"name": "X-Environment", "value": "homelab"}],
    "remove": ["X-Debug"]
  },
  "response_headers": {
    "set": [{"name": "X-Environment", "value": "homelab"}],
    "remove": ["X-Powered-By"]
  }
}
```

`/grafana/a?x=%2B` becomes `/internal/a?x=%2B`. A strip prefix must match a complete
path segment: `/grafana-other` does not match `/grafana` and returns 400 without
calling the application. Strip then add is supported; alternatively specify
`replace_path`, which cannot be combined with either prefix operation. Queries are
preserved verbatim. A stripped non-root prefix is sent as a rebuilt
`X-Forwarded-Prefix`; client values are discarded. Paths use the existing canonical path validation: ambiguous
slashes, dot segments and encoded separators are rejected. This does not implement
regex replacements, query editing, response-body/link rewriting or automatic
application base-URL configuration.

Header sets replace all existing values; removal deletes all occurrences. Each
set/remove list has at most 32 names, sets at most 8 KiB total and 2 KiB per value.
Names are normalized to lowercase; duplicate names and set/remove conflicts are
rejected. Transport/framing, Host, forwarded identity, Cloudflare, WebSocket,
CORS, Vary, Location and credential headers are reserved. Request Content-Type
cannot be changed after inspection. Use typed security settings and CORS controls
for those policies, and ForwardAuth for verified identity. Never put credentials
or secrets into custom header values: configuration is visible in drafts/history.

## CORS

```json
{
  "cors": {
    "origins": ["https://ui.example.org"],
    "methods": ["GET", "POST"],
    "allowed_headers": ["authorization", "content-type"],
    "exposed_headers": ["x-request-id"],
    "credentials": true,
    "max_age_seconds": 600
  }
}
```

Origins are exact HTTP/HTTPS origins with no trailing slash, wildcard subdomain,
path or query. `*` is permitted only as the sole origin with credentials disabled.
Opaque/null origins are rejected. Origins and header lists are bounded to 32;
methods to 16; max age to 86,400 seconds. Duplicate/invalid origins, names and
methods are rejected before apply.

An OPTIONS request with Origin and Access-Control-Request-Method selects the route
for its requested actual method, so a POST-only route can handle its own preflight.
Preflight has no body, and its requested method/headers must be allowed. An allowed
preflight returns 204 after admission/ACL/CrowdSec/WAF, without contacting either
application or ForwardAuth. This is the browser credential negotiation step; the
actual request still requires authentication. OPTIONS without preflight headers
follows normal routing/authentication.

Disallowed origins/methods/headers return 403 when the CORS route matches; absent
routes remain 404. Duplicate Origin/preflight header fields return 400. Controlled
CORS response headers replace upstream values. Vary preserves upstream values and
adds Origin, including responses without Origin; preflight additionally varies on
requested method and headers. CORS is browser access policy, not service authentication.

## ForwardAuth

Create an upstream for the trusted auth service first, with a health endpoint that
can pass without a user's session. Then reference it on the application route:

```json
{
  "forward_auth": {
    "upstream": "auth-service",
    "path": "/api/authz/forward-auth",
    "timeout_ms": 2000,
    "request_headers": ["cookie", "authorization"],
    "response_headers": ["remote-user", "remote-groups", "remote-email", "remote-name"],
    "response_cookies": ["authelia_session"],
    "redirect_origins": ["https://auth.example.org"]
  }
}
```

The path is a fixed origin-form path without query parameters. The service receives
GET with an empty body. Only the selected request headers are copied; generated
X-Forwarded-Method/Uri/Proto/Host/For and X-Real-IP describe the original request and
verified client IP. Forwarded Host preserves the original port. X-OpenWAF-Hop blocks
recursive gateway calls. Client-provided forwarded headers cannot change this context.

2xx authorizes the application request. Only configured identity response headers
are copied, replacing any client values. Configure every identity header your
application trusts; do not let it trust additional arbitrary client headers. Identity
headers cannot also be injected by custom request headers. Cookie/Authorization
forwarding is only for authentication; original application credentials otherwise
follow the existing proxy behavior.

401/403 deny access using a local error body; WWW-Authenticate is forwarded on 401.
301/302/303/307/308 are returned to the browser only when Location is a safe relative
URL or an absolute URL whose exact origin is listed. Redirects are never followed
by OpenWAF. Other statuses, invalid/duplicate identity or Location headers, oversized
headers, TLS/network errors, missing healthy endpoints and timeout all return 503.
No denied/unavailable request reaches the application. Response bodies from the auth
service are not relayed. Set-Cookie is accepted only for the configured cookie names,
on successful auth as well as supported deny/redirect responses.

One gateway has 32 auth exchange permits and no waiting queue. Timeout is 100–5,000 ms
(default 2,000), also bounded by the request's total lifetime. Each exchange has at
most 16 KiB headers/64 response fields, uses one connection, never retries, and closes
without collecting the response body. Cancellation/shutdown drops the owned future,
connection and permits; endpoint force-disconnect uses the existing operations lease.
No detached worker, per-request database access, ambient HTTP proxy or auth cache is
introduced. Trust configuration is loaded at startup; HTTPS verifies certificate
chain/SNI with system trust plus optional `OPENWAF_UPSTREAM_CA_FILE`.

Endpoints share existing DNS TTL, loop validation, active health and maintenance
eligibility. Request leases also refresh auth endpoints for retained snapshots across
apply/rollback. Health registration has the existing 256-slot bound shared with
application upstream registrations. Auth endpoint selection uses healthy round robin;
application affinity settings do not pin the auth exchange. Error details distinguish
`forward_auth_denied`, `forward_auth_unavailable` and `forward_auth_capacity` without
recording auth headers, cookies, body or query values.

Authelia-style paths/header examples describe the protocol configuration. Live
Authelia/Authentik deployments have not been certified by the local fixture tests;
check provider version, health path, cookies, redirect origin and login/logout flow
before migrating an existing service. Host override, Basic/Digest auth, regex rules,
compression, custom error-page services and general Traefik plugin compatibility
remain outside this change.
