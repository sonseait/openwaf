export type Kind = "docker" | "host-ports";
export type Source =
  | {
      kind: "docker_alias";
      container_id: string;
      network: string;
      alias: string;
      port: number;
      observed_at_unix_ms: number;
    }
  | {
      kind: "docker_published";
      container_id: string;
      bind_address: string;
      container_port: number;
      host_port: number;
      observed_at_unix_ms: number;
    }
  | {
      kind: "host_port";
      bind_address: string;
      port: number;
      observed_at_unix_ms: number;
    };
export interface Endpoint {
  weight?: number;
  address: string;
  protocol: "http" | "https";
  tls_server_name?: string | null;
  tls_verify?: boolean;
  source?: Source;
}
export interface Candidate {
  id: string;
  address: string | null;
  source: Source;
  selectable: boolean;
  unavailable_reason: string | null;
  verification: "not_tested";
}
export interface CandidatePage {
  schema_version: 1;
  source: Kind;
  collection_scope: string;
  collector_available: boolean;
  docker_events_connected: boolean | null;
  stale: boolean;
  error: string | null;
  observed_at_unix_ms: number | null;
  revision: string;
  total: number;
  limit: number;
  next_cursor: string | null;
  candidates_truncated: boolean;
  candidates: Candidate[];
}
export interface Step {
  state: "not_run" | "passed" | "failed";
  latency_ms: number | null;
  error: string | null;
}
export interface Probe {
  available: boolean;
  error: string | null;
  endpoint: string | null;
  dns: Step;
  tcp: Step;
  tls: Step;
  http: Step;
  http_status: number | null;
  latency_ms: number;
}
export interface RetryPolicy {
  mode: "disabled" | "connect-only" | "safe" | "idempotent";
  max_attempts: number;
  methods: string[];
  idempotency_scope: "endpoint" | "pool";
  per_try_timeout_ms?: number;
  total_timeout_ms?: number;
  retry_on: string[];
  replay: { mode: "none" | "memory" | "disk"; max_body_size_bytes?: number };
  backoff_base_ms: number;
  backoff_max_ms: number;
}
export interface Route {
  record_body?: {
    request_enabled: boolean;
    response_enabled: boolean;
    query_enabled: boolean;
    redact_fields: string[];
  };
  application?: {
    application_id: string;
    release_id: string;
    mode: "static" | "spa";
    preview_expires_at_unix_ms?: number;
  } | null;
  maintenance?: { message: string; retry_after_seconds: number } | null;
  password_protect?: {
    sealed_verifier: string;
    session_seconds: number;
  } | null;
  error_pages?: ErrorPage[];
  middleware?: {
    rewrite?: {
      strip_prefix?: string | null;
      add_prefix?: string | null;
      replace_path?: string | null;
    } | null;
    request_headers?: HeaderRules;
    response_headers?: HeaderRules;
    cors?: {
      origins: string[];
      methods: string[];
      allowed_headers: string[];
      exposed_headers: string[];
      credentials: boolean;
      max_age_seconds: number;
    } | null;
    api_schema?: {
      mode: "observe" | "block";
      schema: Record<string, unknown> | null;
    } | null;
    detectors?: {
      window_seconds: number;
      min_samples: number;
      requests_per_second: number;
      distinct_paths: number;
      upstream_404_percent: number;
    } | null;
    identity_rate_limit?: {
      header: string;
      per_second: number;
      burst: number;
      require_identity: boolean;
    } | null;
    forward_auth?: {
      upstream: string;
      path: string;
      timeout_ms: number;
      request_headers: string[];
      response_headers: string[];
      identity_headers?: string[];
      response_cookies: string[];
      redirect_origins: string[];
    } | null;
  };
  profile?: {
    kind:
      "api_crud" | "upload" | "sse" | "websocket" | "media" | "payment_webhook";
    version: number;
  };
  content?: { media_types: string[]; require_type_for_body: boolean };
  admission_class?: "api" | "upload" | "stream" | "critical";
  admission?: {
    requests: number;
    streams: number;
    uploads: number;
    per_client: number;
  };
  timeouts?: {
    total_ms: number;
    connect_ms: number;
    tls_ms?: number | null;
    header_ms?: number | null;
    response_idle_ms?: number | null;
    read_ms: number;
    write_ms: number;
    idle_ms: number;
  };
  retry?: RetryPolicy;
  body?: {
    max_body_bytes: number;
    inspection: "full" | "headers-query-only";
    idle_timeout_ms: number;
  };
  id: string;
  hostname: string;
  path: string;
  path_match: "exact" | "prefix";
  methods: string[];
  upstream?: string;
  redirect?: {
    preserve_path?: boolean;
    preserve_query?: boolean;
    url: string;
    status: 301 | 302 | 303 | 307 | 308;
    http_only?: boolean;
  };
  waf?: {
    mode?: "Off" | "DetectionOnly" | "On";
    paranoia_level?: number;
    body_limit_bytes?: number;
    inspection_timeout_ms?: number;
    exclusions?: {
      owner?: string;
      rule_id: number;
      reason: string;
      target?: string;
      expires_at_unix_ms?: number;
    }[];
  } | null;
  access?: {
    allow?: string[];
    deny?: string[];
    geo?: {
      allow?: string[];
      deny?: string[];
      unknown: "allow" | "deny";
    } | null;
    rate_limit?: { per_second: number; burst: number } | null;
    ddos?: { per_second: number; burst: number } | null;
    challenge?: { difficulty: number; clearance_seconds: number } | null;
  };
  security_headers?: {
    hsts_max_age?: number | null;
    hsts_include_subdomains?: boolean;
    content_security_policy?: string | null;
    nosniff?: boolean;
    referrer_policy?:
      | "no-referrer"
      | "same-origin"
      | "strict-origin"
      | "strict-origin-when-cross-origin"
      | null;
    frame_options?: "DENY" | "SAMEORIGIN" | null;
  };
}
export interface HeaderRules {
  set: { name: string; value: string }[];
  remove: string[];
}
export interface Upstream {
  balancing?: {
    algorithm: "round_robin" | "weighted_round_robin" | "least_active_requests";
    slow_start_ms: number;
  };
  affinity?: { lifetime_seconds: number; fallback: "rebalance" | "reject" };
  id: string;
  endpoints: Endpoint[];
  timeouts?: Record<string, number>;
  health?: {
    method?: "HEAD" | "GET";
    path: string;
    host: string | null;
    interval_ms: number;
    timeout_ms: number;
    status_min: number;
    status_max: number;
    healthy_threshold: number;
    unhealthy_threshold: number;
  };
}
export interface ErrorPage {
  status: number;
  html: string;
}
export interface Document {
  global_rules?: Route["access"];
  error_pages?: ErrorPage[];
  routes: Route[];
  upstreams: Upstream[];
  trusted_proxies: string[];
}
export interface Changes {
  added: string[];
  removed: string[];
  changed: string[];
}
export interface Diff {
  global_rules_changed?: boolean;
  error_pages_changed?: boolean;
  routes: Changes;
  upstreams: Changes;
  trusted_proxies_changed: boolean;
}
export interface Config {
  draft_revision: number;
  draft: Document;
  committed_version: number;
  active_version: number;
  active: Document;
  degraded: boolean;
  diff: Diff;
}
export interface Version {
  version: number;
  diff: Diff;
  rollback_from: number | null;
  created_by: number | null;
  created_at: string;
}
export interface Session {
  username: string;
  csrf_token: string;
  expires_at: string;
}
