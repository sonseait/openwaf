export interface EndpointHealth {
  available: boolean;
  reason: string;
  checked_at_ms?: number | null;
  valid_for_ms?: number;
  phase?: string;
  latency_ms?: number | null;
}
export interface EndpointStatus {
  key: string;
  upstream_id: string;
  address: string;
  protocol: string;
  eligible_alternatives?: number;
  expected_downtime?: boolean;
  single_endpoint?: boolean;
  slow_start_ms?: number;
  health?: EndpointHealth | null;
}
export interface EndpointOperation {
  key: string;
  mode: string;
  revision: number;
  reason: string;
  active_requests: number;
  remaining_leases?: number;
  deadline_unix_ms?: number | null;
  deadline_exceeded?: boolean;
  drained?: boolean;
}
export interface EndpointPage {
  observed_at_unix_ms?: number;
  config_version?: number;
  endpoints: EndpointStatus[];
  operations: EndpointOperation[];
  diagnostics?: {
    upstream: number;
    endpoint: number;
    available: boolean;
    reason: string;
    checked_at_ms?: number | null;
    valid_for_ms?: number;
    phase?: string;
    last_check?: {
      latency_ms?: number;
      addresses: {
        address: string;
        tcp: string;
        tls: string;
        http: string;
        http_status: number | null;
        error: string | null;
        latency_ms: number;
      }[];
    };
  }[];
}

// Identity and health come from one gateway snapshot, with no config-index join.
// A paused, failed, expired or incomplete observation must never appear current.
export function currentEndpointHealth(
  endpoint: EndpointStatus,
  page: EndpointPage | undefined,
  now: number,
  stale: boolean,
): EndpointHealth | undefined {
  const health = endpoint.health;
  if (
    stale ||
    page?.config_version == null ||
    !page.observed_at_unix_ms ||
    !health?.checked_at_ms ||
    !health.valid_for_ms ||
    health.phase === "pending" ||
    now >= page.observed_at_unix_ms + health.valid_for_ms
  )
    return undefined;
  return health;
}
