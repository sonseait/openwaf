export interface DimensionCount {
  label: string;
  received: number;
  blocked: number;
}
export interface Metrics {
  host?: string | null;
  statistics_started_at_unix_ms?: number | null;
  persistence?: {
    configured: boolean;
    degraded: boolean;
    last_success_unix_ms: number;
    interval_ms: number;
  };
  dimensions?: {
    source: string;
    countries: DimensionCount[];
    user_agents: DimensionCount[];
    methods: DimensionCount[];
  };
  stream_gap?: boolean;
  epoch: string;
  sequence: number;
  observed_at_unix_ms: number;
  window_ms: number;
  incoming_rps: number;
  forwarded_rps: number;
  blocked_rps: number;
  received_bytes_per_second?: number;
  response_bytes_per_second?: number;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
  latency_p99_ms: number | null;
  log_queue_depth: number;
  log_queue_capacity: number;
  resources?: {
    available: boolean;
    resident_bytes: number | null;
    process_cpu_ticks: number | null;
    unavailable_reason: string | null;
  };
  totals: {
    incoming: number;
    forwarded: number;
    blocked: number;
    completed: number;
    cancelled: number;
    active_requests: number;
    active_connections?: number;
    upstream_errors: number;
    dropped_logs: number;
    received_bytes: number;
    sent_bytes: number;
    status_classes: number[];
  };
}
export interface TrafficLog {
  request_id?: string;
  details?: string;
  epoch: string;
  sequence: number;
  observed_at_unix_ms: number;
  method: string;
  status: number;
  latency_ms: number;
  config_version: number;
  route_index: number | null;
  blocked: boolean;
  forwarded: boolean;
  upstream_error: boolean;
}
export interface Live {
  metrics: Metrics[];
  logs: TrafficLog[];
  gap: boolean;
  lost: number;
  latest: Metrics | null;
}
export const empty = (): Live => ({
  metrics: [],
  logs: [],
  gap: false,
  lost: 0,
  latest: null,
});
export const MAX_LOGS = 1000;
export const CHART_WINDOW_MS = 15 * 60 * 1000;
export function appendMetric(
  items: Metrics[],
  next: Metrics,
  streamGap = false,
): Metrics[] {
  const previous = items.at(-1);
  // Sync/reconnect can repeat the latest observation. Retain its original
  // continuity marker and ignore late events instead of inserting false gaps.
  if (previous?.epoch === next.epoch && next.sequence <= previous.sequence)
    return items;
  return trimMetrics([
    ...(previous && previous.epoch !== next.epoch ? [] : items),
    { ...next, stream_gap: streamGap },
  ]);
}
export function trimMetrics(items: Metrics[], now = Date.now()): Metrics[] {
  const trimmed = items
    .filter((item) => item.observed_at_unix_ms >= now - CHART_WINDOW_MS)
    .slice(-900)
    .map((item) =>
      item.dimensions ? { ...item, dimensions: undefined } : item,
    );
  return trimmed.length === items.length &&
    trimmed.every((item, i) => item === items[i])
    ? items
    : trimmed;
}
export function appendLog(items: TrafficLog[], next: TrafficLog): TrafficLog[] {
  if (
    items.some(
      (item) => item.epoch === next.epoch && item.sequence === next.sequence,
    )
  )
    return items;
  return [...items, next].slice(-MAX_LOGS);
}
