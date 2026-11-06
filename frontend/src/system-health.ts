export interface HealthObservation {
  state: string;
  reason?: string | null;
  error?: string | null;
  observed_at_unix_ms?: number | null;
  stale?: boolean;
  docker_events_connected?: boolean | null;
  schedules?: HealthObservation[];
  dns_state?: string;
  tls_state?: string;
  provider_state?: string;
  renewal_state?: string;
}
export interface HealthComponent extends HealthObservation {
  sources?: Record<string, HealthObservation>;
  details?: {
    queued?: number;
    executing?: number;
    failed_inspections?: number;
    backlog?: number;
    dropped?: number;
    written?: number;
    last_success_age_ms?: number | null;
    checkpoint_status?: string;
    revision?: number;
    certificates?: { hostname: string }[];
  };
}
export interface SystemHealthSnapshot {
  observed_at_unix_ms: number;
  source?: string;
  serving: { state: string; evidence: string };
  monitoring: {
    state: string;
    known_data_loss?: boolean;
    last_heartbeat_unix_ms?: number | null;
  };
  components: Record<string, HealthComponent>;
}

export function healthState(value: HealthObservation) {
  const state = value.state ?? "unknown";
  if (["failed", "error", "unavailable", "invalid", "down"].includes(state))
    return {
      label: `${state.replaceAll("_", " ")}${value.stale ? " · stale" : ""}`,
      color: "red",
      rank: 0,
    };
  if (value.stale)
    return { label: "Stale observation", color: "orange", rank: 1 };
  if (
    ["degraded", "pending", "starting", "retrying", "expires_soon"].includes(
      state,
    )
  )
    return { label: state.replaceAll("_", " "), color: "orange", rank: 1 };
  if (["healthy", "available", "valid", "passed"].includes(state))
    return { label: state, color: "teal", rank: 3 };
  if (
    [
      "observed",
      "running",
      "renewing",
      "current",
      "complete",
      "reserved",
      "connected",
    ].includes(state)
  )
    return { label: state, color: "blue", rank: 4 };
  if (["not_configured", "disabled"].includes(state))
    return { label: state.replaceAll("_", " "), color: "gray", rank: 5 };
  // Unknown/new states remain explicit and need inspection, never imply health.
  return { label: state.replaceAll("_", " "), color: "gray", rank: 2 };
}

export function componentRank(value: HealthComponent) {
  const observations = [value, ...Object.values(value.sources ?? {})];
  return Math.min(
    ...observations.flatMap((item) =>
      [item, ...(item.schedules ?? [])].map((v) => healthState(v).rank),
    ),
  );
}
