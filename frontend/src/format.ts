import dayjs from "dayjs";
import type { Source } from "./types";

export function discoveryReason(reason: string) {
  const labels: Record<string, string> = {
    collector_not_configured: "Collector is not configured.",
    collector_unavailable: "Cannot reach the discovery collector.",
    source_stale: "The last snapshot is out of date.",
    not_yet_refreshed: "Waiting for the first collector snapshot.",
    docker_refresh_failed: "Docker inventory could not be refreshed.",
    host_refresh_failed: "Host listeners could not be refreshed.",
    docker_snapshot_too_large: "Docker inventory exceeded the snapshot limit.",
    host_snapshot_too_large:
      "Host listener inventory exceeded the snapshot limit.",
    docker_events_unavailable: "Docker event stream is disconnected.",
  };
  return labels[reason] ?? reason.replaceAll("_", " ");
}

export function time(value: number | string | null) {
  return value === null
    ? "Not observed"
    : dayjs(value).format("DD MMM YYYY · HH:mm:ss Z");
}
export function sourceLabel(source: Source) {
  if (source.kind === "docker_alias")
    return `Container ${source.container_id.slice(0, 12)} · network ${source.network} · alias ${source.alias}:${source.port}`;
  if (source.kind === "docker_published")
    return `Container ${source.container_id.slice(0, 12)} · bind ${source.bind_address} · host port ${source.host_port} → container port ${source.container_port}`;
  return `Bind ${source.bind_address} · TCP port ${source.port} · host listener`;
}
