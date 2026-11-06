export function windowCountUrl(host: string, prefix: string, seconds: number) {
  const query = new URLSearchParams({ window_seconds: String(seconds) });
  if (host.trim()) query.set("host", host.trim());
  if (prefix) query.set("path_prefix", prefix);
  return `/telemetry/window?${query.toString()}`;
}
