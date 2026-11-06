// Only safe metadata filters are carried across investigation links.
export const FILTER_KEYS = [
  "start_ms",
  "end_ms",
  "host",
  "path",
  "country",
  "route_id",
  "client_ip",
  "config_version",
  "action",
  "layer",
  "rule_id",
  "status_class",
] as const;
export function investigationParams(input: URLSearchParams): URLSearchParams {
  const result = new URLSearchParams();
  for (const key of FILTER_KEYS) {
    const value = input.get(key);
    if (
      value &&
      value.length <= (key === "path" ? 2048 : 253) &&
      ![...value].some(
        (c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127,
      ) &&
      (key !== "path" || !/[?#]/.test(value))
    )
      result.set(key, value);
  }
  return result;
}
export function investigationLink(
  path: string,
  input: URLSearchParams,
  additions: Record<string, string | number | undefined> = {},
): string {
  const params = investigationParams(input);
  for (const [key, value] of Object.entries(additions))
    if (value !== undefined) params.set(key, String(value));
  return `${path}?${params}`;
}
export function defaultRange(
  params: URLSearchParams,
  fallbackEnd = Date.now(),
) {
  const end = Number(params.get("end_ms")) || fallbackEnd;
  const start = Number(params.get("start_ms")) || end - 3600000;
  return { start, end };
}
