import { object, type Fields } from "./request-metadata";
import type { Document } from "./types";

export interface RouteDiagnostic {
  path: string;
  route_id?: string;
  code: string;
  message: string;
}

export function diagnosticTarget(
  diagnostic: RouteDiagnostic,
  document: Pick<Document, "routes">,
): string {
  const match = /^routes\.(\d+)\.(.+)$/.exec(diagnostic.path);
  if (!match) return diagnostic.path;
  // The API's identity belongs to the validated document. Older servers can be
  // resolved against the exact debounced document sent with this query.
  const name = diagnostic.route_id || document.routes[Number(match[1])]?.id;
  return `${name || "Unnamed route"} · ${match[2]}`;
}

export function parseRequestDetails(details?: string): Fields | null {
  try {
    return object(JSON.parse(details ?? "null"));
  } catch {
    return null;
  }
}

export function requestRouteLabel(
  record: { details?: string; route_index?: number | string | null },
  details = parseRequestDetails(record.details),
): string {
  const name = details?.route_id;
  if (typeof name === "string" && name.trim()) return name;
  if (name === null || record.route_index === null) return "No matching route";
  // An index belongs to an old config version; never guess from current config.
  return "Unavailable";
}
