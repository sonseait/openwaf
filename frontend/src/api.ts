import { QueryClient } from "@tanstack/react-query";
import type { Session } from "./types";
import { configCacheOptions } from "./config-cache";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public retryAfter?: string | null,
  ) {
    super(message);
  }
}
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Only safe reads retry transient transport/service failures, with a finite budget.
      retry: (attempt, error) =>
        attempt < 2 &&
        error instanceof ApiError &&
        [0, 503].includes(error.status),
      retryDelay: (attempt) => Math.min(250 * 2 ** attempt, 1000),
      staleTime: 0,
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
      gcTime: 0,
    },
    mutations: { retry: false, gcTime: 0 },
  },
});
queryClient.setQueryDefaults(["config"], configCacheOptions);
export function forgetSession() {
  const protectedQuery = {
    predicate: (query: { queryKey: readonly unknown[] }) =>
      query.queryKey[0] !== "session",
  };
  void queryClient.cancelQueries(protectedQuery);
  queryClient.removeQueries(protectedQuery);
  queryClient.getMutationCache().clear();
  queryClient.setQueryData(["session"], null);
}
export async function api<T>(
  path: string,
  options: { method?: string; body?: unknown; signal?: AbortSignal } = {},
): Promise<T> {
  const method = options.method ?? "GET";
  const session = queryClient.getQueryData<Session | null>(["session"]);
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && session) headers["X-CSRF-Token"] = session.csrf_token;
  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      body:
        options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal
        ? AbortSignal.any([options.signal, AbortSignal.timeout(12000)])
        : AbortSignal.timeout(12000),
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new ApiError(
      0,
      method === "GET"
        ? "Cannot reach Admin API. Retry when it is available."
        : "No acknowledgement received. The action may have completed. Reload server state before retrying.",
    );
  }
  if (!response.ok) {
    if (
      response.status === 401 &&
      path !== "/auth/login" &&
      path !== "/auth/session"
    )
      forgetSession();
    const labels: Record<number, string> = {
      400: "Invalid request.",
      401: "Sign in to continue.",
      403: "Session or CSRF check failed. Sign in again.",
      404: "This item is no longer available.",
      409: "Server state changed. Reload and review before retrying.",
      413: "Configuration exceeds the size limit.",
      422: "Validation failed. Check your values.",
      429: "Rate limit reached.",
      503: "Service unavailable.",
    };
    const cloudflareErrors: Record<string, string> = {
      cloudflare_permission_denied:
        "Cloudflare rejected the credentials or zone permissions. Check the token scope.",
      cloudflare_rate_limited:
        "Cloudflare rate limit reached. Wait before trying again.",
      cloudflare_unavailable:
        "Cloudflare is unavailable or returned an incomplete response.",
      cloudflare_outcome_unknown:
        "Cloudflare did not acknowledge the change. Reload DNS records before retrying; the change may have completed.",
    };
    let providerMessage: string | undefined;
    if (path.startsWith("/certificate-providers")) {
      const detail: unknown = await response.json().catch(() => null);
      if (
        detail &&
        typeof detail === "object" &&
        "error" in detail &&
        typeof detail.error === "string"
      )
        providerMessage = cloudflareErrors[detail.error];
    }
    throw new ApiError(
      response.status,
      providerMessage ?? labels[response.status] ?? "Admin request failed.",
      response.headers.get("Retry-After"),
    );
  }
  if (response.status === 204) return undefined as T;
  const body = await response.text();
  return (body ? JSON.parse(body) : undefined) as T;
}
export function message(error: unknown) {
  return error instanceof Error ? error.message : "Request failed.";
}
