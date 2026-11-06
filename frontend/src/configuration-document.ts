import type { Document } from "./types";

// Normalize only values represented by form controls; preserve unrelated fields and source metadata.
export function normalizeDocument(input: Document): Document {
  const document = structuredClone(input);
  const clean = (values?: string[]) =>
    values?.map((v) => v.trim()).filter(Boolean) ?? [];
  document.trusted_proxies = clean(document.trusted_proxies);
  for (const route of document.routes) {
    route.methods = clean(route.methods);
    if (route.record_body) {
      route.record_body = {
        request_enabled: route.record_body.request_enabled ?? false,
        response_enabled: route.record_body.response_enabled ?? false,
        query_enabled: route.record_body.query_enabled ?? false,
        redact_fields: clean(route.record_body.redact_fields),
      };
    }
    const middleware = route.middleware;
    if (middleware) {
      for (const headers of [
        middleware.request_headers,
        middleware.response_headers,
      ]) {
        if (headers) {
          headers.remove = clean(headers.remove);
          headers.set = (headers.set ?? []).map((h) => ({
            ...h,
            name: h.name.trim(),
          }));
        }
      }
      if (middleware.cors) {
        for (const key of [
          "origins",
          "methods",
          "allowed_headers",
          "exposed_headers",
        ] as const)
          middleware.cors[key] = clean(middleware.cors[key]);
      }
      if (middleware.forward_auth) {
        for (const key of [
          "request_headers",
          "response_headers",
          "response_cookies",
          "identity_headers",
          "redirect_origins",
        ] as const)
          middleware.forward_auth[key] = clean(middleware.forward_auth[key]);
      }
    }
    if (route.waf?.exclusions)
      route.waf.exclusions = route.waf.exclusions.map((e) => ({
        ...e,
        owner: e.owner?.trim() || undefined,
        target: e.target?.trim() || undefined,
      }));
    if (route.content)
      route.content.media_types = clean(route.content.media_types);
    if (route.retry) {
      route.retry.methods = clean(route.retry.methods);
      route.retry.retry_on = clean(route.retry.retry_on);
    }
  }
  for (const access of [
    document.global_rules,
    ...document.routes.map((r) => r.access),
  ]) {
    if (!access) continue;
    access.allow = clean(access.allow);
    access.deny = clean(access.deny);
    if (access.geo) {
      access.geo.allow = clean(access.geo.allow).map((v) => v.toUpperCase());
      access.geo.deny = clean(access.geo.deny).map((v) => v.toUpperCase());
    }
  }
  return document;
}
