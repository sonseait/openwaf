// Optional hardening advice must not inflate the configuration warning count.
// Unknown diagnostics remain warnings so new safety checks are never hidden.
export function isConfigurationRecommendation(code: string): boolean {
  return code === "multipart_body_skipped" || code === "missing_quota";
}
