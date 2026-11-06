export const TIMEOUT_HELP: Record<string, string> = {
  connect_ms: "Time allowed to establish the upstream TCP connection.",
  read_ms:
    "Upstream read timeout; also the fallback for response headers and response idle.",
  write_ms: "Maximum idle time while writing to the upstream.",
  idle_ms: "Keep-alive idle timeout for reusable upstream connections.",
  total_ms: "Total request deadline, including retries and streaming.",
  tls_ms: "TLS handshake deadline. Leave blank to inherit the connect timeout.",
  header_ms:
    "Deadline for upstream final response headers. Blank inherits read timeout.",
  response_idle_ms:
    "Maximum idle time between upstream response reads. Blank inherits read timeout.",
};
