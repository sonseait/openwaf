import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync } from "node:fs";

export default defineConfig(({ command }) => {
  const cert = process.env.OPENWAF_UI_TLS_CERT;
  const key = process.env.OPENWAF_UI_TLS_KEY;
  if (command === "serve" && (!cert || !key)) {
    throw new Error(
      "Set OPENWAF_UI_TLS_CERT and OPENWAF_UI_TLS_KEY for same-origin HTTPS. See README.md.",
    );
  }
  const target = process.env.OPENWAF_ADMIN_TARGET ?? "http://127.0.0.1:9090";
  const parsed = new URL(target);
  const localHttp =
    ["127.0.0.1", "[::1]", "localhost"].includes(parsed.hostname) &&
    parsed.protocol === "http:";
  const remoteHttps = parsed.protocol === "https:";
  if (
    (!localHttp && !remoteHttps) ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(
      "Development Admin target must be a loopback HTTP or verified HTTPS origin, without credentials, path, query or fragment.",
    );
  }
  return {
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      https:
        cert && key
          ? { cert: readFileSync(cert), key: readFileSync(key) }
          : undefined,
      proxy: {
        "/api": {
          target,
          changeOrigin: remoteHttps,
          secure: true,
          // A remote Admin validates its own Origin. Validate the browser's
          // local Origin first, before forwarding an authenticated request.
          bypass(req, res) {
            if (!remoteHttps) return;
            const authority = req.headers.host ?? req.headers[":authority"];
            const localOrigin =
              typeof authority === "string"
                ? `https://${authority}`
                : undefined;
            const origin = req.headers.origin;
            const safeMethod = req.method === "GET" || req.method === "HEAD";
            if (
              (origin && origin !== localOrigin) ||
              (!safeMethod && !origin)
            ) {
              res.statusCode = 403;
              res.end("Development proxy requires the local UI origin.");
              return false;
            }
          },
          configure(proxy) {
            if (!remoteHttps) return;
            proxy.on("proxyReq", (proxyReq, req) => {
              if (req.headers.origin)
                proxyReq.setHeader("Origin", parsed.origin);
              // Do not forward a localhost UI URL to the deployed service.
              proxyReq.removeHeader("Referer");
            });
          },
          timeout: 15000,
          proxyTimeout: 15000,
        },
      },
    },
  };
});
