#!/usr/bin/env python3
"""Run native DNS bootstrap code against a local Postman simulation over verified TLS.
No production tokens, credentials, public DNS writes, or TLS verification bypass.
Requires Postman CLI >=1.70, OpenSSL, Rust + native OpenSSL development files.
"""
import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time

REPO = Path(__file__).resolve().parents[4]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--acme", action="store_true", help="Also exercise real ACME with local Pebble in Docker")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="openwaf-dns-simulation-") as temp:
        root = Path(temp)
        log = root / "postman.ndjson"
        with log.open("w") as output, (root / "postman.err").open("w") as error:
            process = subprocess.Popen(["postman", "simulation", "run", str(REPO / "postman/simulations/admin-dns.sim.yaml"),
                                        "--port", "auto", "--no-history", "--output", "ndjson"], cwd=REPO, stdout=output, stderr=error)
            server = None
            thread = None
            try:
                port = None
                end = time.monotonic() + 30
                while time.monotonic() < end:
                    for line in log.read_text().splitlines():
                        try:
                            value = json.loads(line)
                        except ValueError:
                            continue
                        if value.get("event") == "listening":
                            port = value["port"]
                    if port:
                        break
                    if process.poll() is not None:
                        raise RuntimeError("Postman simulation failed to start; inspect CLI setup")
                    time.sleep(0.2)
                if not port:
                    raise RuntimeError("Postman readiness deadline")
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                                "-keyout", str(root / "key.pem"), "-out", str(root / "ca.pem"), "-subj", "/CN=localhost",
                                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "extendedKeyUsage=serverAuth"], check=True, capture_output=True)

                class Relay(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *args):
                        pass

                    def forward(self):
                        length = int(self.headers.get("Content-Length", "0"))
                        if length > 8192:
                            self.send_error(413)
                            return
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        # Deliberately do not forward credentials to mock logs.
                        connection.request(self.command, "/cloudflare" + self.path, self.rfile.read(length),
                                           {"Content-Type": "application/json"})
                        response = connection.getresponse()
                        data = response.read(65536)
                        self.send_response(response.status)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                        connection.close()

                    do_GET = forward
                    do_POST = forward
                    do_PATCH = forward
                    do_DELETE = forward

                server = http.server.HTTPServer(("127.0.0.1", 0), Relay)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(root / "ca.pem", root / "key.pem")
                server.socket = context.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                env = {key: value for key, value in os.environ.items() if not key.startswith("OPENWAF_")}
                env.update(OPENWAF_TEST_CLOUDFLARE_API=f"https://localhost:{server.server_port}/client/v4",
                           OPENWAF_TEST_CLOUDFLARE_CA=str(root / "ca.pem"))
                subprocess.run(["cargo", "test", "--manifest-path", str(REPO / "backend/Cargo.toml"), "-p", "openwaf-acme",
                                "--features", "integration-test-provider", "admin::tests::cloudflare_",
                                "--", "--ignored", "--nocapture", "--test-threads=1"], check=True, env=env, timeout=180)
                if args.acme:
                    from acme_simulation import run
                    run(REPO, root, port, env)
                events = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
                count = sum(value.get("event") == "request" for value in events)
                if not count:
                    raise RuntimeError("No Postman dependency requests recorded")
                print(f"PASS local Postman simulation: {count} requests recorded; create/current, denied, conflict, unknown ACK, apex/wildcard replacement, preserved records, restart, unknown POST/PATCH/DELETE, two TXT cleanup")
            except Exception:
                # Relay never forwards credentials; these logs contain only fixture paths/status.
                print(log.read_text()[-6000:])
                print((root / "postman.err").read_text()[-2000:])
                raise
            finally:
                if server:
                    server.shutdown()
                    server.server_close()
                if thread:
                    thread.join(timeout=5)
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    main()
