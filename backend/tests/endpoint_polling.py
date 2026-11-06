#!/usr/bin/env python3
"""Real local API + Chromium polling regression; no production/provider access.

Build frontend/dist and cargo build -p openwaf-gateway first. Requires Docker's
postgres:17-bookworm image. Set OPENWAF_PLAYWRIGHT_MODULE to a separate Playwright
installation's entry point (no browser test dependency in the product).
"""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile

from body_recording import ROOT, docker, port, request, wait


def main():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 9090))
    name = "openwaf-endpoint-polling-" + secrets.token_hex(4)
    process = None
    with tempfile.TemporaryDirectory(prefix=name) as temporary:
        directory = Path(temporary)
        password = secrets.token_hex(24)
        pg_env = directory / "postgres.env"
        pg_env.write_text(f"POSTGRES_PASSWORD={password}\n")
        pg_env.chmod(0o600)
        try:
            docker("run", "-d", "--name", name, "--env-file", str(pg_env),
                   "-p", "127.0.0.1::5432", "postgres:17-bookworm")
            pg_port = int(docker("port", name, "5432/tcp").rsplit(":", 1)[1])
            wait(lambda: subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                                        capture_output=True).returncode == 0)
            key = directory / "master.key"
            key.write_bytes(secrets.token_bytes(32))
            key.chmod(0o600)
            gateway_port = port()
            env = {k: v for k, v in os.environ.items() if not k.startswith("OPENWAF_")}
            env.update(OPENWAF_ENV_FILE="/dev/null", OPENWAF_ADMIN_PUBLIC="true",
                       OPENWAF_ADMIN_HOST="admin.example.com", OPENWAF_ADMIN_ORIGIN="https://admin.example.com",
                       OPENWAF_LISTEN=f"127.0.0.1:{gateway_port}", OPENWAF_UPSTREAM="127.0.0.1:9090",
                       OPENWAF_ADMIN_LISTEN="127.0.0.1:9090",
                       OPENWAF_DATABASE_URL=f"postgres://postgres:{password}@127.0.0.1:{pg_port}/postgres?sslmode=disable",
                       OPENWAF_ADMIN_MASTER_KEY_FILE=str(key), OPENWAF_ADMIN_UI_ROOT=str(ROOT.parent / "frontend/dist"),
                       OPENWAF_RULES=str(ROOT / "crates/waf/tests/fixtures/rules.conf"))
            with (directory / "gateway.log").open("wb") as log:
                process = subprocess.Popen([str(ROOT / "target/debug/openwaf-gateway")], env=env, stdout=log, stderr=log)

                def ready():
                    if process.poll() is not None:
                        raise RuntimeError("Fixture gateway stopped; private diagnostics suppressed")
                    return request(9090, "GET", "/api/v1/auth/setup")[0] == 200

                wait(ready)
                headers = {"Origin": env["OPENWAF_ADMIN_ORIGIN"], "Content-Type": "application/json"}
                login = json.dumps({"username": "fixture-owner", "password": secrets.token_hex(24)})
                assert request(9090, "POST", "/api/v1/auth/setup", login, headers)[0] == 201
                status, result, body = request(9090, "POST", "/api/v1/auth/login", login, headers)
                assert status == 200
                auth = {"Cookie": result["set-cookie"].split(";", 1)[0]}
                assert request(9090, "GET", "/api/v1/operations/endpoints?summary=true")[0] == 401
                full_status, _, full_body = request(9090, "GET", "/api/v1/operations/endpoints", headers=auth)
                summary_status, _, summary_body = request(9090, "GET", "/api/v1/operations/endpoints?summary=true", headers=auth)
                assert full_status == summary_status == 200
                full, summary = json.loads(full_body), json.loads(summary_body)
                assert "diagnostics" in full and "diagnostics" not in summary
                assert "health" in summary["endpoints"][0] and "health" not in full["endpoints"][0]
                assert full["endpoints"][0]["key"] == summary["endpoints"][0]["key"]
                assert len(summary_body) < len(full_body)
                assert request(9090, "GET", "/api/v1/operations/endpoints?summary=invalid", headers=auth)[0] == 400
                print(f"PASS authenticated full/summary contract: full={len(full_body)} B, summary={len(summary_body)} B (one-endpoint local fixture)", flush=True)
                browser_env = os.environ.copy()
                browser_env.update(OPENWAF_BROWSER_BASE="http://127.0.0.1:9090",
                                   OPENWAF_BROWSER_COOKIE=auth["Cookie"],
                                   OPENWAF_BROWSER_CSRF=json.loads(body)["csrf_token"],
                                   OPENWAF_BROWSER_ORIGIN=env["OPENWAF_ADMIN_ORIGIN"])
                subprocess.run(["node", str(ROOT / "tests/endpoint_polling_browser.cjs")], env=browser_env, check=True, timeout=90)
        finally:
            if process:
                process.terminate()
                try:
                    process.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            subprocess.run(["docker", "rm", "-fv", name], capture_output=True)


if __name__ == "__main__":
    main()
