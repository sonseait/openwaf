#!/usr/bin/env python3
"""Isolated website/admin quota migration regression with real PostgreSQL and gateway.

Run cargo build -p openwaf-gateway, then python3 tests/admin_admission.py from
backend/. Uses cached postgres:17-bookworm, random loopback ports (except the
reserved Axum 9090 upstream), fixture credentials and HTTP on loopback only.
No production changes or provider calls. Removes only its own container.
"""
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile

from body_recording import ROOT, docker, port, request, wait


def main():
    # Public admin's reserved upstream intentionally cannot be changed by a test.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 9090))
    name = "openwaf-admin-quota-" + secrets.token_hex(4)
    process = None
    streams = []
    stream_responses = []
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
            env = {k: v for k, v in os.environ.items() if not k.startswith("OPENWAF_")}
            env.update(OPENWAF_ADMIN_PUBLIC="true", OPENWAF_ADMIN_HOST="admin.example.com",
                       OPENWAF_ADMIN_ORIGIN="https://admin.example.com",
                       OPENWAF_BOOTSTRAP_TEST_DATABASE_URL=f"postgres://postgres:{password}@127.0.0.1:{pg_port}/postgres?sslmode=disable")
            # Native transaction/validation/audit test, including both historical
            # edge+quota and quota-only migrations, repeat startup and draft edits.
            subprocess.run(["cargo", "test", "-p", "openwaf-admin", "bootstrap::tests::postgres_startup_leaves_first_admin_to_setup",
                            "--", "--ignored", "--exact"], cwd=ROOT, env=env, check=True, timeout=120)
            print("PASS real PostgreSQL scoped quota migration, version/diff/audit, draft preservation and idempotence", flush=True)
            docker("exec", name, "createdb", "-U", "postgres", "admin_resources")
            env.pop("OPENWAF_BOOTSTRAP_TEST_DATABASE_URL")
            key = directory / "master.key"
            key.write_bytes(secrets.token_bytes(32))
            key.chmod(0o600)
            ui = directory / "ui"
            (ui / "assets").mkdir(parents=True)
            (ui / "index.html").write_text('<script type="module" src="/assets/lazy.js"></script>')
            (ui / "assets/lazy.js").write_text('export const ready = true;')
            (ui / "assets/style.css").write_text('body { color: black; }')
            # Exercise the smallest VPS's real node envelope as well.
            import sys
            sys.path.insert(0, str(ROOT / "runtime"))
            import vps_profiles
            budgets = directory / "budgets.json"
            budgets.write_text(json.dumps(vps_profiles.profile("2c4g")["budgets"]))
            budgets.chmod(0o600)
            gateway_port = port()
            env.update(OPENWAF_ENV_FILE="/dev/null", OPENWAF_LISTEN=f"127.0.0.1:{gateway_port}",
                       OPENWAF_UPSTREAM="127.0.0.1:9090", OPENWAF_ADMIN_LISTEN="127.0.0.1:9090",
                       OPENWAF_DATABASE_URL=f"postgres://postgres:{password}@127.0.0.1:{pg_port}/admin_resources?sslmode=disable",
                       OPENWAF_ADMIN_MASTER_KEY_FILE=str(key), OPENWAF_ADMIN_UI_ROOT=str(ui),
                       OPENWAF_RESOURCE_BUDGETS_FILE=str(budgets),
                       OPENWAF_RULES=str(ROOT / "crates/waf/tests/fixtures/rules.conf"))
            with (directory / "gateway.log").open("wb") as log:
                process = subprocess.Popen([str(ROOT / "target/debug/openwaf-gateway")], env=env, stdout=log, stderr=log)
                def ready():
                    if process.poll() is not None:
                        raise RuntimeError("Fixture gateway stopped; private diagnostics suppressed")
                    return request(gateway_port, "GET", "/api/v1/auth/setup", headers={"Host": "admin.example.com"})[0] == 200
                wait(ready)
                headers = {"Host": "admin.example.com", "Origin": env["OPENWAF_ADMIN_ORIGIN"], "Content-Type": "application/json"}
                login = json.dumps({"username": "fixture-owner", "password": secrets.token_hex(16)})
                assert request(gateway_port, "POST", "/api/v1/auth/setup", login, headers)[0] == 201
                status, result, login_body = request(gateway_port, "POST", "/api/v1/auth/login", login, headers)
                assert status == 200
                auth = {"Host": "admin.example.com", "Cookie": result["set-cookie"].split(";", 1)[0]}
                mutations = {**auth, **headers, "X-CSRF-Token": json.loads(login_body)["csrf_token"]}
                def api(method, path, value=None):
                    status, _, body = request(gateway_port, method, "/api/v1" + path,
                        None if value is None else json.dumps(value), mutations)
                    assert status == 200, (path, status)
                    return json.loads(body)
                state = api("GET", "/config")
                document = state["active"]
                # Terminal HTTP fixture reuses Axum's static assets and authenticated SSE.
                upstream = dict(document["upstreams"][0], id="website-assets")
                document["upstreams"].append(upstream)
                document["routes"].append({"id": "website", "hostname": "website.example.com",
                    "path": "/", "path_match": "prefix", "upstream": "website-assets"})
                saved = api("PUT", "/config/draft", {"expected_revision": state["draft_revision"], "document": document})
                api("POST", "/config/apply", {"expected_active_version": state["active_version"], "expected_draft_revision": saved["draft_revision"]})
                # The new snapshot's health checks run asynchronously.
                wait(lambda: request(gateway_port, "GET", "/", headers=auth)[0] == 200)
                route = api("GET", "/config")["active"]["routes"][-1]
                assert route["admission"] == {"requests": 64, "streams": 8, "uploads": 4, "per_client": 32}
                website = {**auth, "Host": "website.example.com"}
                for _ in range(12):
                    connection = http.client.HTTPConnection("127.0.0.1", gateway_port, timeout=5)
                    streams.append(connection)
                    connection.request("GET", "/api/v1/events/metrics", headers=website)
                    response = connection.getresponse()
                    assert response.status == 200, response.status
                    assert response.getheader("Content-Type").startswith("text/event-stream")
                    # Retain the response: dropping it closes the held stream.
                    stream_responses.append(response)
                paths = ["/", "/assets/lazy.js", "/assets/style.css", "/api/v1/auth/session"] * 6
                with ThreadPoolExecutor(max_workers=12) as pool:
                    results = list(pool.map(lambda path: request(gateway_port, "GET", path, headers=website)[0], paths))
                assert results == [200] * len(paths), results
                assert request(gateway_port, "GET", "/", headers=auth)[0] == 200
                print("PASS general website defaults: 12 held same-client SSE + 24 HTML/JS/CSS/session fetches (12 parallel), smallest node budgets; all 200; admin accessible", flush=True)
                assert request(gateway_port, "GET", "/api/v1/auth/session", headers={"Host": "admin.example.com"})[0] == 401
                assert request(gateway_port, "POST", "/api/v1/auth/logout", headers=auth)[0] == 403
                print("PASS session and Origin protection remain enforced", flush=True)
        finally:
            for connection in streams:
                connection.close()
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
