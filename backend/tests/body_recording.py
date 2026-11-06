#!/usr/bin/env python3
"""Isolated real gateway/PostgreSQL/ClickHouse regression test.

Run cargo build -p openwaf-gateway, then python3 tests/body_recording.py from
backend/. Requires Docker with postgres:17-bookworm and
clickhouse/clickhouse-server:25.8 images. Only test-owned containers are removed.
No production credentials, databases or listeners are used.
"""
import copy
import gzip
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def docker(*args):
    return subprocess.check_output(["docker", *args], stderr=subprocess.DEVNULL, text=True).strip()


def wait(check, seconds=40):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, ValueError, http.client.HTTPException):
            pass
        time.sleep(0.05)
    raise AssertionError("test readiness deadline exceeded")


def request(port_number, method, path, body=None, headers=None, encode_chunked=False):
    connection = http.client.HTTPConnection("127.0.0.1", port_number, timeout=5)
    try:
        connection.request(method, path, body, headers or {}, encode_chunked=encode_chunked)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


class Upstream(http.server.BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def do_HEAD(self):
        self.respond()

    def respond(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0], 16)
                if not size:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            body = b"".join(chunks)
        if self.path != "/":
            self.calls.append((self.path, body))
        if self.path.endswith("slow"):
            payload = json.dumps({"ok": "x" * (8 * 1024 * 1024)}).encode()
        elif self.path.endswith("large"):
            payload = json.dumps({"ok": "x" * 65536}).encode()
        else:
            payload = json.dumps({"token": "response_sentinel", "private": "private_sentinel", "ok": True}).encode()
        compressed = self.path.endswith("compressed")
        if compressed:
            payload = gzip.compress(payload)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        chunked = self.path.endswith("chunked")
        self.send_header("Transfer-Encoding" if chunked else "Content-Length", "chunked" if chunked else str(len(payload)))
        if compressed:
            self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        if self.command != "HEAD":
            if chunked:
                for chunk in [payload[:15], payload[15:]]:
                    self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # The slow-client test deliberately closes its socket.


def main():
    test_started = int(time.time()*1000)
    names = []
    process = None
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    prefix = "openwaf-body-test-" + secrets.token_hex(4)
    try:
        with tempfile.TemporaryDirectory(prefix=prefix) as directory:
            directory = Path(directory)
            pg_password = secrets.token_urlsafe(24)
            for suffix, image, internal, env in [
                ("pg", "postgres:17-bookworm", 5432, ["-e", f"POSTGRES_PASSWORD={pg_password}"]),
                ("ch", "clickhouse/clickhouse-server:25.8", 8123, ["-e", "CLICKHOUSE_SKIP_USER_SETUP=1"]),
            ]:
                name = prefix + "-" + suffix
                docker("run", "-d", "--name", name, "-p", f"127.0.0.1::{internal}", *env, image)
                names.append(name)
            pg_port = int(docker("port", names[0], "5432/tcp").rsplit(":", 1)[1])
            ch_port = int(docker("port", names[1], "8123/tcp").rsplit(":", 1)[1])
            wait(lambda: request(ch_port, "GET", "/ping")[0] == 200)
            wait(lambda: subprocess.run(["docker", "exec", names[0], "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
            key = directory / "master.key"
            key.write_bytes(secrets.token_bytes(32))
            key.chmod(0o600)
            rules = directory / "rules.conf"
            rules.write_text((ROOT / "crates/waf/tests/fixtures/rules.conf").read_text() + '\nSecRule REQUEST_HEADERS:X-Block "@streq yes" "id:941101,phase:1,deny,status:403,nolog"\n')
            gateway_port, admin_port = port(), port()
            env = {key: value for key, value in os.environ.items() if not key.startswith("OPENWAF_")}
            env.update({
                "OPENWAF_ENV_FILE": "/dev/null",
                "OPENWAF_LISTEN": f"127.0.0.1:{gateway_port}",
                "OPENWAF_UPSTREAM": f"127.0.0.1:{upstream.server_port}",
                "OPENWAF_ADMIN_LISTEN": f"127.0.0.1:{admin_port}",
                "OPENWAF_ADMIN_ORIGIN": "https://admin.body.test",
                "OPENWAF_ADMIN_MASTER_KEY_FILE": str(key),
                "OPENWAF_DATABASE_URL": f"postgres://postgres:{pg_password}@127.0.0.1:{pg_port}/postgres?sslmode=disable",
                "OPENWAF_CLICKHOUSE_URL": f"http://127.0.0.1:{ch_port}",
                "OPENWAF_RULES": str(rules),
            })
            if os.environ.get("OPENWAF_RUN_BROWSER_CHECKS") == "1":
                env["OPENWAF_ADMIN_UI_ROOT"] = str(ROOT.parent / "frontend/dist")
            with (directory / "gateway.log").open("wb") as log:
                process = subprocess.Popen([str(ROOT / "target/debug/openwaf-gateway")], env=env, stdout=log, stderr=log)
                def gateway_ready():
                    if process.poll() is not None:
                        detail = (directory / "gateway.log").read_text(errors="replace")[-5000:].replace(pg_password, "[REDACTED]")
                        raise AssertionError("gateway stopped during test: " + detail)
                    return request(admin_port, "GET", "/api/v1/auth/setup")[0] == 200
                wait(gateway_ready)
                origin = {"Origin": env["OPENWAF_ADMIN_ORIGIN"], "Content-Type": "application/json"}
                login = json.dumps({"username": "body-test-admin", "password": secrets.token_urlsafe(24)})
                assert request(admin_port, "POST", "/api/v1/auth/setup", login, origin)[0] == 201
                status, headers, body = request(admin_port, "POST", "/api/v1/auth/login", login, origin)
                assert status == 200
                auth = {**origin, "Cookie": headers["set-cookie"].split(";", 1)[0], "X-CSRF-Token": json.loads(body)["csrf_token"]}

                def api(method, path, value=None):
                    status, _headers, body = request(admin_port, method, "/api/v1" + path, None if value is None else json.dumps(value), auth)
                    assert status == 200, f"API {path}: {status}"
                    return json.loads(body)

                def apply(document):
                    current = api("GET", "/config")
                    saved = api("PUT", "/config/draft", {"expected_revision": current["draft_revision"], "document": document})
                    assert api("POST", "/config/validate", {"document": document})["valid"]
                    result = api("POST", "/config/apply", {"expected_draft_revision": saved["draft_revision"], "expected_active_version": current["active_version"]})
                    wait(lambda: request(gateway_port, "GET", "/", headers={"Host": "body.test"})[0] == 200)
                    return result

                document = {"routes": [{"id": "record", "hostname": "body.test", "path": "/", "path_match": "prefix", "upstream": "spy", "record_body": {"request_enabled": True, "response_enabled": True, "redact_fields": ["private"]}, "waf": {"mode": "On"}}], "upstreams": [{"id": "spy", "endpoints": [{"address": f"127.0.0.1:{upstream.server_port}", "protocol": "http"}]}]}
                apply(document)
                initial_version = api("GET", "/config")["active_version"]

                def traffic(path="/record", payload=b'{"password":"request_sentinel","ok":1}', content_type="application/json", method="POST"):
                    status, headers, response = request(gateway_port, method, path, payload, {"Host": "body.test", "Content-Type": content_type, "Accept": "application/json"})
                    assert status == 200, f"traffic {path}: {status}"
                    return headers["x-request-id"], response

                def recorded(reference):
                    return wait(lambda: (value if value["request"]["status"] != "pending" and value["response"]["status"] != "pending" and value.get("query", {}).get("status") != "pending" and value.get("persistence") != "pending" else None) if (value := api("GET", f"/requests/{reference}/body")) else None)

                reference, _ = traffic()
                bodies = recorded(reference)
                assert bodies["request"]["status"] == bodies["response"]["status"] == "recorded"
                assert bodies["persistence"] == "written"
                assert "request_sentinel" not in bodies["request"]["content"]
                assert "response_sentinel" not in bodies["response"]["content"]
                assert "private_sentinel" not in bodies["response"]["content"]
                assert b"request_sentinel" in Upstream.calls[-1][1], "capture must not modify forwarded payload"
                assert request(admin_port, "GET", f"/api/v1/requests/{reference}/body")[0] == 401
                assert request(admin_port, "GET", f"/api/v1/requests/{reference}/body", headers=auth)[1]["cache-control"] == "no-store"
                ordinary = api("GET", f"/requests/{reference}")
                marker = json.loads(ordinary["record"]["details"])["body_recording"]
                assert marker["request"]["content"] is None and marker["response"]["content"] is None, "body content must not enter ordinary telemetry"
                # Investigation endpoints reuse the real config, session and traffic contracts.
                for path in ["/routes/record", "/telemetry/routes", f"/history/changes?start_ms={test_started}&end_ms={int(time.time()*1000)+1}"]:
                    assert request(admin_port, "GET", "/api/v1"+path)[0] == 401
                    assert request(admin_port, "GET", "/api/v1"+path, headers=auth)[1]["cache-control"] == "no-store"
                route_detail = api("GET", "/routes/record")
                assert route_detail["config_version"] == initial_version
                assert route_detail["source"] == "active"
                assert route_detail["sources"]["timeouts"] == "upstream"
                assert api("GET", "/routes/record?draft=true")["source"] == "saved_draft"
                assert request(admin_port, "GET", "/api/v1/routes/missing", headers=auth)[0] == 404
                assert request(admin_port, "GET", "/api/v1/routes/record?version=1&draft=true", headers=auth)[0] == 422
                route_stats = api("GET", "/telemetry/routes")
                sample = next(r for r in route_stats["items"] if r["route_id"] == "record")
                assert sample["totals"]["incoming"] >= 1 and sample["totals"]["completed"] >= 1
                assert len(sample["totals"]["latency_buckets"]) == 16
                changes = api("GET", f"/history/changes?start_ms={test_started}&end_ms={int(time.time()*1000)+1}")
                assert any(c["action"] == "config.committed" for c in changes["items"])
                # Bounded health observations must not infer recovery across a version change.
                observed = int(time.time()*1000)
                rows=[]
                for offset, available, version in [(-30, True, initial_version), (-20, False, initial_version), (-10, True, initial_version+1)]:
                    diagnostic=json.dumps({"observed_at_unix_ms":observed+offset,"config_version":version,"status":{"checked_at_ms":observed+offset,"valid_for_ms":5000,"available":available}})
                    rows.append(f"('fixture/endpoint', to_timestamp({observed+offset}/1000.0), '{diagnostic}'::jsonb)")
                docker("exec", names[0], "psql", "-U", "postgres", "-q", "-c", "INSERT INTO endpoint_checks(endpoint_key,observed_at,diagnostic) VALUES "+",".join(rows))
                transitions=api("GET",f"/history/changes?start_ms={test_started}&end_ms={observed+1}")
                assert any(c["action"]=="upstream.down_observed" for c in transitions["items"])
                assert not any(c["action"]=="upstream.recovered_observed" for c in transitions["items"])
                print("PASS authenticated/no-store route detail, draft selection, exact config version, counters and audit markers")
                print("PASS independent captures, redaction, unchanged upstream body, auth and no-store")

                form_id, _ = traffic("/form", b"%74oken=request_sentinel&TOKEN=request_sentinel&ok=yes", "application/x-www-form-urlencoded")
                assert "request_sentinel" not in recorded(form_id)["request"]["content"]
                compressed_id, _ = traffic("/compressed")
                assert recorded(compressed_id)["response"]["reason"] == "content_encoding"
                large_id, _ = traffic("/large")
                assert recorded(large_id)["response"]["reason"] == "body_too_large"
                head_id, _ = traffic("/head", None, method="HEAD")
                assert recorded(head_id)["response"]["status"] == "empty"
                print("PASS repeated encoded form fields, compressed/large response skip, HEAD")

                before = len(Upstream.calls)
                status, headers, _ = request(gateway_port, "POST", "/blocked", b"value=openwaf-test-attack", {"Host": "body.test", "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
                assert status == 403 and len(Upstream.calls) == before, "WAF block must never reach upstream"
                blocked = recorded(headers["x-request-id"])
                assert blocked["request"]["status"] == blocked["response"]["status"] == "recorded"
                print("PASS body WAF block records request and local JSON response without upstream traffic")

                streaming = copy.deepcopy(document)
                streaming["routes"][0]["body"] = {"inspection": "headers-query-only", "max_body_bytes": 1048576, "idle_timeout_ms": 30000}
                apply(streaming)
                before = len(Upstream.calls)
                status, headers, _ = request(gateway_port, "POST", "/header-block", b'{"password":"request_sentinel"}', {"Host": "body.test", "Content-Type": "application/json", "Accept": "application/json", "X-Block": "yes"})
                assert status == 403 and len(Upstream.calls) == before
                early = recorded(headers["x-request-id"])
                assert early["request"]["reason"] == "incomplete_body" and early["request"]["content"] is None
                print("PASS header WAF block does not drain or record an unread request body")

                status, headers, _ = request(gateway_port, "POST", "/chunked", [b'{"password":"request_', b'sentinel","ok":1}'], {"Host": "body.test", "Content-Type": "application/json"}, encode_chunked=True)
                assert status == 200
                streamed = recorded(headers["x-request-id"])
                assert streamed["request"]["status"] == streamed["response"]["status"] == "recorded"
                assert "request_sentinel" not in streamed["request"]["content"]
                large_request_id, _ = traffic("/upload", json.dumps({"ok": "x" * 65536}).encode())
                assert recorded(large_request_id)["request"]["reason"] == "body_too_large"
                multipart_id, _ = traffic("/file", b"test file", "multipart/form-data; boundary=test")
                assert recorded(multipart_id)["request"]["reason"] == "unsupported_content_type"
                print("PASS chunked streaming in both directions and oversize/multipart request skip")

                response_only = copy.deepcopy(document)
                response_only["routes"][0]["record_body"]["request_enabled"] = False
                apply(response_only)
                disabled_id, _ = traffic()
                disabled = recorded(disabled_id)
                assert disabled["request"]["status"] == "disabled" and disabled["response"]["status"] == "recorded"
                off = copy.deepcopy(response_only)
                off["routes"][0]["record_body"]["response_enabled"] = False
                apply(off)
                off_id, _ = traffic()
                wait(lambda: request(admin_port, "GET", f"/api/v1/requests/{off_id}", headers=auth)[0] == 200)
                off_body = api("GET", f"/requests/{off_id}/body")
                assert off_body["request"]["status"] == off_body["response"]["status"] == "disabled"
                assert off_body["persistence"] == "not_required"

                current = api("GET", "/config")
                api("POST", "/config/rollback", {"version": initial_version, "expected_active_version": current["active_version"], "expected_draft_revision": current["draft_revision"]})
                wait(lambda: request(gateway_port, "GET", "/", headers={"Host": "body.test"})[0] == 200)
                rollback_id, _ = traffic()
                assert recorded(rollback_id)["request"]["status"] == "recorded"
                print("PASS rollback restores the recorded route policy")

                slow = socket.create_connection(("127.0.0.1", gateway_port), timeout=5)
                try:
                    slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                    slow.sendall(b"GET /slow HTTP/1.1\r\nHost: body.test\r\nConnection: close\r\n\r\n")
                    wait(lambda: any(path == "/slow" for path, _body in Upstream.calls))
                    parallel_id, _ = traffic("/parallel")
                    assert recorded(parallel_id)["response"]["status"] == "recorded"
                finally:
                    slow.close()
                print("PASS a stalled response reader does not block another captured request")

                query_only = copy.deepcopy(document)
                query_only["routes"][0]["record_body"].update({"request_enabled": False, "response_enabled": False, "query_enabled": True})
                apply(query_only)
                query_path = "/query?%74oken=query_sentinel&TOKEN=query_sentinel&private=private_query_sentinel&ok=a%26b&tag=one&tag=two&flag"
                query_id, _ = traffic(query_path, None, method="GET")
                query_record = recorded(query_id)
                assert query_record["request"]["status"] == query_record["response"]["status"] == "disabled"
                assert query_record["query"]["status"] == "recorded"
                query_content = query_record["query"]["content"]
                assert "query_sentinel" not in query_content and "private_query_sentinel" not in query_content
                assert urllib.parse.parse_qs(query_content)["ok"] == ["a&b"]
                assert urllib.parse.parse_qs(query_content)["tag"] == ["one", "two"]
                assert Upstream.calls[-1][0] == query_path, "capture must not change forwarded query"
                wait(lambda: request(admin_port, "GET", f"/api/v1/requests/{query_id}", headers=auth)[0] == 200)
                query_details = api("GET", f"/requests/{query_id}")["record"]["details"]
                assert "query_sentinel" not in query_details and "private_query_sentinel" not in query_details
                assert json.loads(query_details)["body_recording"]["query"]["content"] is None
                assert json.loads(query_details)["metadata"]["request"]["query"] == "[REDACTED]"
                empty_query_id, _ = traffic("/no-query", None, method="GET")
                assert recorded(empty_query_id)["query"]["status"] == "empty"
                before = len(Upstream.calls)
                status, blocked_headers, _ = request(gateway_port, "GET", "/query-block?token=query_sentinel&ok=yes", headers={"Host": "body.test", "Accept": "application/json", "X-Block": "yes"})
                assert status == 403 and len(Upstream.calls) == before
                assert recorded(blocked_headers["x-request-id"])["query"]["status"] == "recorded"
                apply(document)
                no_query_id, _ = traffic(query_path, None, method="GET")
                assert recorded(no_query_id)["query"]["status"] == "disabled"
                print("PASS independent query-only recording, decoded/repeated redaction, empty/disabled state, WAF block and unchanged forwarded query")

                historic = api("GET", f"/routes/record?version={initial_version}")
                assert historic["source"] == "historical_config" and historic["upstream_health"] is None
                assert historic["config_version"] == initial_version and historic["active_version"] != initial_version
                selected_versions = api("GET", f"/config/versions?version={initial_version}")
                assert len(selected_versions)==1 and selected_versions[0]["version"]==initial_version
                search = f"start_ms={test_started}&end_ms={int(time.time()*1000)+1}&limit=100&route_id=record&config_version={initial_version}"
                persisted = wait(lambda: api("GET", "/history/traffic?"+search)["items"])
                assert all(int(r["config_version"]) == initial_version for r in persisted)
                tops = api("GET", "/history/top?"+search)
                assert tops["source"] == "clickhouse_records" and tops["items"]["routes"][0]["label"] == "record"
                print("PASS historical config remains separate after apply, exact-version diff lookup and filtered history/top")

                if os.environ.get("OPENWAF_RUN_BROWSER_CHECKS") == "1":
                    browser_env = os.environ.copy()
                    browser_env.update({"OPENWAF_BROWSER_BASE": f"http://127.0.0.1:{admin_port}", "OPENWAF_BROWSER_COOKIE": auth["Cookie"], "OPENWAF_BROWSER_START": str(test_started), "OPENWAF_BROWSER_VERSION": str(initial_version)})
                    subprocess.run(["node", str(ROOT / "tests/investigation_browser.cjs")], env=browser_env, check=True, timeout=120)

                # History remains readable after clearing the live cache by restart.
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=20)
                process = subprocess.Popen([str(ROOT / "target/debug/openwaf-gateway")], env=env, stdout=log, stderr=log)
                wait(gateway_ready)
                wait(lambda: request(gateway_port, "GET", "/", headers={"Host": "body.test"})[0] == 200)
                rollups = api("GET", f"/history/statistics?start_ms={test_started}&end_ms={int(time.time()*1000)+1}&route_id=record")
                assert rollups["source"] == "counter_rollup" and rollups["retention_days"] == 30
                assert len(rollups["items"]) >= 1 and sum(int(r["incoming"]) for r in rollups["items"]) >= 1
                assert all(len(r["latency_buckets"])==16 for r in rollups["items"])
                print("PASS owned rollup shutdown flush and counter history after restart")
                restored = api("GET", f"/requests/{reference}/body")
                assert restored["request"]["content"] == bodies["request"]["content"], f"restored request state: {restored['request']['status']}, reason: {restored['request'].get('reason')}, persistence: {restored.get('persistence')}"
                assert restored["response"]["content"] == bodies["response"]["content"]
                restored_query = api("GET", f"/requests/{query_id}/body")
                assert restored_query["query"]["content"] == query_content
                print("PASS independent route flags, atomic apply and body/query ClickHouse history after restart")

                # Stop only the test history service. Traffic and the live copy survive.
                docker("stop", "-t", "2", names[1])
                outage_id, _ = traffic()
                outage = recorded(outage_id)
                assert outage["response"]["status"] == "recorded"
                assert outage["persistence"] == "failed_or_uncertain"
                print("PASS ClickHouse outage preserves traffic and reports failed persistence")
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)
        for name in reversed(names):
            subprocess.run(["docker", "rm", "-fv", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    main()
