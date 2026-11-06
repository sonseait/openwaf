#!/usr/bin/env python3
"""AB-1..6 integration fixture: real gateway/native rules/PostgreSQL, local only.

Run from backend after cargo build -p openwaf-gateway and frontend npm run build.
Requires Docker postgres:17-bookworm and permission to bind loopback sockets.
Creates random credentials in an owner-only temporary directory. Never reads
production credentials or enables Telegram; only its own container is removed.
"""
import copy
import concurrent.futures
import http.server
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from body_recording import ROOT, docker, port, request, wait


class Fixture(http.server.BaseHTTPRequestHandler):
    calls = []
    auth_calls = 0
    lock = threading.Lock()

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        raw = self.rfile.read(int(self.headers.get("content-length", "0")))
        if self.path == "/verify":
            with self.lock:
                type(self).auth_calls += 1
            identity = self.headers.get("authorization", "")
            self.send_response(200 if identity else 401)
            if identity:
                self.send_header("remote-user", identity)
        else:
            with self.lock:
                type(self).calls.append((self.path, raw, self.headers.get("remote-user")))
            self.send_response(404 if self.path.startswith("/missing") else 200)
        self.send_header("content-length", "0")
        self.end_headers()


def main():
    crs_rules = os.environ.get("OPENWAF_TEST_CRS_RULES")
    attack_path = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" if crs_rules else "/?q=openwaf-test-attack"
    name = "openwaf-ab-" + secrets.token_hex(4)
    ch_name = name + "-ch"
    storage_test = os.environ.get("OPENWAF_TEST_STORAGE") == "1"
    keepalive = os.environ.get("OPENWAF_TEST_KEEPALIVE") == "1"
    if keepalive:
        Fixture.protocol_version = "HTTP/1.1"
    ch_port = None
    process = None
    server = None
    with tempfile.TemporaryDirectory(prefix=name) as temporary:
        directory = Path(temporary)
        password = secrets.token_hex(24)
        pg_env = directory / "pg.env"
        pg_env.write_text("POSTGRES_PASSWORD=" + password + "\n")
        pg_env.chmod(0o600)
        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            upstream_port = server.server_address[1]
            docker("run", "-d", "--name", name, "--env-file", str(pg_env), "-p", "127.0.0.1::5432", "postgres:17-bookworm")
            pg_port = int(docker("port", name, "5432/tcp").rsplit(":", 1)[1])
            if storage_test:
                docker("run", "-d", "--name", ch_name, "-e", "CLICKHOUSE_SKIP_USER_SETUP=1", "-p", "127.0.0.1::8123", "clickhouse/clickhouse-server:25.8")
                ch_port = int(docker("port", ch_name, "8123/tcp").rsplit(":", 1)[1])
                wait(lambda: request(ch_port, "GET", "/ping")[0] == 200)
            # The temporary initialization server accepts Unix sockets before
            # PostgreSQL restarts into its published TCP listener.
            wait(lambda: subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], capture_output=True).returncode == 0)
            key = directory / "key"
            key.write_bytes(secrets.token_bytes(32))
            key.chmod(0o600)
            gateway_port = port()
            env = {k: v for k, v in os.environ.items() if not k.startswith("OPENWAF_")}
            env.update(OPENWAF_ENV_FILE="/dev/null", OPENWAF_LISTEN=f"127.0.0.1:{gateway_port}",
                       OPENWAF_UPSTREAM="127.0.0.1:9090", OPENWAF_ADMIN_LISTEN="127.0.0.1:9090",
                       OPENWAF_ADMIN_PUBLIC="true", OPENWAF_ADMIN_HOST="admin.example.com", OPENWAF_ADMIN_ORIGIN="https://admin.example.com",
                       OPENWAF_DATABASE_URL=f"postgres://postgres:{password}@127.0.0.1:{pg_port}/postgres?sslmode=disable",
                       OPENWAF_ADMIN_MASTER_KEY_FILE=str(key), OPENWAF_ADMIN_UI_ROOT=str(ROOT.parent / "frontend/dist"),
                       OPENWAF_RULES=crs_rules or str(ROOT / "crates/waf/tests/fixtures/rules.conf"))
            log = (directory / "gateway.log").open("wb")
            if storage_test:
                assert ch_port is not None
                env["OPENWAF_CLICKHOUSE_URL"] = f"http://127.0.0.1:{ch_port}"

            def start():
                nonlocal process
                profile = "release" if os.environ.get("OPENWAF_TEST_RELEASE") == "1" else "debug"
                process = subprocess.Popen([str(ROOT / f"target/{profile}/openwaf-gateway")], env=env, stdout=log, stderr=log)
                def ready():
                    if process.poll() is not None:
                        raise RuntimeError("Fixture stopped; private log suppressed")
                    return request(gateway_port, "GET", "/api/v1/auth/setup", headers={"Host": "admin.example.com"})[0] == 200
                wait(ready)

            start()
            public = {"Host": "admin.example.com", "Origin": env["OPENWAF_ADMIN_ORIGIN"], "Content-Type": "application/json"}
            login = json.dumps({"username": "fixture-owner", "password": secrets.token_hex(24)})
            assert request(gateway_port, "POST", "/api/v1/auth/setup", login, public)[0] == 201
            status, response_headers, body = request(gateway_port, "POST", "/api/v1/auth/login", login, public)
            assert status == 200
            auth = {**public, "Cookie": response_headers["set-cookie"].split(";", 1)[0], "X-CSRF-Token": json.loads(body)["csrf_token"]}

            def api(method, path, value=None, expected=200, headers=None):
                status, _, raw = request(gateway_port, method, "/api/v1" + path, None if value is None else json.dumps(value), auth if headers is None else headers)
                assert status == expected, (path, status, expected)
                return json.loads(raw) if raw else None

            def config_ready():
                status, _, raw = request(gateway_port, "GET", "/api/v1/config", headers=auth)
                if status == 503:
                    return None
                assert status == 200, ("/config", status)
                return json.loads(raw)

            def stream_sync(cursor=None):
                connection = http.client.HTTPConnection("127.0.0.1", gateway_port, timeout=5)
                try:
                    headers = {**auth, "Accept": "text/event-stream"}
                    if cursor is not None:
                        headers["Last-Event-ID"] = cursor
                    connection.request("GET", "/api/v1/events/logs", headers=headers)
                    response = connection.getresponse()
                    assert response.status == 200, ("SSE", response.status)
                    assert (response.getheader("content-type") or "").startswith("text/event-stream")
                    fields = {}
                    for _ in range(16):
                        line = response.readline(65537)
                        assert len(line) <= 65536 and line, "bounded SSE initial event"
                        if line in (b"\n", b"\r\n"):
                            break
                        key, _, value = line.decode().strip().partition(":")
                        fields[key] = value.lstrip()
                    assert fields["event"] == "sync"
                    return json.loads(fields["data"])
                finally:
                    connection.close()

            sync = stream_sync()
            assert sync["gap"] is False and sync["reason"] == "no_replay"
            reconnect = stream_sync("stale-epoch:logs:0")
            assert reconnect["gap"] is True and reconnect["reason"] == "no_replay"
            assert reconnect["epoch"] == sync["epoch"]
            print("PASS HTTP SSE: authenticated sync and stale-cursor reconnect reports no-replay gap", flush=True)

            if os.environ.get("OPENWAF_TEST_SSE_LIFETIME") == "1":
                lifetime_connection = http.client.HTTPConnection("127.0.0.1", gateway_port, timeout=10)
                started = time.monotonic()
                cursor = None
                try:
                    lifetime_connection.request("GET", "/api/v1/events/logs", headers={**auth, "Accept": "text/event-stream"})
                    response = lifetime_connection.getresponse()
                    assert response.status == 200
                    for _ in range(512):
                        assert time.monotonic() - started < 40, "finite SSE lifetime"
                        line = response.readline(65537)
                        assert len(line) <= 65536
                        if not line:
                            break
                        if line.startswith(b"id:"):
                            cursor = line.decode().partition(":")[2].strip()
                    else:
                        raise AssertionError("SSE lifetime line budget exceeded")
                    elapsed = time.monotonic() - started
                    assert 20 <= elapsed <= 40, ("SSE lifetime", elapsed)
                    assert cursor is not None
                finally:
                    lifetime_connection.close()
                resumed = stream_sync(cursor)
                assert resumed["epoch"] == sync["epoch"]
                assert resumed["reason"] == "no_replay"
                print(json.dumps({"test": "sse_finite_lifetime_reconnect", "elapsed_seconds": elapsed,
                    "reconnect_gap": resumed["gap"], "reason": resumed["reason"]}), flush=True)

            for path in ["/security/detectors", "/security/incidents"]:
                api("GET", path, expected=401, headers=public)
            api("POST", "/security/simulate", {"source":"active","expected_active_version":0,"request":{"hostname":"app.test","path":"/","method":"GET","client_ip":"192.0.2.1"}}, expected=401, headers=public)
            state = api("GET", "/config")
            document = copy.deepcopy(state["active"])
            document["upstreams"].append({"id": "fixture", "endpoints": [{"address": f"127.0.0.1:{upstream_port}", "protocol": "http", "weight": 1}]})
            def route(route_id, host, middleware=None, waf="DetectionOnly"):
                return {"id": route_id, "hostname": host, "path": "/", "path_match": "prefix", "upstream": "fixture", "waf": {"mode": waf}, "middleware": middleware or {}}
            identity = {"forward_auth": {"upstream": "fixture", "path": "/verify", "response_headers": ["remote-user"], "identity_headers": ["remote-user"]},
                        "identity_rate_limit": {"header": "remote-user", "per_second": 1, "burst": 1, "require_identity": True}}
            document["routes"].extend([route("principal", "principal.test", identity), route("probe", "probe.test", {"detectors": {"window_seconds": 10, "min_samples": 2, "requests_per_second": 1, "distinct_paths": 2, "upstream_404_percent": 50}}), route("native", "native.test", waf="On")])
            schema = route("schema", "schema.test", {"api_schema": {"mode": "observe", "schema": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string", "minLength": 1, "maxLength": 8}}, "additionalProperties": False}}})
            schema.update(content={"media_types": ["application/json"], "require_type_for_body": True}, body={"inspection": "full", "max_body_bytes": 65536, "idle_timeout_ms": 30000})
            document["routes"].append(schema)
            if os.environ.get("OPENWAF_TEST_HTTP_BENCH") == "1":
                assert os.environ.get("OPENWAF_TEST_RELEASE") == "1", "benchmark requires release binary"
                for mode in ["Off", "DetectionOnly", "On"]:
                    document["routes"].append(route("bench-" + mode.lower(), "bench-" + mode.lower() + ".test", waf=mode))

            def save_apply(doc):
                current = api("GET", "/config")
                saved = api("PUT", "/config/draft", {"expected_revision": current["draft_revision"], "document": doc})
                assert api("POST", "/config/validate", {"document": doc})["valid"]
                api("POST", "/config/apply", {"expected_active_version": current["active_version"], "expected_draft_revision": saved["draft_revision"]})
                # Config publication/reconciliation briefly owns the writer.
                # Retry only its explicit unavailable response, with a deadline.
                return wait(config_ready, seconds=10)

            state = save_apply(document)
            correlation_route = route("correlation", "correlation.test", {
                "forward_auth": identity["forward_auth"], "detectors": {"window_seconds": 60, "min_samples": 2, "requests_per_second": 1, "distinct_paths": 2, "upstream_404_percent": 50}})
            document["routes"].append(correlation_route)
            state = save_apply(document)
            for user in ["correlation-a", "correlation-b"]:
                for i in range(3):
                    assert request(gateway_port, "GET", f"/ok?secret={i}", headers={"Host": "correlation.test", "Authorization": user, "remote-user": "spoofed"})[0] == 200
            def correlated_windows():
                diagnostics = api("GET", "/security/detectors")
                assert diagnostics is not None
                rows = diagnostics["windows"]
                rows = [w for w in rows if w["route"] == "correlation" and w["detector"] == "endpoint_probing"]
                return rows if len(rows) == 2 and all(w["evidence"]["samples"] == 3 for w in rows) else None
            correlated = wait(correlated_windows)
            assert all(w["evidence"]["correlation_source"] == "verified_identity" for w in correlated)
            assert all(len(w["evidence"]["recent_events"]) == 3 for w in correlated)
            assert "correlation-a" not in json.dumps(correlated) and "secret" not in json.dumps(correlated)
            print("PASS client correlation: verified identities behind one IP remain separate; recent sequence is metadata-only", flush=True)
            wait(lambda: request(gateway_port, "GET", "/ok", headers={"Host": "probe.test"})[0] == 200)
            with Fixture.lock:
                before = len(Fixture.calls)
            assert request(gateway_port, "GET", attack_path, headers={"Host": "native.test"})[0] == 403
            with Fixture.lock:
                assert len(Fixture.calls) == before, "CRS-blocked request reached upstream"
            print("PASS AB-1/native: enforced CRS block never reaches upstream", flush=True)

            # Subscribe before generating traffic: logs SSE deliberately has no replay.
            connection = http.client.HTTPConnection("127.0.0.1", gateway_port, timeout=5)
            try:
                connection.request("GET", "/api/v1/events/logs", headers={**auth, "Accept": "text/event-stream"})
                response = connection.getresponse()
                assert response.status == 200

                def read_event():
                    fields = {}
                    for _ in range(32):
                        line = response.readline(65537)
                        assert line and len(line) <= 65536, "bounded SSE event"
                        if line in (b"\n", b"\r\n"):
                            return fields
                        key, _, value = line.decode().strip().partition(":")
                        fields[key] = value.lstrip()
                    raise AssertionError("SSE event line budget exceeded")

                assert read_event()["event"] == "sync"
                assert request(gateway_port, "GET", attack_path, headers={"Host": "native.test"})[0] == 403
                found = False
                for _ in range(64):
                    event = read_event()
                    if event.get("event") != "log":
                        continue
                    record = json.loads(event["data"])["data"]
                    if record["status"] != 403:
                        continue
                    details = json.loads(record["details"])
                    if details.get("route_id") != "native":
                        continue
                    signals = details["security_signals"]
                    if crs_rules:
                        assert any(e["source"] == "crs" and e["action"] == "enforced_block" and e["rule_id"] > 0 for e in signals["entries"])
                    else:
                        assert any(e["source"] == "waf" and e["reason"] == "native_decision" and e["action"] == "enforced_block" and e["rule_id"] == 0 for e in signals["entries"])
                    assert "alert(1)" not in record["details"]
                    assert "openwaf-test-attack" not in record["details"]
                    if storage_test:
                        query = f'/history/traffic?start_ms={record["observed_at_unix_ms"]}&end_ms={record["observed_at_unix_ms"] + 1}&limit=100&request_id={record["request_id"]}'
                        def persisted_items():
                            result = api("GET", query)
                            assert result is not None
                            return result["items"]
                        persisted = wait(persisted_items)
                        assert len(persisted) == 1
                        assert persisted[0]["request_id"] == record["request_id"]
                        assert json.loads(persisted[0]["details"])["security_signals"] == signals
                        print("PASS gateway writer → ClickHouse → history: exact SSE request signals preserved", flush=True)
                    found = True
                    break
                assert found, "blocked request signals missing from live HTTP SSE"
                print("PASS HTTP SSE signals: native enforced block metadata and payload redaction", flush=True)
            finally:
                connection.close()

            if storage_test:
                baseline = api("GET", "/telemetry/storage")
                assert baseline is not None
                docker("pause", ch_name)
                try:
                    started = time.perf_counter()
                    saturation = os.environ.get("OPENWAF_TEST_STORAGE_SATURATION") == "1"
                    count = 5000 if saturation else 100
                    traffic = http.client.HTTPConnection("127.0.0.1", gateway_port, timeout=5)
                    try:
                        for _ in range(count):
                            traffic.request("GET", "/ok", headers={"Host": "probe.test"})
                            reply = traffic.getresponse()
                            assert reply.status == 200
                            reply.read()
                    finally:
                        traffic.close()
                    traffic_elapsed = time.perf_counter() - started

                    def degraded_storage():
                        health = api("GET", "/telemetry/storage")
                        assert health is not None
                        enough_loss = not saturation or health["dropped"] - baseline["dropped"] > 1000
                        return health if health["degraded"] and enough_loss else None

                    degraded = wait(degraded_storage, seconds=15)
                    assert degraded["dropped"] > baseline["dropped"], "write failure must disclose lost records"
                    assert request(gateway_port, "GET", "/ok", headers={"Host": "probe.test"})[0] == 200
                    print(json.dumps({"test": "clickhouse_outage", "requests": count,
                        "elapsed_seconds": traffic_elapsed, "degraded": degraded["degraded"],
                        "dropped": degraded["dropped"], "backlog": degraded["backlog"]}), flush=True)
                finally:
                    docker("unpause", ch_name)

                def recovered_storage():
                    assert request(gateway_port, "GET", "/ok", headers={"Host": "probe.test"})[0] == 200
                    health = api("GET", "/telemetry/storage")
                    assert health is not None
                    return health if not health["degraded"] and health["written"] > degraded["written"] else None

                recovered = wait(recovered_storage, seconds=30)
                assert recovered["dropped"] >= degraded["dropped"], "recovery must not erase loss counters"
                print(json.dumps({"test": "clickhouse_recovery", "written": recovered["written"],
                    "dropped": recovered["dropped"], "backlog": recovered["backlog"]}), flush=True)
                print("PASS ClickHouse pause/recovery: traffic continues, degraded explicit, writer resumes", flush=True)

            if os.environ.get("OPENWAF_TEST_SLOW_SSE") == "1":
                slow_connections = []
                slow_responses = []
                traffic_connection = http.client.HTTPConnection("127.0.0.1", gateway_port, timeout=5) if keepalive else None
                try:
                    for _ in range(4):
                        slow = http.client.HTTPConnection("127.0.0.1", gateway_port, timeout=5)
                        slow_connections.append(slow)
                        if os.environ.get("OPENWAF_TEST_SSE_GAP") == "1":
                            slow.connect()
                            assert slow.sock is not None
                            slow.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                        slow.request("GET", "/api/v1/events/logs", headers={**auth, "Accept": "text/event-stream"})
                        response = slow.getresponse()
                        assert response.status == 200
                        # Keep the response alive but intentionally never read its body.
                        slow_responses.append(response)
                    started = time.perf_counter()
                    latencies = []
                    soak = os.environ.get("OPENWAF_TEST_SSE_SOAK") == "1"
                    rss_samples = []
                    max_requests = 100000 if soak else 1000
                    for i in range(max_requests):
                        duration = 5 if os.environ.get("OPENWAF_TEST_SSE_GAP") == "1" else 30
                        if soak and i >= 1000 and time.perf_counter() - started >= duration:
                            break
                        before = time.perf_counter_ns()
                        if traffic_connection is not None:
                            traffic_connection.request("GET", "/ok", headers={"Host": "probe.test"})
                            traffic_response = traffic_connection.getresponse()
                            status = traffic_response.status
                            traffic_response.read()
                        else:
                            status = request(gateway_port, "GET", "/ok", headers={"Host": "probe.test"})[0]
                        if status != 200:
                            diagnostic = {"test": "soak_failure", "index": i, "status": status}
                            try:
                                diagnostic["direct_upstream_status"] = request(upstream_port, "GET", "/ok")[0]
                            except OSError as error:
                                diagnostic["direct_upstream_errno"] = error.errno
                            private_log = (directory / "gateway.log").read_text(errors="replace")
                            diagnostic["native_error_markers"] = {
                                marker: private_log.count(marker) for marker in
                                ["Can't assign requested address", "Address not available", "os error 49", "Connection refused", "Too many open files"]
                            }
                            print(json.dumps(diagnostic), flush=True)
                        assert status == 200, ("soak", i, status)
                        latencies.append(time.perf_counter_ns() - before)
                        if soak and os.environ.get("OPENWAF_TEST_UNPACED") != "1":
                            time.sleep(0.005)  # Bound connection churn on loopback.
                        if soak and i % 1000 == 0:
                            assert process is not None
                            rss_samples.append(int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(process.pid)], text=True).strip()))
                    latencies.sort()
                    gap_proven = False
                    if os.environ.get("OPENWAF_TEST_SSE_GAP") == "1":
                        deadline = time.monotonic() + 20
                        fields = {}
                        for _ in range(32768):
                            assert time.monotonic() < deadline, "SSE gap read deadline"
                            line = slow_responses[0].readline(65537)
                            assert line and len(line) <= 65536, "bounded SSE gap read"
                            if line in (b"\n", b"\r\n"):
                                if fields.get("event") == "gap":
                                    payload = json.loads(fields["data"])["data"]
                                    assert payload["reason"] == "slow_consumer" and payload["lost"] > 0
                                    print(json.dumps({"test": "http_sse_overflow", "lost": payload["lost"], "reason": payload["reason"]}), flush=True)
                                    gap_proven = True
                                    break
                                fields = {}
                            else:
                                key, _, value = line.decode().strip().partition(":")
                                fields[key] = value.lstrip()
                        assert gap_proven, "unread SSE workload did not produce an explicit overflow gap"
                    print(json.dumps({"test": "unread_http_sse", "clients": 4,
                        "requests": len(latencies), "elapsed_seconds": time.perf_counter() - started,
                        "p99_ns": latencies[min(len(latencies) - 1, len(latencies) * 99 // 100)], "max_ns": latencies[-1],
                        "gateway_rss_kib": rss_samples,
                        "keepalive": keepalive,
                        "tcp_backpressure_proven": gap_proven}), flush=True)
                finally:
                    if traffic_connection is not None:
                        traffic_connection.close()
                    for response in slow_responses:
                        response.close()
                    for slow in slow_connections:
                        slow.close()
                assert request(gateway_port, "GET", "/ok", headers={"Host": "probe.test"})[0] == 200
                print("PASS unread SSE clients: traffic continues during unread streams and after close", flush=True)

            if os.environ.get("OPENWAF_TEST_HTTP_BENCH") == "1":
                for mode in ["Off", "DetectionOnly", "On"]:
                    headers = {"Host": "bench-" + mode.lower() + ".test"}
                    wait(lambda: request(gateway_port, "GET", "/ok", headers=headers)[0] == 200)
                    for _ in range(20):
                        assert request(gateway_port, "GET", "/ok", headers=headers)[0] == 200

                    def sample(_):
                        before = time.perf_counter_ns()
                        status = request(gateway_port, "GET", "/ok", headers=headers)[0]
                        return status, time.perf_counter_ns() - before

                    started = time.perf_counter()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
                        results = list(workers.map(sample, range(500)))
                    elapsed = time.perf_counter() - started
                    errors = sum(status != 200 for status, _ in results)
                    timings = sorted(ns for _, ns in results)
                    print(json.dumps({"benchmark": "local_http", "mode": mode,
                        "requests": len(results), "concurrency": 4, "errors": errors,
                        "elapsed_seconds": elapsed, "completed_rps": len(results) / elapsed,
                        "p50_ns": timings[250], "p95_ns": timings[475], "p99_ns": timings[495],
                        "max_ns": timings[-1], "keepalive": False, "tls": False,
                        "rules": "native_fixture_not_full_crs"}), flush=True)
                    assert errors == 0, (mode, errors)

            alice = {"Host": "principal.test", "Authorization": "fixture-alice", "remote-user": "forged"}
            bob = {**alice, "Authorization": "fixture-bob"}
            assert request(gateway_port, "GET", "/ok", headers=alice)[0] == 200
            with Fixture.lock:
                assert Fixture.calls[-1][2] == "fixture-alice", "spoofed identity forwarded"
            assert request(gateway_port, "GET", "/ok", headers=alice)[0] == 429
            assert request(gateway_port, "GET", "/ok", headers=bob)[0] == 200
            assert request(gateway_port, "GET", "/ok", headers={"Host": "principal.test", "remote-user": "forged"})[0] == 401
            print("PASS AB-2: verified identities, same NAT independent quota, spoof stripping, auth failure", flush=True)

            raw = b'{ "name" : "ok" }'
            assert request(gateway_port, "POST", "/", raw, {"Host": "schema.test", "Content-Type": "application/json"})[0] == 200
            with Fixture.lock:
                assert Fixture.calls[-1][1] == raw
            assert request(gateway_port, "POST", "/", b'{}', {"Host": "schema.test", "Content-Type": "application/json"})[0] == 200
            draft = copy.deepcopy(document)
            next(r for r in draft["routes"] if r["id"] == "schema")["middleware"]["api_schema"]["mode"] = "block"
            saved = api("PUT", "/config/draft", {"expected_revision": state["draft_revision"], "document": draft})
            state = api("GET", "/config")
            before_diag = api("GET", "/telemetry/dependencies")
            with Fixture.lock:
                before_calls, before_auth = len(Fixture.calls), Fixture.auth_calls
            simulated = api("POST", "/security/simulate", {"source": "compare", "expected_active_version": state["active_version"], "expected_draft_revision": saved["draft_revision"], "request": {"hostname": "schema.test", "path": "/", "method": "POST", "client_ip": "192.0.2.1", "headers": [["content-type", "application/json"]], "body": "{}"}})
            assert simulated["outputs"]["active"]["api_schema"]["mode"] == "observe"
            assert simulated["outputs"]["draft"]["api_schema"]["mode"] == "block"
            with Fixture.lock:
                assert (len(Fixture.calls), Fixture.auth_calls) == (before_calls, before_auth)
            after_diag = api("GET", "/telemetry/dependencies")
            assert before_diag["identity_rate_limit"] == after_diag["identity_rate_limit"]
            for bad_method, bad_path in [("get", "/"), ("GET", "/%61"), ("GET", "/a/../b")]:
                api("POST", "/security/simulate", {"source": "active", "expected_active_version": state["active_version"], "request": {"hostname": "schema.test", "path": bad_path, "method": bad_method, "client_ip": "192.0.2.1"}}, expected=422)
            api("POST", "/config/apply", {"expected_active_version": state["active_version"], "expected_draft_revision": saved["draft_revision"]})
            with Fixture.lock:
                before = len(Fixture.calls)
            assert request(gateway_port, "POST", "/", b'{}', {"Host": "schema.test", "Content-Type": "application/json"})[0] == 400
            with Fixture.lock:
                assert len(Fixture.calls) == before
            print("PASS AB-5/6: exact active/draft simulation, no auth/upstream/quota mutation, observe/block schema and byte preservation", flush=True)

            # New snapshot health starts unknown until the owned probe completes.
            wait(lambda: request(gateway_port, "GET", "/ok", headers={"Host": "probe.test"})[0] == 200)
            for i in range(35):
                status = request(gateway_port, "GET", f"/missing/{i}", headers={"Host": "probe.test"})[0]
                assert status == 404, ("probe", i, status)
            incidents = wait(lambda: (lambda v: v if v is not None and {i["detector"] for i in v["items"]} == {"route_flood", "endpoint_probing"} else None)(api("GET", "/security/incidents")))
            assert {i["detector"] for i in incidents["items"]} == {"route_flood", "endpoint_probing"}
            assert "fixture-alice" not in json.dumps(incidents) and "missing/" not in json.dumps(incidents)
            incident = incidents["items"][0]
            api("POST", f'/security/incidents/{incident["id"]}', {"state": "ack", "expected_revision": incident["revision"]}, expected=204)
            api("POST", f'/security/incidents/{incident["id"]}', {"state": "resolved", "expected_revision": incident["revision"]}, expected=409)
            assert any(a["action"] == "incident.ack" for a in api("GET", "/audit"))
            docker("pause", name)
            try:
                assert request(gateway_port, "GET", "/ok", headers={"Host": "probe.test"})[0] == 200
            finally:
                docker("unpause", name)
            wait(lambda: api("GET", "/security/incidents"))
            ids = {i["id"] for i in incidents["items"]}
            process.terminate()
            process.wait(timeout=15)
            start()
            persisted = api("GET", "/security/incidents")
            assert ids.issubset({i["id"] for i in persisted["items"]})
            assert all(i["quality"] == "restart_unknown" for i in persisted["items"] if i["id"] in ids)
            assert request(gateway_port, "GET", "/ok", headers=alice)[0] == 200
            print("PASS AB-3/4: real detector incidents, privacy, optimistic/audited ACK, DB outage traffic continuity and restart unknown quality", flush=True)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
            if server is not None:
                server.shutdown()
                server.server_close()
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if storage_test:
                subprocess.run(["docker", "rm", "-f", ch_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
