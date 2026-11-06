#!/usr/bin/env python3
"""Isolated Compose dependency provisioning/restart smoke; no public ACME calls.
Uses the real VPS dependency services and a namespace holder in place of gateway.
Requires OPENWAF_TEST_IMAGE with the current packaged runtime defaults.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "backend/runtime"))
import vps_profiles  # noqa: E402
from compose_fixture import LinuxState, render_stack  # noqa: E402


def run(*args, env=None, timeout=90):
    result = subprocess.run(args, env=env, capture_output=True, timeout=timeout)
    if result.returncode:
        # cscli/init output may contain credentials. Do not emit captured output.
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0]}; output suppressed")
    return result.stdout.decode().strip()


def wait(check, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if check():
                return
        except (RuntimeError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError("Dependency readiness deadline exceeded")


def exercise(image, init_image, sizing, project, root, data_dir):
    model = render_stack(root / "rendered-stack", {
        "openwaf_image": image, "openwaf_init_image": init_image, "openwaf_project_name": project,
        "openwaf_vps_profile": sizing["name"], "openwaf_data_dir": data_dir,
        "openwaf_docker_network_name": project + "-backends",
    })
    services = model["services"]
    assert "collector" in services and "acme" not in services
    assert services["gateway"]["environment"]["OPENWAF_CLICKHOUSE_URL"] == "http://127.0.0.1:8123/"
    assert "crowdsec-seal" in services["gateway"]["depends_on"]
    assert services["gateway"]["environment"]["OPENWAF_CERTIFICATES_ROOT"] == "/var/lib/openwaf/certificate-requests"
    assert "OPENWAF_CERTIFICATES_CONFIG" not in services["gateway"]["environment"]
    mounts = {v["target"]: v for v in services["gateway"]["volumes"]}
    assert not mounts["/var/lib/openwaf/tls"].get("read_only", False)
    assert mounts["/run/openwaf-certificate-key"]["read_only"]
    assert all("docker-engine.sock" not in str(s.get("volumes", []))
               for name, s in services.items() if name != "collector")
    assert all(not s.get("ports") for name, s in services.items() if name != "gateway")
    selected = {name: services[name] for name in ("startup-init", "dependencies-init", "crowdsec-init", "crowdsec-seal", "clickhouse", "crowdsec", "collector")}
    # Namespace holder isolates this test from admin/DB/public TLS provisioning.
    # Dependencies retain their exact entrypoints, users, caps, volumes and healthchecks.
    selected["gateway"] = {"image": init_image, "entrypoint": ["python3", "-c", "import time; time.sleep(86400)"],
                           "user": "10001:10001", "read_only": True, "cap_drop": ["ALL"],
                           "network_mode": "none", "restart": "no",
                           "volumes": [v for v in services["gateway"]["volumes"] if v["target"] == "/run/openwaf-discovery"],
                           "depends_on": {"crowdsec-seal": {"condition": "service_completed_successfully"}}}
    for service in selected.values():
        service["restart"] = "no"
        # Compose JSON export currently renders scalar core:0 as {}.
        if "ulimits" in service:
            service["ulimits"]["core"] = 0
    model = {"services": selected}
    token = root / "token"
    token.write_text(secrets.token_urlsafe(32))
    token.chmod(0o600)
    selected["startup-init"].pop("secrets", None)
    selected["startup-init"]["volumes"].append({"type": "bind", "source": str(token),
                                              "target": "/run/secrets/cloudflare-token", "read_only": True})
    path = root / "compose.json"
    path.write_text(json.dumps(model))
    compose = ["docker", "compose", "--env-file", "/dev/null", "-p", project, "-f", str(path)]

    def execute(service, *args):
        return run(*compose, "exec", "-T", service, *args)

    def healthy(service):
        cid = run(*compose, "ps", "-q", service)
        return bool(cid) and run("docker", "inspect", "--format", "{{.State.Health.Status}}", cid) == "healthy"

    try:
        run(*compose, "up", "-d", "--no-build", "--pull", "never")
        wait(lambda: healthy("clickhouse") and healthy("crowdsec"))
        print("PASS real Compose offline init, cscli provisioning, native credential sealing, healthy ClickHouse/LAPI")
        def discovery_ready():
            # Read inventory through the private Unix protocol; never print it.
            return execute("gateway", "python3", "-c", """
import json,socket
from pathlib import Path
path='/run/openwaf-discovery/collector.sock'
assert Path(path).stat().st_mode & 0o777 == 0o600
for op in ('docker','host-ports'):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5)
        s.connect(path)
        s.sendall(json.dumps({'op':op}).encode()+b'\\n')
        data=json.load(s.makefile())
        assert data['schema_version']==1 and not data['stale'] and not data['snapshot']['degraded'] and data['snapshot']['observed_at_unix_ms']
print('ready')
""") == "ready"
        wait(discovery_ready)
        run(*compose, "restart", "collector")
        wait(discovery_ready)
        print("PASS collector reads Docker/host inventory through private 0600 Unix socket and restarts cleanly")
        key_digest = execute("crowdsec", "sha256sum", "/etc/crowdsec/bouncer.key")
        # Confirm both HTTP listeners are loopback-only inside their namespace.
        sockets = execute("gateway", "python3", "-c",
            "from pathlib import Path; print(Path('/proc/net/tcp').read_text())")
        for port in (8123, 8085):
            rows = [row.split() for row in sockets.splitlines()[1:]]
            assert any(row[1] == f"0100007F:{port:04X}" and row[3] == "0A" for row in rows)
            assert not any(row[1] == f"00000000:{port:04X}" and row[3] == "0A" for row in rows)
        # Durable ClickHouse data and local decisions must survive service restart.
        def clickhouse_query(sql):
            # Distroless has no wget/shell; query from the gateway namespace.
            return execute("gateway", "python3", "-c",
                "import sys,urllib.request; "
                "print(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8123/', "
                "data=sys.argv[1].encode()), timeout=3).read().decode(), end='')", sql)
        query = "CREATE TABLE IF NOT EXISTS deploy_smoke (value UInt8) ENGINE=MergeTree ORDER BY value"
        clickhouse_query(query)
        clickhouse_query("INSERT INTO deploy_smoke VALUES (7)")
        execute("crowdsec", "cscli", "decisions", "add", "--ip", "192.0.2.123", "--duration", "2m")
        run(*compose, "restart", "clickhouse", "crowdsec")
        wait(lambda: healthy("clickhouse") and healthy("crowdsec"))
        assert clickhouse_query("SELECT sum(value) FROM deploy_smoke") == "7"
        assert "192.0.2.123" in execute("crowdsec", "cscli", "decisions", "list", "-o", "json")
        assert execute("crowdsec", "sha256sum", "/etc/crowdsec/bouncer.key") == key_digest
        run(*compose, "run", "--rm", "dependencies-init")
        run(*compose, "run", "--rm", "crowdsec-init")
        run(*compose, "run", "--rm", "crowdsec-seal")
        assert execute("crowdsec", "sha256sum", "/etc/crowdsec/bouncer.key") == key_digest
        print("PASS loopback-only listeners, ClickHouse data and CrowdSec decisions/credentials survive restart and repeat init")
        settings = clickhouse_query(
            "SELECT name,value FROM system.settings WHERE name IN ('max_memory_usage','max_threads') ORDER BY name")
        assert settings.splitlines() == [f'max_memory_usage\t{sizing["clickhouse"]["query_memory_bytes"]}',
                                         f'max_threads\t{sizing["clickhouse"]["threads"]}']
        for name in selected:
            if name == "gateway":
                continue  # Namespace holder; gateway has a separate smoke.
            cid = run(*compose, "ps", "-a", "-q", name)
            state = json.loads(run("docker", "inspect", cid))[0]
            limits = sizing["limits"][name]
            assert not state["State"]["OOMKilled"], name
            assert state["HostConfig"]["Memory"] == limits["memory_mib"] * vps_profiles.MIB
            assert state["HostConfig"]["MemorySwap"] == state["HostConfig"]["Memory"]
            assert state["HostConfig"]["NanoCpus"] == int(limits["cpus"] * 1_000_000_000)
            assert state["HostConfig"]["PidsLimit"] == limits["pids"]
        print(f'PASS {sizing["name"]} Docker-enforced dependency caps, no OOM kill, effective ClickHouse query settings')
        # Recovery guard: an initialized LAPI must not invent a replacement key.
        run(*compose, "run", "--rm", "--entrypoint", "/bin/sh", "crowdsec-init", "-c",
            "mv /etc/crowdsec/bouncer.key /etc/crowdsec/.saved-key")
        result = subprocess.run([*compose, "run", "--rm", "crowdsec-init"], capture_output=True, timeout=75)
        assert result.returncode != 0
        run(*compose, "run", "--rm", "--entrypoint", "/bin/sh", "crowdsec-init", "-c",
            "mv /etc/crowdsec/.saved-key /etc/crowdsec/bouncer.key")
        print("PASS missing persisted bouncer key fails provisioning without replacement")
    except Exception:
        for name in ("clickhouse", "crowdsec", "collector"):
            if name not in selected:
                continue
            cid = run(*compose, "ps", "-a", "-q", name)
            if cid:
                print(name, run("docker", "inspect", "--format", "{{.State.Status}} exit={{.State.ExitCode}}", cid), flush=True)
                diagnostic = subprocess.run(["docker", "logs", "--tail", "12", cid], capture_output=True)
                # Only runtime diagnostics; never dump provisioning/secret volumes.
                print((diagnostic.stdout + diagnostic.stderr).decode(errors="replace"), flush=True)
        raise
    finally:
        run(*compose, "down", "-v", "--remove-orphans")


def main():
    image = os.environ.get("OPENWAF_TEST_IMAGE")
    init_image = os.environ.get("OPENWAF_TEST_INIT_IMAGE")
    if not image or not init_image:
        raise SystemExit("Set OPENWAF_TEST_IMAGE and OPENWAF_TEST_INIT_IMAGE to the matching release images")
    sizing = vps_profiles.profile(os.environ.get("OPENWAF_VPS_PROFILE", vps_profiles.DEFAULT))
    project = "openwaf-deps-smoke-" + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix=project) as tmp, LinuxState(init_image, project) as state:
        exercise(image, init_image, sizing, project, Path(tmp), state.path)


if __name__ == "__main__":
    main()
