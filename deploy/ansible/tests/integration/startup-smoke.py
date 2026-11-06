#!/usr/bin/env python3
"""Isolated Docker smoke: native init + PostgreSQL + Pingora HTTPS + dashboard.
Uses a private test CA and no Cloudflare/ACME calls. Never prints credentials.
Set OPENWAF_TEST_IMAGE to a locally built or pulled release image first.
Removes only resources created by this run.
"""
import argparse
import http.client
import json
import os
import re
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

PREFIX = "openwaf-smoke-" + secrets.token_hex(4)
GATEWAY = os.environ.get("OPENWAF_TEST_IMAGE", "")
INIT = os.environ.get("OPENWAF_TEST_INIT_IMAGE", "")
POSTGRES = "ecr.swissy.shop/c/pgaio:18.6.0"
ROOT = Path(__file__).resolve().parents[4]
DEPLOY = ROOT / "deploy/ansible/files"
sys.path.insert(0, str(ROOT / "backend/runtime"))
import vps_profiles  # noqa: E402
from compose_fixture import render_stack  # noqa: E402

PROFILE = vps_profiles.profile(os.environ.get("OPENWAF_VPS_PROFILE", vps_profiles.DEFAULT))
containers = []


def cmd(*args, timeout=90):
    result = subprocess.run(args, check=False, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed: {args[0]} {args[1] if len(args) > 1 else ''}; output suppressed to protect test secrets")
    return result.stdout.decode().strip()


def docker(*args, **kwargs):
    return cmd("docker", *args, **kwargs)


def start(name, *args):
    name = PREFIX + "-" + name
    docker("run", "-d", "--name", name, *args)
    containers.append(name)
    return name


def wait(check, timeout=50):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except (OSError, RuntimeError, ssl.SSLError, http.client.HTTPException) as error:
            last = error
        time.sleep(0.5)
    raise RuntimeError("Readiness deadline exceeded") from last


def start_postgres(name, data, secret, scripts, tls=None):
    args = ["--network", PREFIX, "--network-alias", "openwaf-managed-postgres" if tls is None else "existing-postgres",
            "--user", "1001:0", "--init", "-e", "POSTGRESQL_DATABASE=postgres",
            "--entrypoint", "/bin/bash",
            "-v", f"{data}:/bitnami/postgresql", "-v", f"{secret}:/run/secrets/postgres:ro",
            "-v", f"{scripts}:/docker-entrypoint-initdb.d:ro",
            "-v", f"{DEPLOY / 'postgres-start.sh'}:/etc/openwaf/postgres-start.sh:ro",
            "-v", f"{DEPLOY / 'pgbouncer.ini'}:/etc/pgbouncer/pgbouncer.ini:ro"]
    limit = PROFILE["limits"]["postgres"]
    flags = vps_profiles.compose(PROFILE["name"])["services"]["postgres"]["environment"]["POSTGRESQL_EXTRA_FLAGS"]
    args += ["--cpus", str(limit["cpus"]), "--memory", f'{limit["memory_mib"]}m',
             "--memory-swap", f'{limit["memory_mib"]}m', "--pids-limit", str(limit["pids"]),
             "--ulimit", "nofile=8192:8192", "--shm-size", "128m",
             "-e", f"POSTGRESQL_EXTRA_FLAGS={flags}"]
    if tls is not None:
        args += ["--network-alias", "wrong-name", "-e", "POSTGRESQL_ENABLE_TLS=yes",
                 "-e", "POSTGRESQL_TLS_CERT_FILE=/run/pg-tls/server.crt",
                 "-e", "POSTGRESQL_TLS_KEY_FILE=/run/pg-tls/server.key", "-v", f"{tls}:/run/pg-tls:ro"]
    pg = start(name, *args, POSTGRES, "/etc/openwaf/postgres-start.sh")
    wait(lambda: docker("exec", pg, "/bin/bash", "-ec",
                       "pg_isready -h /tmp -U postgres -d openwaf >/dev/null && test -f /bitnami/postgresql/.user_scripts_initialized") == "")
    check_postgres_profile(pg)
    return pg


def check_postgres_profile(pg):
    settings = PROFILE["postgres"]
    query = "SELECT " + ",".join(
        f"pg_size_bytes(current_setting('{key[:-3]}'))/1048576" if key.endswith("_mb")
        else f"current_setting('{key}')::int" for key in settings)
    actual = docker("exec", pg, "/bin/bash", "-ec",
                    'export PGPASSWORD="$(cat /run/secrets/postgres/password)"; exec psql -h /tmp -U postgres -d openwaf -Atc "$1"',
                    "openwaf-profile-check", query)
    assert actual == "|".join(str(value) for value in settings.values()), actual
    state = json.loads(docker("inspect", pg))[0]
    assert not state["State"]["OOMKilled"]
    assert state["HostConfig"]["Memory"] == PROFILE["limits"]["postgres"]["memory_mib"] * vps_profiles.MIB
    print(f'PASS PostgreSQL {PROFILE["name"]} cgroup limits + effective settings (fresh start/restart)')


def existing_database(root):
    fixture = root / "existing-postgres"
    fixture.mkdir()
    for name in ("data", "secret", "scripts", "tls"):
        (fixture / name).mkdir()
    password = secrets.token_hex(32)
    (fixture / "secret/password").write_text(secrets.token_hex(32))
    (fixture / "scripts/10-fixture.sql").write_text(
        f"CREATE ROLE openwaf LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '{password}';\n"
        "CREATE DATABASE openwaf OWNER openwaf;\n")
    tls = fixture / "tls"
    cmd("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "60",
        "-keyout", str(tls / "ca.key"), "-out", str(tls / "ca.pem"), "-subj", "/CN=Database smoke CA")
    cmd("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tls / "server.key"),
        "-out", str(tls / "server.csr"), "-subj", "/CN=existing-postgres")
    (tls / "extensions").write_text("subjectAltName=DNS:existing-postgres\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    cmd("openssl", "x509", "-req", "-in", str(tls / "server.csr"), "-CA", str(tls / "ca.pem"),
        "-CAkey", str(tls / "ca.key"), "-CAcreateserial", "-out", str(tls / "server.crt"),
        "-days", "45", "-extfile", str(tls / "extensions"))
    source = root / "existing-database-url"
    source.write_text(f"postgres://openwaf:{password}@existing-postgres:5432/openwaf")
    source.chmod(0o600)
    docker("run", "--rm", "--user", "0:0", "--network", "none", "-v", f"{fixture}:/fixture", "--entrypoint", "python3", INIT,
           "-c", "import os,pathlib; [(os.chmod(p,0o700 if p.is_dir() else 0o600),os.chown(p,1001,0)) for p in [pathlib.Path('/fixture'),*pathlib.Path('/fixture').rglob('*')]]")
    pg = start_postgres("existing-postgres", fixture / "data", fixture / "secret", fixture / "scripts", tls)
    return pg, source, tls / "ca.pem"


def reject_invalid_database_tls(root, data):
    values = dict(line.split("=", 1) for line in (data / "gateway/gateway.env").read_text().splitlines())
    url = values["OPENWAF_DATABASE_URL"]
    parsed = urlsplit(url)
    no_ca = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       urlencode([(k, v) for k, v in parse_qsl(parsed.query) if k != "sslrootcert"]), ""))
    # Establish that both hostnames resolve before checking certificate rejection.
    docker("run", "--rm", "--network", PREFIX, "--entrypoint", "python3", INIT,
           "-c", "import socket; assert socket.gethostbyname('existing-postgres') == socket.gethostbyname('wrong-name')")
    for index, invalid in enumerate((url.replace("@existing-postgres:", "@wrong-name:"), no_ca)):
        source = root / f"negative-database-{index}.env"
        source.write_text(f"OPENWAF_DATABASE_URL={invalid}\nOPENWAF_ADMIN_MASTER_KEY_FILE=/etc/openwaf/master.key\nOPENWAF_ADMIN_ORIGIN=https://admin.example.com\n")
        source.chmod(0o600)
        docker("run", "--rm", "--user", "0:0", "--network", "none", "-v", f"{source}:/probe", "--entrypoint", "python3", INIT,
               "-c", "import os; os.chown('/probe',10001,10001)")
        name = PREFIX + f"-tls-negative-{index}"
        containers.append(name)
        result = subprocess.run(["docker", "run", "--rm", "--name", name, "--network", PREFIX,
            "--read-only", "--cap-drop=ALL", "--user", "10001:10001",
            "-e", "OPENWAF_ENV_FILE=/run/db-probe.env", "-v", f"{data / 'gateway'}:/etc/openwaf:ro",
            "-v", f"{source}:/run/db-probe.env:ro", "--entrypoint", "/usr/local/bin/openwaf-admin", GATEWAY], capture_output=True, timeout=20)
        assert result.returncode == 1 and b"admin database unavailable" in result.stderr
        assert parsed.password.encode() not in result.stdout + result.stderr
    print("PASS existing PostgreSQL TLS rejects a mismatched hostname and an untrusted CA")


def external_gateway(root, mounts):
    # Reuse the actual Compose service/networks. Only replace bootstrap-owned
    # test volumes, dependencies (CA fixture is ready), and the public host port.
    model = render_stack(root / "rendered-stack", {
        "openwaf_image": GATEWAY, "openwaf_init_image": INIT, "openwaf_project_name": PREFIX,
        "openwaf_vps_profile": PROFILE["name"], "openwaf_postgres_create": False,
        "openwaf_docker_network_external": True, "openwaf_docker_network_name": PREFIX,
    })
    assert all("build" not in service for service in model["services"].values())
    assert model["services"]["startup-init"]["image"] == INIT
    assert all(model["services"][name]["image"] == GATEWAY for name in ("admin-bootstrap", "gateway"))
    gateway = model["services"]["gateway"]
    gateway.pop("depends_on", None)
    # This harness covers admin/DB/network only; dependencies have a separate smoke.
    for key in ("OPENWAF_CLICKHOUSE_URL", "OPENWAF_CROWDSEC_CONFIG"):
        gateway["environment"].pop(key, None)
    gateway.update(container_name=PREFIX + "-gateway", restart="no",
                   ports=[{"target": 8443, "published": "0", "host_ip": "127.0.0.1", "protocol": "tcp"}],
                   volumes=[{"type": "bind", "source": str(source), "target": target,
                             "read_only": mode == "ro"} for source, target, mode in mounts])
    # Compose 5.5.1's JSON export writes a scalar core:0 as {}; preserve YAML semantics.
    gateway["ulimits"]["core"] = 0
    model = {"services": {"gateway": gateway}, "networks": model["networks"]}
    path = root / "compose-network.json"
    # First prove a missing external network is an error and is never created.
    model["networks"]["backends"]["name"] = PREFIX + "-missing"
    path.write_text(json.dumps(model))
    command = ["docker", "compose", "--env-file", "/dev/null", "-p", PREFIX, "-f", str(path)]
    result = subprocess.run([*command, "up", "-d", "--no-build"], capture_output=True, timeout=30)
    assert result.returncode != 0 and b"external" in result.stderr
    assert subprocess.run(["docker", "network", "inspect", PREFIX + "-missing"], capture_output=True).returncode != 0
    model["networks"]["backends"]["name"] = PREFIX
    path.write_text(json.dumps(model))
    containers.append(PREFIX + "-gateway")
    cmd(*command, "up", "-d", "--no-build")
    state = json.loads(docker("inspect", PREFIX + "-gateway"))[0]
    assert set(state["NetworkSettings"]["Networks"]) == {PREFIX, PREFIX + "_database"}
    limits = PROFILE["limits"]["gateway"]
    assert state["HostConfig"]["Memory"] == limits["memory_mib"] * vps_profiles.MIB
    assert state["HostConfig"]["MemorySwap"] == state["HostConfig"]["Memory"]
    assert state["HostConfig"]["NanoCpus"] == int(limits["cpus"] * 1_000_000_000)
    assert state["HostConfig"]["PidsLimit"] == limits["pids"]
    print("PASS actual Compose gateway joins existing network + private DB network; missing external network fails")
    return PREFIX + "-gateway"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", choices=["new", "existing"], default="new")
    parser.add_argument("--external-network", action="store_true", help="Run gateway using the actual external-network Compose model")
    parser.add_argument("--ipv6-network", action="store_true", help="Give the isolated shared network both IPv4 and IPv6")
    args = parser.parse_args()
    if not GATEWAY or not INIT:
        parser.error("Set OPENWAF_TEST_IMAGE and OPENWAF_TEST_INIT_IMAGE to matching release images")
    with tempfile.TemporaryDirectory(prefix=PREFIX) as temp:
        root = Path(temp)
        data = root / "volumes"
        data.mkdir()
        token = root / "token"
        token.write_text(secrets.token_urlsafe(32))
        token.chmod(0o600)
        network_options = ["--ipv6", "--subnet", f"fd42:{secrets.token_hex(2)}:{secrets.token_hex(2)}::/64"] if args.ipv6_network else []
        docker("network", "create", *network_options, PREFIX)
        try:
            pg = None
            if args.database == "existing":
                pg, database_source, ca_source = existing_database(root)
            init_args = ["--rm", "--user", "0:0", "--network", "none", "--read-only", "--cap-drop=ALL",
                         "--entrypoint", "/usr/local/bin/openwaf-startup-init",
                         "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--cap-add=FOWNER",
                         "-e", "OPENWAF_ADMIN_HOST=admin.example.com", "-e", "OPENWAF_ORIGIN_IPV4=1.1.1.1",
                         "-e", "OPENWAF_ACME_ACCEPT_TERMS=true", "-v", f"{data}:/init",
                         "-e", f'OPENWAF_VPS_PROFILE={PROFILE["name"]}',
                         "-e", f'OPENWAF_VPS_PROFILE_SHA256={vps_profiles.fingerprint(PROFILE)}',
                         "-v", f"{token}:/run/secrets/cloudflare-token:ro", INIT]
            if args.database == "existing":
                init_args[-1:-1] = ["-e", "OPENWAF_POSTGRES_CREATE=0",
                    "-e", "OPENWAF_DATABASE_URL_FILE=/run/secrets/database-url",
                    "-e", "OPENWAF_DATABASE_CA_FILE=/run/secrets/database-ca",
                    "-v", f"{database_source}:/run/secrets/database-url:ro",
                    "-v", f"{ca_source}:/run/secrets/database-ca:ro"]
            if args.external_network:
                init_args[-1:-1] = ["-e", "OPENWAF_DOCKER_NETWORK_EXTERNAL=true",
                                    "-e", f"OPENWAF_DOCKER_NETWORK_NAME={PREFIX}"]
            docker("run", *init_args)
            docker("run", *init_args, "dependencies")
            certificate_key = (data / "certificate-key/master.key").read_bytes()
            docker("run", *init_args, "dependencies")
            assert certificate_key == (data / "certificate-key/master.key").read_bytes()
            assert certificate_key != (data / "acme-key/master.key").read_bytes()
            if args.database == "existing":
                assert not (data / "gateway/database-password").exists()
                assert not (data / "db-secret/password").exists()
                assert not list((data / "db-init").iterdir())
                assert b"sslmode=verify-full" in (data / "gateway/gateway.env").read_bytes()
                print("PASS existing-instance mode: no generated DB credentials/SQL; verified TLS + private CA configured")
            key = (data / "gateway/master.key").read_bytes()
            password = secrets.token_hex(24)
            username = "vps-owner"
            assert not (data / "admin-access/initial-password").exists()
            docker("run", *init_args)
            assert key == (data / "gateway/master.key").read_bytes()
            assert not (data / "admin-access/initial-password").exists()
            assert (data / "bootstrap/providers/cloudflare.enc").read_bytes().startswith(b"OWCF1")
            print("PASS native init with no network: sealing, private volumes, restart preservation")
            # Isolated CA fixture; no TLS verification bypass.
            cmd("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "60",
                "-keyout", str(root / "ca.key"), "-out", str(root / "ca.pem"), "-subj", "/CN=OpenWAF smoke CA")
            tls = data / "tls"
            cmd("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tls / "key.pem"),
                "-out", str(root / "leaf.csr"), "-subj", "/CN=admin.example.com")
            (root / "extensions").write_text("subjectAltName=DNS:example.com,DNS:*.example.com\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
            cmd("openssl", "x509", "-req", "-in", str(root / "leaf.csr"), "-CA", str(root / "ca.pem"),
                "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-out", str(tls / "leaf.pem"),
                "-days", "45", "-extfile", str(root / "extensions"))
            (tls / "chain.pem").write_bytes((tls / "leaf.pem").read_bytes() + (root / "ca.pem").read_bytes())
            (tls / "manifest.json").write_text(json.dumps({"schema_version": 1, "revision": 1, "certificates": [
                {"hostname": name, "cert_chain": "chain.pem", "private_key": "key.pem"} for name in ("example.com", "*.example.com")]}))
            docker("run", "--rm", "--user", "0:0", "--network", "none", "-v", f"{tls}:/tls", "--entrypoint", "python3", INIT,
                   "-c", "import os,pathlib; [(os.chmod(p,0o600),os.chown(p,10001,10001)) for p in pathlib.Path('/tls').iterdir()]")
            bootstrap = start("bootstrap", "--network", "none", "--read-only", "--cap-drop=ALL", "--user", "10001:10001",
                              "-e", "OPENWAF_ENV_FILE=/dev/null", "-e", "OPENWAF_BOOTSTRAP_PROVIDER_ROOT=/run/openwaf-bootstrap-provider",
                              "-v", f"{data / 'bootstrap-provider'}:/run/openwaf-bootstrap-provider", "-v", f"{data / 'bootstrap'}:/var/lib/openwaf-admin-bootstrap",
                              "-v", f"{data / 'acme-key'}:/run/openwaf-acme-key:ro", "-v", f"{tls}:/var/lib/openwaf/tls",
                              "--entrypoint", "/usr/local/bin/openwaf-acme", GATEWAY, "admin-start")
            wait(lambda: subprocess.run(["docker", "exec", bootstrap, "/usr/local/bin/openwaf-acme", "admin-health"],
                                        capture_output=True).returncode == 0)
            assert not (data / "bootstrap/admin-owned").exists()
            print("PASS existing valid external cert starts offline without ownership takeover")
            docker("stop", "-t", "35", bootstrap)
            # Emulate persistent native ownership with a current certificate. The
            # renewal child also has network:none, proving readiness needs no API.
            worker_root = "/var/lib/openwaf-admin-bootstrap"
            production = {"directory_url": "https://acme-v02.api.letsencrypt.org/directory", "hostname": "example.com", "additional_dns_names": ["*.example.com"], "retire_hostname": "admin.example.com",
                          "state_dir": worker_root + "/production", "master_key_file": "/run/openwaf-acme-key/master.key",
                          "tls_manifest": "/var/lib/openwaf/tls/manifest.json", "terms_of_service_agreed": True,
                          "deadline_seconds": 180, "cloudflare": {"zone_id": "a" * 32, "zone_name": "example.com",
                          "token_file": worker_root + "/providers/cloudflare.enc", "propagation_seconds": 90}}
            state = data / "bootstrap"
            (state / "production").mkdir(mode=0o700)
            (state / "production-v2.json").write_text(json.dumps(production, sort_keys=True, separators=(",", ":")))
            descriptor = {"schema_version": 2, "hostname": "admin.example.com", "zone_id": "a" * 32, "zone_name": "example.com"}
            handoff = data / "bootstrap-provider"
            for name in ("zone.json", "reserved.json"):
                (handoff / name).write_text(json.dumps(descriptor, separators=(",", ":")))
            (state / "zone.json").write_text(json.dumps({"id": "a" * 32, "name": "example.com"}))
            (state / "dns-v2-complete.json").write_text(json.dumps({"version": 2, "zone_id": "a" * 32, "zone_name": "example.com", "hostname": "admin.example.com", "ipv4": "1.1.1.1", "ipv6": None}))
            (state / "staging-v2-verified").write_text("verified")
            docker("run", "--rm", "--user", "0:0", "--network", "none", "-v", f"{handoff}:/handoff", "--entrypoint", "python3", INIT,
                   "-c", "import os,pathlib; [(os.chmod(p,0o600),os.chown(p,10001,10001)) for p in pathlib.Path('/handoff').iterdir()]")
            (state / "admin-owned").write_text("admin.example.com")
            docker("run", "--rm", "--user", "0:0", "--network", "none", "-v", f"{state}:/state", "--entrypoint", "python3", INIT,
                   "-c", "import os,pathlib; [(os.chmod(p,0o700 if p.is_dir() else 0o600),os.chown(p,10001,10001)) for p in pathlib.Path('/state').iterdir()]")
            docker("start", bootstrap)
            wait(lambda: (state / "production/.scheduler.lock").exists())
            wait(lambda: subprocess.run(["docker", "exec", bootstrap, "/usr/local/bin/openwaf-acme", "admin-health"],
                                        capture_output=True).returncode == 0)
            print("PASS current native-owned cert starts renewal supervisor offline")
            if pg is None:
                pg = start_postgres("postgres", data / "postgres", data / "db-secret", data / "db-init")
            docker("run", "--rm", "--network", PREFIX, "--read-only", "--cap-drop=ALL", "--user", "10001:10001",
                   "-e", "OPENWAF_BOOTSTRAP_PROVIDER_ROOT=/run/openwaf-bootstrap-provider",
                   "-v", f"{data / 'gateway'}:/etc/openwaf:ro", "-v", f"{handoff}:/run/openwaf-bootstrap-provider",
                   "--entrypoint", "/usr/local/bin/openwaf-admin", GATEWAY, "bootstrap-certificates")
            gateway_args = ["--network", PREFIX, "--read-only", "--cap-drop=ALL", "--user", "10001:10001",
                            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m,mode=1777", "--ulimit", "nofile=8192:8192",
                            "-p", "127.0.0.1::8443", "-e", "OPENWAF_ENV_FILE=/etc/openwaf/gateway.env",
                            "-e", "OPENWAF_APPLICATIONS_ROOT=/var/lib/openwaf/applications",
                            "-e", "OPENWAF_BOOTSTRAP_PROVIDER_ROOT=/run/openwaf-bootstrap-provider",
                            "-e", "OPENWAF_CERTIFICATES_ROOT=/var/lib/openwaf/certificate-requests",
                            "-e", "OPENWAF_CERTIFICATES_MASTER_KEY_FILE=/run/openwaf-certificate-key/master.key"]
            mounts = [(data / source, target, mode) for source, target, mode in [("gateway", "/etc/openwaf", "ro"), ("tls", "/var/lib/openwaf/tls", "rw"),
                                         ("certificate-requests", "/var/lib/openwaf/certificate-requests", "rw"),
                                         ("certificate-key", "/run/openwaf-certificate-key", "ro"),
                                         ("bootstrap-provider", "/run/openwaf-bootstrap-provider", "ro"),
                                         ("discovery", "/run/openwaf-discovery", "ro"),
                                         ("applications", "/var/lib/openwaf/applications", "rw"),
                                         ("replay", "/var/lib/openwaf/replay", "rw"), ("security", "/var/lib/openwaf/security", "rw")]]
            for source, target, mode in mounts:
                gateway_args += ["-v", f"{source}:{target}:{mode}"]
            if args.external_network:
                gateway = external_gateway(root, mounts)
            else:
                gateway = start("gateway", *gateway_args, GATEWAY)
            port = int(docker("port", gateway, "8443/tcp").split(":")[-1])
            context = ssl.create_default_context(cafile=str(root / "ca.pem"))

            def request(method, path, body=None, headers=None, stream=False):
                conn = http.client.HTTPSConnection("admin.example.com", port, context=context, timeout=5)
                sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                conn.sock = context.wrap_socket(sock, server_hostname="admin.example.com")
                conn.request(method, path, json.dumps(body) if body is not None else None,
                             {"Host": "admin.example.com", "Content-Type": "application/json", **(headers or {})})
                response = conn.getresponse()
                result = response.status, dict(response.getheaders()), (response.readline(16384) if stream else response.read())
                conn.close()
                return result

            wait(lambda: request("GET", "/")[0] == 200)
            status, ui_headers, html = request("GET", "/")
            assert b'id="root"' in html and status == 200
            assert "script-src 'self'" in ui_headers["content-security-policy"]
            assert ui_headers["cache-control"] == "no-store"
            assert request("HEAD", "/")[2] == b""
            assert request("GET", "/configuration", headers={"Accept": "text/html"})[2] == html
            asset = re.search(rb'src="(/assets/[^" ]+\.js)"', html).group(1).decode()
            asset_status, asset_headers, _ = request("GET", asset)
            assert asset_status == 200 and "javascript" in asset_headers["content-type"]
            for path in ("/assets/missing.js", "/api/missing", "/.env", "/%2e%2e/secret"):
                status, headers, body = request("GET", path, headers={"Accept": "text/html"})
                assert status in (400, 404) and b'id="root"' not in body
            print("PASS Axum static UI/assets/HEAD/SPA, CSP and API/traversal boundaries")
            assert json.loads(request("GET", "/api/v1/auth/setup")[2]) == {"setup_required": True}
            assert request("GET", "/api/v1/auth/session")[0] == 401
            assert request("POST", "/api/v1/auth/setup", {"username": username, "password": password},
                           {"Origin": "https://wrong.example.com"})[0] == 403
            assert json.loads(request("GET", "/api/v1/auth/setup")[2]) == {"setup_required": True}
            assert request("POST", "/api/v1/auth/setup", {"username": username, "password": password},
                           {"Origin": "https://admin.example.com"})[0] == 201
            assert json.loads(request("GET", "/api/v1/auth/setup")[2]) == {"setup_required": False}
            assert request("POST", "/api/v1/auth/setup", {"username": "extra-owner", "password": secrets.token_hex(24)},
                           {"Origin": "https://admin.example.com"})[0] == 409
            print("PASS no precreated user: first-admin setup via HTTPS, Origin enforced, setup closes after creation")
            assert request("GET", "/api/v1/auth/session")[0] == 401
            status, headers, body = request("POST", "/api/v1/auth/login", {"username": username, "password": password},
                                            {"Origin": "https://admin.example.com"})
            assert status == 200
            cookie = headers["set-cookie"]
            assert all(flag in cookie for flag in ("Secure", "HttpOnly", "SameSite=Strict", "__Host-"))
            assert request("GET", "/api/v1/auth/session", headers={"Cookie": cookie.split(";")[0]})[0] == 200
            csrf = json.loads(body)["csrf_token"]
            auth_headers = {"Cookie": cookie.split(";")[0], "Origin": "https://admin.example.com"}
            def certificates_available(headers):
                for path in ("/api/v1/certificates", "/api/v1/certificate-providers"):
                    status, _, response = request("GET", path, headers=headers)
                    result = json.loads(response)
                    assert status == 200 and result["enabled"] is True and result["unavailable_reason"] is None
                    assert len(result["providers"]) == 1 and result["providers"][0]["environment"] == "production"
                    assert not any(word in response for word in (b"master.key", b"/var/lib/", b"cloudflare.enc"))

            certificates_available(auth_headers)
            assert request("POST", "/api/v1/certificates", {
                "hostname": "*.cert-smoke.example.com", "provider_id": "not-configured",
                "terms_of_service_agreed": True,
            }, {**auth_headers, "X-CSRF-Token": csrf})[0] == 422
            provider_id = json.loads(request("GET", "/api/v1/certificate-providers", headers=auth_headers)[2])["providers"][0]["id"]
            for hostname in ("example.com", "*.example.com", "admin.example.com"):
                assert request("POST", "/api/v1/certificates", {"hostname": hostname, "provider_id": provider_id,
                    "terms_of_service_agreed": True}, {**auth_headers, "X-CSRF-Token": csrf})[0] == 409
            status, _, payload = request("GET", "/api/v1/telemetry/dependencies", headers=auth_headers)
            assert status == 200
            assert all(set(item["dns_names"]) == {"example.com", "*.example.com"} for item in json.loads(payload)["tls"]["certificates"])
            def bootstrap_healthy():
                status, _, payload = request("GET", "/api/v1/health/system", headers=auth_headers)
                assert status == 200
                assert not any(word in payload for word in (b"master.key", b"/var/lib/", b"cloudflare.enc", b"credential.enc"))
                source = json.loads(payload)["components"]["acme"]["sources"]["bootstrap"]
                return (source["state"] == "healthy" and source["ready"] is True
                        and source["tls_state"] == "current" and source["dns_state"] == "complete"
                        and source["provider_state"] == "reserved" and source["renewal_state"] == "current")
            wait(bootstrap_healthy)
            print("PASS auto-imported Production provider, reserved renewal owners, SAN metadata and private runtime; unknown provider rejected without ACME dispatch")
            if args.external_network:
                start("web", "--network", PREFIX, "--network-alias", "fixture-web",
                      "--entrypoint", "python3", INIT, "-m", "http.server", "8000", "--bind", "::" if args.ipv6_network else "0.0.0.0")
                endpoint = {"address": "fixture-web:8000", "protocol": "http", "tls_server_name": None}
                check_headers = {**auth_headers, "X-CSRF-Token": csrf}
                wait(lambda: json.loads(request("POST", "/api/v1/upstreams/test", endpoint, check_headers)[2]).get("available"))
                document = json.loads(request("GET", "/api/v1/config", headers=auth_headers)[2])["draft"]
                addresses = json.loads(docker("inspect", gateway))[0]["NetworkSettings"]["Networks"]
                self_addresses = []
                for network in addresses.values():
                    self_addresses.append(network["IPAddress"] + ":8443")
                    if network.get("GlobalIPv6Address"):
                        self_addresses.append("[" + network["GlobalIPv6Address"] + "]:8443")
                if args.ipv6_network:
                    assert any(address.startswith("[") for address in self_addresses)
                for address in self_addresses:
                    proposed = json.loads(json.dumps(document))
                    proposed["upstreams"].append({"id": "self-loop", "endpoints": [{**endpoint, "address": address}]})
                    result = json.loads(request("POST", "/api/v1/config/validate", {"document": proposed}, check_headers)[2])
                    assert result["valid"] is False and result["error"] == "proxy_loop"
                result = json.loads(request("POST", "/api/v1/upstreams/test",
                                    {**endpoint, "address": "gateway:8443"}, check_headers)[2])
                assert result["available"] is False and result["error"] == "forbidden_endpoint"
                print("PASS gateway DNS/HTTP probe to existing-stack alias; config rejects self-loop on every dynamic IPv4/IPv6 address and probe rejects its own DNS alias")
            assert request("POST", "/api/v1/auth/logout", headers=auth_headers)[0] == 403
            assert request("POST", "/api/v1/auth/logout", headers={**auth_headers, "Origin": "https://other.example.com", "X-CSRF-Token": csrf})[0] == 403
            assert request("GET", "/metrics")[0] == 404
            status, headers, event = request("GET", "/api/v1/events/metrics", headers=auth_headers, stream=True)
            assert status == 200 and headers["content-type"].startswith("text/event-stream") and event
            assert request("POST", "/api/v1/auth/logout", headers={**auth_headers, "X-CSRF-Token": csrf})[0] == 204
            print("PASS verified HTTPS Pingora → Axum: owner login, secure session, CSRF/Origin, SSE, private metrics, setup closed")
            if args.database == "existing":
                reject_invalid_database_tls(root, data)
            # Restart preserves the user created through setup and keeps setup closed.
            docker("stop", "-t", "35", gateway)
            docker("restart", pg)
            wait(lambda: docker("exec", pg, "pg_isready", "-h", "/tmp", "-U", "postgres", "-d", "openwaf"))
            check_postgres_profile(pg)
            docker("start", gateway)
            port = int(docker("port", gateway, "8443/tcp").split(":")[-1])
            wait(lambda: request("GET", "/api/v1/auth/setup")[0] == 200)
            assert json.loads(request("GET", "/api/v1/auth/setup")[2]) == {"setup_required": False}
            status, headers, _ = request("POST", "/api/v1/auth/login", {"username": username, "password": password},
                                         {"Origin": "https://admin.example.com"})
            assert status == 200
            certificates_available({"Cookie": headers["set-cookie"].split(";")[0]})
            assert certificate_key == (data / "certificate-key/master.key").read_bytes()
            assert docker("exec", pg, "/bin/bash", "-ec",
                          'export PGPASSWORD="$(cat /run/secrets/postgres/password)"; exec psql -h /tmp -U postgres -d openwaf -Atc "$1"',
                          "openwaf-smoke", "SELECT (SELECT count(*) FROM admin_users),(SELECT count(*) FROM admin_audit WHERE action='config.admin_bootstrap'),(SELECT committed_version FROM config_state)") == "1|1|1"
            print("PASS PostgreSQL + gateway restart: owner/password/config version unchanged; first setup remains closed")
            docker("stop", "-t", "35", bootstrap)
            assert not (data / "bootstrap/.admin-owner.lock").exists()
            assert not (data / "bootstrap/production/.scheduler.lock").exists()
            print("PASS SIGTERM releases bootstrap + renewal locks with owned child shutdown")
        except Exception:
            for container in containers:
                if container.endswith("-gateway"):
                    diagnostic = subprocess.run(["docker", "logs", "--tail", "25", container], capture_output=True).stderr.decode(errors="replace")
                    for path in (token, data / "gateway/database-password", data / "admin-access/initial-password", data / "db-secret/password"):
                        if path.exists():
                            diagnostic = diagnostic.replace(path.read_text(), "[REDACTED]")
                    print(container.rsplit("-", 1)[-1], diagnostic)
            raise
        finally:
            for container in reversed(containers):
                subprocess.run(["docker", "rm", "-f", "-v", container], capture_output=True)
            if (root / "compose-network.json").exists():
                cmd("docker", "compose", "--env-file", "/dev/null", "-p", PREFIX,
                    "-f", str(root / "compose-network.json"), "down", "--volumes")
                docker("network", "inspect", PREFIX)
                print("PASS Compose down preserves external network")
            subprocess.run(["docker", "network", "rm", PREFIX], capture_output=True)


if __name__ == "__main__":
    main()
