#!/usr/bin/env python3
"""Local volume initialization only; no DNS, network, Docker socket or secret logs."""
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
import vps_profiles

BASE = Path(os.environ.get("OPENWAF_INIT_ROOT", "/init"))
UID = 10001
DEFAULTS = Path("/defaults")
POSTGRES_IMAGE = "ecr.swissy.shop/c/pgaio:18.6.0"
POSTGRES_UID = 1001


class InitError(Exception):
    pass


# Diagnostic labels only contain fixed runtime paths, never caller-controlled paths.
CONTEXT = "select initializer mode"
VOLUME_NAMES = frozenset({
    "gateway", "tls", "bootstrap", "acme-key", "db-secret", "db-init",
    "postgres", "replay", "security", "applications", "discovery", "dependencies",
    "security-key", "crowdsec-config", "crowdsec-data", "clickhouse-data",
    "certificate-key", "certificate-requests",
})
DEFAULT_NAMES = frozenset({"resource-budgets.json", "clickhouse.xml", "crowdsec.json", "crowdsec-bootstrap.sh"})
# Frozen former VPS profile: only this exact configuration may be upgraded.
# Custom reservations/limits still require an explicit migration.
LEGACY_RESOURCE_BUDGETS = {
    "requests": 256, "classes": [128, 32, 64, 32], "connections": 128,
    "handshakes": 32, "headers": 128, "waf_workers": 2, "waf_queue_per_worker": 4,
    "health_jobs": 4, "retry_slots": 16, "replay_memory_bytes": 67108864,
    "replay_disk_bytes": 2147483648, "replay_io_slots": 4,
    "ram_budget_bytes": 2147483648, "fd_budget": 4096, "reserved_routes": [],
}
FILE_NAMES = DEFAULT_NAMES | frozenset({
    "resource-budgets.json.previous", "clickhouse.xml.previous",
    ".init.lock", "instance.json", "master.key", "database-password",
    "password", "admin.json", "cloudflare.enc", "bouncer.key", "crowdsec.enc",
    "certificate-runtime.json", "crowdsec-sealed.json", "config.yaml", "profiles.yaml",
    "console.yaml", "bootstrap.sh", ".index.json", "gateway.env", "10-openwaf.sql", "database-ca.crt",
})


def target_label(path):
    path = Path(path)
    if path.parent == DEFAULTS and path.name in DEFAULT_NAMES:
        return "/defaults/" + path.name
    try:
        parts = path.relative_to(BASE).parts
    except ValueError:
        return "private input"
    if not parts or parts[0] not in VOLUME_NAMES:
        return "private input"
    label = "/init/" + parts[0]
    if len(parts) > 1 and parts[-1] in FILE_NAMES:
        label += "/" + parts[-1]
    return label


def context(operation, path=None):
    global CONTEXT
    CONTEXT = operation + (" " + target_label(path) if path is not None else "")


def default_file(name):
    if name not in DEFAULT_NAMES:
        raise InitError("Unknown packaged runtime default")
    path = DEFAULTS / name
    context("read packaged default", path)
    try:
        return path.read_bytes()
    except FileNotFoundError:
        raise InitError(f"Image is missing /defaults/{name}; rebuild/push the complete runtime image and use the same release for init and gateway") from None


def error_summary(error):
    # Never stringify Python/subprocess errors: they can contain data or argv.
    if isinstance(error, OSError):
        code = errno.errorcode.get(error.errno, "IO_ERROR")
        hints = {
            errno.ENOENT: "required input or packaged file is missing",
            errno.EACCES: "permission denied; check volume ownership and init capabilities",
            errno.EPERM: "operation not permitted; check volume filesystem and init capabilities",
            errno.EROFS: "filesystem is read-only; check the init volume mounts",
            errno.ENOSPC: "filesystem has no free space",
            errno.EDQUOT: "filesystem quota exceeded",
            errno.ELOOP: "symlink rejected",
            errno.EAGAIN: "another initializer holds the volume lock; retry after it exits",
        }
        return code + ": " + hints.get(error.errno, "filesystem operation failed")
    if isinstance(error, subprocess.TimeoutExpired):
        return "native credential sealing deadline exceeded"
    if isinstance(error, subprocess.CalledProcessError):
        return "native credential sealing failed; check binary and private inputs"
    if isinstance(error, json.JSONDecodeError):
        return "persisted JSON metadata is invalid; inspect or restore the original state"
    if isinstance(error, UnicodeError):
        return "input has invalid text encoding"
    if isinstance(error, KeyError):
        return "persisted metadata is missing a required field"
    return "input or persisted metadata has an invalid format"


def read(path, limit=65536):
    context("read private file", path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_mode & 0o077:
            raise InitError("Input must be a bounded owner-only regular file")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise InitError("Input exceeds limit")
        return data


def directory(path, uid=UID):
    context("prepare directory", path)
    if path.is_symlink():
        raise InitError("Directory symlinks are forbidden")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise InitError("Expected a real directory")
    path.chmod(0o700)
    os.chown(path, uid, uid)


def write(path, data, uid=UID):
    context("write private file", path)
    if isinstance(data, str):
        data = data.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), uid, uid)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync(path.parent)


def sync(path):
    context("sync directory", path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def immutable(path, data, uid=UID):
    if isinstance(data, str):
        data = data.encode()
    if path.exists() or path.is_symlink():
        if read(path) != data:
            raise InitError("Persisted startup configuration differs; explicit migration required")
    else:
        write(path, data, uid)


def validate_resource_budgets(data):
    context("validate packaged resource budgets", DEFAULTS / "resource-budgets.json")
    if not data or len(data) > 8192:
        raise InitError("Packaged resource budgets exceed the gateway input limit")
    try:
        subprocess.run(["/usr/local/bin/openwaf-gateway", "check-resources"], input=data,
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=30,
                       env={"OPENWAF_ENV_FILE": "/dev/null", "PATH": "/usr/local/bin:/usr/bin:/bin"})
    except (subprocess.SubprocessError, OSError):
        raise InitError("Packaged resource budgets failed gateway check-resources; use a complete compatible runtime image and check FD limits") from None


def selected_profile():
    try:
        value = vps_profiles.profile(os.environ.get("OPENWAF_VPS_PROFILE", vps_profiles.DEFAULT))
    except ValueError as error:
        raise InitError(str(error)) from None
    expected = os.environ.get("OPENWAF_VPS_PROFILE_SHA256")
    if expected is not None and expected != vps_profiles.fingerprint(value):
        raise InitError("VPS profile differs between Compose and runtime image; update both to the same release")
    return value


def atomic_private(path, data):
    if path.exists() or path.is_symlink():
        read(path)
    temporary = path.parent / (".budgets-" + secrets.token_hex(8))
    try:
        write(temporary, data)
        context("publish validated resource profile", path)
        os.replace(temporary, path)
        sync(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def install_resource_budgets(config, data):
    """Called under the gateway initializer lock, after native validation.

    Only replace known packaged VPS profiles. Atomic replacement keeps
    readers on one complete document, with a private, restart-safe prior copy.
    Runtime budgets take effect when the gateway is recreated.
    """
    path = config / "resource-budgets.json"
    if not path.exists() and not path.is_symlink():
        write(path, data)
        return
    current = read(path, 8192)
    if json.loads(current) == json.loads(data):
        return
    known = [LEGACY_RESOURCE_BUDGETS, json.loads(default_file("resource-budgets.json"))]
    known.extend(vps_profiles.profile(name)["budgets"] for name in vps_profiles.NAMES)
    if json.loads(current) not in known:
        raise InitError("Persisted resource budgets are customized; explicit migration required")
    backup = config / "resource-budgets.json.previous"
    if (backup.exists() or backup.is_symlink()) and json.loads(read(backup, 8192)) not in known:
        raise InitError("Prior resource budgets are customized; explicit migration required")
    atomic_private(backup, current)
    atomic_private(path, data)
    print("Resource budgets upgraded; prior profile retained as resource-budgets.json.previous.")


def xml_value(data):
    try:
        root = ET.fromstring(data)
        ET.indent(root)
        return ET.tostring(root)
    except ET.ParseError:
        raise InitError("Persisted ClickHouse configuration is invalid; explicit migration required") from None


def clickhouse_config(value):
    root = ET.fromstring(default_file("clickhouse.xml"))
    settings = value["clickhouse"]
    for tag, number in {"max_server_memory_usage": settings["server_memory_bytes"],
                        "mark_cache_size": settings["cache_bytes"],
                        "uncompressed_cache_size": settings["cache_bytes"] // 2,
                        "profiles/default/max_memory_usage": settings["query_memory_bytes"],
                        "profiles/default/max_threads": settings["threads"]}.items():
        element = root.find(tag)
        if element is None:
            element = ET.SubElement(root, tag)
        element.text = str(number)
    return xml_value(ET.tostring(root)) + b"\n"


def install_clickhouse(config, value):
    data = clickhouse_config(value)
    path = config / "clickhouse.xml"
    if not path.exists() and not path.is_symlink():
        write(path, data)
        return
    current = read(path)
    if xml_value(current) == xml_value(data):
        return
    known = [xml_value(default_file("clickhouse.xml"))]
    known.extend(xml_value(clickhouse_config(vps_profiles.profile(name))) for name in vps_profiles.NAMES)
    if xml_value(current) not in known:
        raise InitError("Persisted ClickHouse configuration is customized; explicit migration required")
    backup = config / "clickhouse.xml.previous"
    if (backup.exists() or backup.is_symlink()) and xml_value(read(backup)) not in known:
        raise InitError("Prior ClickHouse configuration is customized; explicit migration required")
    atomic_private(backup, current)
    atomic_private(path, data)


def inputs(env):
    host = env.get("OPENWAF_ADMIN_HOST", "").lower().rstrip(".")
    if (len(host) > 253 or not 2 <= len(host.split('.')) <= 16 or
            any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in host.split('.'))):
        raise InitError("OPENWAF_ADMIN_HOST requires an exact ASCII/punycode DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise InitError("Admin host cannot be an IP")
    ips = []
    for key, version in [("OPENWAF_ORIGIN_IPV4", 4), ("OPENWAF_ORIGIN_IPV6", 6)]:
        raw = env.get(key, "")
        ip = ipaddress.ip_address(raw) if raw else None
        if ip and (ip.version != version or not ip.is_global):
            raise InitError("Origin IP must be public and match its address family")
        ips.append(str(ip) if ip else None)
    if not any(ips):
        raise InitError("An explicit public origin IPv4 or IPv6 is required")
    if env.get("OPENWAF_ACME_ACCEPT_TERMS") != "true":
        raise InitError("Set OPENWAF_ACME_ACCEPT_TERMS=true after reviewing Let's Encrypt terms")
    return {"hostname": host, "ipv4": ips[0], "ipv6": ips[1], "proxied": True,
            "tls_manifest": "/var/lib/openwaf/tls/manifest.json"}


def database_inputs(env):
    create = env.get("OPENWAF_POSTGRES_CREATE", "1")
    source = env.get("OPENWAF_DATABASE_URL_FILE", "")
    ca_source = env.get("OPENWAF_DATABASE_CA_FILE", "")
    if create not in {"0", "1"}:
        raise InitError("OPENWAF_POSTGRES_CREATE must be 1 (new) or 0 (existing)")
    if create == "1":
        if source or ca_source:
            raise InitError("Existing database files require OPENWAF_POSTGRES_CREATE=0")
        return {"mode": "managed", "image": POSTGRES_IMAGE}, None, None
    if not source:
        raise InitError("Existing PostgreSQL requires a private OPENWAF_DATABASE_URL_FILE")
    raw = read(Path(source), 4096).decode("utf-8").strip()
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        if (parsed.scheme not in {"postgres", "postgresql"} or not host
                or not parsed.username or not parsed.password or not parsed.path.strip("/")
                or parsed.port is None or parsed.port == 0 or parsed.fragment
                or any(c.isspace() or ord(c) < 32 for c in raw)
                or re.search(r"%(?![0-9a-fA-F]{2})", raw)):
            raise ValueError()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if host.lower() == "localhost" or not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
                raise ValueError()
        else:
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                raise ValueError()
        options = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True) if parsed.query else []
        if len(options) > 16 or len({key for key, _ in options}) != len(options):
            raise ValueError()
        values = dict(options)
        # Remote defaults verify both the CA and hostname. Private plaintext is
        # opt-in; prefer/require are not substitutes for certificate verification.
        sslmode = values.get("sslmode", "verify-full")
        if sslmode not in {"disable", "verify-full"}:
            raise ValueError()
        if "sslmode" not in values:
            options.append(("sslmode", sslmode))
        ca = read(Path(ca_source), 256 * 1024) if ca_source else None
        if ca is not None:
            if sslmode != "verify-full" or b"-----BEGIN CERTIFICATE-----" not in ca:
                raise ValueError()
            expected = "/etc/openwaf/database-ca.crt"
            if values.get("sslrootcert", expected) != expected:
                raise ValueError()
            if "sslrootcert" not in values:
                options.append(("sslrootcert", expected))
        elif "sslrootcert" in values:
            raise ValueError()
        # Percent-encode dotenv metacharacters so credential values are never
        # expanded, truncated or interpreted as generated configuration lines.
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(options), ""))
        url = quote(url, safe=":/?[]@!&()*+,;=%")
    except (ValueError, UnicodeError):
        raise InitError("Invalid existing PostgreSQL URL/TLS settings; use an explicit host, port, database and credentials") from None
    descriptor = {"mode": "external", "url_sha256": hashlib.sha256(url.encode()).hexdigest(),
                  "ca_sha256": hashlib.sha256(ca).hexdigest() if ca is not None else None}
    return descriptor, url, ca


def network_inputs(env):
    name = env.get("OPENWAF_DOCKER_NETWORK_NAME", "") or "openwaf-backends"
    external = env.get("OPENWAF_DOCKER_NETWORK_EXTERNAL", "") or "false"
    if external not in {"false", "true"}:
        raise InitError("OPENWAF_DOCKER_NETWORK_EXTERNAL must be false or true")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", name):
        raise InitError("OPENWAF_DOCKER_NETWORK_NAME requires a Docker network name (maximum 128 ASCII characters)")
    if name in {"host", "none", "bridge"}:
        raise InitError("Use a user-defined Docker bridge network with service DNS")
    return {"name": name, "external": external == "true"}


def run():
    value = selected_profile()
    budgets = json.dumps(value["budgets"], sort_keys=True).encode()
    validate_resource_budgets(budgets)
    context("validate admin hostname/origin/terms")
    settings = inputs(os.environ)
    context("validate database inputs")
    database, database_url, ca = database_inputs(os.environ)
    context("validate Docker network inputs")
    network = network_inputs(os.environ)
    directory(BASE / "gateway")
    config = BASE / "gateway"
    marker = config / "instance.json"
    previous = json.loads(read(marker)) if marker.exists() else None
    if previous and previous.get("database") != database:
        raise InitError("Database mode/connection or engine changed; use a reviewed backup/restore migration (legacy PostgreSQL 17 volumes cannot be reused by PGAIO 18)")
    if previous and previous.get("network", {"name": "openwaf-backends", "external": False}) != network:
        raise InitError("Docker network changed; review connectivity and migrate persisted gateway configuration explicitly")
    for name in ["tls", "bootstrap", "acme-key", "db-secret", "db-init",
                 "replay", "security", "applications", "discovery", "bootstrap-provider"]:
        directory(BASE / name, POSTGRES_UID if name in ("db-secret", "db-init") else UID)
    if database["mode"] == "managed":
        directory(BASE / "postgres", POSTGRES_UID)
    directory(BASE / "bootstrap/providers")
    directory(BASE / "bootstrap/staging-tls")
    descriptor = {"schema_version": 2, "settings": settings, "database": database, "network": network}
    if previous and previous.get("settings") != settings:
        raise InitError("Admin host/origin changed; migrate DNS/config explicitly")
    populated = previous is not None or any((BASE / "bootstrap" / name).exists()
                                           for name in ("admin-owned", "production.json"))
    hashes = {}
    secret_files = [
        ("admin_key", config / "master.key", 32, UID),
        ("acme_key", BASE / "acme-key/master.key", 32, UID),
    ]
    if database["mode"] == "managed":
        secret_files.extend([
            ("database_password", config / "database-password", 64, UID),
            ("postgres_password", BASE / "db-secret/password", 64, POSTGRES_UID),
        ])
    for name, path, size, uid in secret_files:
        if not path.exists():
            if populated:
                raise InitError("Persisted secret missing; restore it instead of generating a replacement")
            write(path, secrets.token_bytes(size) if size == 32 else secrets.token_hex(size // 2), uid)
        data = read(path, size)
        if len(data) != size:
            raise InitError("Persisted secret has invalid length")
        digest = hashlib.sha256(data).hexdigest()
        if previous and previous["secret_hashes"].get(name) != digest:
            raise InitError("Persisted secret changed; restore original key/credential")
        hashes[name] = digest
    raw = Path(os.environ.get("OPENWAF_CLOUDFLARE_API_TOKEN_FILE", "/run/secrets/cloudflare-token"))
    token = read(raw, 1024).strip()
    if not 16 <= len(token) <= 512 or not all(33 <= byte <= 126 for byte in token):
        raise InitError("Cloudflare API token must contain 16..512 printable bytes")
    token_hash = hashlib.sha256(token).hexdigest()
    encrypted = BASE / "bootstrap/providers/cloudflare.enc"
    if not encrypted.exists() or not previous or previous.get("token_hash") != token_hash:
        temporary = encrypted.with_name(".new-" + secrets.token_hex(8))
        try:
            # Only paths in argv. Native encryption never prints token or key.
            context("seal Cloudflare credential")
            subprocess.run(["/usr/local/bin/openwaf-acme", "seal-cloudflare-token", str(raw),
                            str(temporary), str(BASE / "acme-key/master.key")], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30,
                           env={"OPENWAF_ENV_FILE": "/dev/null", "PATH": "/usr/local/bin:/usr/bin:/bin"})
            os.chown(temporary, UID, UID)
            os.replace(temporary, encrypted)
            sync(encrypted.parent)
        finally:
            temporary.unlink(missing_ok=True)
    else:
        read(encrypted, 4096)
    seed = BASE / "bootstrap-provider/credential.enc"
    if not seed.exists():
        temporary = seed.with_name(".seed-" + secrets.token_hex(8))
        try:
            context("seal bootstrap provider credential")
            subprocess.run(["/usr/local/bin/openwaf-acme", "seal-bootstrap-provider", str(raw),
                            str(temporary), str(config / "master.key"), settings["hostname"]], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30,
                           env={"OPENWAF_ENV_FILE": "/dev/null", "PATH": "/usr/local/bin:/usr/bin:/bin"})
            os.chown(temporary, UID, UID)
            os.replace(temporary, seed)
            sync(seed.parent)
        finally:
            temporary.unlink(missing_ok=True)
    else:
        read(seed, 2081)
    immutable(BASE / "bootstrap/admin.json", json.dumps(settings, sort_keys=True))
    if database["mode"] == "managed":
        password = read(config / "database-password").decode("ascii")
        database_url = f"postgres://openwaf:{password}@openwaf-managed-postgres:5432/openwaf?sslmode=disable"
    if ca is not None:
        immutable(config / "database-ca.crt", ca)
    # Container interface addresses are read by the gateway at each startup.
    # Origin addresses also cover the host-published listener outside its netns.
    local_ips = ["127.0.0.1", "::1"]
    local_ips += [ip for ip in (settings["ipv4"], settings["ipv6"]) if ip]
    values = {
        "OPENWAF_LISTEN": "0.0.0.0:8443", "OPENWAF_ADMIN_LISTEN": "127.0.0.1:9090",
        "OPENWAF_ADMIN_HOST": settings["hostname"], "OPENWAF_ADMIN_PUBLIC": "true",
        "OPENWAF_ADMIN_ORIGIN": "https://" + settings["hostname"],
        "OPENWAF_ADMIN_MASTER_KEY_FILE": "/etc/openwaf/master.key",
        "OPENWAF_DATABASE_URL": database_url,
        "OPENWAF_TLS_MANIFEST": settings["tls_manifest"],
        "OPENWAF_RESOURCE_BUDGETS_FILE": "/etc/openwaf/resource-budgets.json",
        "OPENWAF_REPLAY_DIRECTORY": "/var/lib/openwaf/replay",
        "OPENWAF_REPLAY_MIN_FREE_BYTES": "67108864", "OPENWAF_WAF_MODE": "DetectionOnly",
        "OPENWAF_REQUIRE_MANAGED": "true", "OPENWAF_DISCOVERY_SOCKET": "/run/openwaf-discovery/collector.sock",
        "OPENWAF_DISCOVERY_UID": str(UID), "OPENWAF_GATEWAY_NETWORK_MODE": "bridge",
        "OPENWAF_GATEWAY_DOCKER_NETWORKS": network["name"], "OPENWAF_LOCAL_IPS": ",".join(local_ips),
        "OPENWAF_DISCOVER_LOCAL_IPS": "true",
    }
    gateway_env = "".join(f"{key}={value}\n" for key, value in values.items()).encode()
    env_path = config / "gateway.env"
    if previous and env_path.exists():
        # Retire only the generated legacy password setting. All other persisted
        # settings must still match exactly; existing users and secret files stay intact.
        current = read(env_path)
        legacy = b"OPENWAF_ADMIN_INITIAL_PASSWORD_FILE=/run/openwaf-admin/initial-password\n"
        if current != gateway_env and current.replace(legacy, b"", 1) == gateway_env:
            temporary = config / (".gateway-" + secrets.token_hex(8))
            write(temporary, gateway_env)
            os.replace(temporary, env_path)
            sync(config)
    immutable(env_path, gateway_env)
    install_resource_budgets(config, budgets)
    if database["mode"] == "managed":
        immutable(BASE / "db-init/10-openwaf.sql",
                  f"CREATE ROLE openwaf LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '{password}';\n"
                  "CREATE DATABASE openwaf OWNER openwaf;\n", POSTGRES_UID)
    descriptor.update(secret_hashes=hashes, token_hash=token_hash)
    temporary = config / (".instance-" + secrets.token_hex(8))
    write(temporary, json.dumps(descriptor, sort_keys=True))
    os.replace(temporary, marker)
    sync(config)
    print("Startup volumes ready; secrets retained in private volumes.")


def dependencies():
    """Additive provisioning, separate from immutable gateway/DB bootstrap state."""
    value = selected_profile()
    defaults = {name: default_file(name) for name in ("clickhouse.xml", "crowdsec.json", "crowdsec-bootstrap.sh")}
    config = BASE / "dependencies"
    marker = config / "instance.json"
    previous = json.loads(read(marker)) if marker.exists() else None
    for name in ["dependencies", "security-key", "crowdsec-config", "crowdsec-data",
                 "clickhouse-data"]:
        directory(BASE / name)
    for name in ["hub", "notifications"]:
        directory(BASE / "crowdsec-config" / name)
    key = BASE / "security-key/master.key"
    if not key.exists():
        if previous or (config / "crowdsec.enc").exists():
            raise InitError("Persisted CrowdSec master key missing; restore the original key")
        write(key, secrets.token_bytes(32))
    data = read(key, 32)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != 32 or (previous and previous.get("master_key_sha256") != digest):
        raise InitError("Persisted CrowdSec master key changed or invalid")
    install_clickhouse(config, value)
    # Manual-decision mode has no downloaded hub. cscli still expects a local index.
    immutable(BASE / "crowdsec-config/hub/.index.json", "{}\n")
    immutable(BASE / "crowdsec-config/bootstrap.sh", defaults["crowdsec-bootstrap.sh"])
    immutable(BASE / "crowdsec-config/config.yaml", defaults["crowdsec.json"])
    immutable(BASE / "crowdsec-config/profiles.yaml", json.dumps({
        "name": "default_ip_remediation",
        "filters": ["Alert.Remediation == true && Alert.GetScope() == 'Ip'"],
        "decisions": [{"type": "ban", "duration": "4h"}], "on_success": "break",
    }))
    immutable(BASE / "crowdsec-config/console.yaml", json.dumps({
        "share_tainted": False, "share_custom": False, "share_manual_decisions": False,
        "share_context": False, "console_management": False,
    }))
    immutable(config / "crowdsec.json", json.dumps({
        "lapi_url": "http://127.0.0.1:8085",
        "key_file": "/etc/openwaf-dependencies/crowdsec.enc",
        "master_key_file": "/run/openwaf-security-key/master.key",
        "checkpoint_file": "/var/lib/openwaf/security/crowdsec-checkpoint.json",
        "poll_seconds": 10,
    }))
    immutable(marker, json.dumps({"schema_version": 1, "master_key_sha256": digest}, sort_keys=True))
    certificate_runtime()
    print("Dependency volumes ready; existing state and keys retained.")


def certificate_runtime():
    """Provision the existing Admin certificate module, without provider/catalog inputs."""
    directory(BASE / "certificate-key")
    directory(BASE / "certificate-requests")
    key = BASE / "certificate-key/master.key"
    # Keep the integrity marker outside key/state volumes so losing both cannot
    # silently create a new issuance identity while PostgreSQL keeps old jobs.
    marker = BASE / "dependencies/certificate-runtime.json"
    previous = json.loads(read(marker)) if marker.exists() else None
    if not key.exists():
        if previous or any((BASE / "certificate-requests").iterdir()):
            raise InitError("Persisted certificate master key missing; restore the original key")
        write(key, secrets.token_bytes(32))
    data = read(key, 32)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != 32 or (previous and previous.get("key_sha256") != digest):
        raise InitError("Persisted certificate master key changed or invalid")
    immutable(marker, json.dumps({"schema_version": 1, "key_sha256": digest}, sort_keys=True))


def seal_crowdsec():
    """Run after cscli provisioning; only the encrypted bouncer key reaches gateway."""
    config = BASE / "dependencies"
    raw = BASE / "crowdsec-config/bouncer.key"
    master = BASE / "security-key/master.key"
    key = read(raw, 1024)
    if not 16 <= len(key) <= 512 or not all(33 <= byte <= 126 for byte in key):
        raise InitError("Invalid private CrowdSec bouncer credential")
    descriptor = {"key_sha256": hashlib.sha256(key).hexdigest(),
                  "master_key_sha256": hashlib.sha256(read(master, 32)).hexdigest()}
    output = config / "crowdsec.enc"
    marker = config / "crowdsec-sealed.json"
    if marker.exists():
        if json.loads(read(marker)) != descriptor or not output.exists():
            raise InitError("CrowdSec credential changed or envelope missing; explicit recovery required")
        read(output, 1100)
        return
    if output.exists():
        # Recover a crash between envelope publication and marker creation. The
        # original plaintext and master key are still mandatory; reseal atomically.
        read(output, 1100)
    temporary = config / (".crowdsec-" + secrets.token_hex(8))
    try:
        context("seal CrowdSec credential")
        subprocess.run(["/usr/local/bin/openwaf-security", "seal-crowdsec-key", str(raw),
                        str(temporary), str(master)], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30,
                       env={"OPENWAF_ENV_FILE": "/dev/null", "PATH": "/usr/local/bin:/usr/bin:/bin"})
        os.chown(temporary, UID, UID)
        os.replace(temporary, output)
        sync(config)
    finally:
        temporary.unlink(missing_ok=True)
    immutable(marker, json.dumps(descriptor, sort_keys=True))
    print("CrowdSec credential sealed; no plaintext key mounted in gateway.")


def main():
    try:
        # Same lock survives process crashes; kernel releases ownership on exit.
        mode = sys.argv[1:]
        actions = {(): ("gateway", run), ("vps-start",): ("gateway", run),
                   ("vps-dependencies",): ("dependencies", dependencies), ("dependencies",): ("dependencies", dependencies),
                   ("seal-crowdsec",): ("dependencies", seal_crowdsec)}
        if tuple(mode) not in actions:
            raise InitError("Unknown startup initialization mode")
        owner, action = actions[tuple(mode)]
        directory(BASE / owner)
        context("acquire initializer lock", BASE / owner / ".init.lock")
        fd = os.open(BASE / owner / ".init.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as lock:
            os.fchown(lock.fileno(), UID, UID)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            action()
    except InitError as error:
        print(f"Startup initialization failed [{CONTEXT}]: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Startup initialization failed [{CONTEXT}]: {error_summary(error)}; secrets were not printed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
