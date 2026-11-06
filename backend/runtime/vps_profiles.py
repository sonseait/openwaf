"""VPS sizing source of truth; rendered Compose fragments ship with the repo.

CPU quotas are ceilings, not reservations. RAM limits include caches/tmpfs;
even the sum of all service ceilings leaves host memory. Native check-resources
remains the authority for gateway envelope validation.
"""
import hashlib
import json

MIB = 1024 * 1024
NAMES = ("2c4g", "4c8g", "8c16g", "8c32g", "16c64g")
DEFAULT = NAMES[0]
SERVICES = ("gateway", "postgres", "clickhouse", "crowdsec", "collector", "admin-bootstrap",
            "startup-init", "dependencies-init", "crowdsec-init", "crowdsec-seal", "bootstrap-provider")


def profile(name):
    if name not in NAMES:
        raise ValueError("Unknown VPS profile; choose 2c4g, 4c8g, 8c16g, 8c32g or 16c64g")
    # cores, RAM GiB, workers, queue, connections, requests, accounting MiB,
    # memory ceilings MiB (gateway, PG, CH, CrowdSec, collector, ACME), CPU ceilings.
    rows = {
        "2c4g": (2, 4, 2, 4, 56, 64, 1024,
                  (1280, 512, 768, 192, 96, 128), (1, .4, .3, .1, .05, .05)),
        "4c8g": (4, 8, 4, 8, 128, 128, 2048,
                  (2560, 1024, 1536, 256, 128, 192), (2, .8, .65, .15, .1, .1)),
        "8c16g": (8, 16, 8, 8, 256, 256, 4096,
                   (5120, 2048, 3072, 384, 256, 256), (4.5, 1.25, 1.25, .25, .15, .2)),
        "8c32g": (8, 32, 8, 16, 768, 256, 8192,
                   (10240, 6144, 8192, 512, 256, 256), (4.5, 1.25, 1.25, .25, .15, .2)),
        "16c64g": (16, 64, 16, 16, 1024, 256, 16384,
                    (20480, 12288, 16384, 768, 384, 256), (9.5, 2, 2.5, .5, .25, .25)),
    }
    cores, ram, workers, queue, connections, requests, accounting, memory, cpus = rows[name]
    budgets = {
        "requests": requests,
        "classes": [requests // 2, requests // 8, requests // 4, requests // 8],
        "connections": connections, "handshakes": min(128, connections // 2),
        "headers": min(256, connections), "waf_workers": workers,
        "waf_queue_per_worker": queue, "health_jobs": min(8, cores), "retry_slots": min(16, cores * 2),
        "replay_memory_bytes": min(64, cores * 8) * MIB,
        "replay_disk_bytes": (512 if cores == 2 else 2048) * MIB,
        "replay_io_slots": min(4, cores), "ram_budget_bytes": accounting * MIB,
        "fd_budget": 4096 if cores <= 4 else 8192, "reserved_routes": [],
    }
    pids = ((192, 256, 384, 384, 512)[NAMES.index(name)], 192, 256, 128, 96, 128)
    limits = {service: {"memory_mib": mem, "cpus": cpu, "pids": pid}
              for service, mem, cpu, pid in zip(SERVICES, memory, cpus, pids)}
    for service, mem in zip(SERVICES[6:], (128, 96, 128, 96, 128 if cores == 2 else 192)):
        # The startup validator is synchronous and starts no worker pools.
        limits[service] = {"memory_mib": mem, "cpus": .25,
                           "pids": 16 if service in ("startup-init", "dependencies-init") else 128}
    return {"name": name, "host_cpus": cores, "host_memory_mib": ram * 1024,
            "budgets": budgets, "limits": limits,
            "postgres": {"shared_buffers_mb": max(64, memory[1] // 8),
                         "work_mem_mb": 2 if cores == 2 else 4,
                         "maintenance_work_mem_mb": 32 if cores <= 4 else 64,
                         "max_connections": 40, "max_parallel_workers": min(4, cores // 2)},
            "clickhouse": {"server_memory_bytes": memory[2] * MIB * 3 // 4,
                           "query_memory_bytes": min(256, memory[2] // 8) * MIB,
                           "cache_bytes": min(128, memory[2] // 16) * MIB,
                           "threads": max(1, min(4, cores // 4))}}


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def compose(name):
    value = profile(name)
    services = {}
    for service, limit in value["limits"].items():
        memory = f'{limit["memory_mib"]}m'
        services[service] = {"cpus": limit["cpus"], "mem_limit": memory,
                             "memswap_limit": memory, "pids_limit": limit["pids"],
                             "cpu_shares": 1024 if service == "gateway" else 256,
                             "ulimits": {"nofile": {"soft": 8192, "hard": 8192}}}
    for service in ("startup-init", "dependencies-init"):
        services[service]["environment"] = {"OPENWAF_VPS_PROFILE": name,
                                            "OPENWAF_VPS_PROFILE_SHA256": fingerprint(value)}
    for service in ("admin-bootstrap", "bootstrap-provider", "collector"):
        services[service].setdefault("environment", {})["TOKIO_WORKER_THREADS"] = "2"
    pg = value["postgres"]
    services["postgres"]["environment"] = {"POSTGRESQL_EXTRA_FLAGS": " ".join(
        f'-c {key}={number}{"MB" if key.endswith("_mb") else ""}'
        .replace("_mb=", "=") for key, number in pg.items())}
    return {"x-openwaf-generated": "backend/runtime/vps_profiles.py; run deploy/ansible/scripts/generate-profiles.py",
            "services": services}
