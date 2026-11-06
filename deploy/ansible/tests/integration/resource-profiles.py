#!/usr/bin/env python3
"""Check generated Compose, host headroom and native gateway compatibility.

No secrets or provider calls. --image runs only check-resources, offline.
Otherwise use --binary (defaults to the local debug build).
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "backend/runtime"))
import vps_profiles  # noqa: E402
from compose_fixture import FixtureError, render_stack  # noqa: E402


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=90, **kwargs).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--image")
    parser.add_argument("--init-image", default=os.environ.get("OPENWAF_TEST_INIT_IMAGE", "openwaf-init:render-only"))
    group.add_argument("--binary", default=str(ROOT / "backend/target/debug/openwaf-gateway"))
    args = parser.parse_args()
    run([sys.executable, str(ROOT / "deploy/ansible/scripts/generate-profiles.py"), "--check"])
    for name in vps_profiles.NAMES:
        value = vps_profiles.profile(name)
        with tempfile.TemporaryDirectory(prefix="openwaf-profile-check-") as tmp:
            model = render_stack(tmp, {"openwaf_image": args.image or "openwaf-profile-check:unused",
                                       "openwaf_init_image": args.init_image,
                                       "openwaf_vps_profile": name})
        services = model["services"]
        assert set(services) == set(value["limits"])
        total_memory = sum(int(s["mem_limit"]) for s in services.values())
        reserve = value["host_memory_mib"] * vps_profiles.MIB - total_memory
        assert reserve >= 512 * vps_profiles.MIB, name
        steady = ("gateway", "postgres", "clickhouse", "crowdsec", "collector", "admin-bootstrap")
        assert sum(float(services[s]["cpus"]) for s in steady) <= value["host_cpus"]
        assert value["budgets"]["ram_budget_bytes"] <= int(services["gateway"]["mem_limit"]) * .8
        for service, limits in value["limits"].items():
            actual = services[service]
            assert int(actual["mem_limit"]) == int(actual["memswap_limit"]) == limits["memory_mib"] * vps_profiles.MIB
            assert float(actual["cpus"]) == limits["cpus"]
            assert actual["pids_limit"] == limits["pids"]
            assert actual["ulimits"]["nofile"] == {"soft": 8192, "hard": 8192}
            if service != "gateway":
                assert not actual.get("ports"), service
            if service != "collector":
                assert not any("docker.sock" in mount.get("source", "") for mount in actual.get("volumes", []))
        assert services["startup-init"]["command"] == ["vps-start"]
        assert services["dependencies-init"]["command"] == ["vps-dependencies"]
        for service in ("startup-init", "dependencies-init"):
            env = services[service]["environment"]
            assert env["OPENWAF_VPS_PROFILE"] == name
            assert env["OPENWAF_VPS_PROFILE_SHA256"] == vps_profiles.fingerprint(value)
        if args.image:
            command = ["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop=ALL",
                       "--security-opt", "no-new-privileges:true", "--pids-limit", "16", "--memory", "128m",
                       "--cpus", ".25", "-e", "OPENWAF_ENV_FILE=/dev/null",
                       "--ulimit", "nofile=8192:8192",
                       "--entrypoint", "/usr/local/bin/openwaf-gateway", args.image, "check-resources"]
        else:
            command = [args.binary, "check-resources"]
        run(command, env=os.environ | {"OPENWAF_ENV_FILE": "/dev/null"}, input=json.dumps(value["budgets"]).encode())
        print(f"PASS {name}: Compose caps, native validator; all-service host headroom {reserve // vps_profiles.MIB} MiB")
    with tempfile.TemporaryDirectory(prefix="openwaf-invalid-profile-") as tmp:
        try:
            render_stack(tmp, {"openwaf_image": args.image or "openwaf-profile-check:unused",
                               "openwaf_init_image": args.init_image,
                               "openwaf_vps_profile": "unknown"})
        except FixtureError:
            pass
        else:
            raise AssertionError("Unknown profile unexpectedly rendered")
    print("PASS unknown profile fails Compose resolution")


if __name__ == "__main__":
    main()
