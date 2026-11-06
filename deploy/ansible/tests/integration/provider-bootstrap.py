#!/usr/bin/env python3
"""Run transactional provider/ownership tests against an isolated local PostgreSQL.
Only test-created containers are removed. No Cloudflare credentials or requests.
"""
import os
from pathlib import Path
import secrets
import subprocess
import time

REPO = Path(__file__).resolve().parents[4]


def main():
    name = "openwaf-provider-test-" + secrets.token_hex(5)
    try:
        subprocess.run(["docker", "run", "-d", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
                        "-p", "127.0.0.1::5432", "postgres:17-bookworm"], check=True, capture_output=True)
        end = time.monotonic() + 30
        while subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True).returncode:
            if time.monotonic() > end:
                raise RuntimeError("PostgreSQL readiness deadline")
            time.sleep(0.2)
        port = subprocess.check_output(["docker", "port", name, "5432/tcp"], text=True).strip().rsplit(":", 1)[1]
        env = {key: value for key, value in os.environ.items() if not key.startswith("OPENWAF_")}
        env["OPENWAF_ENV_FILE"] = "/dev/null"
        env["OPENWAF_BOOTSTRAP_TEST_DATABASE_URL"] = f"postgres://postgres@127.0.0.1:{port}/postgres?sslmode=disable"
        subprocess.run(["cargo", "test", "--manifest-path", str(REPO / "backend/Cargo.toml"), "-p", "openwaf-admin",
                        "certificate_bootstrap::tests::postgres_", "--", "--ignored", "--nocapture"], check=True, env=env, timeout=180)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


if __name__ == "__main__":
    main()
