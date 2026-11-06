#!/usr/bin/env python3
"""Isolated PostgreSQL/ClickHouse statistics integration, never deployment services."""
import os
import secrets
import subprocess
from body_recording import ROOT, docker, request, wait


def main():
    prefix = "openwaf-statistics-test-" + secrets.token_hex(4)
    names = []
    password = secrets.token_urlsafe(24)
    try:
        for suffix, image, internal, env in [
            ("pg", "postgres:17-bookworm", 5432, ["-e", f"POSTGRES_PASSWORD={password}"]),
            ("ch", "clickhouse/clickhouse-server:25.8", 8123, ["-e", "CLICKHOUSE_SKIP_USER_SETUP=1"]),
        ]:
            name = prefix + "-" + suffix
            docker("run", "-d", "--name", name, "-p", f"127.0.0.1::{internal}", *env, image)
            names.append(name)
        pg_port = int(docker("port", names[0], "5432/tcp").rsplit(":", 1)[1])
        ch_port = int(docker("port", names[1], "8123/tcp").rsplit(":", 1)[1])
        wait(lambda: request(ch_port, "GET", "/ping")[0] == 200)
        wait(lambda: subprocess.run(["docker", "exec", names[0], "pg_isready", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
        env = os.environ.copy()
        env["OPENWAF_TEST_CLICKHOUSE_URL"] = f"http://127.0.0.1:{ch_port}/"
        env["OPENWAF_STATISTICS_TEST_DATABASE_URL"] = f"postgres://postgres:{password}@127.0.0.1:{pg_port}/postgres?sslmode=disable"
        for package, selection in [
            ("openwaf-storage", "clickhouse_"),
            ("openwaf-admin", "postgres_certificate_baseline_does_not_invent_renewal_on_restart"),
            ("openwaf-admin", "postgres_migrates_saves_and_restores_host_statistics"),
        ]:
            subprocess.run(["cargo", "test", "-p", package, selection, "--", "--ignored", "--test-threads=1"], cwd=ROOT, env=env, check=True, timeout=180)
    finally:
        for name in reversed(names):
            subprocess.run(["docker", "rm", "-fv", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    main()
