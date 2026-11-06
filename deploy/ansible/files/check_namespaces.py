"""Read-only Linux readiness check; exit 3 means sidecars need recreation."""
import argparse
import os
import subprocess
import sys


def output(argv):
    try:
        return subprocess.run(argv, check=True, capture_output=True, text=True,
                              timeout=10).stdout.strip()
    except (subprocess.SubprocessError, OSError) as exc:
        raise RuntimeError("namespace readiness command failed") from exc


def check(socket, project, probe=False):
    docker = ["docker", "--host", "unix://" + socket]
    namespaces = []
    gateway_pid = None
    for service in ("gateway", "clickhouse", "crowdsec", "prometheus"):
        ids = output(docker + ["ps", "-a", "--filter",
                     "label=com.docker.compose.project=" + project, "--filter",
                     "label=com.docker.compose.service=" + service,
                     "--format", "{{.ID}}"] ).splitlines()
        if len(ids) != 1:
            raise RuntimeError(service + ": expected exactly one container")
        state = output(docker + ["inspect", "--format",
                       "{{.State.Status}} {{.State.Pid}}", ids[0]]).split()
        if len(state) != 2 or state[0] != "running" or not state[1].isdigit() or int(state[1]) <= 0:
            raise RuntimeError(service + ": container is not running")
        pid = state[1]
        if service == "gateway":
            gateway_pid = pid
        try:
            namespace = os.readlink("/proc/" + pid + "/ns/net")
        except OSError as exc:
            raise RuntimeError(service + ": network namespace unavailable") from exc
        namespaces.append(namespace)
        print(service + ": " + namespace)
    if len(set(namespaces)) != 1:
        return 3
    if probe:
        response = output(["nsenter", "-t", gateway_pid, "-n", "curl", "--fail",
                           "--silent", "--show-error", "--noproxy", "*",
                           "--connect-timeout", "1", "--max-time", "3",
                           "http://127.0.0.1:8123/ping"])
        if response != "Ok.":
            raise RuntimeError("gateway-origin ClickHouse ping returned unexpected response")
        print("gateway-origin ClickHouse ping passed")
        response = output(["nsenter", "-t", gateway_pid, "-n", "curl", "--fail",
                           "--silent", "--show-error", "--noproxy", "*",
                           "--connect-timeout", "1", "--max-time", "3",
                           "http://127.0.0.1:9091/-/ready"])
        if response != "Prometheus Server is Ready.":
            raise RuntimeError("gateway-origin Prometheus readiness failed")
        print("gateway-origin Prometheus readiness passed")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("socket")
    parser.add_argument("project")
    parser.add_argument("--probe", action="store_true")
    args = parser.parse_args()
    try:
        sys.exit(check(args.socket, args.project, args.probe))
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
