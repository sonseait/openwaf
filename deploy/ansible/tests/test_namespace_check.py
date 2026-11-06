"""Namespace readiness regressions without Docker or credentials."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "files/check_namespaces.py"


class NamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("check_namespaces", SCRIPT)
        assert spec is not None and spec.loader is not None
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def run_check(self, namespaces, stopped=False, probe=False, ping="Ok."):
        def command(argv, **kwargs):
            if argv[0] == "nsenter":
                return subprocess.CompletedProcess(argv, 0, "Prometheus Server is Ready." if argv[-1].endswith('/-/ready') else ping)
            if "ps" in argv:
                service = next(x.split("=", 2)[2] for x in argv
                               if x.startswith("label=com.docker.compose.service="))
                return subprocess.CompletedProcess(argv, 0, service + "\n")
            pid = {"gateway": 100, "clickhouse": 101, "crowdsec": 102, "prometheus": 103}[argv[-1]]
            return subprocess.CompletedProcess(argv, 0, f"{'exited' if stopped else 'running'} {pid}\n")
        with patch.object(self.module.subprocess, "run", side_effect=command), \
                patch.object(self.module.os, "readlink", side_effect=namespaces):
            return self.module.check("/var/run/docker.sock", "openwaf-vps", probe)

    def test_gateway_origin_probe(self):
        self.assertEqual(self.run_check(["net:[1]"] * 4, probe=True), 0)
        with self.assertRaises(RuntimeError):
            self.run_check(["net:[1]"] * 4, probe=True, ping="unexpected")

    def test_transport_failure_is_fatal(self):
        with patch.object(self.module.subprocess, "run", side_effect=subprocess.TimeoutExpired("docker", 10)):
            with self.assertRaises(RuntimeError):
                self.module.check("/var/run/docker.sock", "openwaf-vps")

    def test_shared_namespace(self):
        self.assertEqual(self.run_check(["net:[1]"] * 4), 0)

    def test_stale_sidecar_is_repairable(self):
        self.assertEqual(self.run_check(["net:[1]", "net:[2]", "net:[2]", "net:[1]"]), 3)

    def test_stopped_service_is_not_reported_as_mismatch(self):
        with self.assertRaises(RuntimeError):
            self.run_check([], stopped=True)

    def test_missing_or_duplicate_service_fails(self):
        for ids in ("", "one\ntwo\n"):
            with self.subTest(ids=ids), patch.object(self.module.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, ids)):
                with self.assertRaises(RuntimeError):
                    self.module.check("/var/run/docker.sock", "openwaf-vps")


if __name__ == "__main__":
    unittest.main()
