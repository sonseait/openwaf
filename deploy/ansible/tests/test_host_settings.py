"""Host-detection decisions with synthetic facts; no provider or Engine calls."""
import importlib.util
import json
from pathlib import Path
import unittest

from ansible.errors import AnsibleFilterError


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("host_settings", ROOT / "filter_plugins/host_settings.py")
DETECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECTION)
CAPACITIES = json.loads((ROOT / "files/profile-capacity.json").read_text())


class HostSettingsTests(unittest.TestCase):
    def detect(self, cpus=4, memory=8000, facts=None, **settings):
        host = {"processor_vcpus": cpus, "memtotal_mb": memory,
                "default_ipv4": {"address": "93.184.215.14"}}
        host.update(facts or {})
        return DETECTION.host_settings(host, CAPACITIES, **settings)

    def test_selects_by_both_cpu_and_total_memory(self):
        cases = [(2, 4000, "2c4g"), (4, 8000, "4c8g"), (8, 16000, "8c16g"),
                 (8, 32000, "8c32g"), (16, 64000, "16c64g"), (64, 128000, "16c64g"),
                 (6, 16000, "4c8g"), (16, 8000, "4c8g"), (2, 64000, "2c4g")]
        for cpus, memory, expected in cases:
            with self.subTest(cpus=cpus, memory=memory):
                self.assertEqual(self.detect(cpus, memory)["profile"], expected)

    def test_memory_tolerance_does_not_use_swap_or_free_memory(self):
        self.assertEqual(self.detect(2, 3892, facts={"memfree_mb": 100})["profile"], "2c4g")
        for cpus, memory in [(2, 3891), (1, 64000), (0, 0)]:
            with self.subTest(cpus=cpus, memory=memory):
                with self.assertRaisesRegex(AnsibleFilterError, "No supported"):
                    self.detect(cpus, memory, facts={"swaptotal_mb": 65536})

    def test_explicit_smaller_profile_and_rejects_oversized_or_unknown(self):
        self.assertEqual(self.detect(16, 64000, profile="2c4g")["profile"], "2c4g")
        for profile in ["unknown", "8c16g", "16c64g"]:
            with self.subTest(profile=profile):
                with self.assertRaisesRegex(AnsibleFilterError, "unknown or exceeds"):
                    self.detect(profile=profile)

    def test_missing_capacity_facts_fail_without_guessing(self):
        with self.assertRaisesRegex(AnsibleFilterError, "facts are unavailable"):
            DETECTION.host_settings({}, CAPACITIES)

    def test_detects_global_default_interfaces_for_both_families(self):
        value = self.detect(facts={"default_ipv6": {"address": "2606:4700:4700::1111"}})
        self.assertEqual(value["ipv4"], "93.184.215.14")
        self.assertEqual(value["ipv6"], "2606:4700:4700::1111")
        self.assertEqual(self.detect(facts={"default_ipv4": {}, "default_ipv6": {
            "address": "2606:4700:4700::1111"}})["ipv4"], "")

    def test_private_loopback_documentation_and_linklocal_are_not_public_origins(self):
        for address in ["10.0.0.1", "172.16.0.1", "192.168.0.1", "127.0.0.1", "169.254.1.1", "203.0.113.1"]:
            with self.subTest(address=address):
                with self.assertRaisesRegex(AnsibleFilterError, "No global origin"):
                    self.detect(facts={"default_ipv4": {"address": address},
                                       "default_ipv6": {"address": "fe80::1"},
                                       "all_ipv4_addresses": ["93.184.215.14"]})

    def test_explicit_nat_origin_and_disabling_ipv6(self):
        value = self.detect(ipv4="93.184.215.15", ipv6="", facts={
            "default_ipv4": {"address": "10.0.0.1"},
            "default_ipv6": {"address": "2606:4700:4700::1111"}})
        self.assertEqual(value["ipv4"], "93.184.215.15")
        self.assertEqual(value["ipv6"], "")

    def test_database_mode_follows_url_file_and_preserves_explicit_choice(self):
        self.assertTrue(self.detect()["postgres_create"])
        self.assertFalse(self.detect(database_url_file="/private/db-url")["postgres_create"])
        self.assertFalse(self.detect(postgres=False)["postgres_create"])
        self.assertTrue(self.detect(postgres=True, database_url_file="/private/db-url")["postgres_create"])
        with self.assertRaisesRegex(AnsibleFilterError, "auto or a boolean"):
            self.detect(postgres="false")


if __name__ == "__main__":
    unittest.main()
