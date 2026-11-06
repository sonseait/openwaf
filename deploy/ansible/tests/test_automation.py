"""Local automation regressions: no containers, cloud APIs or real credentials.

Uses the actual Ansible tasks/templates and Docker Compose model parser.
Run with the controller venv after installing requirements and the collection.
"""
import json
import importlib.util
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

import yaml


SOURCE = Path(__file__).resolve().parents[1]


class AutomationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ansible = shutil.which("ansible-playbook") or str(Path(sys.executable).with_name("ansible-playbook"))
        if not Path(cls.ansible).is_file():
            raise RuntimeError("Install deploy/ansible/requirements.txt in the test interpreter's venv")
        if not shutil.which("docker"):
            raise RuntimeError("Docker Compose CLI is required (Engine is not used)")
        cls.sandbox = tempfile.TemporaryDirectory(prefix="openwaf-ansible-tests-")
        cls.root = Path(cls.sandbox.name)
        cls.automation = cls.root / "release/deploy/ansible"
        shutil.copytree(SOURCE, cls.automation, ignore=shutil.ignore_patterns(
            ".venv", ".collections", "tests", "inventory.yml", "inventory.*.yml", "host_vars", "group_vars", "local"))
        cls.inventory = cls.root / "inventory.yml"
        cls.inventory.write_text(yaml.safe_dump({"all": {"hosts": {"localhost": {
            "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
        }}}}))
        cls.env = {key: value for key, value in os.environ.items() if not key.startswith("OPENWAF_")}
        cls.env.update(ANSIBLE_CONFIG=str(cls.automation / "ansible.cfg"), ANSIBLE_NOCOLOR="1")
        spec = importlib.util.spec_from_file_location("sizing_source", SOURCE.parents[1] / "backend/runtime/vps_profiles.py")
        cls.sizing = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.sizing)

    @classmethod
    def tearDownClass(cls):
        cls.sandbox.cleanup()

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.root))
        self.private = self.case / "private"
        self.private.mkdir(mode=0o700)
        self.token = self.private / "cloudflare-token"
        self.token.write_text(secrets.token_hex(32))
        self.token.chmod(0o600)
        self.settings = {
            "openwaf_install_dir": str(self.case / "remote/runtime"),
            "openwaf_secrets_dir": str(self.case / "remote/secrets"),
            "openwaf_data_dir": str(self.case / "state"),
            "openwaf_image": "registry.invalid/openwaf:release-test",
            "openwaf_init_image": "registry.invalid/openwaf-init:release-test",
            "openwaf_admin_host": "admin.example.com",
            "openwaf_origin_ipv4": "203.0.113.10",
            "openwaf_cloudflare_token_file": str(self.token),
            "openwaf_acme_accept_terms": True,
            "openwaf_public_admin_enabled": True,
        }

    def run_tasks(self, extra_tasks=(), overrides=None, check=False, success=True, environment=None,
                  facts_override=None, docker_detection=False):
        settings = dict(self.settings, **(overrides or {}))
        # Synthetic host facts only: the tests do not install packages or
        # claim Linux deployment evidence from the controller's platform.
        facts = {"system": "Linux", "architecture": "x86_64", "distribution": "Ubuntu",
                 "distribution_version": "24.04", "distribution_major_version": "24",
                 "os_family": "Debian", "processor_vcpus": 16, "memtotal_mb": 65536}
        facts.update(facts_override or {})
        pre_tasks = yaml.safe_load((self.automation / "playbook.yml").read_text())[0]["pre_tasks"]
        if not docker_detection:
            # Input/storage tests isolate those tasks from host probes. The
            # dedicated Docker test runs the complete read-only detection path.
            pre_tasks = [task for task in pre_tasks
                         if task.get("ansible.builtin.import_tasks") != "tasks/docker-detect.yml"]
        play = [{"name": "Local automation regression", "hosts": "all", "gather_facts": False,
                 "become": False, "vars": {"ansible_facts": facts, "openwaf_socket": {"stat": {"gid": 1234}}},
                 "pre_tasks": pre_tasks, "tasks": list(extra_tasks)}]
        harness = self.automation / "test-harness.yml"
        harness.write_text(yaml.safe_dump(play, sort_keys=False))
        self.inventory.write_text(yaml.safe_dump({"all": {"hosts": {"localhost": {
            "ansible_connection": "local", "ansible_python_interpreter": sys.executable, **settings,
        }}}}))
        command = [self.ansible, "-i", str(self.inventory), str(harness)]
        if check:
            command.append("--check")
        result = subprocess.run(command, env=dict(self.env, **(environment or {})),
                                text=True, capture_output=True, timeout=90)
        output = result.stdout + result.stderr
        self.assertNotIn(self.token.read_text(), output, "Private token leaked in Ansible output")
        if success:
            self.assertEqual(result.returncode, 0, output)
        else:
            self.assertNotEqual(result.returncode, 0, output)
        return output

    def test_check_mode_accepts_valid_inputs_and_preserves_inventory_overrides(self):
        self.run_tasks([{"ansible.builtin.assert": {"that": [
            "openwaf_image == 'registry.invalid/openwaf:release-test'",
            "openwaf_vps_profile == '4c8g'", "openwaf_pull == 'always'",
            "openwaf_detected.profile == '4c8g'",
            "openwaf_install_docker", "openwaf_origin_ipv6 == '2001:db8::1'",
        ]}}], overrides={"openwaf_vps_profile": "4c8g", "openwaf_origin_ipv6": "2001:db8::1"}, check=True)
        self.assertFalse((self.case / "remote").exists())

    def test_rejects_unsafe_or_incomplete_inputs_before_writing(self):
        cases = [
            {"openwaf_image": "registry.invalid/openwaf:latest"},
            {"openwaf_init_image": ""},
            {"openwaf_init_image": "registry.invalid:5000/openwaf-init"},
            {"openwaf_image": "registry.invalid:5000/openwaf"},
            {"openwaf_admin_host": "admin.example.com\nINJECTED=true"},
            {"openwaf_origin_ipv4": "999.1.1.1"},
            {"openwaf_origin_ipv4": "", "openwaf_origin_ipv6": ""},
            {"openwaf_origin_ipv6": "bad:ip"},
            {"openwaf_acme_accept_terms": False},
            {"openwaf_public_admin_enabled": False},
            {"openwaf_vps_profile": "unknown"},
            {"openwaf_postgres_create": False},
            {"openwaf_install_dir": "/"},
            {"openwaf_data_dir": "/srv"},
            {"openwaf_data_dir": self.settings["openwaf_install_dir"] + "/data"},
            {"openwaf_data_dir": self.settings["openwaf_secrets_dir"]},
        ]
        for settings in cases:
            with self.subTest(settings=settings):
                self.run_tasks(overrides=settings, check=True, success=False)
                self.assertFalse((self.case / "remote").exists())

    def test_rejects_readable_by_others_or_symlinked_secret(self):
        self.token.chmod(0o644)
        self.run_tasks(check=True, success=False)
        self.token.chmod(0o600)
        link = self.private / "link"
        link.symlink_to(self.token)
        self.run_tasks(overrides={"openwaf_cloudflare_token_file": str(link)}, check=True, success=False)

    def test_local_input_validation_does_not_inherit_remote_sudo(self):
        self.run_tasks(overrides={"ansible_become": True}, check=True)

    def test_persistent_state_must_stay_outside_docker_data_root(self):
        docker_tasks = yaml.safe_load((self.automation / "tasks/docker.yml").read_text())
        guard = next(task for task in docker_tasks if task["name"] == "Keep persistent host storage outside the Docker data root")
        tasks = [{"ansible.builtin.set_fact": {
            "openwaf_engine": {"stdout": json.dumps({"DockerRootDir": "/var/lib/docker/"})},
        }}, guard]
        self.run_tasks(tasks)
        for data_dir in ("/var/lib/docker", "/var/lib/docker/openwaf"):
            with self.subTest(data_dir=data_dir):
                output = self.run_tasks(tasks, overrides={"openwaf_data_dir": data_dir}, success=False)
                self.assertIn("outside Docker's data root", output)

    def test_all_profiles_and_database_modes_render_canonical_compose(self):
        database = self.private / "database-url"
        database.write_text("postgresql://openwaf:" + secrets.token_hex(32)
                            + "@db.example.com:5432/openwaf?sslmode=verify-full")
        database.chmod(0o600)
        profiles = ["2c4g", "4c8g", "8c16g", "8c32g", "16c64g"]
        model_dir = self.case / "model"
        model_dir.mkdir()
        shutil.copytree(self.automation / "files/profiles", model_dir / "profiles")
        tasks = [{"ansible.builtin.template": {
            "src": "compose.yaml.j2", "dest": str(model_dir / "compose.yaml"), "mode": "0644"}}]
        for profile in profiles:
            tasks.extend([
                {"ansible.builtin.set_fact": {"openwaf_detected":
                    "{{ openwaf_detected | combine({'profile': '" + profile + "'}) }}"}},
                {"ansible.builtin.template": {
                    "src": "vps.env.j2", "dest": str(self.case / f"{profile}.env"), "mode": "0600"}},
            ])
        for managed in (True, False):
            with self.subTest(managed=managed):
                self.run_tasks(tasks, overrides={
                    "openwaf_postgres_create": managed,
                    "openwaf_database_url_file": "" if managed else str(database),
                    "openwaf_docker_network_external": not managed,
                    "openwaf_docker_network_name": "openwaf-backends" if managed else "apps_default",
                    "openwaf_geoip_file": str(self.private / "country.mmdb") if not managed else "",
                    "openwaf_acme_dns_resolver": "1.1.1.1:53" if managed else "[2606:4700:4700::1111]:53",
                })
                for profile in profiles:
                    envfile = self.case / f"{profile}.env"
                    rendered = envfile.read_text()
                    self.assertNotIn(self.token.read_text(), rendered)
                    self.assertNotIn(database.read_text(), rendered)
                    result = subprocess.run([
                        "docker", "compose", "--env-file", str(envfile), "-f", str(model_dir / "compose.yaml"),
                        "config", "--format", "json",
                    ], env=self.env, text=True, capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    model = json.loads(result.stdout)
                    services = model["services"]
                    for service in ("admin-bootstrap", "gateway"):
                        self.assertEqual(services[service]["environment"]["OPENWAF_ACME_DNS_RESOLVER"],
                                         "1.1.1.1:53" if managed else "[2606:4700:4700::1111]:53")
                    self.assertFalse(model.get("volumes"), "Unexpected Docker-managed persistent volume")
                    state_names = set(yaml.safe_load((self.automation / "files/storage-directories.yml").read_text()))
                    state_sources = set()
                    self.assertEqual(services["postgres"]["scale"], int(managed))
                    self.assertEqual(model["networks"]["backends"].get("external", False), not managed)
                    self.assertEqual(services["collector"]["group_add"], ["1234"])
                    self.assertEqual(services["collector"]["network_mode"], "host")
                    self.assertEqual(services["gateway"]["ports"][0]["published"], "443")
                    self.assertEqual(services["startup-init"]["environment"]["OPENWAF_VPS_PROFILE"], profile)
                    sizing = self.sizing.profile(profile)
                    self.assertEqual(services["startup-init"]["environment"]["OPENWAF_VPS_PROFILE_SHA256"],
                                     self.sizing.fingerprint(sizing))
                    for name, service in services.items():
                        expected = sizing["limits"][name]
                        self.assertEqual(int(service["mem_limit"]), expected["memory_mib"] * self.sizing.MIB)
                        self.assertEqual(int(service["memswap_limit"]), int(service["mem_limit"]))
                        self.assertEqual(float(service["cpus"]), expected["cpus"])
                        self.assertEqual(service["pids_limit"], expected["pids"])
                        for mount in service.get("volumes", []):
                            self.assertEqual(mount["type"], "bind")
                            if mount["source"].startswith(self.settings["openwaf_data_dir"] + "/"):
                                self.assertFalse(mount["bind"]["create_host_path"])
                                state_sources.add(Path(mount["source"]).name)
                        sockets = [v for v in service.get("volumes", []) if v["target"] == "/run/docker-engine.sock"]
                        self.assertEqual(bool(sockets), name == "collector")
                        if name != "gateway":
                            self.assertFalse(service.get("ports"), name)
                    self.assertEqual(state_sources, state_names)
                    geoip = services["gateway"]["environment"].get("OPENWAF_GEOIP_DB")
                    self.assertEqual(geoip, None if managed else "/etc/openwaf-geoip/GeoLite2-Country.mmdb")

    def test_runtime_fingerprint_tracks_success_retry_and_secret_rotation(self):
        # Run the actual transfer tasks against a local temporary directory,
        # retaining the invoking user's ownership instead of requiring sudo.
        runtime = (self.automation / "tasks/runtime.yml").read_text()
        runtime = runtime.replace("owner: root", "owner: '" + str(os.getuid()) + "'")
        runtime = runtime.replace("group: root", "group: '" + str(os.getgid()) + "'")
        local_runtime = self.automation / "tasks/test-runtime.yml"
        local_runtime.write_text(runtime)
        report = self.case / "runtime-result.json"
        tasks = [
            {"ansible.builtin.import_tasks": "tasks/test-runtime.yml"},
            {"ansible.builtin.copy": {"dest": str(report), "mode": "0600", "content":
                '{{ {"recreate": openwaf_recreate, "fingerprint": openwaf_release_fingerprint} | to_json }}'}},
        ]
        self.run_tasks(tasks)
        first = json.loads(report.read_text())
        self.assertTrue(first["recreate"])
        envfile = Path(self.settings["openwaf_install_dir"]) / ".env"
        copied_token = Path(self.settings["openwaf_secrets_dir"]) / "cloudflare-token"
        self.assertEqual(copied_token.stat().st_mode & 0o777, 0o600)
        self.assertEqual(envfile.stat().st_mode & 0o777, 0o600)
        # No success marker: retry must still recreate, even when copy is unchanged.
        self.run_tasks(tasks)
        self.assertTrue(json.loads(report.read_text())["recreate"])
        marker = envfile.parent / ".ansible-applied"
        marker.write_text(first["fingerprint"])
        marker.chmod(0o600)
        self.run_tasks(tasks)
        self.assertFalse(json.loads(report.read_text())["recreate"])
        self.token.write_text(secrets.token_hex(32))
        self.run_tasks(tasks)
        rotated = json.loads(report.read_text())
        self.assertTrue(rotated["recreate"])
        self.assertNotEqual(rotated["fingerprint"], first["fingerprint"])
        self.assertEqual(marker.read_text(), first["fingerprint"], "Unapplied release overwrote success marker")

    def storage_tasks(self):
        # Fake only read-only Docker metadata calls. Directory and identity
        # operations run through the actual Ansible storage tasks.
        bin_dir = self.case / "bin"
        bin_dir.mkdir(exist_ok=True)
        docker = bin_dir / "docker"
        docker.write_text("#!" + sys.executable + "\n" + '''import os, sys
args = sys.argv[1:]
assert args[:1] == ['--host']
args = args[2:]
if args[:2] == ['volume', 'ls']:
    print(os.environ.get('FAKE_VOLUMES', ''))
elif args[:1] == ['ps'] and '--all' in args:
    print(os.environ.get('FAKE_GATEWAY', ''))
elif args[:1] == ['ps']:
    print(os.environ.get('FAKE_RUNNING', ''))
elif args[:2] == ['volume', 'inspect']:
    name = args[-1]
    volumes = os.environ.get('FAKE_VOLUMES', '').splitlines()
    if name not in volumes:
        raise SystemExit(1)
    print(name)
elif args[:1] == ['inspect']:
    print(os.environ['FAKE_MOUNTS'])
else:
    raise SystemExit('Unexpected Docker call in storage preflight')
''')
        docker.chmod(0o755)
        source = (self.automation / "tasks/storage.yml").read_text()
        source = source.replace("owner: root", "owner: '" + str(os.getuid()) + "'")
        source = source.replace("group: root", "group: '" + str(os.getgid()) + "'")
        (self.automation / "tasks/test-storage.yml").write_text(source)
        return [{"ansible.builtin.import_tasks": "tasks/test-storage.yml"}], {
            "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
        }

    def test_existing_named_volume_mode_renders_external_volumes_for_all_state(self):
        envfile = self.case / "named.env"
        shutil.copytree(self.automation / "files/profiles", self.case / "profiles")
        self.run_tasks([{"ansible.builtin.template": {
            "src": "vps.env.j2", "dest": str(envfile), "mode": "0600"}},
            {"ansible.builtin.template": {
                "src": "compose.yaml.j2", "dest": str(self.case / "compose.yaml"), "mode": "0644"}}],
            overrides={"openwaf_storage_mode": "existing_volumes",
                       "openwaf_existing_volume_names": {"gateway-config": "oldstack_gateway-config"}})
        result = subprocess.run([
            "docker", "compose", "--env-file", str(envfile), "-f", str(self.case / "compose.yaml"),
            "config", "--format", "json",
        ], env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        model = json.loads(result.stdout)
        state_names = set(yaml.safe_load((self.automation / "files/storage-directories.yml").read_text()))
        self.assertEqual(set(model["volumes"]), state_names)
        self.assertTrue(all(volume.get("external") for volume in model["volumes"].values()))
        self.assertEqual(model["volumes"]["gateway-config"]["name"], "oldstack_gateway-config")
        for service in model["services"].values():
            for mount in service.get("volumes", []):
                if mount["target"] in ("/run/docker-engine.sock", "/etc/openwaf-geoip"):
                    continue
                if mount["type"] == "volume":
                    self.assertIn(mount["source"], state_names)
                elif mount["source"].startswith(self.settings["openwaf_data_dir"] + "/"):
                    self.fail(f"persistent state unexpectedly bind mounted: {mount}")
        self.assertEqual(model["services"]["gateway"]["volumes"][0]["type"], "volume")

    def test_named_volume_mode_rejects_missing_volume_before_storage_writes(self):
        tasks, environment = self.storage_tasks()
        environment.update(FAKE_VOLUMES="", FAKE_GATEWAY="")
        self.run_tasks(tasks, overrides={"openwaf_storage_mode": "existing_volumes"},
                       environment=environment, success=False)
        self.assertFalse(Path(self.settings["openwaf_data_dir"]).exists())

    def test_storage_mode_is_part_of_identity(self):
        tasks, environment = self.storage_tasks()
        self.run_tasks(tasks, environment=environment)
        marker = Path(self.settings["openwaf_install_dir"]) / ".ansible-storage.json"
        self.assertEqual(set(json.loads(marker.read_text())), {"schema_version", "project_name", "data_dir"})
        names = " ".join("openwaf-vps_" + name for name in
                         yaml.safe_load((self.automation / "files/storage-directories.yml").read_text()))
        environment["FAKE_VOLUMES"] = names
        self.run_tasks(tasks, overrides={"openwaf_storage_mode": "existing_volumes"},
                       environment=environment, success=False)
        self.assertTrue(Path(self.settings["openwaf_data_dir"]).exists())

    def test_existing_volume_names_are_verified_and_storage_is_not_created(self):
        tasks, environment = self.storage_tasks()
        logical = yaml.safe_load((self.automation / "files/storage-directories.yml").read_text())
        names = ["oldstack_" + name for name in logical]
        environment["FAKE_VOLUMES"] = "\n".join(names)
        mapping = {name: "oldstack_" + name for name in logical}
        self.run_tasks(tasks, overrides={"openwaf_storage_mode": "existing_volumes",
                                        "openwaf_existing_volume_names": mapping}, environment=environment)
        marker = Path(self.settings["openwaf_install_dir"]) / ".ansible-storage.json"
        saved = json.loads(marker.read_text())
        self.assertEqual(saved["storage_mode"], "existing_volumes")
        self.assertEqual(saved["existing_volume_names"], mapping)
        self.assertFalse(Path(self.settings["openwaf_data_dir"]).exists())

    def test_recovery_requires_no_running_project_containers(self):
        tasks, environment = self.storage_tasks()
        self.run_tasks(tasks, environment=environment)
        logical = yaml.safe_load((self.automation / "files/storage-directories.yml").read_text())
        environment["FAKE_VOLUMES"] = "\n".join("openwaf-vps_" + name for name in logical)
        environment["FAKE_RUNNING"] = "still-running"
        self.run_tasks(tasks, overrides={"openwaf_storage_mode": "existing_volumes",
                                         "openwaf_storage_recovery": True},
                       environment=environment, success=False)
        environment["FAKE_RUNNING"] = ""
        self.run_tasks(tasks, overrides={"openwaf_storage_mode": "existing_volumes",
                                         "openwaf_storage_recovery": True},
                       environment=environment)
        marker = Path(self.settings["openwaf_install_dir"]) / ".ansible-storage.json"
        self.assertEqual(json.loads(marker.read_text())["storage_mode"], "existing_volumes")
        self.assertTrue(Path(self.settings["openwaf_data_dir"]).exists(), "Bind state was modified")

    def test_old_named_volumes_do_not_block_fresh_bind_mount_storage(self):
        tasks, environment = self.storage_tasks()
        environment["FAKE_VOLUMES"] = "openwaf-vps_gateway-config"
        self.run_tasks(tasks, environment=environment)
        root = Path(self.settings["openwaf_data_dir"])
        self.assertTrue((root / "gateway-config").is_dir())
        self.assertTrue((root / "postgres-data18").is_dir())
        marker = Path(self.settings["openwaf_install_dir"]) / ".ansible-storage.json"
        self.assertEqual(json.loads(marker.read_text())["data_dir"], str(root))
        self.assertEqual(set(json.loads(marker.read_text())), {"schema_version", "project_name", "data_dir"})

    def test_storage_identity_preserves_permissions_and_rejects_missing_or_changed_state(self):
        tasks, environment = self.storage_tasks()
        self.run_tasks(tasks, environment=environment)
        root = Path(self.settings["openwaf_data_dir"])
        state = root / "gateway-config"
        state.chmod(0o750)  # Simulate permissions installed by runtime ownership setup.
        self.run_tasks(tasks, environment=environment)
        self.assertEqual(state.stat().st_mode & 0o777, 0o750)
        other = str(self.case / "other-data")
        self.run_tasks(tasks, overrides={"openwaf_data_dir": other}, environment=environment, success=False)
        self.assertFalse(Path(other).exists())
        self.run_tasks(tasks, overrides={"openwaf_project_name": "other-project"},
                       environment=environment, success=False)
        (root / "certificate-key").rmdir()
        self.run_tasks(tasks, environment=environment, success=False)
        self.assertFalse((root / "certificate-key").exists(), "Missing initialized state was silently recreated")

    def test_auto_settings_reach_the_environment_with_inventory_defaults(self):
        envfile = self.case / "detected.env"
        self.run_tasks([{"ansible.builtin.template": {
            "src": "vps.env.j2", "dest": str(envfile), "mode": "0600"}}],
            overrides={"openwaf_origin_ipv4": "auto"},
            facts_override={"processor_vcpus": 6, "memtotal_mb": 16000,
                            "default_ipv4": {"address": "93.184.215.14"}})
        rendered = envfile.read_text()
        self.assertIn("OPENWAF_VPS_PROFILE=4c8g\n", rendered)
        self.assertIn("OPENWAF_ORIGIN_IPV4=93.184.215.14\n", rendered)
        self.assertIn("OPENWAF_POSTGRES_CREATE=1\n", rendered)
        self.run_tasks(check=True, overrides={"openwaf_vps_profile": "8c16g"},
                       facts_override={"processor_vcpus": 4, "memtotal_mb": 8192}, success=False)

    def test_database_url_selects_existing_postgres_without_a_separate_flag(self):
        database = self.private / "database-url"
        database.write_text("postgresql://fixture:" + secrets.token_hex(32) + "@db.example.test/openwaf")
        database.chmod(0o600)
        self.run_tasks([{"ansible.builtin.assert": {"that": [
            "not openwaf_detected.postgres_create",
            "openwaf_private_files | length == 2",
        ]}}], overrides={"openwaf_database_url_file": str(database)}, check=True)

    def test_existing_docker_on_other_linux_never_enters_package_tasks(self):
        binary = self.case / "bin"
        binary.mkdir()
        fake = binary / "docker"
        fake.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
args = sys.argv[1:]
if args == ['--version']:
    if os.environ.get('FAKE_DOCKER_VERSION_FAILURE'):
        raise SystemExit(2)
    print('Docker version 29.8.2')
elif args[:2] == ['compose', 'version']:
    print('v5.5.1')
elif 'info' in args:
    print(json.dumps({'OSType': 'linux', 'SecurityOptions': ['name=seccomp'], 'DockerRootDir': '/var/lib/docker'}))
else:
    raise SystemExit('Unexpected Docker mutation/probe')
''')
        fake.chmod(0o700)
        sock = socket.socket(socket.AF_UNIX)
        # macOS limits sockaddr_un paths to 104 bytes; keep the fixture short.
        with tempfile.TemporaryDirectory(prefix="ow-sock-") as directory:
            path = str(Path(directory) / "docker.sock")
            try:
                sock.bind(path)
                alias = Path(directory) / "alias.sock"
                alias.symlink_to(path)
                tasks = [{"ansible.builtin.import_tasks": "tasks/docker.yml"}]
                for check in (True, False):
                    self.run_tasks([] if check else tasks, check=check,
                                   overrides={"openwaf_docker_socket": str(alias), "openwaf_install_docker": False},
                                   facts_override={"distribution": "Fedora", "os_family": "RedHat"},
                                   docker_detection=True,
                                   environment={"PATH": str(binary) + os.pathsep + self.env["PATH"]})
                self.run_tasks(check=True, success=False, docker_detection=True,
                               overrides={"openwaf_docker_socket": str(alias)},
                               environment={"PATH": str(binary) + os.pathsep + self.env["PATH"],
                                            "FAKE_DOCKER_VERSION_FAILURE": "1"})
            finally:
                sock.close()

    def test_docker_plans_missing_dependencies_and_refuses_unsafe_replacement(self):
        baseline = {
            "openwaf_docker_cli": {"rc": 0},
            "openwaf_socket": {"stat": {"exists": True, "issock": True}},
            "openwaf_engine": {"rc": 0, "stdout": json.dumps({"OSType": "linux", "SecurityOptions": []})},
            "openwaf_compose_version": {"rc": 0, "stdout": "2.22.0"},
            "openwaf_official_engine": {"rc": 0, "stdout": "install ok installed"},
            "openwaf_compose_package": {"rc": 1},
            "openwaf_curl": {"rc": 0}, "openwaf_ca_bundle": {"stat": {"exists": True}},
        }
        absent = {"openwaf_docker_cli": {"rc": 2}, "openwaf_socket": {"stat": {"exists": False}},
                  "openwaf_compose_version": {"rc": 1}}
        cases = [
            (absent, {}, True, (True, True)),
            ({"openwaf_compose_version": {"rc": 1}}, {}, True, (False, True)),
            ({"openwaf_compose_version": {"rc": 1}, "openwaf_official_engine": {"rc": 1}}, {}, False, None),
            ({"openwaf_compose_version": {"rc": 1}, "openwaf_compose_package": {"rc": 0, "stdout": "install ok installed"}}, {}, False, None),
            (absent, {"openwaf_install_docker": False}, False, None),
            ({"openwaf_engine": {"rc": 1}}, {}, False, None),
            ({"openwaf_socket": {"stat": {"exists": False}}}, {}, False, None),
            ({"openwaf_compose_version": {"rc": 0, "stdout": "2.21.0"}}, {}, False, None),
            ({"openwaf_engine": {"rc": 0, "stdout": json.dumps({"OSType": "linux", "SecurityOptions": ['name=rootless']})}}, {}, False, None),
        ]
        for probes, settings, success, expected in cases:
            with self.subTest(probes=probes, settings=settings):
                tasks = [{"ansible.builtin.set_fact": dict(baseline, **probes)},
                         {"ansible.builtin.import_tasks": "tasks/docker-plan.yml"}]
                if expected:
                    tasks.append({"ansible.builtin.assert": {"that": [
                        f"openwaf_need_engine == {expected[0]}", f"openwaf_need_compose == {expected[1]}",
                    ]}})
                self.run_tasks(tasks, overrides=settings, check=True, success=success)

    def test_existing_gateway_prevents_state_path_change_even_without_storage_marker(self):
        tasks, environment = self.storage_tasks()
        environment.update(FAKE_GATEWAY="fixture-container", FAKE_MOUNTS=json.dumps([
            {"Destination": "/etc/openwaf", "Type": "bind", "Source": "/original/state/gateway-config"},
        ]))
        self.run_tasks(tasks, environment=environment, success=False)
        self.assertFalse(Path(self.settings["openwaf_install_dir"]).exists())

    def test_symlinked_data_root_is_rejected_before_writes(self):
        tasks, environment = self.storage_tasks()
        real = self.case / "elsewhere"
        real.mkdir()
        Path(self.settings["openwaf_data_dir"]).symlink_to(real, target_is_directory=True)
        self.run_tasks(tasks, environment=environment, success=False)
        self.assertEqual(list(real.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
