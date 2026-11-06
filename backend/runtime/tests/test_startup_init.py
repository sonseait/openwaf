import contextlib
import errno
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).parents[1]))
SPEC = importlib.util.spec_from_file_location("startup_init", Path(__file__).parents[1] / "startup-init.py")
init = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(init)


class StartupInitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.token = self.root / "token"
        self.token.write_bytes(os.urandom(24).hex().encode())
        self.token.chmod(0o600)
        defaults = self.root / "defaults"
        defaults.mkdir()
        (defaults / "resource-budgets.json").write_bytes((Path(__file__).parents[1] / "resource-budgets.json").read_bytes())
        for name in ("clickhouse.xml", "crowdsec.json", "crowdsec-bootstrap.sh"):
            (defaults / name).write_bytes((Path(__file__).parents[1] / name).read_bytes())
        self.env = {"OPENWAF_ADMIN_HOST": "admin.example.com", "OPENWAF_ORIGIN_IPV4": "1.1.1.1",
                    "OPENWAF_ACME_ACCEPT_TERMS": "true", "OPENWAF_CLOUDFLARE_API_TOKEN_FILE": str(self.token)}
        for name, value in [("BASE", self.root / "volumes"), ("DEFAULTS", defaults)]:
            patcher = patch.object(init, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for patcher in [patch.dict(os.environ, self.env, clear=True), patch.object(init.os, "chown"),
                        patch.object(init.os, "fchown"), patch.object(init.subprocess, "run", self.seal)]:
            patcher.start()
            self.addCleanup(patcher.stop)

    def seal(self, args, **kwargs):
        if args == ["/usr/local/bin/openwaf-gateway", "check-resources"]:
            self.assertLessEqual(len(kwargs["input"]), 8192)
            json.loads(kwargs["input"])
            self.assertEqual(kwargs["timeout"], 30)
            return
        self.assertIn(args[1], ("seal-cloudflare-token", "seal-bootstrap-provider"))
        self.assertNotIn(self.token.read_text(), str(args) + str(kwargs))
        Path(args[3]).write_bytes(b"OWCF1" + os.urandom(64))
        Path(args[3]).chmod(0o600)

    def command(self, mode="dependencies"):
        error = io.StringIO()
        with patch.object(init.sys, "argv", ["openwaf-startup-init", mode]), contextlib.redirect_stderr(error):
            result = init.main()
        return result, error.getvalue()

    def test_missing_packaged_defaults_fail_before_creating_keys_with_actionable_error(self):
        (init.DEFAULTS / "crowdsec.json").unlink()
        code, message = self.command()
        self.assertEqual(code, 1)
        self.assertIn("/defaults/crowdsec.json", message)
        self.assertIn("rebuild/push the complete runtime image", message)
        self.assertFalse((init.BASE / "security-key/master.key").exists())

    def test_filesystem_errors_show_safe_context_without_native_exception_text(self):
        for number, expected in ((errno.EPERM, "EPERM"), (errno.EACCES, "EACCES"),
                                 (errno.ENOSPC, "ENOSPC"), (errno.EROFS, "EROFS")):
            with self.subTest(number=number), patch.object(init.os, "chown", side_effect=OSError(number, self.token.read_text(), self.token.read_text())):
                code, message = self.command()
                self.assertEqual(code, 1)
                self.assertIn(expected, message)
                self.assertIn("prepare directory /init/dependencies", message)
                self.assertNotIn(self.token.read_text(), message)

    def test_corrupt_metadata_error_does_not_print_json_contents(self):
        init.dependencies()
        (init.BASE / "dependencies/instance.json").write_text(self.token.read_text())
        code, message = self.command()
        self.assertEqual(code, 1)
        self.assertIn("read private file /init/dependencies/instance.json", message)
        self.assertIn("persisted JSON metadata is invalid", message)
        self.assertNotIn(self.token.read_text(), message)

    def test_diagnostic_target_does_not_echo_caller_controlled_path(self):
        self.assertEqual(init.target_label(self.root / self.token.read_text()), "private input")
        self.assertEqual(init.target_label(init.BASE / "dependencies" / self.token.read_text()), "/init/dependencies")
        self.assertEqual(init.target_label(init.DEFAULTS / "clickhouse.xml"), "/defaults/clickhouse.xml")

    def test_lock_contention_has_explicit_error_and_does_not_initialize(self):
        with patch.object(init.fcntl, "flock", side_effect=BlockingIOError(errno.EAGAIN, self.token.read_text())):
            code, message = self.command()
        self.assertEqual(code, 1)
        self.assertIn("another initializer holds the volume lock", message)
        self.assertNotIn(self.token.read_text(), message)
        self.assertFalse((init.BASE / "security-key/master.key").exists())

    def test_restart_keeps_keys_and_database_password_without_admin_password(self):
        init.run()
        files = [init.BASE / path for path in ("gateway/master.key", "gateway/database-password",
                                               "acme-key/master.key")]
        before = [init.read(path) for path in files]
        init.run()
        self.assertEqual(before, [init.read(path) for path in files])
        for path in files:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.token.read_bytes(), (init.BASE / "gateway/gateway.env").read_bytes())
        self.assertIn(b"NOSUPERUSER", (init.BASE / "db-init/10-openwaf.sql").read_bytes())
        self.assertFalse((init.BASE / "admin-access").exists())
        self.assertNotIn(b"INITIAL_PASSWORD", (init.BASE / "gateway/gateway.env").read_bytes())
        self.assertNotIn("initial_password", json.loads(init.read(init.BASE / "gateway/instance.json"))["secret_hashes"])

    def legacy_resource_budgets(self):
        init.run()
        path = init.BASE / "gateway/resource-budgets.json"
        original = (Path(__file__).parents[2] / "resource-budgets.example.json").read_bytes()
        path.write_bytes(original)
        return path, original

    def test_resource_upgrade_is_private_idempotent_and_keeps_instance_state(self):
        path, original = self.legacy_resource_budgets()
        files = [init.BASE / name for name in ("gateway/master.key", "gateway/database-password",
                                               "acme-key/master.key", "gateway/gateway.env",
                                               "gateway/instance.json", "bootstrap-provider/credential.enc")]
        before = [init.read(p) for p in files]
        init.run()
        backup = path.with_name(path.name + ".previous")
        self.assertEqual(json.loads(init.read(path)), init.selected_profile()["budgets"])
        self.assertEqual(init.read(backup), original)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        inode = path.stat().st_ino
        init.run()
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(init.read(backup), original)
        self.assertEqual([init.read(p) for p in files], before)

    def test_resource_upgrade_never_overwrites_custom_limits_or_reservations(self):
        path, original = self.legacy_resource_budgets()
        for change in ({"waf_workers": 4}, {"reserved_routes": [{"route": "checkout", "class": "critical", "slots": 8}]}):
            with self.subTest(change=change):
                path.write_text(json.dumps(json.loads(original) | change))
                before = init.read(path)
                with self.assertRaisesRegex(init.InitError, "resource budgets are customized"):
                    init.run()
                self.assertEqual(init.read(path), before)
                self.assertFalse(path.with_name(path.name + ".previous").exists())

    def test_resource_validation_failure_leaves_profiles_and_keys_untouched(self):
        path, original = self.legacy_resource_budgets()
        key = init.read(init.BASE / "gateway/master.key")
        errors = [init.subprocess.CalledProcessError(1, "check-resources"),
                  init.subprocess.TimeoutExpired("check-resources", 30)]
        for error in errors:
            with self.subTest(error=type(error).__name__), patch.object(init.subprocess, "run", side_effect=error):
                with self.assertRaisesRegex(init.InitError, "failed gateway check-resources"):
                    init.run()
            self.assertEqual(init.read(path), original)
            self.assertEqual(init.read(init.BASE / "gateway/master.key"), key)
            self.assertFalse(path.with_name(path.name + ".previous").exists())

    def test_resource_publish_failure_can_retry_without_partial_document(self):
        path, original = self.legacy_resource_budgets()
        replace = init.os.replace

        def fail_budget(source, target):
            if Path(target) == path:
                raise OSError(errno.ENOSPC, "fixture disk full")
            return replace(source, target)

        with patch.object(init.os, "replace", side_effect=fail_budget), self.assertRaises(OSError):
            init.run()
        self.assertEqual(init.read(path), original)
        self.assertEqual(init.read(path.with_name(path.name + ".previous")), original)
        self.assertEqual(list(path.parent.glob(".budgets-*")), [])
        init.run()
        self.assertEqual(json.loads(init.read(path)), init.selected_profile()["budgets"])

    def test_resource_upgrade_rejects_symlink_or_conflicting_prior_copy(self):
        path, original = self.legacy_resource_budgets()
        backup = path.with_name(path.name + ".previous")
        backup.symlink_to(self.token)
        with self.assertRaises(OSError):
            init.run()
        self.assertEqual(init.read(path), original)
        backup.unlink()
        init.write(backup, "{}")
        with self.assertRaisesRegex(init.InitError, "explicit migration required"):
            init.run()
        self.assertEqual(init.read(path), original)

    def test_profile_selection_rejects_unknown_name_or_mismatched_image_before_keys(self):
        for values in ({"OPENWAF_VPS_PROFILE": "../homelab"},
                       {"OPENWAF_VPS_PROFILE": "4c8g", "OPENWAF_VPS_PROFILE_SHA256": "old-release"}):
            with self.subTest(values=values), patch.dict(os.environ, values), self.assertRaises(init.InitError):
                init.run()
            self.assertFalse((init.BASE / "gateway/master.key").exists())

    def test_profile_upsize_and_downsize_keep_credentials_and_latest_prior_copy(self):
        init.run()
        key = init.read(init.BASE / "gateway/master.key")
        path = init.BASE / "gateway/resource-budgets.json"
        for name in ("16c64g", "8c32g", "2c4g"):
            before = init.read(path)
            with patch.dict(os.environ, {"OPENWAF_VPS_PROFILE": name}):
                init.run()
                self.assertEqual(json.loads(init.read(path)), init.selected_profile()["budgets"])
            self.assertEqual(init.read(path.with_name(path.name + ".previous")), before)
            self.assertEqual(init.read(init.BASE / "gateway/master.key"), key)

    def test_clickhouse_sizing_migrates_only_managed_configs_and_keeps_keys(self):
        init.dependencies()
        key = init.read(init.BASE / "security-key/master.key")
        path = init.BASE / "dependencies/clickhouse.xml"
        # Recognize the pre-profile configuration already stored in VPS volumes.
        path.write_bytes(init.default_file("clickhouse.xml"))
        for name in ("16c64g", "2c4g"):
            before = init.read(path)
            with patch.dict(os.environ, {"OPENWAF_VPS_PROFILE": name}):
                init.dependencies()
                xml = init.ET.fromstring(init.read(path))
                self.assertEqual(int(xml.findtext("max_server_memory_usage")), init.selected_profile()["clickhouse"]["server_memory_bytes"])
            self.assertEqual(init.read(path.with_name(path.name + ".previous")), before)
            self.assertEqual(init.read(init.BASE / "security-key/master.key"), key)
        path.write_bytes(init.read(path).replace(b"<max_threads>1</max_threads>", b"<max_threads>17</max_threads>"))
        before = init.read(path)
        with self.assertRaisesRegex(init.InitError, "ClickHouse configuration is customized"):
            init.dependencies()
        self.assertEqual(init.read(path), before)

    def legacy_admin_password_setting(self):
        init.run()
        env = init.BASE / "gateway/gateway.env"
        expected = init.read(env)
        legacy = b"OPENWAF_ADMIN_INITIAL_PASSWORD_FILE=/run/openwaf-admin/initial-password\n"
        env.write_bytes(expected + legacy)
        marker = init.BASE / "gateway/instance.json"
        descriptor = json.loads(init.read(marker))
        descriptor["secret_hashes"]["initial_password"] = "retired"
        marker.write_text(json.dumps(descriptor))
        return env, expected

    def test_upgrade_retires_password_setting_without_requiring_or_generating_password(self):
        env, expected = self.legacy_admin_password_setting()
        key = init.read(init.BASE / "gateway/master.key")
        init.run()
        init.run()
        self.assertEqual(init.read(env), expected)
        self.assertEqual(init.read(init.BASE / "gateway/master.key"), key)
        self.assertFalse((init.BASE / "admin-access").exists())

    def test_upgrade_preserves_retired_password_file(self):
        self.legacy_admin_password_setting()
        init.directory(init.BASE / "admin-access")
        password = init.BASE / "admin-access/initial-password"
        init.write(password, os.urandom(24).hex())
        original = init.read(password)
        init.run()
        self.assertEqual(init.read(password), original)

    def test_upgrade_rejects_unrelated_gateway_configuration_changes(self):
        env, _ = self.legacy_admin_password_setting()
        env.write_bytes(init.read(env).replace(b"OPENWAF_WAF_MODE=DetectionOnly", b"OPENWAF_WAF_MODE=Off"))
        before = init.read(env)
        with self.assertRaisesRegex(init.InitError, "explicit migration required"):
            init.run()
        self.assertEqual(init.read(env), before)

    def test_provider_handoff_is_private_one_time_and_independent_from_token_rotation(self):
        init.run()
        path = init.BASE / "bootstrap-provider/credential.enc"
        original = init.read(path, 2081)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.token.read_bytes(), original)
        self.token.write_bytes(os.urandom(24).hex().encode())
        init.run()
        self.assertEqual(init.read(path, 2081), original)

    def test_missing_or_changed_keys_fail_without_replacement(self):
        init.run()
        key = init.BASE / "acme-key/master.key"
        key.unlink()
        with self.assertRaises(init.InitError):
            init.run()
        self.assertFalse(key.exists())
        init.write(key, os.urandom(32))
        with self.assertRaises(init.InitError):
            init.run()

    def test_hostname_or_origin_change_never_rewrites_instance(self):
        init.run()
        before = init.read(init.BASE / "gateway/gateway.env")
        with patch.dict(os.environ, {"OPENWAF_ADMIN_HOST": "different.example.com"}):
            with self.assertRaises(init.InitError):
                init.run()
        self.assertEqual(before, init.read(init.BASE / "gateway/gateway.env"))

    def test_token_rotation_only_replaces_encrypted_credential(self):
        init.run()
        before = init.read(init.BASE / "acme-key/master.key")
        envelope = init.read(init.BASE / "bootstrap/providers/cloudflare.enc")
        self.token.write_bytes(os.urandom(24).hex().encode())
        init.run()
        self.assertEqual(before, init.read(init.BASE / "acme-key/master.key"))
        self.assertNotEqual(envelope, init.read(init.BASE / "bootstrap/providers/cloudflare.enc"))

    def test_private_files_reject_symlinks_permissions_and_oversize(self):
        self.token.chmod(0o644)
        with self.assertRaises(init.InitError):
            init.read(self.token)
        self.token.chmod(0o600)
        with self.assertRaises(init.InitError):
            init.read(self.token, 4)
        link = self.root / "link"
        link.symlink_to(self.token)
        with self.assertRaises(OSError):
            init.read(link)

    def test_invalid_inputs_cannot_start(self):
        for values in ({"OPENWAF_ACME_ACCEPT_TERMS": "false"}, {"OPENWAF_ADMIN_HOST": "*.example.com"},
                       {"OPENWAF_ADMIN_HOST": "https://example.com"}, {"OPENWAF_ORIGIN_IPV4": "127.0.0.1"},
                       {"OPENWAF_ORIGIN_IPV4": ""}, {"OPENWAF_ORIGIN_IPV4": "::1"}):
            with self.subTest(values=values), self.assertRaises((init.InitError, ValueError)):
                init.inputs(self.env | values)

    def test_dependencies_are_additive_and_preserve_credentials(self):
        init.run()
        before = init.read(init.BASE / "gateway/gateway.env")
        init.dependencies()
        master = init.read(init.BASE / "security-key/master.key")
        init.dependencies()
        self.assertEqual(init.read(init.BASE / "security-key/master.key"), master)
        self.assertEqual(init.read(init.BASE / "gateway/gateway.env"), before)
        config = json.loads(init.read(init.BASE / "dependencies/crowdsec.json"))
        self.assertEqual(config["lapi_url"], "http://127.0.0.1:8085")
        self.assertIn("/security/", config["checkpoint_file"])
        self.assertEqual((init.BASE / "security-key").stat().st_mode & 0o777, 0o700)

    def test_certificate_runtime_keeps_key_and_is_separate_from_bootstrap(self):
        init.run()
        init.dependencies()
        key = init.BASE / "certificate-key/master.key"
        before = init.read(key)
        self.assertNotEqual(before, init.read(init.BASE / "acme-key/master.key"))
        init.dependencies()
        self.assertEqual(init.read(key), before)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual((init.BASE / "certificate-requests").stat().st_mode & 0o777, 0o700)

    def test_certificate_runtime_rejects_missing_or_changed_key(self):
        init.dependencies()
        key = init.BASE / "certificate-key/master.key"
        key.unlink()
        with self.assertRaisesRegex(init.InitError, "certificate master key missing"):
            init.dependencies()
        self.assertFalse(key.exists())
        init.write(key, os.urandom(32))
        with self.assertRaisesRegex(init.InitError, "certificate master key changed"):
            init.dependencies()

    def test_certificate_runtime_rejects_loss_of_both_key_and_state_volumes(self):
        init.dependencies()
        (init.BASE / "certificate-key/master.key").unlink()
        (init.BASE / "certificate-key").rmdir()
        (init.BASE / "certificate-requests").rmdir()
        with self.assertRaisesRegex(init.InitError, "certificate master key missing"):
            init.dependencies()
        self.assertFalse((init.BASE / "certificate-key/master.key").exists())

    def test_certificate_runtime_does_not_invent_key_for_existing_request_state(self):
        init.directory(init.BASE / "certificate-requests")
        init.write(init.BASE / "certificate-requests/request.json", "{}")
        with self.assertRaisesRegex(init.InitError, "certificate master key missing"):
            init.dependencies()
        self.assertFalse((init.BASE / "certificate-key/master.key").exists())

    def test_dependencies_reject_lost_or_changed_master_key(self):
        init.dependencies()
        key = init.BASE / "security-key/master.key"
        key.unlink()
        with self.assertRaisesRegex(init.InitError, "missing"):
            init.dependencies()
        self.assertFalse(key.exists())
        init.write(key, os.urandom(32))
        with self.assertRaisesRegex(init.InitError, "changed"):
            init.dependencies()

    def test_sealed_crowdsec_credential_restart_and_recovery_guards(self):
        init.dependencies()
        raw = init.BASE / "crowdsec-config/bouncer.key"
        init.write(raw, os.urandom(32).hex())

        def native_seal(args, **kwargs):
            self.assertEqual(args[1], "seal-crowdsec-key")
            self.assertNotIn(init.read(raw).decode(), str(args) + str(kwargs))
            init.write(Path(args[3]), b"OWCS1" + os.urandom(96))

        with patch.object(init.subprocess, "run", native_seal):
            init.seal_crowdsec()
            output = init.BASE / "dependencies/crowdsec.enc"
            envelope = init.read(output)
            init.seal_crowdsec()
            self.assertEqual(init.read(output), envelope)
            raw.write_text(os.urandom(32).hex())
            with self.assertRaisesRegex(init.InitError, "credential changed"):
                init.seal_crowdsec()
            self.assertEqual(init.read(output), envelope)

    def test_crowdsec_missing_envelope_never_silently_replaces_credentials(self):
        init.dependencies()
        init.write(init.BASE / "crowdsec-config/bouncer.key", os.urandom(32).hex())
        def native_seal(args, **_kwargs):
            init.write(Path(args[3]), b"OWCS1" + os.urandom(96))
        with patch.object(init.subprocess, "run", native_seal):
            init.seal_crowdsec()
            output = init.BASE / "dependencies/crowdsec.enc"
            output.unlink()
            with self.assertRaisesRegex(init.InitError, "envelope missing"):
                init.seal_crowdsec()
            self.assertFalse(output.exists())

    def existing_database(self, url="postgres://openwaf:private@db.example.com:5432/openwaf"):
        source = self.root / "database-url"
        source.write_text(url)
        source.chmod(0o600)
        os.environ.update(OPENWAF_POSTGRES_CREATE="0", OPENWAF_DATABASE_URL_FILE=str(source))
        return source

    def test_external_network_updates_discovery_and_uses_runtime_interface_inventory(self):
        os.environ.update(OPENWAF_DOCKER_NETWORK_EXTERNAL="true", OPENWAF_DOCKER_NETWORK_NAME="existing-stack_default")
        init.run()
        values = dict(line.split("=", 1) for line in (init.BASE / "gateway/gateway.env").read_text().splitlines())
        self.assertEqual(values["OPENWAF_GATEWAY_DOCKER_NETWORKS"], "existing-stack_default")
        self.assertEqual(values["OPENWAF_DISCOVER_LOCAL_IPS"], "true")
        self.assertEqual(values["OPENWAF_LOCAL_IPS"], "127.0.0.1,::1,1.1.1.1")
        before = init.read(init.BASE / "gateway/gateway.env")
        init.run()
        self.assertEqual(before, init.read(init.BASE / "gateway/gateway.env"))
        with patch.dict(os.environ, {"OPENWAF_DOCKER_NETWORK_NAME": "another-stack"}):
            with self.assertRaisesRegex(init.InitError, "Docker network changed"):
                init.run()
        self.assertEqual(before, init.read(init.BASE / "gateway/gateway.env"))

    def test_network_configuration_rejects_unsafe_or_ambiguous_names(self):
        for name in ("host", "bridge", "none", "a,b", "my network", "a\nINJECTED=1", "${OTHER}", "-bad", "a" * 129):
            with self.subTest(name=name), self.assertRaises(init.InitError):
                init.network_inputs({"OPENWAF_DOCKER_NETWORK_NAME": name})
        with self.assertRaises(init.InitError):
            init.network_inputs({"OPENWAF_DOCKER_NETWORK_EXTERNAL": "yes"})

    def test_existing_database_never_creates_database_credentials_or_init_sql(self):
        self.existing_database()
        init.run()
        self.assertFalse((init.BASE / "gateway/database-password").exists())
        self.assertFalse((init.BASE / "db-secret/password").exists())
        self.assertEqual(list((init.BASE / "db-init").iterdir()), [])
        before = init.read(init.BASE / "gateway/gateway.env")
        self.assertIn(b"sslmode=verify-full", before)
        key = init.read(init.BASE / "gateway/master.key")
        init.run()
        self.assertEqual(before, init.read(init.BASE / "gateway/gateway.env"))
        self.assertEqual(key, init.read(init.BASE / "gateway/master.key"))

    def test_database_mode_url_and_engine_changes_never_retarget_instance(self):
        source = self.existing_database()
        init.run()
        before = init.read(init.BASE / "gateway/gateway.env")
        source.write_text("postgres://openwaf:different@db.example.com:5432/openwaf")
        with self.assertRaises(init.InitError):
            init.run()
        with patch.dict(os.environ, {"OPENWAF_POSTGRES_CREATE": "1", "OPENWAF_DATABASE_URL_FILE": ""}):
            with self.assertRaises(init.InitError):
                init.run()
        self.assertEqual(before, init.read(init.BASE / "gateway/gateway.env"))

    def test_legacy_postgres_marker_requires_explicit_migration(self):
        init.run()
        marker = init.BASE / "gateway/instance.json"
        value = json.loads(marker.read_text())
        del value["database"]
        marker.write_text(json.dumps(value))
        before = init.read(init.BASE / "gateway/gateway.env")
        with self.assertRaisesRegex(init.InitError, "legacy PostgreSQL 17"):
            init.run()
        self.assertEqual(before, init.read(init.BASE / "gateway/gateway.env"))

    def test_existing_database_defaults_to_verified_tls_and_encodes_dotenv_metacharacters(self):
        self.existing_database("postgres://openwaf:pa$s'word@db.example.com:5432/openwaf")
        _, url, _ = init.database_inputs(os.environ)
        parsed = urlsplit(url)
        self.assertEqual(unquote(parsed.password), "pa$s'word")
        self.assertNotIn("$", url)
        self.assertNotIn("'", url)
        self.assertEqual(parse_qs(parsed.query)["sslmode"], ["verify-full"])

    def test_existing_database_accepts_explicit_private_plaintext_and_custom_ca(self):
        source = self.existing_database("postgres://openwaf:private@db.example.com:5432/openwaf?sslmode=disable")
        _, url, ca = init.database_inputs(os.environ)
        self.assertIn("sslmode=disable", url)
        self.assertIsNone(ca)
        cert = self.root / "database-ca"
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n")
        cert.chmod(0o600)
        source.write_text("postgres://openwaf:private@db.example.com:5432/openwaf")
        with patch.dict(os.environ, {"OPENWAF_DATABASE_CA_FILE": str(cert)}):
            init.run()
            self.assertEqual(init.read(init.BASE / "gateway/database-ca.crt"), cert.read_bytes())

    def test_database_options_reject_ambiguous_unsafe_or_missing_inputs(self):
        with patch.dict(os.environ, {"OPENWAF_POSTGRES_CREATE": "invalid"}):
            with self.assertRaises(init.InitError):
                init.database_inputs(os.environ)
        with patch.dict(os.environ, {"OPENWAF_POSTGRES_CREATE": "0"}):
            with self.assertRaises(init.InitError):
                init.database_inputs(os.environ)
        source = self.existing_database()
        with patch.dict(os.environ, {"OPENWAF_POSTGRES_CREATE": "1"}):
            with self.assertRaises(init.InitError):
                init.database_inputs(os.environ)
        for url in ("not-a-url", "postgres://u:p@localhost:5432/db", "postgres://u:p@127.0.0.1:5432/db",
                    "postgres://u:p@[::1]:5432/db", "postgres://u:p@db:0/db", "postgres://db:5432/db",
                    "postgres://u:p@db/db", "postgres://u:p@db:5432/db#fragment",
                    "postgres://u:p@db:5432/db?sslmode=require", "postgres://u:p@db:5432/db?sslmode=prefer",
                    "postgres://u:p@db:5432/db?sslmode=disable&sslmode=verify-full",
                    "postgres://u:p@db:5432/db?sslrootcert=/unmounted-ca"):
            source.write_text(url)
            with self.subTest(url=url), self.assertRaises(init.InitError):
                init.database_inputs(os.environ)


if __name__ == "__main__":
    unittest.main()
