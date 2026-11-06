"""Render test models from the maintained Ansible templates, never legacy YAML.

All credentials here are temporary fixtures. This module only renders models;
callers select offline/test services before starting containers. LinuxState
provides isolated POSIX storage in the Engine for Linux and Docker Desktop.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

import yaml


ROOT = Path(__file__).resolve().parents[4]
AUTOMATION = ROOT / "deploy/ansible"


class FixtureError(RuntimeError):
    """A local fixture could not be prepared; captured output stays private."""


def render_stack(root, settings):
    """Return Compose's normalized model using actual templates and profiles."""
    root = Path(root).resolve()
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    shutil.copytree(AUTOMATION / "files/profiles", root / "profiles", dirs_exist_ok=True)
    for name in ("postgres-start.sh", "pgbouncer.ini"):
        shutil.copyfile(AUTOMATION / "files" / name, root / name)
    (root / "geoip").mkdir(exist_ok=True)
    private = root / "private"
    private.mkdir(mode=0o700, exist_ok=True)
    (private / "cloudflare-token").write_text(secrets.token_hex(32))
    (private / "database-url").write_text(
        "postgresql://fixture:" + secrets.token_hex(32) + "@db.example.test:5432/openwaf?sslmode=verify-full")
    for path in private.iterdir():
        path.chmod(0o600)
    variables = yaml.safe_load((AUTOMATION / "defaults.yml").read_text())
    variables.update({
        "openwaf_project_name": "openwaf-fixture-" + secrets.token_hex(4),
        "openwaf_install_dir": str(root), "openwaf_secrets_dir": str(private),
        "openwaf_data_dir": str(root / "data"),
        "openwaf_vps_profile": "2c4g", "openwaf_admin_host": "admin.example.com", "openwaf_origin_ipv4": "1.1.1.1",
        "openwaf_acme_accept_terms": True, "openwaf_socket": {"stat": {"gid": 0}},
    })
    variables.update(settings)
    # These render-only harnesses specify fixture capacity/origins explicitly;
    # real host detection is exercised by the automation regression suite.
    variables["openwaf_detected"] = {
        "profile": variables["openwaf_vps_profile"], "ipv4": variables["openwaf_origin_ipv4"],
        "ipv6": "", "postgres_create": (not variables["openwaf_database_url_file"]
            if variables["openwaf_postgres_create"] == "auto" else variables["openwaf_postgres_create"]),
    }
    tasks = [{"ansible.builtin.template": {
        "src": str(AUTOMATION / "templates" / source), "dest": str(root / target), "mode": mode,
    }, "diff": False} for source, target, mode in (
        ("compose.yaml.j2", "compose.yaml", "0644"), ("vps.env.j2", ".env", "0600"))]
    playbook = root / "render.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "become": False, "vars": variables, "tasks": tasks,
    }]))
    playbook.chmod(0o600)
    ansible = Path(sys.executable).with_name("ansible-playbook")
    executable = str(ansible) if ansible.is_file() else shutil.which("ansible-playbook")
    if not executable:
        raise FixtureError("Install the Ansible controller requirements before running integration harnesses")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENWAF_")}
    environment["ANSIBLE_CONFIG"] = str(AUTOMATION / "ansible.cfg")
    result = subprocess.run([executable, "-i", "localhost,", str(playbook),
                             "-e", "ansible_python_interpreter=" + sys.executable],
                            env=environment, capture_output=True, timeout=60)
    if result.returncode:
        raise FixtureError("Ansible fixture rendering failed; captured output suppressed")
    result = subprocess.run(["docker", "compose", "--env-file", str(root / ".env"),
                             "-f", str(root / "compose.yaml"), "config", "--format", "json"],
                            env=environment, capture_output=True, timeout=30)
    if result.returncode:
        raise FixtureError("Compose fixture validation failed; check the selected profile/settings")
    return json.loads(result.stdout)


class LinuxState:
    """A test-only Engine volume backing bind sources with Linux ownership.

    This is not an application named volume or a production migration. The
    application model still uses bind mounts to individual state directories.
    Callers must stop their containers before exiting this context.
    """

    def __init__(self, image, project):
        self.image = image
        self.volume = project + "-fixture-" + secrets.token_hex(4)
        self.path = None

    def __enter__(self):
        created = False
        try:
            subprocess.run(["docker", "volume", "create", self.volume], check=True,
                           capture_output=True, timeout=30)
            created = True
            self.path = subprocess.check_output([
                "docker", "volume", "inspect", "--format", "{{.Mountpoint}}", self.volume,
            ], text=True, timeout=30).strip()
            names = yaml.safe_load((AUTOMATION / "files/storage-directories.yml").read_text())
            code = "import os\nfor name in " + repr(names) + ": os.mkdir('/state/' + name, 0o700)"
            subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "0:0",
                            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                            "-v", self.volume + ":/state", "--entrypoint", "python3", self.image, "-c", code],
                           check=True, capture_output=True, timeout=30)
            return self
        except (subprocess.SubprocessError, OSError) as error:
            if created:
                subprocess.run(["docker", "volume", "rm", self.volume], check=True,
                               capture_output=True, timeout=30)
            raise FixtureError("Could not prepare isolated Linux state storage") from error

    def __exit__(self, exc_type, exc_value, traceback):
        subprocess.run(["docker", "volume", "rm", self.volume], check=True,
                       capture_output=True, timeout=30)
