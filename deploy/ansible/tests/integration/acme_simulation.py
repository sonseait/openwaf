"""Local real ACME (Pebble) + Postman Cloudflare + authoritative TXT fixture.
Called by dns-simulation.py --acme; all trust roots and credentials are temporary.
"""
import http.client
import json
import os
from pathlib import Path
import secrets
import socketserver
import ssl
import struct
import subprocess
import threading
import time
import urllib.request


def run(repo, root, mock_port, env):
    def mock(path):
        connection = http.client.HTTPConnection("127.0.0.1", mock_port, timeout=5)
        connection.request("GET", "/cloudflare/client/v4/" + path)
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        assert response.status == 200
        return result["result"]

    mock("__control/v2-ok")
    fixture = root / "acme"
    fixture.mkdir(mode=0o700)
    dns_queries = []
    hold_txt = [False]

    class DNS(socketserver.BaseRequestHandler):
        def handle(self):
            packet, sock = self.request
            index = 12
            labels = []
            while packet[index]:
                length = packet[index]
                index += 1
                labels.append(packet[index:index + length].decode("ascii"))
                index += length
            index += 1
            kind, klass = struct.unpack("!HH", packet[index:index + 4])
            end = index + 4
            name = ".".join(labels)
            answers = []
            if kind == 16 and not hold_txt[0]:
                for row in mock("__txt"):
                    if row["name"] == name:
                        value = row["content"].strip('"').encode()
                        answers.append(b"\xc0\x0c" + struct.pack("!HHIH", 16, klass, 0, len(value) + 1) + bytes([len(value)]) + value)
            dns_queries.append((name, kind, len(answers)))
            header = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, len(answers), 0, 0)
            sock.sendto(header + packet[12:end] + b"".join(answers), self.client_address)

    dns = socketserver.ThreadingUDPServer(("0.0.0.0", 0), DNS)
    dns_thread = threading.Thread(target=dns.serve_forever, daemon=True)
    dns_thread.start()
    container = "openwaf-pebble-" + secrets.token_hex(5)
    image = os.environ.get("OPENWAF_PEBBLE_IMAGE", "ghcr.io/letsencrypt/pebble:2.8.0")
    try:
        subprocess.run(["docker", "run", "-d", "--name", container, "-p", "127.0.0.1::14000",
                        "-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0",
                        image, "-config", "/test/config/pebble-config.json", "-dnsserver",
                        f"host.docker.internal:{dns.server_address[1]}"], check=True, capture_output=True)
        subprocess.run(["docker", "cp", f"{container}:/test/certs/pebble.minica.pem", str(fixture / "ca.pem")], check=True, capture_output=True)
        mapping = subprocess.check_output(["docker", "port", container, "14000/tcp"], text=True).strip()
        port = int(mapping.rsplit(":", 1)[1])
        context = ssl.create_default_context(cafile=str(fixture / "ca.pem"))
        directory = f"https://localhost:{port}/dir"
        end = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen(directory, context=context, timeout=2):
                    break
            except OSError:
                if time.monotonic() >= end:
                    raise RuntimeError("Pebble startup deadline")
                time.sleep(0.2)
        binary = repo / "backend/target/debug/openwaf-acme"
        subprocess.run(["cargo", "build", "--manifest-path", str(repo / "backend/Cargo.toml"), "-p", "openwaf-acme",
                        "--features", "integration-test-provider"], check=True, env=env, timeout=180)
        key = fixture / "master.key"
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        token = fixture / "token"
        token.write_text(secrets.token_hex(24))
        token.chmod(0o600)
        (fixture / "providers").mkdir(mode=0o700)
        encrypted = fixture / "providers/credential.enc"
        subprocess.run([str(binary), "seal-cloudflare-token", str(token), str(encrypted), str(key)], check=True, env=env, capture_output=True)
        state = fixture / "state"
        state.mkdir(mode=0o700)
        config = {"directory_url": directory, "hostname": "example.com", "additional_dns_names": ["*.example.com"],
                  "state_dir": str(state), "master_key_file": str(key), "tls_manifest": str(fixture / "tls/manifest.json"),
                  "ca_pem": str(fixture / "ca.pem"), "terms_of_service_agreed": True, "deadline_seconds": 180,
                  "cloudflare": {"zone_id": "a" * 32, "zone_name": "example.com", "token_file": str(encrypted),
                                 "resolver": f"127.0.0.1:{dns.server_address[1]}", "propagation_seconds": 15,
                                 "test_api": {"base_url": env["OPENWAF_TEST_CLOUDFLARE_API"], "ca_pem": env["OPENWAF_TEST_CLOUDFLARE_CA"]}}}
        path = fixture / "config.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        for operation in ("renew-once", "renew-once", "issue"):
            before = Path(config["tls_manifest"]).read_bytes() if Path(config["tls_manifest"]).exists() else None
            result = subprocess.run([str(binary)] + ([] if operation == "issue" else [operation]) + [str(path)],
                                    env=env, text=True, capture_output=True, timeout=210)
            if result.returncode:
                # Native worker redacts credentials/TXT; keep provider mock logs separate.
                raise RuntimeError("Local ACME failed: " + result.stderr[-3000:])
            manifest = json.loads(Path(config["tls_manifest"]).read_bytes())
            assert len(manifest["certificates"]) == 2
            assert {item["hostname"] for item in manifest["certificates"]} == {"example.com", "*.example.com"}
            assert manifest["certificates"][0]["cert_chain"] == manifest["certificates"][1]["cert_chain"]
            cert = fixture / "tls" / manifest["certificates"][0]["cert_chain"]
            san = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-noout", "-text"], text=True)
            assert "DNS:example.com" in san and "DNS:*.example.com" in san
            assert not mock("__txt") and not (state / "dns-lease.enc").exists()
            if operation == "renew-once" and before is not None:
                assert before == Path(config["tls_manifest"]).read_bytes(), "restart outside renewal window must not issue"
        assert any(name == "_acme-challenge.example.com" and count == 2 for name, kind, count in dns_queries)
        assert (state / "account.enc").exists()
        # Cancellation during propagation must finish owned cleanup, without publishing.
        hold_txt[0] = True
        config["hostname"] = "cancel.example.com"
        config["additional_dns_names"] = []
        config["state_dir"] = str(fixture / "cancel-state")
        config["tls_manifest"] = str(fixture / "cancel-tls/manifest.json")
        path.write_text(json.dumps(config))
        cancelled = subprocess.Popen([str(binary), str(path)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            end = time.monotonic() + 20
            while not mock("__txt"):
                if cancelled.poll() is not None or time.monotonic() > end:
                    raise RuntimeError("Cancellation fixture did not reach TXT propagation")
                time.sleep(0.1)
            cancelled.terminate()
            _, error = cancelled.communicate(timeout=25)
            assert cancelled.returncode != 0 and not mock("__txt")
            assert not Path(config["tls_manifest"]).exists()
            assert not (Path(config["state_dir"]) / "dns-lease.enc").exists()
        finally:
            if cancelled.poll() is None:
                cancelled.kill()
                cancelled.wait(timeout=5)
        print("PASS local Pebble ACME: actual two-SAN order/CSR/cert, shared TXT owner, cleanup, restart skip, renewal with saved account and cancellation cleanup")
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        dns.shutdown()
        dns.server_close()
        dns_thread.join(timeout=5)
