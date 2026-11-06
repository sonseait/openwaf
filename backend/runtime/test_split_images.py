"""Built-image contract checks; opt-in with OPENWAF_TEST_SPLIT_IMAGES=1."""
import io
import os
import subprocess
import tarfile
import unittest


def docker(*args):
    return subprocess.check_output(['docker', *args], timeout=60)


@unittest.skipUnless(os.environ.get('OPENWAF_TEST_SPLIT_IMAGES') == '1', 'requires built split-test images')
class SplitImages(unittest.TestCase):
    def test_release_labels_match_and_roles_are_explicit(self):
        releases = []
        for role in ('init', 'gateway'):
            image = 'openwaf-' + role + ':split-test'
            self.assertEqual(docker('image', 'inspect', '--format',
                                    '{{index .Config.Labels "io.openwaf.role"}}', image).decode().strip(), role)
            releases.append(docker('image', 'inspect', '--format',
                                   '{{index .Config.Labels "org.opencontainers.image.version"}}', image).strip())
        self.assertTrue(releases[0])
        self.assertEqual(releases[0], releases[1])

    def files(self, image):
        container = docker('create', image).decode().strip()
        try:
            with tarfile.open(fileobj=io.BytesIO(docker('export', container))) as archive:
                return {member.name.lstrip('./') for member in archive}
        finally:
            docker('rm', container)

    def test_gateway_has_native_payload_without_interpreters(self):
        files = self.files('openwaf-gateway:split-test')
        for binary in ('gateway', 'admin', 'acme', 'discovery', 'security'):
            self.assertIn('usr/local/bin/openwaf-' + binary, files)
        for path in ('usr/share/openwaf/admin/index.html', 'usr/share/openwaf/modsecurity.conf',
                     'etc/modsecurity/crs/crs-setup.conf', 'etc/ssl/certs/ca-certificates.crt'):
            self.assertIn(path, files)
        for path in ('bin/sh', 'usr/bin/sh', 'usr/bin/apt', 'usr/bin/dpkg',
                     'usr/local/bin/openwaf-startup-init', 'defaults'):
            self.assertNotIn(path, files)
        self.assertFalse(any(path.startswith(('usr/bin/python', 'usr/local/bin/python')) for path in files))
        user = docker('image', 'inspect', '--format', '{{.Config.User}}',
                      'openwaf-gateway:split-test').decode().strip()
        self.assertEqual(user, '10001:10001')

    def test_init_has_initializer_and_required_native_helpers_without_ui(self):
        files = self.files('openwaf-init:split-test')
        self.assertIn('usr/local/bin/openwaf-startup-init', files)
        self.assertIn('defaults/resource-budgets.json', files)
        for helper in ('gateway', 'acme', 'security'):
            self.assertIn('usr/local/bin/openwaf-' + helper, files)
        self.assertNotIn('usr/share/openwaf/admin/index.html', files)
        self.assertEqual(docker('run', '--rm', '--network', 'none', '--entrypoint', 'python3',
                                'openwaf-init:split-test', '-c', 'print("init-python-ok")').strip(),
                         b'init-python-ok')


if __name__ == '__main__':
    unittest.main()
