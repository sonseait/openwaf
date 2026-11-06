"""Image routing checks alongside actual Compose render regressions."""
from pathlib import Path
import re
import unittest


class ImageSplitTests(unittest.TestCase):
    def test_services_render_with_explicit_init_and_runtime_images(self):
        template = (Path(__file__).parents[1] / 'templates/compose.yaml.j2').read_text()
        services = dict(re.findall(r'^  ([a-z-]+):\n(.*?)(?=^  [a-z-]+:|^secrets:|\Z)', template, re.M | re.S))
        for service in ('startup-init', 'dependencies-init', 'crowdsec-seal'):
            self.assertIn('OPENWAF_INIT_IMAGE', services[service])
        for service in ('gateway', 'collector', 'admin-bootstrap', 'bootstrap-provider'):
            self.assertIn('OPENWAF_IMAGE', services[service])
            self.assertNotIn('OPENWAF_INIT_IMAGE', services[service])

    def test_init_image_is_required_and_validated(self):
        root = Path(__file__).parents[1]
        self.assertIn('openwaf_init_image: ""', (root / 'defaults.yml').read_text())
        validation = (root / 'tasks/validate.yml').read_text()
        self.assertIn('openwaf_init_image is match', validation)
        self.assertIn('openwaf_init_image is search', validation)


if __name__ == '__main__':
    unittest.main()
