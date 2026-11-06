"""VPS metrics history dependency contract, without credentials."""
from pathlib import Path
import unittest
import yaml
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]

class PrometheusTests(unittest.TestCase):
    def test_private_bounded_service_and_gateway_configuration(self):
        env = Environment()
        env.filters['to_json'] = __import__('json').dumps
        stack = yaml.safe_load(env.from_string((ROOT / 'templates/compose.yaml.j2').read_text()).render(
            openwaf_project_name='test', openwaf_storage_mode='bind', openwaf_data_dir='/data',
            openwaf_install_dir='/opt/test', openwaf_docker_socket='/var/run/docker.sock'))
        service = stack['services']['prometheus']
        self.assertEqual(service['network_mode'], 'service:gateway')
        self.assertNotIn('ports', service)
        self.assertEqual(service['mem_limit'], '256m')
        self.assertIn('--web.listen-address=127.0.0.1:9091', service['command'])
        self.assertIn('--storage.tsdb.retention.time=7d', service['command'])
        self.assertIn('--storage.tsdb.retention.size=1GB', service['command'])
        gateway = stack['services']['gateway']['environment']
        self.assertEqual(gateway['OPENWAF_PROMETHEUS_URL'], 'http://127.0.0.1:9091/')
        self.assertEqual(gateway['OPENWAF_METRICS_TOKEN_FILE'], '/etc/openwaf-metrics/token')
        config = yaml.safe_load((ROOT / 'files/prometheus.yml').read_text())
        scrape = config['scrape_configs'][0]
        self.assertEqual(scrape['static_configs'][0]['targets'], ['127.0.0.1:9090'])
        self.assertEqual(scrape['authorization']['credentials_file'], '/etc/openwaf-metrics/token')

if __name__ == '__main__':
    unittest.main()
