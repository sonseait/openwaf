"""Disposable real Prometheus: authenticated scrape, range query, restart persistence."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]

def run(*args):
    return subprocess.check_output(['docker', *args], text=True, timeout=90).strip()

def main():
    name = 'openwaf-prom-smoke-' + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix=name, dir=os.environ.get('TMPDIR')) as directory:
        root = Path(directory)
        (root / 'token').write_text(secrets.token_hex(32))
        (root / 'prometheus.yml').write_text((ROOT / 'files/prometheus.yml').read_text())
        (root / 'server.py').write_text('''import http.server,pathlib
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self):
  if self.headers.get('Authorization') != 'Bearer '+pathlib.Path('/etc/openwaf-metrics/token').read_text():
   self.send_response(401); self.end_headers(); return
  self.send_response(200); self.send_header('Content-Type','text/plain; version=0.0.4'); self.end_headers()
  self.wfile.write(b'# TYPE openwaf_incoming_total counter\\nopenwaf_incoming_total 42\\n')
http.server.HTTPServer(('127.0.0.1',9090),Handler).serve_forever()
''')
        try:
            run('volume','create',name+'-data')
            run('run','--rm','--user','0:0','-v',name+'-data:/prometheus','--entrypoint','python3','openwaf-init:anti-abuse-local-check','-c','import os; os.chown("/prometheus",10001,10001); os.chmod("/prometheus",0o700)')
            run('run','-d','--name',name,'-p','127.0.0.1::9091','-v',f'{root}:/etc/openwaf-metrics:ro','--entrypoint','python3','openwaf-init:anti-abuse-local-check','/etc/openwaf-metrics/server.py')
            base = 'http://' + run('port',name,'9091/tcp')
            args = ['run','-d','--name',name+'-prom','--network','container:'+name,
                    '--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                    '--memory','256m','--cpus','0.5','--pids-limit','128',
                    '-v',name+'-data:/prometheus:nocopy',
                    '-v',f'{root}:/etc/openwaf-metrics:ro',
                    'prom/prometheus:v3.15.1-distroless',
                    '--config.file=/etc/openwaf-metrics/prometheus.yml','--storage.tsdb.path=/prometheus',
                    '--storage.tsdb.retention.time=7d','--storage.tsdb.retention.size=1GB',
                    '--web.listen-address=0.0.0.0:9091','--log.level=warn']
            run(*args)
            def query(path):
                with urllib.request.urlopen(base+path, timeout=3) as response:
                    return json.load(response)
            deadline=time.monotonic()+60
            while True:
                try:
                    data=query('/api/v1/query?query=openwaf_incoming_total')
                    if data['data']['result']: break
                except Exception:
                    pass
                if time.monotonic()>deadline:
                    print(run('logs',name+'-prom'))
                    raise AssertionError('authenticated scrape not ready')
                time.sleep(1)
            assert data['data']['result'][0]['value'][1]=='42'
            time.sleep(16)
            now=int(time.time())
            data=query(f'/api/v1/query_range?query=openwaf_incoming_total&start={now-60}&end={now}&step=15')
            assert data['status']=='success' and data['data']['resultType']=='matrix' and data['data']['result']

            # Prevent fresh scrapes so the next query proves WAL recovery.
            run('pause',name)
            run('restart',name+'-prom')
            deadline=time.monotonic()+30
            while True:
                try:
                    if query('/api/v1/query?query=openwaf_incoming_total')['data']['result']: break
                except Exception: pass
                if time.monotonic()>deadline: raise AssertionError('restart query failed')
                time.sleep(1)
            print('PASS real non-root/read-only Prometheus: bearer scrape, matrix query_range, restart data recovery')
        finally:
            subprocess.run(['docker','unpause',name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            for container in (name+'-prom', name):
                subprocess.run(['docker','rm','-f',container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            subprocess.run(['docker','volume','rm',name+'-data'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)

if __name__=='__main__': main()
