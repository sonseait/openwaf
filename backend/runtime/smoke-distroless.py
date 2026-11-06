"""Exercise real CRS blocking and clean forwarding in a disposable Docker network."""
import json
import subprocess
import time
import uuid


def run(*args, check=True):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=60)
    if check and result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return (result.stdout + (result.stderr if not check else '')).strip()


def main():
    prefix = 'openwaf-split-' + uuid.uuid4().hex[:10]
    network, upstream, gateway = prefix, prefix + '-upstream', prefix + '-gateway'
    try:
        run('network', 'create', network)
        code = ('from http.server import HTTPServer,BaseHTTPRequestHandler\n'
                'class Handler(BaseHTTPRequestHandler):\n'
                ' def do_GET(self):\n'
                '  print("UPSTREAM_REQUEST", flush=True)\n'
                '  self.send_response(200); self.end_headers(); self.wfile.write(b"upstream-ok")\n'
                'HTTPServer(("0.0.0.0",8081),Handler).serve_forever()')
        run('run', '-d', '--name', upstream, '--network', network,
            '--entrypoint', 'python3', 'openwaf-init:split-test', '-u', '-c', code)
        ip = run('inspect', '--format', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', upstream)
        run('run', '-d', '--name', gateway, '--network', network, '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m,mode=1777',
            '-e', 'OPENWAF_ENV_FILE=/dev/null', '-e', 'OPENWAF_LISTEN=0.0.0.0:8080',
            '-e', 'OPENWAF_UPSTREAM=' + ip + ':8081', '-e', 'OPENWAF_WAF_MODE=On',
            'openwaf-gateway:split-test')
        probe = ('import urllib.request,urllib.error,time,json\n'
                 'for i in range(30):\n'
                 ' try:\n'
                 '  r=urllib.request.urlopen("http://' + gateway + ':8080/",timeout=2)\n'
                 '  assert r.status==200 and r.read()==b"upstream-ok"; break\n'
                 ' except OSError: time.sleep(1)\n'
                 'else: raise RuntimeError("gateway did not become ready")\n'
                 'try:\n'
                 ' urllib.request.urlopen("http://' + gateway + ':8080/?id=1%20OR%201%3D1%20--",timeout=3)\n'
                 ' raise RuntimeError("SQLi reached upstream")\n'
                 'except urllib.error.HTTPError as e: assert e.code==403,e.code\n'
                 'print("PASS clean forwarding and CRS SQLi 403")')
        print(run('run', '--rm', '--network', network, '--entrypoint', 'python3',
                  'openwaf-init:split-test', '-c', probe))
        logs = run('logs', upstream)
        assert logs.count('UPSTREAM_REQUEST') == 1, 'blocked request reached upstream'
        print('PASS blocked request did not reach upstream')
        started = time.monotonic()
        run('stop', '--time', '15', gateway)
        state = json.loads(run('inspect', '--format', '{{json .State}}', gateway))
        assert state['ExitCode'] == 0, state
        print('PASS gateway SIGTERM exit=0 in %.2fs' % (time.monotonic() - started))
    except Exception:
        print(run('logs', gateway, check=False))
        raise
    finally:
        run('rm', '-f', gateway, upstream, check=False)
        run('network', 'rm', network, check=False)


if __name__ == '__main__':
    main()
