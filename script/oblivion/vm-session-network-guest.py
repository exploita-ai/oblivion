#!/usr/bin/python3
"""Unprivileged guest probe for the real host grant and gateway network."""
import base64
import http.client
import hashlib
import json
import os
import select
import socket
import subprocess
import sys
import time
from pathlib import Path

assert os.getuid() == 1000
token = Path('/run/oblivion-api/token').read_text()
assert len(token) == 64 and all(c in '0123456789abcdef' for c in token)
assert Path('/run/oblivion-api/token').stat().st_mode & 0o777 == 0o640
assert ' /run tmpfs ' in Path('/proc/mounts').read_text()
assert not Path('/run/oblivion/general').exists()
assert not Path('/run/oblivion-gateway-vm').exists()


def request(bearer, body):
    client = http.client.HTTPConnection('10.88.0.1', 8111, timeout=20)
    client.request('POST', '/v1/chat/completions', json.dumps(body),
        {'Authorization': 'Bearer ' + bearer, 'Content-Type': 'application/json'})
    response = client.getresponse()
    code, payload = response.status, response.read().decode()
    client.close()
    return code, payload


def tools_request(bearer, target):
    client = http.client.HTTPConnection('10.88.0.1', 8112, timeout=20)
    auth = base64.b64encode(('oblivion-tools:' + bearer).encode()).decode()
    client.request('CONNECT', target, headers={'Host': target, 'Proxy-Authorization': 'Basic ' + auth})
    response = client.getresponse()
    code, payload = response.status, response.read()
    assert token.encode() not in payload
    client.close()
    return code


with Path('/usr/bin/oblivion').open('rb') as binary:
    print('OBLIVION_SESSION_CLIENT_SHA256 ' + hashlib.file_digest(binary, 'sha256').hexdigest(), flush=True)
print('OBLIVION_SESSION_READY', flush=True)
stream_child = None
stream_output = b''
for command in sys.stdin:
    command = command.strip()
    if command == 'probe':
        assert request('0' * 64, {})[0] == 401
        assert request(token, {})[0] == 400
        code, payload = request(token, {'model': 'abliterated-model', 'stream': True,
            'messages': [{'role': 'user', 'content': 'synthetic network probe'}]})
        assert code == 502 and 'provider_unavailable' in payload, (code, payload)
        for address in [('10.88.0.1', 9050), ('10.0.2.2', 80), ('1.1.1.1', 443)]:
            try:
                with socket.create_connection(address, timeout=1):
                    raise AssertionError('unexpected network path')
            except OSError:
                pass
        # This token exists only in this laboratory console socket, never the
        # outer log or a persisted file. The host uses it to test stale grants.
        print('TOKEN ' + token, flush=True)
        print('OBLIVION_SESSION_PROBED', flush=True)
    elif command == 'tools-denied':
        assert tools_request('0' * 64, 'denied.example.com:443') == 407
        assert tools_request(token, 'denied.example.com:443') == 403
        assert tools_request(token, 'unknown.example.com:443') == 403
        assert tools_request(token, '127.0.0.1:443') == 400
        print('OBLIVION_TOOLS_POLICY_ENFORCED', flush=True)
    elif command == 'tools-scoped-denied':
        assert tools_request(token, 'api.abliteration.ai:443') == 403
        assert tools_request(token, 'api.abliteration.ai:80') == 403
        print('OBLIVION_OTHER_POLICY_DENIED', flush=True)
    elif command == 'webtools':
        result = subprocess.run(['/usr/lib/oblivion/guest/conversation.sh', 'run', '--auto', '--format', 'json',
            'OBLIVION_WEB_TOOLS_REQUEST'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180,
            env={**os.environ, 'NODE_EXTRA_CA_CERTS': '/usr/lib/oblivion-stream-fixture/cert.pem',
                'HTTP_PROXY': 'http://127.0.0.1:1', 'https_proxy': 'http://127.0.0.1:1',
                'NO_PROXY': '*', 'no_proxy': '*'})
        assert token not in result.stdout + result.stderr
        # JSON-mode failures are emitted on stdout, so stderr alone hides the
        # cause. This laboratory contains only synthetic prompts and secrets.
        if result.returncode != 0:
            print('OBLIVION_WEBTOOLS_FAILED ' + json.dumps({'exit': result.returncode,
                'stdout': result.stdout[-6000:], 'stderr': result.stderr[-2000:]}), flush=True)
            raise AssertionError('compiled web tools failed')
        assert 'OBLIVION_WEB_TOOLS_VERIFIED' in result.stdout, result.stdout[-4000:]
        events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        fetches = {event['part']['state']['input']['url']: event['part']['state'] for event in events
            if event.get('part', {}).get('tool') == 'webfetch'}
        assert set(fetches) == {'http://api.abliteration.ai/tools', 'https://api.abliteration.ai/tools',
            'http://api.abliteration.ai/redirect', 'https://unknown.example.com/tools',
            'https://api.abliteration.ai:4443/tools'}
        for url in ['http://api.abliteration.ai/redirect', 'https://unknown.example.com/tools',
                'https://api.abliteration.ai:4443/tools']:
            assert fetches[url]['status'] == 'error', url
            assert fetches[url]['error'] == f'Transport error (GET {url})', url
        for scheme in ['http', 'https']:
            state = fetches[f'{scheme}://api.abliteration.ai/tools']
            assert state['status'] == 'completed'
            assert state['output'] == f'OBLIVION_WEB_{scheme.upper()}\n'
        print('OBLIVION_COMPILED_WEBTOOLS_VERIFIED', flush=True)
    elif command.startswith('old '):
        assert request(command[4:], {})[0] == 401
        assert request(token, {})[0] == 400
        print('OBLIVION_OLD_TOKEN_DENIED', flush=True)
    elif command == 'revoked':
        try:
            request(token, {})
            raise AssertionError('broker survived revocation')
        except OSError:
            pass
        with socket.socket() as proxy:
            proxy.settimeout(1)
            assert proxy.connect_ex(('10.88.0.1', 8112)) != 0
        print('OBLIVION_SESSION_REVOKED', flush=True)
    elif command == 'stream':
        assert stream_child is None
        stream_child = subprocess.Popen(['/usr/lib/oblivion/guest/conversation.sh', 'run', '--format', 'json',
            'OBLIVION_STREAM_REQUEST'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stream_output = b''
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if not select.select([stream_child.stdout], [], [], 1)[0]:
                continue
            chunk = os.read(stream_child.stdout.fileno(), 65536)
            assert chunk, 'adapter exited before stream start'
            stream_output += chunk
            assert len(stream_output) <= 1024 * 1024 and token.encode() not in stream_output
            if any(json.loads(line).get('type') == 'step_start' for line in stream_output.split(b'\n')[:-1] if line):
                break
        else:
            raise AssertionError('adapter stream deadline')
        print('OBLIVION_STREAM_STARTED', flush=True)
    elif command == 'stream-ended':
        assert stream_child is not None
        output, errors = stream_child.communicate(timeout=60)
        stream_output += output
        assert token.encode() not in stream_output + errors
        events = [json.loads(line) for line in stream_output.splitlines() if line]
        assert any(event.get('type') == 'error' for event in events)
        stream_child = None
        print('OBLIVION_STREAM_FAILED', flush=True)
    elif command == 'adapter':
        result = subprocess.run(['/usr/lib/oblivion/guest/conversation.sh', 'run', '--format', 'json',
            'Synthetic adapter connectivity check'], stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=150)
        output = result.stdout + result.stderr
        assert 'provider_unavailable' in output, output[-4000:].replace(token, '<local-token>')
        assert 'request_denied' not in output and 'invalid_session' not in output
        assert token not in output
        for path in Path('/vault').rglob('*'):
            if path.is_file():
                assert path.suffix not in {'.log', '.heapsnapshot', '.cpuprofile'}, str(path)
                with path.open('rb') as stream:
                    tail = b''
                    while chunk := stream.read(1024 * 1024):
                        assert token.encode() not in tail + chunk, str(path)
                        tail = chunk[-64:]
        print('OBLIVION_ADAPTER_AUTHENTICATED', flush=True)
    else:
        raise AssertionError('unknown probe operation')
