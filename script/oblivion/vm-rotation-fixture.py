"""Lab-only operations for the real gateway rotation contract."""
import base64
from contextlib import closing
import http.client
import json
import os
import signal
import socket
import ssl
import subprocess
import threading
from pathlib import Path

rotation = None
result = None
held = []


def circuits():
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(5)
        peer.connect('/run/tor/control')
        reader = peer.makefile('rb')
        peer.sendall(('AUTHENTICATE ' + Path('/run/tor/control.authcookie').read_bytes().hex() + '\r\n').encode())
        assert reader.readline() == b'250 OK\r\n'
        peer.sendall(b'GETINFO circuit-status\r\n')
        header = reader.readline()
        lines = []
        if header.startswith(b'250-circuit-status='):
            value = header.removeprefix(b'250-circuit-status=').removesuffix(b'\r\n')
            if value:
                lines.append(value)
        else:
            assert header == b'250+circuit-status=\r\n', header
            while (line := reader.readline()) != b'.\r\n':
                assert line
                lines.append(line)
        assert reader.readline() == b'250 OK\r\n'
        exits = []
        for line in lines:
            fields = line.decode().split()
            if fields[1] == 'BUILT' and any(p in fields for p in ('PURPOSE=GENERAL', 'PURPOSE=CONFLUX_LINKED', 'PURPOSE=CONFLUX_UNLINKED')):
                hops = fields[2].split(',')
                if len(hops) >= 3:
                    exits.append(hops[-1].split('~')[0].split('=')[0].upper())
        return sorted(set(exits))


def call(role, operation, command):
    global rotation, result
    if role == 'gateway':
        if operation == 'rotation-circuits':
            return {'exits': circuits()}
        if operation in ('rotation-tor-pause', 'rotation-tor-resume'):
            pid = int(subprocess.check_output(['systemctl', 'show', 'oblivion-tor.service', '-p', 'MainPID', '--value']))
            assert pid > 1
            os.kill(pid, signal.SIGSTOP if operation.endswith('pause') else signal.SIGCONT)
            return {'ok': True}
        if operation == 'rotation-state':
            rules = json.loads(subprocess.check_output(['nft', '-j', 'list', 'ruleset']))['nftables']
            barrier = any(item.get('table', {}).get('name') == 'oblivion_rotation' for item in rules)
            drops = sum(part.get('counter', {}).get('packets', 0)
                for item in rules if item.get('rule', {}).get('table') == 'oblivion_rotation'
                for part in item['rule']['expr'])
            processes = [p.read_text().strip() for p in Path('/proc').glob('[0-9]*/comm')]
            return {'barrier': barrier, 'dropped_packets': drops,
                'data_processes': sum(p in ['oblivion-api', 'oblivion-egress', 'oblivion-tools', 'oblivion-web'] for p in processes),
                'rotation_processes': processes.count('oblivion-rotati')}
        raise AssertionError(operation)
    if operation == 'rotation-start':
        assert rotation is None or not rotation.is_alive()
        result = None
        def request():
            global result
            try:
                with closing(http.client.HTTPConnection('10.88.0.1', 8114, timeout=155)) as peer:
                    peer.request('POST', '/tor/rotate', headers={'Authorization': 'Bearer ' + command['token']})
                    response = peer.getresponse()
                    result = {'code': response.status, 'body': json.loads(response.read(1024))}
            except OSError as error:
                result = {'error': type(error).__name__}
        rotation = threading.Thread(target=request, daemon=True)
        rotation.start()
        return {'started': True}
    if operation == 'rotation-result':
        return {'done': result is not None, 'result': result}
    if operation == 'rotation-held-open':
        assert not held
        auth = base64.b64encode(('oblivion-tools:' + command['token']).encode()).decode()
        peer = socket.create_connection(('10.88.0.1', 8112), timeout=45)
        peer.sendall(('CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic ' + auth + '\r\n\r\n').encode())
        header = b''
        while not header.endswith(b'\r\n\r\n'):
            chunk = peer.recv(1)
            assert chunk
            header += chunk
        assert header.startswith(b'HTTP/1.1 200'), header
        peer = ssl.create_default_context().wrap_socket(peer, server_hostname='example.com')
        held.append(peer)
        # Accepted sockets on both other data services, before the barrier.
        for port in (8111, 8113):
            peer = socket.create_connection(('10.88.0.1', port), timeout=5)
            peer.sendall(b'POST / HTTP/1.1\r\n')
            held.append(peer)
        return {'open': len(held), 'verified_tls_tunnel': True}
    if operation == 'rotation-held-blocked':
        assert len(held) == 3
        for peer in held:
            peer.settimeout(.3)
            try:
                peer.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
                assert peer.recv(4096) == b'', 'application bytes delivered during rotation'
            except (TimeoutError, ConnectionError, ssl.SSLError):
                pass
            peer.close()
        held.clear()
        return {'old_connections_blocked': 3}
    if operation == 'rotation-probes':
        subprocess.run(['ip', 'route', 'replace', 'default', 'via', '10.88.0.1', 'dev', 'chat0'], check=True)
        denied = []
        for host, port in [('10.88.0.1', p) for p in (8111, 8112, 8113, 9050, 9051, 53)] + [('1.1.1.1', 443)]:
            with socket.socket() as peer:
                peer.settimeout(.1)
                assert peer.connect_ex((host, port)) != 0, (host, port)
                denied.append(port)
        for host in ('10.88.0.1', '1.1.1.1'):
            with socket.socket(type=socket.SOCK_DGRAM) as peer:
                peer.sendto(b'ROTATION_DENIED_UDP', (host, 53))
        return {'tcp_denied': len(denied), 'udp_attempts': 2}
    if operation == 'rotation-https':
        completed = subprocess.run(['curl', '--silent', '--show-error', '--fail', '--max-time', '60',
            '--proxy', 'http://10.88.0.1:8112', '--proxy-user', 'oblivion-tools:' + command['token'],
            'https://example.com/'], capture_output=True, timeout=65, env={'PATH': '/usr/bin:/bin'})
        assert completed.returncode == 0, completed.stderr.decode()
        assert b'Example Domain' in completed.stdout
        return {'https': True, 'certificate_verified': True}
    raise AssertionError(operation)
