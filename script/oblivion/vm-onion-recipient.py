#!/usr/bin/python3 -B
"""Disposable public Tor caller. Private keys never leave this container's RAM.

Used only by the explicit online host laboratory, not a product service. The
two independent Tor clients prove authorization against a reachable service;
curl gets URLs on stdin and daemon output is discarded. Only bounded metadata
and the recipient's public key go back over the private test channel.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import socket
import subprocess
import sys
import time
import zipfile

ROOT = Path('/run/onion-recipient')
PAYLOAD = b'OBLIVION_ONION_PUBLIC_APPROVED_9b72\n'
UNSELECTED = b'OBLIVION_ONION_PUBLIC_UNSELECTED_841c\n'


def pair():
    private = subprocess.check_output(['/usr/bin/openssl', 'genpkey', '-algorithm', 'X25519', '-outform', 'DER'],
                                      stderr=subprocess.DEVNULL)
    public = subprocess.check_output(['/usr/bin/openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
                                     input=private, stderr=subprocess.DEVNULL)
    assert private[:16] == bytes.fromhex('302e020100300506032b656e04220420') and len(private) == 48
    assert public[:12] == bytes.fromhex('302a300506032b656e032100') and len(public) == 44
    return private[16:], base64.b32encode(public[12:]).decode().rstrip('=')


class Tor:
    def __init__(self, index):
        self.root = ROOT / str(index)
        self.root.mkdir(mode=0o700)
        self.port = 9150 + index
        self.process = subprocess.Popen([
            '/usr/bin/tor', '-f', '/etc/oblivion-recipient.torrc', '--DataDirectory', str(self.root),
            '--ControlPort', 'unix:' + str(self.root/'control'), '--CookieAuthentication', '1',
            '--SocksPort', f'127.0.0.1:{self.port}', '--ClientOnly', '1', '--ClientUseIPv6', '0',
            '--ClientUseIPv4', '1', '--SafeLogging', '1', '--Log', 'err file /dev/null',
            '--AvoidDiskWrites', '1', '--RunAsDaemon', '0', '--DisableDebuggerAttachment', '1',
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={})

    def control(self, command):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(5)
            stream.connect(str(self.root/'control'))
            with stream.makefile('rb') as reader:
                cookie = (self.root/'control_auth_cookie').read_bytes()
                assert len(cookie) == 32, 'Invalid Tor cookie'
                stream.sendall(b'AUTHENTICATE ' + cookie.hex().encode() + b'\r\n')
                assert reader.readline(4096) == b'250 OK\r\n', 'Tor authentication failed'
                stream.sendall(command.encode() + b'\r\n')
                lines = []
                while len(lines) < 32:
                    line = reader.readline(4096)
                    assert len(line) < 4096 and line.endswith(b'\r\n'), 'Invalid Tor reply'
                    assert line[:3] in (b'250', b'251', b'252'), 'Tor command rejected'
                    lines.append(line)
                    if line[3:4] == b' ':
                        return b''.join(lines)
                raise AssertionError('Tor reply limit')

    def ready(self):
        assert self.process.poll() is None, 'Tor exited'
        if not (self.root/'control').exists() or not (self.root/'control_auth_cookie').exists():
            return False
        return b'PROGRESS=100 ' in self.control('GETINFO status/bootstrap-phase')

    def authorize(self, service, private):
        # No Permanent flag: Tor keeps these credentials in memory only.
        self.control('ONION_CLIENT_AUTH_ADD ' + service + ' x25519:' + base64.b64encode(private).decode())

    def request(self, url, upload=False, download=False, byte_range=None):
        options = [f'url = "{url}{"upload-ajax" if upload else ""}"',
                   f'socks5-hostname = "127.0.0.1:{self.port}"', 'noproxy = ""',
                   'silent', 'show-error', 'max-time = 40', 'connect-timeout = 30',
                   f'output = "{ROOT / "download" if download else "/dev/null"}"', 'write-out = "%{http_code}"']
        if download:
            options[0] = f'url = "{url}download"'
        if byte_range is not None:
            options += [f'range = "{byte_range}"', f'dump-header = "{ROOT}/headers"']
        if upload:
            options += [f'form = "file[]=@{ROOT}/selected.txt;filename=selected.txt"',
                        f'form = "file[]=@{ROOT}/unselected.txt;filename=unselected.txt"']
        result = subprocess.run(['/usr/bin/curl', '--config', '-'], input=('\n'.join(options)+'\n').encode(),
                                capture_output=True, timeout=45, env={})
        # Never propagate curl stderr: an error may contain the private URL.
        return result.returncode == 0 and result.stdout == (b'206' if byte_range is not None else b'200')

    def reachable(self, url):
        deadline = time.monotonic() + 180
        while not self.request(url):
            assert time.monotonic() < deadline, 'Onion service did not become reachable'
            time.sleep(2)

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    assert os.getuid() == 1000 and not list(ROOT.iterdir()), 'Unexpected recipient runtime'
    private, public = pair()
    clients = []
    url = None
    print(json.dumps({'ready': True, 'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      'tor_version': subprocess.check_output(['/usr/bin/tor', '--version'], text=True).splitlines()[0]}), flush=True)
    try:
        for line in sys.stdin.buffer:
            assert len(line) <= 4096, 'Recipient request limit'
            request = json.loads(line)
            if request == {'action': 'prepare'}:
                assert not clients, 'Recipient already prepared'
                clients = [Tor(0), Tor(1)]
                deadline = time.monotonic() + 180
                while not all(client.ready() for client in clients):
                    assert time.monotonic() < deadline, 'Recipient bootstrap deadline'
                    time.sleep(1)
                response = {'ok': True, 'public_key': public}
            elif set(request) == {'action', 'url'} and request['action'] == 'upload':
                assert clients and url is None, 'Recipient not prepared'
                match = re.fullmatch(r'http://([a-z2-7]{56})\.onion/', request['url'])
                assert match is not None, 'Invalid private address'
                url = request['url']
                clients[0].authorize(match[1], private)
                clients[0].reachable(url)
                assert not clients[1].request(url), 'Unauthenticated recipient reached private service'
                wrong, _ = pair()
                clients[1].authorize(match[1], wrong)
                assert not clients[1].request(url), 'Wrong recipient key reached private service'
                clients[1].authorize(match[1], private)
                clients[1].reachable(url)
                (ROOT/'selected.txt').write_bytes(PAYLOAD)
                (ROOT/'unselected.txt').write_bytes(UNSELECTED)
                assert clients[0].request(url, upload=True), 'Upload was not accepted'
                response = {'ok': True, 'unauthenticated_refused': True, 'wrong_key_refused': True,
                            'authorized_clients': 2, 'uploaded_files': 2, 'uploaded_bytes': len(PAYLOAD)+len(UNSELECTED)}
            elif request == {'action': 'revoked'}:
                assert url is not None, 'No published service'
                assert not clients[0].request(url), 'Revoked service is still reachable'
                response = {'ok': True, 'revoked': True}
            elif set(request) == {'action', 'url'} and request['action'] == 'download':
                assert clients and url is not None, 'Recipient not prepared'
                match = re.fullmatch(r'http://([a-z2-7]{56})\.onion/', request['url'])
                assert match is not None and request['url'] != url, 'Invalid or reused private address'
                url = request['url']
                clients[0].authorize(match[1], private)
                clients[0].reachable(url)
                assert not clients[1].request(url), 'Unauthenticated recipient reached private share'
                assert clients[0].request(url, download=True), 'Download was not accepted'
                path = ROOT/'download'
                if zipfile.is_zipfile(path):
                    with zipfile.ZipFile(path) as archive:
                        files = [entry for entry in archive.infolist() if not entry.is_dir()]
                        assert len(files) == 1 and files[0].filename.endswith('/selected.txt'), 'Unselected file was shared'
                        assert files[0].file_size == len(PAYLOAD), 'Unexpected download size'
                        content = archive.read(files[0])
                else:
                    content = path.read_bytes()
                assert content == PAYLOAD, 'Downloaded content changed'
                response = {'ok': True, 'unauthenticated_refused': True, 'selected_only': True,
                            'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
            elif set(request) == {'action', 'url', 'bytes', 'first_sha256', 'last_sha256', 'sha256'} and request['action'] == 'backup':
                match = re.fullmatch(r'http://([a-z2-7]{56})\.onion/', request['url'])
                assert match is not None and request['url'] != url, 'Invalid or reused backup address'
                assert request['bytes'] == 512 * 1024 ** 2, 'Unexpected backup size'
                url = request['url']
                clients[0].authorize(match[1], private)
                clients[0].reachable(url)
                assert not clients[1].request(url), 'Unauthenticated recipient reached backup'
                size = request['bytes']
                for start, end, expected in [(0, 1024**2-1, request['first_sha256']), (size-1024**2, size-1, request['last_sha256'])]:
                    assert re.fullmatch(r'[a-f0-9]{64}', expected), 'Invalid backup digest'
                    assert clients[0].request(url, download=True, byte_range=f'{start}-{end}'), 'Backup range was not served'
                    content = (ROOT/'download').read_bytes()
                    assert len(content) == 1024**2 and hashlib.sha256(content).hexdigest() == expected, 'Backup ciphertext changed'
                    headers = (ROOT/'headers').read_text().lower()
                    assert f'content-range: bytes {start}-{end}/{size}' in headers, 'Invalid backup range'
                    assert 'session.oblivion' in headers and 'content-encoding: gzip' not in headers, 'Backup must remain raw ciphertext'
                    if start == 0: assert content[:8] == b'LUKS\xba\xbe\0\x02', 'Backup lost its LUKS2 header'
                assert re.fullmatch(r'[a-f0-9]{64}', request['sha256']), 'Invalid full backup digest'
                digest = hashlib.sha256()
                length = 0
                attempts = []
                deadline = time.monotonic() + 3000
                while length < size:
                    remaining = int(deadline - time.monotonic())
                    assert remaining > 0 and len(attempts) < 8, 'Full backup download deadline'
                    offset = length
                    options = [f'url = "{url}download"', f'socks5-hostname = "127.0.0.1:{clients[0].port}"',
                               'noproxy = ""', 'silent', 'fail', f'max-time = {remaining}', 'connect-timeout = 30',
                               'output = "-"', f'dump-header = "{ROOT}/headers"']
                    if offset:
                        options += [f'range = "{offset}-"']
                    with subprocess.Popen(['/usr/bin/curl','--config','-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL, env={}) as download:
                        download.stdin.write(('\n'.join(options)+'\n').encode())
                        download.stdin.close()
                        while chunk := download.stdout.read(65536):
                            length += len(chunk)
                            assert length <= size, 'Backup download exceeded its approved size'
                            digest.update(chunk)
                        code = download.wait(timeout=10)
                    attempts.append({'offset': offset, 'bytes': length-offset, 'curl_exit': code})
                    headers = (ROOT/'headers').read_text().lower()
                    if length > offset:
                        expected = ' 206 ' if offset else ' 200 '
                        assert expected in headers.splitlines()[0], 'Invalid backup response status'
                        assert f'content-length: {size-offset}' in headers, 'Invalid backup response length'
                        if offset:
                            assert f'content-range: bytes {offset}-{size-1}/{size}' in headers, 'Invalid resumed backup range'
                    # A live circuit can close mid-body. Resume the same immutable
                    # ciphertext using upstream HTTP Range, within one deadline;
                    # record each failure rather than silently restarting a test.
                    assert code in (0, 18, 28, 52, 56, 97), f'Backup curl failure {code} after {length} bytes'
                    if length < size:
                        assert code != 0, 'Successful backup response was truncated'
                        time.sleep(1)
                assert length == size and digest.hexdigest() == request['sha256'], 'Full encrypted backup differs from its source'
                response = {'ok': True, 'unauthenticated_refused': True, 'volume_bytes': size,
                            'downloaded_bytes': length, 'first_and_last_ranges_match': True, 'full_sha256_match': True,
                            'attempts': attempts}
            elif request == {'action': 'finish'}:
                for client in clients:
                    client.stop()
                assert all(client.process.poll() is not None for client in clients)
                print(json.dumps({'ok': True, 'closed': True}), flush=True)
                return
            else:
                raise AssertionError('Invalid recipient action')
            print(json.dumps(response), flush=True)
    finally:
        for client in clients:
            client.stop()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Tracebacks and exception representations can include command inputs.
        # Assertion messages in this fixture are fixed, input-free strings.
        reason = str(error) if isinstance(error, AssertionError) else type(error).__name__
        print(json.dumps({'ok': False, 'error': 'recipient_failed', 'reason': reason}), flush=True)
        raise SystemExit(1)
