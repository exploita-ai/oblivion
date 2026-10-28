"""Private metadata bridge to the disposable, independent online Tor caller."""
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import threading
import time


class Recipient:
    def __init__(self, image, share=False, backup=False):
        self.name = f'oblivion-onion-recipient-{os.getpid()}'
        self.metadata = {'image_id': subprocess.check_output(
            ['docker', 'image', 'inspect', '--format', '{{.Id}}', image], text=True).strip()}
        self.stream = None
        self.thread = None
        self.failed = threading.Event()
        self.closed = False
        self.failure = None
        self.steps = ('prepare', 'upload', 'revoked', 'download', 'revoked-share', 'finish') if share else ('prepare', 'upload', 'revoked', 'finish')
        if backup: self.steps = self.steps[:-1] + ('backup', 'revoked-backup', 'finish')
        self.process = subprocess.Popen([
            'docker', 'run', '--rm', '--name', self.name, '--log-driver', 'none', '-i',
            '--read-only', '--user', '1000:1000', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '96',
            '--memory', '512m', '--memory-swap', '512m', '--ulimit', 'core=0',
            '--tmpfs', '/run/onion-recipient:rw,nosuid,nodev,noexec,size=96m,mode=0700,uid=1000,gid=1000',
            image,
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        try:
            response = self.receive(20)
            expected = hashlib.sha256(Path(__file__).with_name('vm-onion-recipient.py').read_bytes()).hexdigest()
            assert set(response) == {'ready', 'source_sha256', 'tor_version'} and response['ready']
            assert response['source_sha256'] == expected, 'Recipient source mismatch'
            self.metadata.update(response)
        except BaseException:
            self.stop()
            raise

    def receive(self, timeout):
        deadline = time.monotonic() + timeout
        data = b''
        while not data.endswith(b'\n'):
            assert select.select([self.process.stdout], [], [], max(0, deadline-time.monotonic()))[0], 'Recipient deadline'
            chunk = self.process.stdout.read(1)
            assert chunk and len(data) < 4096, 'Recipient closed or exceeded metadata limit'
            data += chunk
        response = json.loads(data)
        if response.get('ok', response.get('ready')) is not True:
            self.failure = response.get('reason', 'recipient_failed')
            raise AssertionError('Independent recipient failed')
        return response

    def attach(self, path):
        self.stream = socket.socket(socket.AF_UNIX)
        self.stream.settimeout(600)
        self.stream.connect(str(path))
        os.chmod(path, 0o600)
        self.thread = threading.Thread(target=self.bridge, daemon=True)
        self.thread.start()

    def exact(self, length):
        value = b''
        while len(value) < length:
            chunk = self.stream.recv(length-len(value))
            assert chunk, 'Private recipient channel closed'
            value += chunk
        return value

    def bridge(self):
        try:
            for step in self.steps:
                expected = 'revoked' if step in ('revoked-share', 'revoked-backup') else step
                length = struct.unpack('>I', self.exact(4))[0]
                assert 0 < length <= 4096, 'Recipient request limit'
                request = json.loads(self.exact(length))
                assert request.get('action') == expected, 'Unexpected recipient lifecycle'
                assert set(request) == ({'action', 'url', 'bytes', 'first_sha256', 'last_sha256', 'sha256'} if expected == 'backup' else {'action', 'url'} if expected in ('upload', 'download') else {'action'}), 'Invalid recipient fields'
                self.process.stdin.write(json.dumps(request, separators=(',', ':')).encode()+b'\n')
                self.process.stdin.flush()
                response = self.receive(3100 if expected == "backup" else 600)
                if expected == 'finish':
                    assert self.process.wait(timeout=20) == 0, 'Recipient did not stop'
                    self.closed = True
                encoded = json.dumps(response, separators=(',', ':')).encode()
                self.stream.sendall(struct.pack('>I', len(encoded))+encoded)
                # Never retain address/public key in the evidence report.
                self.metadata[step] = {key: value for key, value in response.items() if key != 'public_key'}
        except Exception:
            self.failed.set()

    def stop(self):
        if self.stream is not None:
            try:
                self.stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.stream.close()
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                # Only this invocation's named test container is removed.
                subprocess.run(['docker', 'rm', '-f', self.name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20)
                self.process.wait(timeout=10)
        if self.thread is not None:
            self.thread.join(timeout=5)
            assert not self.thread.is_alive(), 'Recipient bridge thread survived cleanup'
