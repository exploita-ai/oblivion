#!/usr/bin/env python3
"""Explicit online test probe, installed only in disposable session VMs."""
import base64
import http.client
import json
import os
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

SOCKET = '/tmp/oblivion-rotation-traffic.sock'


def serve():
    os.umask(0o077)
    token = Path('/run/oblivion-api/token').read_text().strip()
    assert len(token) == 64
    lock = threading.Lock()
    stop = threading.Event()
    state = {'phase': 'baseline', 'rotation': None, 'lanes': {
        lane: {'connections': 0, 'successes': 0, 'failures': 0, 'phases': {}, 'last_success': None}
        for lane in ['persistent', 'fresh']}}

    def connect():
        peer = socket.create_connection(('10.88.0.1', 8112), timeout=20)
        try:
            auth = base64.b64encode(('oblivion-tools:' + token).encode()).decode()
            peer.sendall(('CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n'
                'Proxy-Authorization: Basic ' + auth + '\r\n\r\n').encode())
            header = b''
            while not header.endswith(b'\r\n\r\n'):
                part = peer.recv(1)
                assert part and len(header) < 8192
                header += part
            if not header.startswith(b'HTTP/1.1 200'):
                code = header.split(b' ', 2)[1]
                raise ValueError('proxy_status_' + (code.decode() if code.isdigit() else 'invalid'))
            peer = ssl.create_default_context().wrap_socket(peer, server_hostname='example.com')
            connection = http.client.HTTPConnection('example.com', timeout=20)
            connection.sock = peer
            return connection
        except BaseException:
            peer.close()
            raise

    def traffic(lane):
        connection = None
        while not stop.is_set():
            started = time.monotonic()
            error = None
            try:
                if connection is None:
                    connection = connect()
                    with lock:
                        state['lanes'][lane]['connections'] += 1
                connection.request('GET', '/', headers={
                    'Host': 'example.com', 'Connection': 'keep-alive',
                    'User-Agent': 'Oblivion-network-validation/1'})
                response = connection.getresponse()
                body = response.read(65537)
                if response.status != 200:
                    raise ValueError('https_status_' + str(response.status))
                assert b'Example Domain' in body and len(body) <= 65536
                # Do not hide a closed persistent connection with a reconnect.
                if lane == 'persistent':
                    assert not response.will_close, 'remote_closed_keepalive'
            except Exception as failure:
                error = str(failure) if isinstance(failure, ValueError) else type(failure).__name__
            with lock:
                metrics = state['lanes'][lane]
                phase = metrics['phases'].setdefault(state['phase'], {
                    'successes': 0, 'failures': 0, 'max_request_seconds': 0, 'errors': {}})
                outcome = 'failures' if error else 'successes'
                metrics[outcome] += 1
                phase[outcome] += 1
                phase['max_request_seconds'] = round(max(phase['max_request_seconds'], time.monotonic() - started), 3)
                if error:
                    phase['errors'][error] = phase['errors'].get(error, 0) + 1
                else:
                    metrics['last_success'] = time.time()
            if error or lane == 'fresh':
                if connection:
                    connection.close()
                connection = None
            stop.wait(1)
        if connection:
            connection.close()

    def rotate():
        peer = http.client.HTTPConnection('10.88.0.1', 8114, timeout=155)
        started = time.monotonic()
        try:
            peer.request('POST', '/tor/rotate', headers={'Authorization': 'Bearer ' + token})
            reply = peer.getresponse()
            result = {'code': reply.status, 'body': json.loads(reply.read(1024))}
        except Exception as failure:
            result = {'error': type(failure).__name__}
        finally:
            peer.close()
        with lock:
            state['rotation'] = {**result, 'seconds': round(time.monotonic() - started, 3)}

    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(SOCKET)
        listener.listen(2)
        workers = [threading.Thread(target=traffic, args=(lane,), daemon=True) for lane in state['lanes']]
        for worker in workers:
            worker.start()
        while not stop.is_set():
            peer, _ = listener.accept()
            with peer, peer.makefile('rb') as reader:
                request = json.loads(reader.readline(4096))
                operation = request['operation']
                with lock:
                    if operation == 'phase':
                        state['phase'] = request['name']
                    if operation == 'rotate':
                        assert state['rotation'] != {'running': True}
                        state['rotation'] = {'running': True}
                        threading.Thread(target=rotate, daemon=True).start()
                    if operation == 'stop':
                        stop.set()
                    snapshot = json.loads(json.dumps(state))
                if operation == 'probes':
                    denied = []
                    for address in [('10.88.0.1', p) for p in [8111, 8112, 8113, 9050, 53]] + [('1.1.1.1', 443)]:
                        with socket.socket() as attempt:
                            attempt.settimeout(.2)
                            denied.append(attempt.connect_ex(address) != 0)
                    snapshot['tcp_denied'] = denied
                peer.sendall(json.dumps(snapshot).encode() + b'\n')
        for worker in workers:
            worker.join(timeout=22)
    Path(SOCKET).unlink()


if __name__ == '__main__':
    if sys.argv[1] == 'serve':
        serve()
    else:
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(5)
            peer.connect(SOCKET)
            peer.sendall(sys.argv[1].encode() + b'\n')
            with peer.makefile('rb') as reader:
                print('OBLIVION_PROBE_RESULT_' + base64.b64encode(reader.readline(65536)).decode() + '_END')
