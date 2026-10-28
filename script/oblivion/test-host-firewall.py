#!/usr/bin/python3
"""Real packets in disposable Linux network namespaces; never the machine's uplink."""
import os
import json
from pathlib import Path
import selectors
import subprocess
import sys

assert os.geteuid() == 0
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'Run with unshare --net'
policy = Path(sys.argv[1]).resolve(strict=True)
peer = 'oblivion-firewall-' + str(os.getpid())
processes = []


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10, **kwargs)


def server(namespace, address, ports):
    code = '''import selectors,socket,sys
s=selectors.DefaultSelector()
for port in sys.argv[2:]:
    kind,number=port.split(':')
    sock=socket.socket(type=socket.SOCK_STREAM if kind=='tcp' else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.bind((sys.argv[1],int(number)))
    if kind=='tcp': sock.listen()
    s.register(sock,selectors.EVENT_READ,kind)
print('ready',flush=True)
while True:
    for key,_ in s.select():
        if key.data=='tcp':
            connection,_=key.fileobj.accept()
            connection.sendall(b'fixture')
            connection.close()
        else:
            data,address=key.fileobj.recvfrom(256)
            key.fileobj.sendto(data,address)
'''
    command = (['ip', 'netns', 'exec', namespace] if namespace else []) + ['python3', '-u', '-c', code, address, *ports]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    processes.append(process)
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(10), 'fixture listener did not start'
        assert process.stdout.readline().strip() == 'ready'


def probes(uid, checks, namespace=None):
    code = '''import json,socket,sys
results=[]
for port,udp,bind in json.loads(sys.argv[2]):
    with socket.socket(type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        if bind: sock.bind(('0.0.0.0',bind))
        try:
            sock.connect((sys.argv[1],port))
            if udp: sock.send(b'fixture')
            results.append(sock.recv(64)==b'fixture')
        except OSError:
            results.append(False)
print(json.dumps(results))
'''
    command = (['ip', 'netns', 'exec', namespace] if namespace else []) + ['setpriv', '--reuid='+str(uid), '--regid='+str(uid), '--clear-groups', '--no-new-privs', '--', 'python3', '-c', code, '10.222.0.2' if namespace else '10.222.0.1', json.dumps(checks)]
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
    values = json.loads(result.stdout)
    assert len(values) == len(checks) and all(type(value) is bool for value in values)
    return values


def connects(uid, namespace=None, port=8081, udp=False, bind=0):
    return probes(uid, [(port, udp, bind)], namespace)[0]


try:
    run('ip', 'netns', 'add', peer)
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', 'outside', 'type', 'veth', 'peer', 'name', 'inside')
    run('ip', 'link', 'set', 'inside', 'netns', peer)
    run('ip', 'address', 'add', '10.222.0.2/24', 'dev', 'outside')
    run('ip', 'link', 'set', 'outside', 'up')
    run('ip', '-n', peer, 'address', 'add', '10.222.0.1/24', 'dev', 'inside')
    run('ip', '-n', peer, 'link', 'set', 'inside', 'up')
    run('ip', '-n', peer, 'link', 'set', 'lo', 'up')
    server(peer, '10.222.0.1', ['tcp:8081', 'tcp:53', 'tcp:853', 'udp:53', 'udp:123', 'udp:443', 'udp:9999', 'udp:67'])
    server(None, '10.222.0.2', ['tcp:22'])
    assert connects(1000), 'positive control must reach the fixture before filtering'
    run('nft', '-f', str(policy))
    assert connects(1101), 'gateway UID must reach its external TCP transport'
    for uid in (0, 1000, 1100, 1101, 1102, 1103, 1104, 1105, 1106):
        # Keep every UID/port probe, but pay interpreter/setpriv startup once
        # per identity rather than 60 times inside the software-emulated VM.
        checks = ([(port, False, 0) for port in (53, 853, 8081)] if uid != 1101 else [])
        checks += [(port, True, 0) for port in (53, 123, 443, 9999)]
        for (port, udp, _), allowed in zip(checks, probes(uid, checks)):
            assert not allowed, f"{'UDP' if udp else 'TCP'} port {port} escaped: UID {uid}"
    assert connects(0, port=67, udp=True, bind=68), 'DHCP exchange must work'
    assert not connects(1000, peer, port=22), 'debug SSH must be closed by default'
    run('nft', 'add', 'element', 'inet', 'oblivion_host', 'debug4', '{', '10.222.0.0/24', '}')
    assert connects(1000, peer, port=22), 'explicit diagnostic subnet must reach SSH'
    run('nft', 'flush', 'set', 'inet', 'oblivion_host', 'debug4')
    assert not connects(1000, peer, port=22), 'revoking diagnostics must block SSH'
    # Reload is idempotent and never opens a window by flushing other tables.
    run('nft', '-f', str(policy))
    assert not connects(1000)
    assert connects(1101)
    print('PASS: gateway-only TCP, blocked host/session/transfer egress and DNS, DHCP, debug opt-in/revoke, atomic reload')
finally:
    for process in processes:
        process.terminate()
        process.wait(timeout=5)
        process.stdout.close()
    subprocess.run(['ip', 'netns', 'delete', peer], capture_output=True, timeout=5)
