#!/usr/bin/env python3
"""Opt-in online acceptance test in a debug live host. Creates only test volumes.

Run as root inside the debug host with rotation-traffic-probe.py beside this
file. Uses the real controller, encrypted sessions, gateways and Tor. Existing
sessions stay open. No provider calls or user documents are used.
"""
import argparse
import array
import base64
import hashlib
import json
import os
import pwd
import re
import secrets
import select
import shlex
import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path


def call(slot, operation, secret=b'', session=None):
    peer = socket.socket(socket.AF_UNIX)
    peer.settimeout(180)
    user = pwd.getpwnam('oblivion-manager')
    os.setegid(user.pw_gid)
    os.seteuid(user.pw_uid)
    try:
        peer.connect('/run/oblivion-control.sock')
    finally:
        os.seteuid(0)
        os.setegid(0)
    body = json.dumps({'operation': operation, 'slot': slot, 'session': session, 'secret_len': len(secret)}).encode()
    peer.sendall(struct.pack('!I', len(body)) + body + secret)
    peer.shutdown(socket.SHUT_WR)
    if operation == 'console':
        _, ancillary, _, _ = peer.recvmsg(1, socket.CMSG_SPACE(4))
        assert len(ancillary) == 1
        descriptor = array.array('i')
        descriptor.frombytes(ancillary[0][2][:4])
        peer.close()
        return socket.socket(fileno=descriptor[0])
    data = b''
    while chunk := peer.recv(65536):
        data += chunk
    peer.close()
    reply = json.loads(data)
    if not reply['ok']:
        raise RuntimeError(reply['error'])
    return reply['output']


def status(slot=0):
    return json.loads(call(slot, 'status'))


def qmp(slot, operation, arguments=None):
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(10)
        peer.connect(f'/run/oblivion-gateway-vm-s{slot}/qmp.sock')
        with peer.makefile('rwb', buffering=0) as stream:
            assert 'QMP' in json.loads(stream.readline())
            for index, command in enumerate([{'execute': 'qmp_capabilities'},
                {'execute': operation, 'arguments': arguments or {}}]):
                stream.write(json.dumps({**command, 'id': index}).encode() + b'\n')
                while True:
                    result = json.loads(stream.readline())
                    if 'event' in result:
                        continue
                    assert result.get('id') == index and 'return' in result, result
                    break
            return result['return']


def identities(slot):
    return {role: int(subprocess.check_output(['systemctl', 'show',
        f'oblivion-{role}-s{slot}.service', '-p', 'MainPID', '--value']))
        for role in ['session', 'gateway-vm']}


class Console:
    def __init__(self, slot):
        self.peer = call(slot, 'console')
        self.peer.setblocking(False)
        deadline = time.monotonic() + 60
        ready = b''
        while b'\x1b]777;oblivion;ready\x07' not in ready:
            assert time.monotonic() < deadline, ('guest console not ready', ready[-500:])
            ready += self.drain(.2)
        self.peer.sendall(b'\x1b[8;50;200t')
        self.drain(5)
        self.peer.sendall(b'\x02c')
        self.drain(1)
        self.command('stty -echo')
        self.command('tmux -S /run/oblivion-terminal/tmux.sock set-option -g status off')

    def drain(self, seconds):
        data = b''
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([self.peer], [], [], .1)[0]:
                part = self.peer.recv(65536)
                assert part, 'test console disconnected'
                data += part
        return data

    def command(self, command, timeout=15):
        marker = 'R' + secrets.token_hex(8)
        self.peer.sendall((command + "; printf '\\n" + marker + ":%s\\n' $?\r").encode())
        data = b''
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data += self.drain(.1)
            clean = re.sub(rb'\x1b\[[0-9;?]*[ -/]*[@-~]', b'', data)
            # tmux can position the next row with a cursor sequence instead of
            # a newline. The random marker itself is sufficient framing.
            match = re.search(marker.encode() + rb':(\d+)', clean)
            if match:
                assert match[1] == b'0', ('test command failed', clean[-1500:].decode(errors='replace'))
                return clean[:match.start()].decode(errors='replace')
        raise AssertionError(('test shell command timed out', clean[-1500:].decode(errors='replace')))

    def install(self, source):
        data = base64.b64encode(source).decode()
        self.command(': > /tmp/rotation-probe.b64')
        for offset in range(0, len(data), 1800):
            self.command('printf %s ' + shlex.quote(data[offset:offset + 1800]) + ' >> /tmp/rotation-probe.b64')
        self.command('base64 -d /tmp/rotation-probe.b64 > /tmp/rotation-probe.py')
        self.command('(python3 -B /tmp/rotation-probe.py serve > /tmp/rotation-probe.out 2>&1 &)')
        self.command('for i in $(seq 1 20); do test -S /tmp/oblivion-rotation-traffic.sock && break; sleep .1; done; test -S /tmp/oblivion-rotation-traffic.sock')

    def probe(self, operation='status', **values):
        output = self.command('python3 -B /tmp/rotation-probe.py ' + shlex.quote(json.dumps({'operation': operation, **values})))
        match = re.search(r'OBLIVION_PROBE_RESULT_([A-Za-z0-9+/=\r\n]+)_END', output)
        if match:
            return json.loads(base64.b64decode(match[1]))
        raise AssertionError(('missing probe response', output[-1000:]))

    def close(self):
        self.peer.close()


def egress(path):
    data = path.read_bytes()
    assert data[:4] == b'\xd4\xc3\xb2\xa1'
    offset, outgoing = 24, 0
    while offset < len(data):
        _, _, size, original = struct.unpack_from('<IIII', data, offset)
        assert size == original and offset + 16 + size <= len(data)
        packet = data[offset + 16:offset + 16 + size]
        offset += 16 + size
        if packet[12:14] == b'\x08\x00' and packet[6:12] == bytes.fromhex('5254006f0002'):
            outgoing += 1
        assert packet[12:14] != b'\x86\xdd', 'IPv6 on the external link'
    return outgoing


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rotations', type=int, choices=range(1, 5), default=1)
    args = parser.parse_args()
    assert os.geteuid() == 0
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    before = status()
    assert before['general_open'] and not before['general_readonly'] and not before['recovery_required']
    slots = [slot for slot in range(1, 32) if slot not in [s['slot'] for s in before['open_sessions']]][:2]
    original = {s['slot']: identities(s['slot']) for s in before['open_sessions']}
    records, consoles, captures = [], [], []
    report = {'passed': False, 'checks': [], 'existing_sessions': before['session_titles'],
        'scope': 'Two new protected sessions through the real UTM host controller, real Tor and HTTPS example.com; no provider requests',
        'runtime_sha256': {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in [
            '/usr/lib/oblivion/vm/gateway/root.squashfs', '/usr/lib/oblivion/vm/gateway/initrd', '/usr/bin/oblivion-storage']},
        'scripts': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ['test-utm-rotation-isolation.py', 'rotation-traffic-probe.py']}}
    def check(label):
        report['checks'].append(label)
        print('PASS: ' + label, flush=True)
    started = time.monotonic()
    try:
        for slot, letter in zip(slots, ['A', 'B']):
            password = secrets.token_urlsafe(24).encode()
            identifier = call(slot, 'create', password).strip()
            assert identifier not in before['sessions'] and re.fullmatch('[a-f0-9]{32}', identifier)
            records.append({'slot': slot, 'id': identifier, 'title': 'Tor isolation test ' + letter})
            call(slot, 'rename-session', json.dumps({'id': identifier, 'title': records[-1]['title']}).encode())
            call(slot, 'open-documents', password, identifier)
            del password
            print(f'Opened test {letter} in slot {slot}', flush=True)
            deadline = time.monotonic() + 240
            while True:
                try:
                    call(slot, 'start-chat')
                    break
                except RuntimeError as failure:
                    assert str(failure) == 'gateway_not_ready' and time.monotonic() < deadline, failure
                    time.sleep(1)
            call(slot, 'chat-ready')
            current = status(slot)
            assert current['network_status']['label'] == 'TOR READY' and current['network_status']['direct_blocked']
            path = Path(f'/run/oblivion-gateway-vm-s{slot}/rotation-outside.pcap')
            qmp(slot, 'object-add', {'qom-type': 'filter-dump', 'id': 'rotation-capture', 'netdev': 'outside', 'file': str(path)})
            captures.append((slot, path, letter))
            console = Console(slot)
            consoles.append(console)
            console.install(Path(__file__).with_name('rotation-traffic-probe.py').read_bytes())
            print(f'Test {letter}: continuous HTTPS probes started', flush=True)
        a, b = consoles
        deadline = time.monotonic() + 120
        while True:
            initial = [c.probe() for c in consoles]
            if all(lane['successes'] >= 3 for s in initial for lane in s['lanes'].values()):
                break
            assert time.monotonic() < deadline, initial
            time.sleep(1)
        report['baseline'] = initial
        stable = identities(slots[1])
        baseline_b = initial[1]['lanes']
        def uninterrupted(snapshot):
            assert snapshot['lanes']['persistent']['failures'] == baseline_b['persistent']['failures'], snapshot
            assert snapshot['lanes']['persistent']['connections'] == baseline_b['persistent']['connections'], snapshot
        check('Two isolated session/gateway pairs simultaneously pass fresh HTTPS and persistent verified TLS requests')
        report['rotations'] = []
        for iteration in range(args.rotations):
            if iteration:
                time.sleep(30)
            for c in consoles:
                c.probe('phase', name=f'rotation_{iteration + 1}')
            a.probe('rotate')
            deadline = time.monotonic() + 120
            while (outcome := a.probe())['rotation'] == {'running': True}:
                assert time.monotonic() < deadline
                healthy = b.probe()
                uninterrupted(healthy)
                time.sleep(.5)
            after = b.probe()
            report['rotations'].append({'result': outcome['rotation'], 'b': after})
            assert identities(slots[1]) == stable
            uninterrupted(after)
            assert outcome['rotation']['code'] == 200 and outcome['rotation']['body']['status'] == 'rotated', outcome
            check(f'Rotation {iteration + 1} of A succeeds while B keeps the same TLS connection and processes, with zero errors on the retained connection')
            recovered = f'recovered_{iteration + 1}'
            for c in consoles:
                c.probe('phase', name=recovered)
            deadline = time.monotonic() + 60
            while not all(v['phases'].get(recovered, {}).get('successes', 0) >= 2 for v in a.probe()['lanes'].values()):
                assert time.monotonic() < deadline
                time.sleep(1)
            check('A resumes HTTPS on new connections after successful rotation')
        # The production cooldown is real, not patched out for this test.
        time.sleep(30)
        for c in consoles:
            c.probe('phase', name='failed_rotation')
        qmp(slots[0], 'set_link', {'name': 'outside', 'up': False})
        a.probe('rotate')
        deadline = time.monotonic() + 135
        while (outcome := a.probe())['rotation'] == {'running': True}:
            assert time.monotonic() < deadline
            healthy = b.probe()
            uninterrupted(healthy)
            assert identities(slots[1]) == stable
            time.sleep(1)
        assert outcome['rotation']['code'] == 503 and outcome['rotation']['body']['status'] == 'blocked', outcome
        report['failed_rotation'] = outcome['rotation']
        check('Cutting only A’s uplink makes its rotation fail closed; B continues on its retained HTTPS connection without errors')
        qmp(slots[0], 'set_link', {'name': 'outside', 'up': True})
        for c in consoles:
            c.probe('phase', name='failure_latched')
        time.sleep(2)
        frozen = a.probe()
        packets = egress(captures[0][1])
        assert packets > 0
        healthy_before = b.probe()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert all(a.probe('probes')['tcp_denied'])
            time.sleep(1)
        final = [c.probe() for c in consoles]
        assert egress(captures[0][1]) == packets
        assert all(final[0]['lanes'][k]['successes'] == frozen['lanes'][k]['successes'] for k in frozen['lanes'])
        assert all(final[1]['lanes'][k]['successes'] > healthy_before['lanes'][k]['successes'] for k in healthy_before['lanes'])
        uninterrupted(final[1])
        assert identities(slots[1]) == stable
        assert not status(slots[0])['network_status']['label'].endswith('READY')
        assert status(slots[1])['network_status']['label'] == 'TOR READY'
        report['final'] = final
        report['b_measured'] = {lane: {metric: final[1]['lanes'][lane][metric] - baseline_b[lane][metric]
            for metric in ['successes', 'failures', 'connections']} for lane in baseline_b}
        report['blocked_egress_packets'] = {'before': packets, 'after': egress(captures[0][1])}
        check('Restoring A’s uplink does not reopen it: zero outgoing IP packets; B keeps serving on its original TLS connection')
        if original:
            assert all(identities(slot) == ids for slot, ids in original.items())
            check('Existing user sessions retain the same VM and gateway processes')
        report['passed'] = all(lane['failures'] == 0 for lane in report['b_measured'].values())
        if not report['passed']:
            print('FAIL: new-connection errors occurred during the measurement window; inspect b_measured and phases', flush=True)
    finally:
        for console in consoles:
            try:
                console.probe('stop')
            except Exception:
                pass
            console.close()
        for slot, path, letter in captures:
            try:
                qmp(slot, 'object-del', {'id': 'rotation-capture'})
                shutil.copyfile(path, args.output / f'{letter}-outside.pcap')
            except Exception as error:
                report.setdefault('cleanup_errors', []).append(type(error).__name__)
        for record in records:
            slot, identifier = record['slot'], record['id']
            try:
                current = status(slot)
                assert current['active_session'] in [None, identifier]
                call(slot, 'close')
                assert not Path(f'/dev/mapper/oblivion-session-s{slot}').exists()
                folder = Path('/run/oblivion/general/sessions')
                assert (folder / (identifier + '.title')).read_text().strip() == record['title']
                for extension in ['luks', 'title']:
                    (folder / (identifier + '.' + extension)).unlink()
                profile = Path('/run/oblivion/general/profile/sessions') / identifier
                if profile.exists():
                    assert not profile.is_symlink()
                    entries = list(profile.iterdir())
                    assert all(p.name in ['transport.json', 'access.json', 'network-policy.json', 'tor-state'] and p.is_file() and not p.is_symlink() for p in entries)
                    for p in entries:
                        p.unlink()
                    profile.rmdir()
            except Exception as error:
                report.setdefault('cleanup_errors', []).append({'slot': slot, 'id': identifier, 'error': str(error)})
        report['seconds'] = round(time.monotonic() - started, 2)
        report['test_sessions'] = records
        remaining = status()
        report['original_sessions_preserved'] = remaining['session_titles'] == before['session_titles'] and remaining['session_sizes'] == before['session_sizes']
        report['passed'] = report['passed'] and not report.get('cleanup_errors') and report['original_sessions_preserved']
        (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']), 'seconds': report['seconds'],
            'cleanup_errors': report.get('cleanup_errors', [])}), flush=True)


if __name__ == '__main__':
    main()
