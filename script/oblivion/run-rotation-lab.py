#!/usr/bin/env python3
"""Production Tor rotation in two disposable VMs, with external packet capture."""
import argparse
import hashlib
import json
import resource
import secrets
import shutil
import struct
import tempfile
import time
from pathlib import Path
import importlib.util
spec = importlib.util.spec_from_file_location("network_lab", Path(__file__).with_name("run-network-lab.py"))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
VM, Control, verify_image = lab.VM, lab.Control, lab.verify_image
from packet_capture import capture


def observe(control):
    body = b'{"operation":"observe"}'
    control.socket.sendall(struct.pack('!I', len(body)) + body)
    reply = control.receive()
    assert reply['isolated']
    return reply


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--accelerator', choices=['hvf', 'tcg'], default='hvf')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    image, output = args.image.resolve(), args.output.resolve()
    verify_image(image)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(image / 'initrd', output / 'lab-initrd')
    checks = []
    report = {'scope': 'Production gateway and isolated probe VM, real Tor; synthetic credentials; no provider requests',
        'passed': False, 'checks': checks, 'image_manifest': (image / 'SHA256SUMS').read_text()}
    def check(text):
        checks.append(text)
        print('PASS: ' + text, flush=True)
    vms, control = [], None
    started = time.monotonic()
    fixture_hash = hashlib.sha256(Path(__file__).with_name('vm-network-fixture.py').read_bytes()).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix='oblivion-rotate-', dir='/tmp') as temporary:
            wire = Path(temporary) / 'inside.sock'
            gateway = VM('gateway', image, output, wire, True, args.accelerator)
            vms.append(gateway)
            deadline = time.monotonic() + 10
            while not (wire.parent / 'control.sock').exists():
                assert time.monotonic() < deadline and gateway.process.poll() is None
                time.sleep(.01)
            control = Control(wire.parent / 'control.sock')
            chat = VM('chat', image, output, wire, True, args.accelerator)
            vms.append(chat)
            gateway.ready(fixture_hash)
            chat.ready(fixture_hash)
            assert control.receive() == {'ready': True, 'version': 1}
            control.call('configure', provider='abliteration-ai', api_key='synthetic-' + secrets.token_hex(32), transport={'mode': 'tor'})
            control.call('tor-initialize', state=None)
            control.call('tor-enable')
            deadline = time.monotonic() + 300
            while not gateway.call('tor-status')['bootstrapped']:
                assert time.monotonic() < deadline, 'Tor bootstrap timed out'
                time.sleep(1)
            token = secrets.token_hex(32)
            control.call('grant', token=token, rotation_allowed=True, tools={'session': 'a' * 32, 'access': 'open', 'policy': {'version': 1, 'rules': []}})
            gateway.call('supervisor-info', tools=True)
            check('Real Tor bootstrapped; production children use separate unprivileged identities')
            control.call('rotation-allowed', allowed=False)
            chat.call('rotation-start', token=token)
            deadline = time.monotonic() + 10
            while not (reply := chat.call('rotation-result'))['done']:
                assert time.monotonic() < deadline
                control.call('status')
                time.sleep(.1)
            assert reply['result'] == {'code': 409, 'body': {'status': 'rotation_not_allowed'}}
            assert not gateway.call('rotation-state')['barrier']
            control.call('rotation-allowed', allowed=True)
            check('Transfer interlock refuses rotation without changing the current transport')
            assert chat.call('rotation-https', token=token)['https']
            assert chat.call('rotation-held-open', token=token)['open'] == 3
            old = gateway.call('rotation-circuits')['exits']
            assert old
            check('HTTPS with certificate verification works; API, tools and web sockets are open before rotation')
            chat.call('rotation-start', token=token)
            deadline = time.monotonic() + 15
            while not gateway.call('rotation-state')['barrier']:
                assert time.monotonic() < deadline
                control.call('status')
            while (barrier := gateway.call('rotation-state'))['data_processes']:
                assert time.monotonic() < deadline
                time.sleep(.05)
            assert barrier['rotation_processes'] == 1, barrier
            chat.call('rotation-held-blocked')
            chat.call('rotation-probes')
            state = gateway.call('rotation-state')
            assert state['barrier'] and state['dropped_packets'] > 0
            assert not observe(control)['ready']
            check('While rotating: old connections unusable, all three data services stopped, new TCP/DNS probes dropped, readiness false')
            deadline = time.monotonic() + 100
            while not (reply := chat.call('rotation-result'))['done']:
                assert time.monotonic() < deadline
                control.call('status')
                time.sleep(.2)
            assert reply['result'] == {'code': 200, 'body': {'status': 'rotated'}}, reply
            state = gateway.call('rotation-state')
            assert not state['barrier'] and state['data_processes'] == 4, state
            fresh = gateway.call('rotation-circuits')['exits']
            assert fresh and not set(old).intersection(fresh), (old, fresh)
            assert observe(control)['ready']
            assert chat.call('rotation-https', token=token)['https']
            check('Verified different exit relay identities before reopening; HTTPS works again through the proxy')
            report['exits'] = {'before': old, 'after': fresh}
            # Cooldown is deliberately real in this full-system test.
            while time.monotonic() < started + 35:
                time.sleep(.2)
            # Ensure a full 30 seconds from the successful request even after a fast bootstrap.
            time.sleep(30)
            gateway.call('rotation-tor-pause')
            chat.call('rotation-start', token=token)
            deadline = time.monotonic() + 35
            while not (reply := chat.call('rotation-result'))['done']:
                assert time.monotonic() < deadline
                control.call('status')
                time.sleep(.2)
            assert reply['result']['code'] == 503 and reply['result']['body']['status'] == 'blocked', reply
            state = gateway.call('rotation-state')
            assert state['barrier'] and state['data_processes'] == 0, state
            assert not observe(control)['ready']
            chat.call('rotation-probes')
            time.sleep(1)
            shutil.copyfile(output / 'gateway-outside.pcap', output / 'blocked-before.pcap')
            before = capture(output / 'blocked-before.pcap', source='10.0.2.15')
            assert before['ipv4'] > 0, 'capture did not observe the gateway egress'
            for _ in range(3):
                chat.call('rotation-probes')
                control.call('status')
            shutil.copyfile(output / 'gateway-outside.pcap', output / 'blocked-after.pcap')
            after = capture(output / 'blocked-after.pcap', source='10.0.2.15')
            assert before['ipv4'] == after['ipv4'], (before, after)
            assert capture(output / 'blocked-after.pcap')['ipv6'] == 0
            report['blocked_egress_packets'] = {'before': before['ipv4'], 'after': after['ipv4']}
            check('Paused Tor causes a real control timeout: rotation fails, barrier remains, zero additional outgoing IP packets despite repeated probes')
            gateway.call('rotation-tor-resume')
            chat.call('rotation-probes')
            assert gateway.call('rotation-state')['barrier']
            check('Tor recovering by itself does not reopen the session')
            gateway.call('supervisor-crash')
            gateway.call('supervisor-stopped')
            assert chat.call('disconnected')['disconnected']
            check('Supervisor crash kills every data service and Tor; no direct fallback')
            report['passed'] = True
    finally:
        if control:
            control.close()
        for vm in vms:
            vm.stop()
        report['seconds'] = round(time.monotonic() - started, 2)
        report['captures'] = {p.name: capture(p) for p in output.glob('*.pcap')}
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'checks': len(checks), 'seconds': report['seconds']}), flush=True)


if __name__ == '__main__':
    main()
