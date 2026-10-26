#!/usr/bin/env python3
"""Real USB/GPT/LUKS and reboot persistence, only in a disposable offline VM."""
import codecs
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import termios
import time
import pyte

os.umask(0o077)
CONFIG = '/run/oblivion-persistence-test.json'
GENERAL = b'oblivion-usb-general-canary-82ab'
SESSION = b'oblivion-usb-session-canary-91cd'
API = 'OBLIVION_USB_API_CANARY_46c1'
WIFI = 'OBLIVION_USB_WIFI_CANARY_f81a'
DOCUMENT = b'OBLIVION_USB_DOCUMENT_CANARY_44d7'
PHASE = next(x.split('=', 1)[1] for x in Path('/proc/cmdline').read_text().split() if x.startswith('oblivion.phase='))
ROOT = Path('/run/oblivion/general')
MOUNT = Path('/run/session-inspection')
assert len(Path('/proc/swaps').read_text().splitlines()) == 1

def run(args, secret=None, success=True):
    r = subprocess.run(args, input=secret, capture_output=True, timeout=120)
    assert (r.returncode == 0) == success, (args[0], args[1:3], r.stderr.decode(errors='replace'))
    return r.stdout

def command(action, *args, secret=None, success=True):
    return run(['/usr/bin/oblivion-storage', '--config', CONFIG, action, *args], secret, success)

def status():
    return json.loads(command('status'))

def check(label):
    print('PASS: ' + label, flush=True)

def digest(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()

def wait(condition, timeout=30):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, 'condition deadline'
        time.sleep(.05)

Path(CONFIG).write_text(json.dumps({'general_image':'/persist/oblivion/general.luks', 'general_mib':512,
    'session_mib':128, 'pbkdf_memory_kib':65536, 'manager_uid':1000, 'usb_persistence':True, 'network_profiles':True}))
command('recover')
assert status()['persistence']['unavailable'] == 'usb_live_medium_missing'
check('No live USB refuses persistent setup without falling back to RAM')
run(['modprobe','usb_storage'])
run(['modprobe','iso9660'])
run(['modprobe','hfsplus'])
wait(lambda: Path('/dev/sda').exists())
Path('/run/live/medium').mkdir(parents=True, exist_ok=True)
run(['mount','-t','iso9660','-o','ro,nodev,nosuid,noexec','/dev/sda','/run/live/medium'])
assert status()['persistence']['unavailable']=='usb_loop_boot_required'
run(['umount','/run/live/medium'])
# Same zero-offset loop topology selected by Debian live-media-offset=0.
# GRUB hybrid images can also be found through their boot partition.
backing='/dev/sda' if PHASE=='prepare' else '/dev/sda3'
loop=run(['losetup','--find','--show','--offset','0',backing]).decode().strip()
run(['mount','-t','iso9660' if PHASE=='prepare' else 'hfsplus','-o','ro,nodev,nosuid,noexec',loop,'/run/live/medium'])
check('Whole-device boot refuses writes; Debian zero-offset loop boot permits the data partition')
MOUNT.mkdir()
initial = status()
assert initial['persistence']['unavailable'] is None, initial['persistence']
print('OBLIVION_PERSISTENCE_STORAGE_SHA256 ' + digest('/usr/bin/oblivion-storage'), flush=True)
print('OBLIVION_PERSISTENCE_FIXTURE_SHA256 ' + digest(__file__), flush=True)

if PHASE == 'prepare':
    assert not initial['general_present'] and not initial['general_incomplete']
    plan = initial['persistence']['plan']
    assert plan['device'] == 'sda'
    table_before = run(['sfdisk','--dump','/dev/sda'])
    command('init-general', secret=GENERAL, success=False)
    command('prepare-usb', secret=json.dumps({'plan':{**plan, 'disk_bytes':plan['disk_bytes']+512},'password':GENERAL.decode()}).encode(), success=False)
    assert run(['sfdisk','--dump','/dev/sda']) == table_before
    check('Explicit USB confirmation is required and changed device selection is rejected without writes')
    # Kill the real creator after the partition is published as pending, while
    # cryptsetup is still deriving a key. No mock formatter or disk is used.
    child = subprocess.Popen(['/usr/bin/oblivion-storage','--config',CONFIG,'prepare-usb'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    child.stdin.write(json.dumps({'plan':plan,'password':GENERAL.decode()}).encode())
    child.stdin.close()
    wait(lambda: len(json.loads(run(['sfdisk','--json','/dev/sda']))['partitiontable']['partitions']) > plan['partition']-1)
    os.killpg(child.pid, signal.SIGKILL)
    child.wait(timeout=10)
    # If interrupted before partx, ask the kernel to discover the newly written
    # entry as it would at reboot; never ask the product to format it again.
    run(['partx','--update','/dev/sda'])
    run(['udevadm','settle'])
    command('recover')
    assert status()['general_incomplete'] and not status()['general_present']
    command('unlock', secret=GENERAL, success=False)
    command('prepare-usb', secret=json.dumps({'plan':plan,'password':GENERAL.decode()}).encode(), success=False)
    check('Interrupted preparation remains incomplete and cannot be reopened or reformatted implicitly')
    command('discard-general-pending')
    assert not status()['general_incomplete']
    check('Explicit cleanup removes only the incomplete data partition')
    run(['sfdisk','--append','--no-reread','--no-tell-kernel','--wipe=never','--wipe-partitions=never','/dev/sda'],
        f'start={plan["start"]}, size={plan["sectors"]}, type=linux, name="Foreign partition"\n'.encode())
    run(['partx','--update','--nr',str(plan['partition']),'/dev/sda'])
    run(['udevadm','settle'])
    foreign_table=run(['sfdisk','--dump','/dev/sda'])
    assert status()['persistence']['unavailable']=='usb_foreign_partitions'
    command('prepare-usb',secret=json.dumps({'plan':plan,'password':GENERAL.decode()}).encode(),success=False)
    assert run(['sfdisk','--dump','/dev/sda'])==foreign_table
    run(['sfdisk','--no-reread','--no-tell-kernel','--delete','/dev/sda',str(plan['partition'])])
    run(['partx','--delete','--nr',str(plan['partition']),'/dev/sda'])
    check('A foreign partition blocks setup and remains unchanged')

    server = subprocess.Popen(['/usr/bin/oblivion-storage','--config',CONFIG,'serve'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait(lambda: Path('/run/oblivion-control.sock').exists())
    master, slave = os.openpty()
    fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,80,0,0))
    def terminal_session():
        os.setsid()
        fcntl.ioctl(0,termios.TIOCSCTTY,0)
    manager = subprocess.Popen(['/usr/bin/oblivion-manager'],stdin=slave,stdout=slave,stderr=slave,user=1000,group=1000,extra_groups=[],
        preexec_fn=terminal_session,env={'TERM':'linux','HOME':'/run','PATH':'/usr/bin:/bin'})
    os.close(slave)
    screen=pyte.Screen(80,24)
    stream=pyte.Stream(screen)
    decoder=codecs.getincrementaldecoder('utf-8')('replace')
    def visible(text, timeout=90):
        deadline=time.monotonic()+timeout
        while text not in '\n'.join(screen.display):
            view='\n'.join(screen.display)
            if manager.poll() is not None or time.monotonic()>=deadline or 'Operazione non completata' in view:
                print('MANAGER_DIAGNOSTIC '+view,flush=True)
                print('STATUS_DIAGNOSTIC '+json.dumps(status()),flush=True)
                print(run(['journalctl','-b','--no-pager','-n','90']).decode(errors='replace'),flush=True)
                raise AssertionError('manager deadline/error: '+text)
            if select.select([master],[],[],.1)[0]:
                chunk=os.read(master,65536)
                assert GENERAL not in chunk
                stream.feed(decoder.decode(chunk))
    try:
        visible('Prima preparazione della USB')
        os.write(master,b'\r');visible('Conferma questa USB')
        os.write(master,b'\x1b');visible('Prima preparazione della USB')
        assert not status()['general_present'] and not status()['general_incomplete']
        check('Nonroot manager cancellation leaves the USB unprepared')
        os.write(master,b'\r');visible('Conferma questa USB')
        os.write(master,b's');visible('Nuovo volume generale')
        os.write(master,GENERAL+b'\r');visible('Ripeti la password')
        os.write(master,GENERAL+b'\r');visible('Archivio generale bloccato')
        assert status()['general_present']
        check('Real nonroot manager provisions the confirmed USB with a hidden LUKS password')
    finally:
        manager.terminate();manager.wait(timeout=10);os.close(master)
        server.terminate();server.wait(timeout=10)

    command('unlock', secret=GENERAL)
    a=command('create', secret=SESSION).decode().strip()
    b=command('create', secret=b'oblivion-usb-second-session-72ae').decode().strip()
    (ROOT/'profile/test-session-id').write_text(a)
    command('api-keys', secret=json.dumps({'action':'add','name':'USB fixture','key':API}).encode())
    network=Path('/run/NetworkManager/system-connections/oblivion-test.nmconnection')
    network.parent.mkdir(parents=True,exist_ok=True)
    network.write_text('[connection]\nid=oblivion-test\nuuid=86004721-dabd-441b-823a-7cbdc56ac50d\ntype=wifi\nautoconnect=false\n[wifi]\nssid=Oblivion synthetic test\nmode=infrastructure\n[wifi-security]\nkey-mgmt=wpa-psk\npsk='+WIFI+'\n[ipv4]\nmethod=auto\n[ipv6]\nmethod=disabled\n')
    network.chmod(0o600)
    command('save-network')
    saved=digest(ROOT/'profile/network-connections.json')
    hostile=network.parent/'unsafe.nmconnection'
    hostile.symlink_to('/etc/passwd')
    command('save-network',success=False)
    assert digest(ROOT/'profile/network-connections.json')==saved
    hostile.unlink()
    network.chmod(0o644)
    command('save-network',success=False)
    assert digest(ROOT/'profile/network-connections.json')==saved
    network.chmod(0o600)
    check('Symlinks and public network profiles are refused without replacing the saved archive')
    command('network-policy',secret=json.dumps({'action':'put','rule':{'destination':'usb-fixture.example.com','port':443,'action':'allow'},'save':True}).encode())
    command('open', a, secret=SESSION)
    command('open', b, secret=b'oblivion-usb-second-session-72ae', success=False)
    run(['mount','-o','nodev,nosuid,noexec','/dev/mapper/oblivion-session',str(MOUNT)])
    (MOUNT/'document.txt').write_bytes(DOCUMENT)
    run(['umount',str(MOUNT)])
    command('close')
    command('lock')
    assert not status()['general_open'] and not status()['session_open']
    command('discard-general-pending', success=False)
    check('Nested session, provider key and Wi-Fi profile are saved in LUKS; one-session interlock and lock succeed')
elif PHASE == 'reopen':
    assert initial['general_present'] and not initial['general_open']
    assert not Path('/run/NetworkManager/system-connections/oblivion-test.nmconnection').exists()
    command('unlock', secret=b'wrong-general-password', success=False)
    assert not status()['general_open']
    command('unlock', secret=GENERAL)
    assert status()['api_key_present'] and status()['network_profiles_saved']
    assert 'usb-fixture.example.com' in json.dumps(status()['network_policy'])
    assert WIFI in Path('/run/NetworkManager/system-connections/oblivion-test.nmconnection').read_text()
    assert b'86004721-dabd-441b-823a-7cbdc56ac50d' in run(['nmcli','-t','-f','UUID','connection','show'])
    a=(ROOT/'profile/test-session-id').read_text()
    command('open',a,secret=b'wrong-session-password',success=False)
    assert not status()['session_open']
    command('open',a,secret=SESSION)
    run(['mount','-o','ro,noload,nodev,nosuid,noexec','/dev/mapper/oblivion-session',str(MOUNT)])
    assert (MOUNT/'document.txt').read_bytes()==DOCUMENT
    run(['umount',str(MOUNT)])
    command('close');command('lock')
    check('After a full VM power cycle, both passwords, document, API key and NetworkManager profile recover from USB')
elif PHASE == 'readonly':
    command('unlock-ephemeral',secret=GENERAL)
    assert status()['general_readonly'] and status()['api_key_present']
    assert WIFI in Path('/run/NetworkManager/system-connections/oblivion-test.nmconnection').read_text()
    command('save-network',success=False)
    command('create',secret=SESSION,success=False)
    command('lock')
    check('Ephemeral unlock restores the profile in RAM and rejects persistent writes')
else:
    raise AssertionError('unknown phase')
assert not status()['general_open'] and not status()['session_open']
print('OBLIVION_PERSISTENCE_PASS '+PHASE,flush=True)
