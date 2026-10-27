#!/usr/bin/python3
"""Compiled chat API on two synthetic LUKS layers; killed by the outer harness."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys

CANARY = 'OBLIVION_POWERLOSS_CHAT_91e38'
KEY = b'synthetic-powerloss-password'
VAULT = Path('/run/audit-session')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.DEVNULL, timeout=60, **kwargs)


if sys.argv[1:] != ['workload']:
    assert os.getuid() == 0
    assert sorted(path.name for path in Path('/sys/class/net').iterdir()) == ['lo']
    fresh = subprocess.run(['cryptsetup', 'isLuks', '/dev/vdb'], capture_output=True).returncode != 0
    if fresh:
        run('cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--pbkdf-memory', '65536', '--iter-time', '100', '--key-file', '-', '/dev/vdb', input=KEY)
    run('cryptsetup', 'open', '--key-file', '-', '/dev/vdb', 'audit-general', input=KEY)
    general = Path('/run/audit-general')
    general.mkdir(mode=0o700)
    if fresh:
        run('mkfs.ext4', '-q', '/dev/mapper/audit-general')
    run('mount', '/dev/mapper/audit-general', str(general))
    session = general/'session.luks'
    if fresh:
        with session.open('xb') as file:
            os.posix_fallocate(file.fileno(), 0, 128*1024*1024)
        run('cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--pbkdf-memory', '65536', '--iter-time', '100', '--key-file', '-', str(session), input=KEY)
    run('cryptsetup', 'open', '--key-file', '-', str(session), 'audit-session', input=KEY)
    if fresh:
        run('mkfs.ext4', '-q', '/dev/mapper/audit-session')
    VAULT.mkdir(mode=0o700)
    run('mount', '/dev/mapper/audit-session', str(VAULT))
    os.chown(VAULT, 1000, 1000)
    subprocess.run(['setpriv', '--reuid=1000', '--regid=1000', '--clear-groups', sys.executable, __file__, 'workload'], check=True, timeout=170)
    run('umount', str(VAULT))
    run('cryptsetup', 'close', 'audit-session')
    run('umount', str(general))
    run('cryptsetup', 'close', 'audit-general')
    print('OBLIVION_POWERLOSS_PASS', flush=True)
    raise SystemExit(0)

spec = importlib.util.spec_from_file_location('chat', '/usr/libexec/chat-database.py')
chat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chat)
runtime = Path('/run/audit-client')
runtime.mkdir(mode=0o700, exist_ok=True)
workspace = VAULT/'workspace'
workspace.mkdir(exist_ok=True)
path = VAULT/'oblivion.db'
fresh = not path.exists()
with chat.server('/run/audit-guest/usr/bin/oblivion', path, runtime) as request:
    if fresh:
        # Prepare documents before the chat commits. No global sync/checkpoint
        # occurs after the API acknowledges the final durable inbox admission.
        with (workspace/'document.txt').open('xb') as file:
            file.write(CANARY.encode())
            file.flush()
            os.fsync(file.fileno())
        for index in range(2):
            base = request('/api/session', {'title': CANARY+str(index), 'location': {'directory': str(workspace)}})
            request('/api/experimental/session/import', {
                'info': {**base, 'id': 'ses_powerloss_'+str(index)},
                'messages': [{'id': 'msg_powerloss_'+str(index), 'type': 'user', 'text': CANARY+str(index),
                    'time': {'created': 1700000000000}, 'files': [], 'agents': [], 'skills': []}],
                'location': {'directory': str(workspace)},
            })
        request('/api/session/ses_powerloss_0/prompt', {'text': CANARY+'_pending', 'resume': False})
        print('OBLIVION_POWERLOSS_CUT_NOW', flush=True)
        while True:
            signal.pause()
    assert (workspace/'document.txt').read_text() == CANARY
    for index in range(2):
        transcript = request('/api/experimental/session/ses_powerloss_'+str(index)+'/export')
        assert transcript['info']['title'] == CANARY+str(index)
        assert len(transcript['messages']) == 1
        assert transcript['messages'][0]['text'] == CANARY+str(index)
    with sqlite3.connect(path) as db:
        assert db.execute('pragma integrity_check').fetchone() == ('ok',)
        assert db.execute('select count(*) from session_inbox').fetchone() == (1,)
    print('PASS: two chat histories, titles, pending input and a document survive outer-VM SIGKILL on nested LUKS', flush=True)
