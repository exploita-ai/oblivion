#!/bin/sh
# Laboratory console only. Optional chat probe executes the actual CLI, not the TUI.
set -eu
trap '[ "$?" = 0 ] || printf "OBLIVION_GUEST_PROBE_FAILED\n"' EXIT
printf 'OBLIVION_GUEST_READY\n'
while IFS= read -r command; do
    case "$command" in
        ready) printf 'OBLIVION_GUEST_READY\n' ;;
        model-initial|model-alternate)
            python3 - "$command" <<'PY'
import http.client, json, sys
from pathlib import Path
token = Path('/run/oblivion-api/token').read_text()
client = http.client.HTTPConnection('10.88.0.1', 8111, timeout=20)
client.request('POST', '/v1/chat/completions', json.dumps({'model': 'abliterated-model', 'stream': True,
    'messages': [{'role': 'user', 'content': 'OBLIVION_KEY_PROBE'}]}),
    {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
response = client.getresponse()
assert response.status == 200
assert ('OBLIVION_KEY_' + sys.argv[1].removeprefix('model-')).encode() in response.read()
client.close()
print('OBLIVION_MODEL_KEY_VERIFIED')
PY
            ;;
        network-ok|network-blocked)
            python3 - "$command" <<'PY'
import sys, urllib.request
from pathlib import Path
token = Path('/run/oblivion-api/token').read_text()
client = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://oblivion-tools:' + token + '@10.88.0.1:8112'}))
try:
    with client.open('http://api.abliteration.ai/shell', timeout=10) as response:
        assert response.read() == b'OBLIVION_WEB_SHELL\n'
except OSError:
    assert sys.argv[1] == 'network-blocked'
else:
    assert sys.argv[1] == 'network-ok'
print('OBLIVION_NETWORK_VERIFIED')
PY
            ;;
        probe)
            [ "$(id -u)" = 1000 ]
            [ ! -e /run/oblivion/general ]
            [ ! -e /dev/mapper/oblivion-general ]
            [ ! -r /dev/vdb ]
            [ "$(wc -l < /proc/swaps)" = 1 ]
            if touch /etc/oblivion-write 2>/dev/null; then exit 1; fi
            grep -q ' / overlay rw,' /proc/mounts
            [ "$(sudo -n id -u)" = 0 ]
            grep -q ' /tmp tmpfs ' /proc/mounts
            grep -q ' /var/log tmpfs ' /proc/mounts
            grep -q ' /var/tmp tmpfs ' /proc/mounts
            [ "$(ls /sys/class/net)" = lo ]
            systemctl show systemd-logind.service --property=ActiveState,SubState,Result
            systemctl show systemd-udevd.service --property=ActiveState,SubState,Result
            cat /proc/bus/input/devices
            ls -l /dev/input || true
            ls -d /sys/firmware/devicetree/base/gpio-keys || true
            cat /proc/modules
            printf 'OBLIVION_GUEST_CONFINED\n'
            ;;
        write-a)
            printf OBLIVION_VM_A_CANARY_4d02 > /vault/workspace/document.txt
            printf OBLIVION_VM_TEMP_CANARY_d9ae > /tmp/session-temporary
            printf OBLIVION_VM_TEMP_CANARY_d9ae > /var/tmp/session-temporary
            setsid sh -c 'while :; do sleep 1; done' > /dev/null 2>&1 &
            printf '%s' "$!" > /tmp/detached-worker
            sync
            printf 'OBLIVION_A_WRITTEN\n'
            ;;
        check-b)
            [ ! -e /vault/workspace/document.txt ]
            [ ! -e /tmp/session-temporary ]
            [ ! -e /var/tmp/session-temporary ]
            [ ! -e /tmp/detached-worker ]
            printf OBLIVION_VM_B_CANARY_b0ca > /vault/workspace/other.txt
            sync
            printf 'OBLIVION_B_ISOLATED\n'
            ;;
        check-a)
            [ "$(cat /vault/workspace/document.txt)" = OBLIVION_VM_A_CANARY_4d02 ]
            [ ! -e /vault/workspace/other.txt ]
            [ ! -e /tmp/session-temporary ]
            [ ! -e /var/tmp/session-temporary ]
            [ ! -e /tmp/detached-worker ]
            printf 'OBLIVION_A_RESTORED\n'
            ;;
        imports-empty)
            [ -z "$(ls -A /vault/imports)" ]
            [ ! -r /vault/.oblivion-inbox ]
            printf 'OBLIVION_IMPORTS_EMPTY\n'
            ;;
        terminal-live)
            systemctl show oblivion-terminal.service --property=ActiveState,SubState,Result
            tmux -S /run/oblivion-terminal/tmux.sock list-clients -F '#{client_tty}'
            [ "$(systemctl is-active oblivion-terminal.service)" = active ]
            kill -0 "$(cat /run/oblivion-terminal/controller-pid)"
            printf 'OBLIVION_TERMINAL_JOB_ALIVE\n'
            ;;
        imports-check)
            set -- /vault/imports/*
            [ "$#" = 1 ]
            [ "$(cat "$1/files/documenti/note.txt")" = OBLIVION_USB_SELECTED_CANARY_82f1 ]
            [ -d "$1/files/documenti/vuota" ]
            [ "$(cat "$1/files/documenti/caffè.txt")" = OBLIVION_USB_SELECTED_CANARY_82f1 ]
            [ ! -e "$1/files/unselected.txt" ]
            [ ! -r /vault/.oblivion-inbox ]
            if touch /vault/imports/chat-created 2>/dev/null; then exit 1; fi
            printf OBLIVION_USB_EDIT_CANARY_1b72 > "$1/files/documenti/note.txt"
            sync
            printf 'OBLIVION_IMPORT_VERIFIED\n'
            ;;
        imports-resumed)
            set -- /vault/imports/*
            [ "$#" = 1 ]
            [ "$(cat "$1/files/documenti/note.txt")" = OBLIVION_USB_EDIT_CANARY_1b72 ]
            [ ! -r /vault/.oblivion-inbox ]
            printf 'OBLIVION_IMPORT_RESUMED\n'
            ;;
        imports-roundtrip)
            set -- /vault/imports/*
            [ "$#" = 2 ]
            [ "$(find /vault/imports -name note.txt | wc -l)" = 2 ]
            [ "$(find /vault/imports -name note.txt -exec cat '{}' \;)" = OBLIVION_USB_EDIT_CANARY_1b72OBLIVION_USB_EDIT_CANARY_1b72 ]
            [ "$(find /vault/imports -name caffè.txt | wc -l)" = 2 ]
            [ "$(find /vault/imports -name caffè.txt -exec cat '{}' \;)" = OBLIVION_USB_SELECTED_CANARY_82f1OBLIVION_USB_SELECTED_CANARY_82f1 ]
            printf 'OBLIVION_IMPORT_ROUNDTRIP\n'
            ;;
        export-faults)
            mkdir -p /vault/workspace/collision /vault/workspace/space
            printf first > /vault/workspace/collision/note.txt
            printf second > /vault/workspace/collision/NOTE.txt
            dd if=/dev/zero of=/vault/workspace/space/large.txt bs=1M count=8 2>/dev/null
            sync
            printf 'OBLIVION_EXPORT_FAULTS_READY\n'
            ;;
        export-originals)
            [ "$(cat /vault/workspace/collision/note.txt)" = first ]
            [ "$(cat /vault/workspace/collision/NOTE.txt)" = second ]
            [ "$(stat -c %s /vault/workspace/space/large.txt)" = 8388608 ]
            printf 'OBLIVION_EXPORT_ORIGINALS\n'
            ;;
        chat-a|chat-b|chat-resume)
            python3 /usr/libexec/oblivion-chat-probe "$command"
            ;;
        *) exit 1 ;;
    esac
done
