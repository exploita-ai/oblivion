#!/bin/sh
# Debian owns these OS preferences; this launcher supplies no settings catalog.
set -eu
export HOME=/ TERM=linux LANG=C.UTF-8 LC_ALL=C.UTF-8
umask 077
case "${1:-}" in
    keyboard) title='Keyboard'; package=keyboard-configuration ;;
    timezone) title='Time zone'; package=tzdata ;;
    *) exit 2 ;;
esac
exec 9>/run/oblivion-os-config.lock
while :; do
    printf '\033[2J\033[H%s — Debian Live\n\n' "$title"
    printf 'Press Enter to open the Debian configuration dialog.\n'
    printf 'Ctrl+Alt+F1 returns to Oblivion. Changes last for this boot.\n\n'
    IFS= read -r answer || exit 0
    if ! /usr/bin/flock -n 9; then
        printf 'Finish the configuration on the other console, then press Enter.\n'
        IFS= read -r answer || exit 0
        continue
    fi
    status=0
    /usr/sbin/dpkg-reconfigure --frontend=dialog "$package" || status=$?
    if [ "$status" = 0 ] && [ "$package" = keyboard-configuration ]; then
        /usr/bin/setupcon --keyboard-only || status=$?
        /usr/bin/systemctl start oblivion-live-keymap.service || status=$?
    fi
    /usr/bin/flock -u 9
    if [ "$status" = 0 ]; then
        printf '\nDebian preferences updated. Press Enter to return.\n'
    else
        printf '\nConfiguration was not fully applied. Press Enter to retry.\n'
    fi
    IFS= read -r answer || exit 0
done
