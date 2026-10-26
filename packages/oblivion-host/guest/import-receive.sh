#!/bin/sh
set -eu
umask 077
exec 3<>"$1"
printf 'ready\n' >&3
case "$(dd bs=1 count=1 <&3 2>/dev/null)" in
    G) exec /usr/bin/oblivion-copy import /vault/.oblivion-inbox /vault/imports 300000 ;;
    R) exec /usr/bin/oblivion-copy recover /vault/.oblivion-inbox /vault/imports 300000 ;;
    *) exit 1 ;;
esac
