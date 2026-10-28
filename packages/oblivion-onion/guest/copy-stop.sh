#!/bin/sh
set -eu
# A failed endpoint cannot leave an unattended private copy channel alive.
if [ "${SERVICE_RESULT:-unknown}" != success ]; then
    /usr/bin/systemctl --no-block poweroff
fi
