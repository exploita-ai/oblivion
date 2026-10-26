#!/bin/sh
set -eu
test "$(id -u)" = 1000
# Build channels must never select a different conversation history. Migration
# runs inside the session VM, before the provider capability is loaded.
OPENCODE_DB=$(/usr/bin/python3 /usr/lib/oblivion/guest/chat-database.py)
export OPENCODE_DB
# A revocable local capability is intentionally available to this session's
# tools. No infrastructure credential or arbitrary endpoint is supplied here.
ABLIT_KEY=$(cat /run/oblivion-api/token)
export ABLIT_KEY
# Proxy-aware tools share only this opening's revocable capability. Programs
# that ignore these variables still have no direct route through the gateway.
HTTP_PROXY="http://oblivion-tools:${ABLIT_KEY}@10.88.0.1:8112"
HTTPS_PROXY=$HTTP_PROXY
ALL_PROXY=$HTTP_PROXY
http_proxy=$HTTP_PROXY
https_proxy=$HTTP_PROXY
all_proxy=$HTTP_PROXY
# Keep the local API broker and this guest's own server on their local paths.
NO_PROXY='127.0.0.1,localhost,::1,10.88.0.1:8111'
no_proxy=$NO_PROXY
export HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy NO_PROXY no_proxy
export OPENCODE_CONFIG_CONTENT='{"model":"abliteration-ai/abliterated-model","snapshots":false,"providers":{"abliteration-ai":{"settings":{"baseURL":"http://10.88.0.1:8111/v1"}}}}'
exec /usr/bin/python3 /usr/lib/oblivion/guest/console.py /usr/bin/oblivion "$@" --standalone
