#!/bin/sh
# Sourced only inside the guest. This is an opening-scoped tool capability,
# never the real provider key, and is kept solely in the process environment.
oblivion_tools_token=$(cat /run/oblivion-api/token)
test "${#oblivion_tools_token}" = 64
printf '%s' "$oblivion_tools_token" | LC_ALL=C grep -Eq '^[a-f0-9]{64}$'
HTTP_PROXY="http://oblivion-tools:${oblivion_tools_token}@10.88.0.1:8112"
HTTPS_PROXY=$HTTP_PROXY
ALL_PROXY=$HTTP_PROXY
http_proxy=$HTTP_PROXY
https_proxy=$HTTP_PROXY
all_proxy=$HTTP_PROXY
NO_PROXY='127.0.0.1,localhost,::1,10.88.0.1:8111'
no_proxy=$NO_PROXY
export HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy NO_PROXY no_proxy
unset oblivion_tools_token
