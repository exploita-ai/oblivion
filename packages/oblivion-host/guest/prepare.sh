#!/bin/sh
set -eu
umask 077
mountpoint -q /vault
mkdir -p /vault/home /vault/workspace /vault/state /vault/config /tmp/oblivion-cache
chown 1000:1000 /vault/home /vault/workspace /vault/state /vault/config /tmp/oblivion-cache
chmod 0700 /vault/home /vault/workspace /vault/state /vault/config /tmp/oblivion-cache
mkdir -p /vault/home/.oblivion-history
chown 1000:1000 /vault/home/.oblivion-history
chmod 0700 /vault/home/.oblivion-history
mkdir -p /vault/home/.oblivion-file-staging
chown 1000:1000 /vault/home/.oblivion-file-staging
chmod 0700 /vault/home/.oblivion-file-staging
mkdir -p /vault/.oblivion-inbox /vault/imports
chown 1001:1000 /vault/.oblivion-inbox /vault/imports
chmod 0700 /vault/.oblivion-inbox
chmod 0750 /vault/imports
