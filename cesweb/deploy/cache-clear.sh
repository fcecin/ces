#!/usr/bin/env bash
# Wipe the cesweb content cache on a deployed box, so the next request for every
# path re-fetches from CES. ADDITIVE + SAFE: touches only /opt/cesweb (the
# gateway) — never /opt/ces or the running CES server.
#
# cesweb already revalidates cached files against CES via L2 STAT (size +
# modifiedUs) on a short TTL, so ordinary content changes refresh on their own.
# Use this only to FORCE an immediate whole-cache refresh — e.g. after an
# out-of-band content swap that kept the same size and mtime, which STAT cannot
# see. It stops the gateway, clears the cache dir, and starts it again (the
# engine boots with an empty, consistent index); in-flight fetches and open
# /dev/dial terminals are dropped for ~1 s.
#
# Usage:  HOST=user@server bash cache-clear.sh
#         HOST=user@server CACHE_DIR=/opt/cesweb/cache SERVICE=cesweb bash cache-clear.sh

set -euo pipefail

HOST="${HOST:?set HOST=user@server (the deployed cesweb box)}"
CACHE_DIR="${CACHE_DIR:-/opt/cesweb/cache}"
SERVICE="${SERVICE:-cesweb}"

# Guard the rm: never wipe a broad or wrong target.
case "$CACHE_DIR" in
  ""|/|/opt|/opt/ces|/opt/ces/*|/opt/cesweb|/root|/home|/etc|/var|/usr|/bin|/boot)
    echo "refusing CACHE_DIR='$CACHE_DIR' (unsafe target)" >&2; exit 1;;
esac
[ "${CACHE_DIR#/}" != "$CACHE_DIR" ] || { echo "CACHE_DIR must be absolute: '$CACHE_DIR'" >&2; exit 1; }

echo "==> cesweb cache clear on $HOST  (dir=$CACHE_DIR service=$SERVICE)"
ssh -o BatchMode=yes "$HOST" "
  set -e
  echo '-- before --'; du -sh '$CACHE_DIR' 2>/dev/null || echo '(no cache dir)'
  systemctl stop '$SERVICE'
  rm -rf -- '$CACHE_DIR'
  mkdir -p -- '$CACHE_DIR'
  systemctl start '$SERVICE'
  sleep 1
  echo '-- after --'; systemctl is-active '$SERVICE'; du -sh '$CACHE_DIR' 2>/dev/null || true
"
echo "==> done. cache cleared; next request per path re-fetches from CES."
