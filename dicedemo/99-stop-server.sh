#!/usr/bin/env bash
# Stop the demo server. Workspace is left intact for inspection.
set -euo pipefail
. "$(dirname "$0")/common.sh"

if [ ! -f "${SERVER_PID}" ]; then
  echo "no server.pid — nothing to stop."
  exit 0
fi
PID=$(cat "${SERVER_PID}")
if kill -0 "${PID}" 2>/dev/null; then
  kill "${PID}"
  sleep 1
  if kill -0 "${PID}" 2>/dev/null; then
    kill -9 "${PID}"
  fi
  echo "stopped pid ${PID}"
else
  echo "pid ${PID} not running"
fi
rm -f "${SERVER_PID}"
