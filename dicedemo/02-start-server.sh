#!/usr/bin/env bash
# Start ces in the background. All knobs as CLI flags (no TOML).
# Logs to ./workspace/server.log.
set -euo pipefail
. "$(dirname "$0")/common.sh"

if [ ! -f "${ENV_FILE}" ]; then
  echo "error: workspace not initialized — run ./01-setup.sh first." >&2
  exit 1
fi
if [ -f "${SERVER_PID}" ] && kill -0 "$(cat "${SERVER_PID}")" 2>/dev/null; then
  echo "error: server already running (pid $(cat "${SERVER_PID}"))." >&2
  echo "       run ./99-stop-server.sh first." >&2
  exit 1
fi

"${CES_BIN}" \
  --datadir "${DATA_DIR}" \
  --port ${CES_PORT} \
  --serverkey "${SERVER_PRIV}" \
  --nopowengine \
  --rpcport ${CES_RPC_PORT} \
  --filestoremaxbytes 104857600 \
  --computemaxinstances 8 \
  --computeuser "${USER}" \
  --cesplexmount /ces/file/1=builtin:file \
  --cesplexmount /ces/compute/1=builtin:compute \
  --cesplexmount /ces/lua/1=builtin:lua \
  --extension dice \
  > "${SERVER_LOG}" 2>&1 &
echo $! > "${SERVER_PID}"
sleep 3

echo "server started (pid $(cat "${SERVER_PID}")) — log: ${SERVER_LOG}"
echo
echo "--- last 25 lines of server.log ---"
tail -25 "${SERVER_LOG}"
echo
echo "look for 'extension launched dice'. if you see that, dice is up."
echo "next: ./03-wallet.sh"
