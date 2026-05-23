#!/usr/bin/env bash
# Donate 1T raw credits (~10,000 user-credits) from the server
# (slot @1) to the client (slot @0). The server's account is
# auto-topped to 2^62 every boot, so it's bottomless. --open
# auto-creates the client's account on first transfer.
set -euo pipefail
. "$(dirname "$0")/common.sh"

if [ ! -f "${WALLET}" ]; then
  echo "error: wallet not set up — run ./03-wallet.sh first." >&2
  exit 1
fi

"${CESH_BIN}" \
  -r "${WALLET}" \
  --server localhost:${CES_PORT} \
  -a @1 \
  transfer @0 1000000000000 --open

echo
echo "--- client (@0) account ---"
"${CESH_BIN}" \
  -r "${WALLET}" \
  --server localhost:${CES_PORT} \
  query @0

echo
echo "next: ./05-play.sh"
