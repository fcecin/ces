#!/usr/bin/env bash
# Build the demo wallet:
#   slot @0 = a fresh client key (the dice player)
#   slot @1 = the server's own privkey
# Slot @1 is how cesh acts as the server's bottomless donor in the
# next step — no special-case "server credit" command needed.
set -euo pipefail
. "$(dirname "$0")/common.sh"

if [ ! -f "${ENV_FILE}" ]; then
  echo "error: workspace not initialized — run ./01-setup.sh first." >&2
  exit 1
fi

# Detach from any ambient wallet (env var or ~/.cesh/CESH_WALLET).
# Without this, `cesh keys gen` and `cesh keys add` would silently
# load an existing wallet, then `-w WALLET` would write the merged
# result here — which both leaks the user's home keys into this
# demo and loses our freshly-generated client key on the second
# command. The demo wallet must be self-contained.
unset CESH_WALLET
: > "${WALLET}"   # truthful empty file so `-r WALLET` has something to load

# @0 = fresh client key. -r is the demo wallet so no home wallet leaks in.
"${CESH_BIN}" -r "${WALLET}" keys gen -w "${WALLET}" 1

# @1 = server's privkey, appended to the same wallet.
"${CESH_BIN}" -r "${WALLET}" keys add "${SERVER_PRIV}" -w "${WALLET}"

echo
echo "--- wallet contents (priv (pub)) ---"
"${CESH_BIN}" -r "${WALLET}" keys list --public
echo
echo "@1's pubkey above should match the house pubkey from 01-setup.sh:"
echo "  ${SERVER_PUB}"
echo
echo "slot @0 = client (dice player)"
echo "slot @1 = server (the donor)"
echo
echo "next: ./04-fund.sh"
