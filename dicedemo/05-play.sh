#!/usr/bin/env bash
# Place a bet and roll. Two-step:
#   1. transfer BET from client (@0) to the house (server pubkey)
#   2. dial the dice instance, send `play`, then `quit` to close
# Dice reads `lastXferAmount` for the bet, flips a fair coin via
# ces.random_bytes, and either pays 2×BET back (heads) or keeps it
# (tails). Re-run this script to play another round.
#
# Usage: ./05-play.sh [BET]   (default BET=100; minimum 1, no upper
# cap — the transfer layer enforces "can't bet more than you have").
set -euo pipefail
. "$(dirname "$0")/common.sh"

if [ ! -f "${WALLET}" ]; then
  echo "error: wallet not set up — run ./03-wallet.sh first." >&2
  exit 1
fi

BET="${1:-100}"
if ! [[ "${BET}" =~ ^[0-9]+$ ]] || [ "${BET}" -lt 1 ]; then
  echo "error: bet must be a positive integer; got '${BET}'" >&2
  exit 1
fi
echo "bet: ${BET}"

INSTANCE=$( "${CESH_BIN}" \
  -r "${WALLET}" \
  --server localhost:${CES_PORT} \
  --rpc-port ${CES_RPC_PORT} \
  -a @0 \
  compute instances /s/dice.lua | head -1 )

if [ -z "${INSTANCE}" ]; then
  echo "error: no /s/dice.lua instance found." >&2
  echo "       check ./workspace/server.log for builtin_app launch failures." >&2
  exit 1
fi
echo "dice instance id: ${INSTANCE}"

"${CESH_BIN}" \
  -r "${WALLET}" \
  --server localhost:${CES_PORT} \
  -a @0 \
  transfer "${SERVER_PUB}" "${BET}"

echo
echo "--- dialing dice ---"
printf 'play\nquit\n' | "${CESH_BIN}" \
  -r "${WALLET}" \
  --server localhost:${CES_PORT} \
  --rpc-port ${CES_RPC_PORT} \
  -a @0 \
  dial "${INSTANCE}"

echo
echo "--- balances after the round ---"
echo
echo "client (@0):"
"${CESH_BIN}" \
  -r "${WALLET}" \
  --server localhost:${CES_PORT} \
  query @0
echo
echo "house (@1, server's account — auto-topped to 2^62 each boot):"
"${CESH_BIN}" \
  -r "${WALLET}" \
  --server localhost:${CES_PORT} \
  query @1

echo
echo "run ./05-play.sh [BET] again to bet again. when done: ./99-stop-server.sh"
