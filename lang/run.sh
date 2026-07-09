#!/usr/bin/env bash
# Compile one example, deploy it as an asset on the devnet, and execute
# it via CES_RUN_ASSET. Extra args pass through to `cesh asset run`
# (e.g. --input <hex>, --allowance <credits>).
#
#   ./run.sh answer.casm
#   ./run.sh fib.cesl
#   ./run.sh vault.cesl --input 0500000000000000 --allowance 500
set -euo pipefail
. "$(dirname "$0")/common.sh"

if [ $# -lt 1 ]; then
  echo "usage: $0 <example.casm|.cesl> [cesh asset run args...]" >&2
  exit 1
fi
SRC="$1"
shift
if [ ! -f "${SRC}" ]; then
  SRC="${LANG_DIR}/examples/${SRC}"
fi
if [ ! -f "${SRC}" ]; then
  echo "error: no such source file or example: $1" >&2
  exit 1
fi
if ! { [ -f "${SERVER_PID}" ] && kill -0 "$(cat "${SERVER_PID}")" 2>/dev/null; }; then
  echo "error: devnet not running -- ./devnet.sh up first" >&2
  exit 1
fi

# --boot pads/enforces the single-asset shape; --hex prints the 210-byte
# content the asset gets created with. Programs past 210 bytes need the
# bundle deployment (cesc --bundle), which this script does not drive.
HEX=$("${CESC_BIN}" "${SRC}" --boot --hex)

NAME="$(basename "${SRC}")-$$-${RANDOM}"
echo "deploying ${SRC} as asset '${NAME}'"
"${CESH_BIN}" -r "${WALLET}" --server localhost:${CES_PORT} \
  asset create "${NAME}" --hexcontent "${HEX}" --days 2 >/dev/null

"${CESH_BIN}" -r "${WALLET}" --server localhost:${CES_PORT} \
  asset run "${NAME}" --budget 1000000000 "$@"
