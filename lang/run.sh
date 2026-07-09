#!/usr/bin/env bash
# Compile one example, deploy it on the devnet, and execute it via
# CES_RUN_ASSET. Programs up to 210 bytes deploy as one asset; larger
# ones deploy as a bundle (chunk assets + key tables + boot loader).
# Extra args pass through to `cesh asset run` (e.g. --input <hex>,
# --allowance <credits>).
#
#   ./run.sh answer.casm
#   ./run.sh vault.cesl --input 0500000000000000 --allowance 500
#   ./run.sh cruncher.cesl        # 399 bytes: bundle deployment
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

NAME="$(basename "${SRC}")-$$-${RANDOM}"
CESH="${CESH_BIN} -r ${WALLET} --server localhost:${CES_PORT}"

# Fits one asset? --boot pads to the 210-byte content. Otherwise
# cesc --bundle plus `cesh asset deploy-bundle` (chunks, key tables,
# boot loader). A fresh salt per run keeps the deterministic keys from
# colliding with earlier deployments of the same program.
if HEX=$("${CESC_BIN}" "${SRC}" --boot --hex 2>/dev/null); then
  echo "deploying ${SRC} as asset '${NAME}'"
  ${CESH} asset create "${NAME}" --hexcontent "${HEX}" --days 2 >/dev/null
else
  OUT="${BUILD_DIR}/bundle-$$"
  "${CESC_BIN}" "${SRC}" --bundle "${OUT}" --salt "$$-${RANDOM}"
  echo "deploying ${SRC} as bundle '${NAME}'"
  ${CESH} asset deploy-bundle "${NAME}" "${OUT}" --days 2 >/dev/null
fi

${CESH} asset run "${NAME}" --budget 1000000000 "$@"
