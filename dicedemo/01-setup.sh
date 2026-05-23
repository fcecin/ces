#!/usr/bin/env bash
# Wipe & recreate ./workspace, generate the server keypair, and copy
# /s/dice.lua into the file store. Run this first.
set -euo pipefail
. "$(dirname "$0")/common.sh"

if [ ! -x "${CES_BIN}" ] || [ ! -x "${CESH_BIN}" ]; then
  echo "error: ces / cesh not built." >&2
  echo "  run \`./build.sh debug\` from ${CES_ROOT}" >&2
  exit 1
fi

rm -rf "${WORKSPACE}"
mkdir -p "${DATA_DIR}/cesfilestore/s"
cp "${DICE_LUA}" "${DATA_DIR}/cesfilestore/s/dice.lua"

"${CES_BIN}" --genkeypair > "${WORKSPACE}/server-keys.txt"
SERVER_PRIV=$(awk -F': *' '/Private/{print $2}' "${WORKSPACE}/server-keys.txt")
SERVER_PUB=$(awk -F': *'  '/Public/{print  $2}' "${WORKSPACE}/server-keys.txt")

cat > "${ENV_FILE}" <<EOF
export SERVER_PRIV="${SERVER_PRIV}"
export SERVER_PUB="${SERVER_PUB}"
EOF

echo "workspace:                ${WORKSPACE}"
echo "server pubkey (= house):  ${SERVER_PUB}"
echo
echo "next: ./02-start-server.sh"
