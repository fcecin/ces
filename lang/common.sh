# Sourced by every lang/ script: shared paths, ports, wallet env.
# Assumes the tree was built with `./build.sh debug` from the repo root.

LANG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CES_ROOT="$(cd "${LANG_DIR}/.." && pwd)"
BUILD_DIR="${LANG_DIR}/build"

DEVNET_DIR="${BUILD_DIR}/devnet"
DATA_DIR="${DEVNET_DIR}/data"
WALLET="${DEVNET_DIR}/wallet.txt"
SERVER_LOG="${DEVNET_DIR}/server.log"
SERVER_PID="${DEVNET_DIR}/server.pid"
ENV_FILE="${DEVNET_DIR}/env.sh"

CES_BIN="${CES_ROOT}/build/debug/ces"
CESH_BIN="${CES_ROOT}/build/debug/cesh"
CESC_BIN="${CES_ROOT}/build/debug/cesc"

CES_PORT=53850

# Detach from any ambient cesh wallet -- the devnet manages its own.
unset CESH_WALLET

# Auto-load SERVER_PRIV / SERVER_PUB once devnet.sh has bootstrapped.
if [ -f "${ENV_FILE}" ]; then
  . "${ENV_FILE}"
fi
