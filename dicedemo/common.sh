# Sourced by every dicedemo script. Defines shared paths and ports.
# Hardcoded `..` for the binaries — assumes scripts are run from
# inside dicedemo/ on a project tree that's been built via:
#   ./build.sh debug

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${DEMO_DIR}/workspace"
DATA_DIR="${WORKSPACE}/data"
WALLET="${WORKSPACE}/wallet.txt"
SERVER_LOG="${WORKSPACE}/server.log"
SERVER_PID="${WORKSPACE}/server.pid"
ENV_FILE="${WORKSPACE}/env.sh"

CES_ROOT="$(cd "${DEMO_DIR}/.." && pwd)"
CES_BIN="${CES_ROOT}/build/debug/ces"
CESH_BIN="${CES_ROOT}/build/debug/cesh"
DICE_LUA="${CES_ROOT}/src/ceslib/builtin_apps/dice.lua"

CES_PORT=53830
CES_RPC_PORT=53831

# Detach from any ambient cesh wallet — the demo manages its own.
unset CESH_WALLET

# Auto-load SERVER_PRIV / SERVER_PUB once 01-setup.sh has run.
if [ -f "${ENV_FILE}" ]; then
  . "${ENV_FILE}"
fi
