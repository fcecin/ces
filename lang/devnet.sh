#!/usr/bin/env bash
# One-command local playground server: a no-PoW ces server plus a
# funded wallet, everything under lang/build/devnet (gitignored).
#
#   ./devnet.sh up       start (bootstraps key, wallet, funding on first run)
#   ./devnet.sh down     stop
#   ./devnet.sh status   pid / wallet / balance
#
# Wallet slots: @0 = you (funded), @1 = the server key (bottomless donor).
set -euo pipefail
. "$(dirname "$0")/common.sh"

server_alive() {
  [ -f "${SERVER_PID}" ] && kill -0 "$(cat "${SERVER_PID}")" 2>/dev/null
}

up() {
  if [ ! -x "${CES_BIN}" ] || [ ! -x "${CESH_BIN}" ]; then
    echo "error: ces / cesh not built. run \`./build.sh debug\` from ${CES_ROOT}" >&2
    exit 1
  fi
  if server_alive; then
    echo "devnet already running (pid $(cat "${SERVER_PID}"))"
    exit 0
  fi

  if [ ! -f "${ENV_FILE}" ]; then
    mkdir -p "${DATA_DIR}"
    "${CES_BIN}" --genkeypair > "${DEVNET_DIR}/server-keys.txt"
    SERVER_PRIV=$(awk -F': *' '/Private/{print $2}' "${DEVNET_DIR}/server-keys.txt")
    SERVER_PUB=$(awk -F': *'  '/Public/{print  $2}' "${DEVNET_DIR}/server-keys.txt")
    cat > "${ENV_FILE}" <<EOF
export SERVER_PRIV="${SERVER_PRIV}"
export SERVER_PUB="${SERVER_PUB}"
EOF
    : > "${WALLET}"
    "${CESH_BIN}" -r "${WALLET}" keys gen -w "${WALLET}" 1
    "${CESH_BIN}" -r "${WALLET}" keys add "${SERVER_PRIV}" -w "${WALLET}"
  fi
  . "${ENV_FILE}"

  "${CES_BIN}" \
    --datadir "${DATA_DIR}" \
    --port ${CES_PORT} \
    --serverkey "${SERVER_PRIV}" \
    --nopowengine \
    > "${SERVER_LOG}" 2>&1 &
  echo $! > "${SERVER_PID}"

  for _ in $(seq 1 20); do
    if "${CESH_BIN}" --server localhost:${CES_PORT} ping >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
  if ! "${CESH_BIN}" --server localhost:${CES_PORT} ping >/dev/null 2>&1; then
    echo "error: server did not come up; last log lines:" >&2
    tail -15 "${SERVER_LOG}" >&2
    exit 1
  fi

  # Top up @0 from the server's bottomless account (idempotent enough
  # for a playground; every `up` adds another 10,000 credits).
  "${CESH_BIN}" -r "${WALLET}" --server localhost:${CES_PORT} \
    -a @1 transfer @0 1000000000000 --open >/dev/null

  echo "devnet up (pid $(cat "${SERVER_PID}"), port ${CES_PORT})"
  "${CESH_BIN}" -r "${WALLET}" --server localhost:${CES_PORT} query @0
  echo
  echo "try: ./run.sh answer.casm"
}

down() {
  if ! server_alive; then
    echo "devnet not running"
    rm -f "${SERVER_PID}"
    exit 0
  fi
  kill "$(cat "${SERVER_PID}")"
  rm -f "${SERVER_PID}"
  echo "devnet stopped"
}

status() {
  if server_alive; then
    echo "devnet running (pid $(cat "${SERVER_PID}"), port ${CES_PORT})"
    "${CESH_BIN}" -r "${WALLET}" --server localhost:${CES_PORT} query @0
  else
    echo "devnet not running"
  fi
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 up|down|status" >&2; exit 1 ;;
esac
