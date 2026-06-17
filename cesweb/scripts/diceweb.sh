#!/usr/bin/env bash
# diceweb e2e — the authoritative "cesweb signs, real CES verifies" check.
#
# Boots the CES dicedemo (a real CES server + the /s/dice Lua L2 program),
# starts cesweb against it, and plays a full dice round through the web terminal
# over a WebSocket. This is the ONLY test that runs cesweb's JS signing
# (src/cessign.js) against a real CES server: cesweb signs the CesPlex bind +
# ATTACH, cesh --extsign tunnels the signatures, and the server cryptographically
# verifies them. If the JS digest format ever drifted from CES, the round fails.
#
# Requires a built CES tree (ces / cesh / cesluajitd) at $CES_ROOT/build/debug
# and the dicedemo scripts at $CES_ROOT/dicedemo. Not part of `npm test` (that
# stays fast + CES-free via the fake cesh); run this manually:  bash scripts/diceweb.sh
set -uo pipefail
# cesweb lives at ces/cesweb, so the CES repo root is two levels up.
CES_ROOT="${CES_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DEMO="$CES_ROOT/dicedemo"
CESH="$CES_ROOT/build/debug/cesh"
CESWEB="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBPID=""

[ -x "$CESH" ] || { echo "no cesh at $CESH — build CES first (./build.sh debug)"; exit 1; }
[ -d "$DEMO" ] || { echo "no dicedemo at $DEMO"; exit 1; }

cleanup() {
  [ -n "$WEBPID" ] && kill "$WEBPID" 2>/dev/null || true
  ( cd "$DEMO" && ./99-stop-server.sh ) 2>/dev/null || true
}
trap cleanup EXIT

cd "$DEMO"
./01-setup.sh        >/tmp/diceweb-01.log 2>&1 || { echo "setup failed";  tail /tmp/diceweb-01.log; exit 1; }
./02-start-server.sh >/tmp/diceweb-02.log 2>&1 || { echo "server failed"; tail /tmp/diceweb-02.log; exit 1; }
grep -q "builtin_app launched" /tmp/diceweb-02.log || { echo "dice did not launch"; tail -20 /tmp/diceweb-02.log; exit 1; }
./03-wallet.sh       >/tmp/diceweb-03.log 2>&1 || { echo "wallet failed";  tail /tmp/diceweb-03.log; exit 1; }
./04-fund.sh         >/tmp/diceweb-04.log 2>&1 || { echo "fund failed";    tail /tmp/diceweb-04.log; exit 1; }
. ./common.sh

PID=$( "$CESH" -r "$WALLET" --server localhost:$CES_PORT --rpc-port $CES_RPC_PORT -a @0 \
        compute instances /s/dice.lua | head -1 )
[ -n "$PID" ] || { echo "no dice instance"; exit 1; }
PKEY=$(sed -n '1p' "$WALLET")
echo "dice pid=$PID"

cd "$CESWEB"
CESWEB_PORT=0 CESWEB_BIND=127.0.0.1 CESWEB_CESH="$CESH" \
  CESWEB_DEFAULT_HOST=localhost CESWEB_DEFAULT_CES_PORT=$CES_PORT \
  CESWEB_ALLOW_HOSTS=localhost CESWEB_ALLOW_PRIVATE_HOSTS=1 \
  node src/server.js >/tmp/diceweb-web.log 2>&1 &
WEBPID=$!
sleep 1.5
WEBPORT=$(grep -oE 'http://127\.0\.0\.1:[0-9]+' /tmp/diceweb-web.log | head -1 | grep -oE '[0-9]+$')
[ -n "$WEBPORT" ] || { echo "cesweb did not start"; cat /tmp/diceweb-web.log; exit 1; }

echo "=== playing dice over the web terminal (cesweb signs; real CES verifies) ==="
WS_PORT=$WEBPORT WS_PID=$PID WS_KEY=$PKEY \
  CESH="$CESH" WALLET="$WALLET" CES_PORT=$CES_PORT \
  node scripts/diceweb-client.mjs
RC=$?
echo "=== diceweb e2e exit: $RC ==="
exit $RC
