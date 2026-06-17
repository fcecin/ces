#!/usr/bin/env bash
# Redeploy the cesweb gateway to a box (set HOST=user@server). ADDITIVE and SAFE:
# it never touches /opt/ces or restarts the CES server — cesweb is just a client.
#
# Assumes ONE-TIME SETUP is already done (see README.md):
#   - node + nginx installed (apt)
#   - /opt/cesweb/wallet.txt exists (the gateway wallet)
#   - nginx default site removed, cesweb site enabled
#   - ufw allows 80,443/tcp
#
# Usage:  HOST=user@server bash deploy.sh          # rsync app + cesh + unit + nginx, restart
#         SKIP_BUILD=1 HOST=user@server bash deploy.sh   # don't rebuild release first

set -euo pipefail

HOST="${HOST:?set HOST=user@server (the box to deploy to)}"
DOMAIN="${DOMAIN:?set DOMAIN=your.public.host (nginx server_name + TLS cert)}"
CESHOST="${CESHOST:-$DOMAIN}"   # the CES server cesweb fronts (default: the same host)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # ces/cesweb/deploy
CESWEB="${CESWEB:-$(cd "$HERE/.." && pwd)}"            # ces/cesweb
CES="${CES:-$(cd "$HERE/../.." && pwd)}"               # ces repo root

if [ "${SKIP_BUILD:-}" != "1" ]; then
  echo "==> building release cesh"
  ( cd "$CES" && ./build.sh release >/tmp/cesweb-deploy-build.log 2>&1 ) \
    || { echo "build failed; see /tmp/cesweb-deploy-build.log"; exit 1; }
fi

echo "==> shipping cesh + libs + app to /opt/cesweb"
ssh -o BatchMode=yes "$HOST" 'mkdir -p /opt/cesweb'
rsync -avzL \
  "$CES/build/release/cesh" \
  "$CES/build/release/_deps/randomx-build/librandomx.so" \
  "$CES/build/release/_deps/crc32c-build/libcrc32c.so.1" \
  "$HOST:/opt/cesweb/"
rsync -avz --delete "$CESWEB/src" "$CESWEB/package.json" "$HOST:/opt/cesweb/"
# Ship node_modules (the `ws` dep is pure JS — safe to rsync, no native build).
rsync -avz --delete "$CESWEB/node_modules" "$HOST:/opt/cesweb/"

echo "==> installing systemd unit + nginx site (rendering DOMAIN=$DOMAIN CESHOST=$CESHOST)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
sed "s/@@CESHOST@@/$CESHOST/g" "$HERE/cesweb.service"    > "$TMP/cesweb.service"
sed "s/@@DOMAIN@@/$DOMAIN/g"   "$HERE/nginx-cesweb.conf" > "$TMP/cesweb"
rsync -avz "$TMP/cesweb.service" "$HOST:/etc/systemd/system/cesweb.service"
rsync -avz "$TMP/cesweb"         "$HOST:/etc/nginx/sites-available/cesweb"

echo "==> restart cesweb + reload nginx (CES server untouched)"
ssh -o BatchMode=yes "$HOST" '
  systemctl daemon-reload
  systemctl restart cesweb
  ln -sf /etc/nginx/sites-available/cesweb /etc/nginx/sites-enabled/cesweb
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx
  sleep 1
  systemctl is-active cesweb nginx
  curl -s -o /dev/null -w "self-check :80 redirect -> HTTP %{http_code}\n" http://localhost/p/site/index.html || true
'
[ -n "$DOMAIN" ] && curl -s -o /dev/null -w "self-check https://$DOMAIN -> HTTP %{http_code}\n" "https://$DOMAIN/p/site/index.html" || true
echo "==> done.${DOMAIN:+ https://$DOMAIN/p/site/index.html}"
