#!/usr/bin/env bash
# Stand up a LONG-RUNNING local CES box + cesweb gateway, pre-loaded with a
# small sample site, for browsing in a real browser. Stays up until killed
# (Ctrl-C / TaskStop). Engine-free (instant boot).
#
#   CES server : localhost:53830  (rpc 53831)   -- file store on, no PoW engine
#   gateway    : http://localhost:8088
#   site       : /p/site/...   (served at /localhost/p/site/...)

set -euo pipefail

# cesweb lives at ces/cesweb, so the CES build is two levels up (ces/build/debug).
CES_DIR="${CES_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/build/debug}"
CES="$CES_DIR/ces"; CESH="$CES_DIR/cesh"
CESPORT="${CESPORT:-53830}"; RPCPORT="${RPCPORT:-53831}"; WEBPORT="${WEBPORT:-8088}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[ -x "$CES" ] && [ -x "$CESH" ] || { echo "build CES first (need $CES and $CESH)"; exit 1; }
command -v node >/dev/null || { echo "node not found"; exit 1; }

WORK="$HERE/demo-work"; rm -rf "$WORK"; mkdir -p "$WORK/site"
DATADIR="$WORK/data"; WALLET="$WORK/wallet.txt"; mkdir -p "$DATADIR"

SP=""; WP=""
cleanup(){ echo "stopping..."; [ -n "$WP" ] && kill "$WP" 2>/dev/null||true; [ -n "$SP" ] && kill "$SP" 2>/dev/null||true; }
trap cleanup EXIT INT TERM

# --- key (genkeypair gives cleanly labeled priv/pub) ---
KP="$("$CES" --genkeypair 2>&1)"
PRIV="$(echo "$KP" | grep -i private | grep -oE '[0-9a-fA-F]{64}')"
PUB="$(echo  "$KP" | grep -i public  | grep -oE '[0-9a-fA-F]{64}')"
printf '00%s\n' "$PRIV" > "$WALLET"
"$CES" -d "$DATADIR" credit 1000000000000 "$PUB" >/dev/null 2>&1
echo "gateway account: $PUB"

# --- sample site ---
cat > "$WORK/site/index.html" <<'HTML'
<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Hello from the CES web</title>
<link rel=stylesheet href="style.css">
<body>
<header><img src="logo.svg" width=72 height=72 alt="logo">
<h1>Hello from the CES web 👋</h1></header>
<p>Every byte on this page lives in a CES <strong>L2 file store</strong> on a
sovereign CES server. Your browser can't speak CES — so a small gateway
(<code>cesweb</code>) fetched these bytes via the <code>cesh</code> CLI and
handed them to you over plain HTTP.</p>
<p>The server runs with <em>no PoW engine</em> — pure file serving needs none.</p>
<nav><a href="about.html">About</a> · <a href="notes.md">notes.md</a> ·
<a href="data.json">data.json</a> · <a href="hello.txt">hello.txt</a> ·
<a href="missing.html">a 404</a></nav>
<footer>served from <code>/p/site/</code></footer>
</body></html>
HTML

cat > "$WORK/site/about.html" <<'HTML'
<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>About</title><link rel=stylesheet href="style.css"><body>
<h1>About this page</h1>
<p>This is a second page in the same CES file-store zone. The link back is just
a relative URL — the gateway resolves <code>/localhost/p/site/about.html</code>
to a READ of <code>/p/site/about.html</code> on the CES server. No translation:
the CES zone path <em>is</em> the URL path.</p>
<p><a href="index.html">← home</a></p>
</body>
HTML

cat > "$WORK/site/style.css" <<'CSS'
:root{color-scheme:light dark}
body{font:17px/1.6 system-ui,sans-serif;max-width:42rem;margin:2.5rem auto;padding:0 1.1rem;color:#1c1c1e}
header{display:flex;align-items:center;gap:1rem}
h1{font-size:1.7rem;margin:.2em 0}
code{background:#00000010;padding:.1em .35em;border-radius:4px}
nav{margin:1.5rem 0;padding:.8rem 1rem;background:#0b66001a;border-radius:8px;line-height:2}
a{color:#0a7d33;text-decoration:none}a:hover{text-decoration:underline}
footer{margin-top:2rem;color:#8a8a8e;font-size:.9rem}
CSS

cat > "$WORK/site/logo.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0b6"/><stop offset="1" stop-color="#084"/></linearGradient></defs><circle cx="50" cy="50" r="46" fill="url(#g)"/><text x="50" y="66" font-family="system-ui,sans-serif" font-size="52" font-weight="700" text-anchor="middle" fill="#fff">C</text></svg>
SVG

cat > "$WORK/site/hello.txt" <<'TXT'
Hello from a plain text file in the CES web.
This one renders inline because the gateway tagged it text/plain (from .txt).
TXT

cat > "$WORK/site/notes.md" <<'MD'
# notes.md

Markdown served as text/markdown. Most browsers show it inline as text
(or offer to download it) — the gateway just sets the type from the extension
and lets the browser decide.

- file scope: passive bytes (this file)
- compute scope: a Lua program generating bytes (next)
- metadata scope: query + sign = web wallet (later)
MD

cat > "$WORK/site/data.json" <<'JSON'
{ "from": "the CES web", "scope": "L2 file", "engine": "none", "ok": true }
JSON

# --- boot CES server (engine-free), wait, upload, start gateway ---
echo "booting CES server on :$CESPORT (rpc $RPCPORT), no PoW engine..."
"$CES" -d "$DATADIR" --port "$CESPORT" --rpcport "$RPCPORT" --mindiff 1 \
  --nopowengine --filestoremaxbytes 64000000 \
  --cesplexmount "/ces/file/1=builtin:file" --webport 0 \
  > "$WORK/ces.log" 2>&1 &
SP=$!
for i in $(seq 1 80); do
  "$CESH" -q --server "localhost:$CESPORT" ping >/dev/null 2>&1 && break
  sleep 0.2; kill -0 "$SP" 2>/dev/null || { echo "server died:"; cat "$WORK/ces.log"; exit 1; }
done

echo "uploading sample site to /p/site/ ..."
for f in "$WORK"/site/*; do
  name="$(basename "$f")"
  "$CESH" --server "localhost:$CESPORT" --rpc-port "$RPCPORT" -r "$WALLET" \
    file put "$f" "/p/site/$name" --deposit 2000000 >/dev/null \
    && echo "  + /p/site/$name"
done

echo "starting cesweb gateway on :$WEBPORT ..."
CESWEB_PORT="$WEBPORT" CESWEB_CESH="$CESH" CESWEB_DEFAULT_CES_PORT="$CESPORT" \
CESWEB_WALLET_FILE="$WALLET" CESWEB_ALLOW_PRIVATE_HOSTS=1 \
node "$HERE/src/server.js" > "$WORK/web.log" 2>&1 &
WP=$!
sleep 1

echo
echo "================================================================"
echo "  OPEN IN YOUR BROWSER:"
echo "    http://localhost:$WEBPORT/localhost/p/site/index.html"
echo "    http://localhost:$WEBPORT/localhost/p/site/about.html"
echo "    http://localhost:$WEBPORT/localhost            (gateway landing)"
echo "  ('localhost' with no -port works because CES is on the default $CESPORT)"
echo "================================================================"
curl -s -o /dev/null -w "  self-check index.html -> HTTP %{http_code}\n" \
  "http://localhost:$WEBPORT/localhost/p/site/index.html" || true
echo "  (running — leave this process up; stop it to tear down)"
wait "$WP"
