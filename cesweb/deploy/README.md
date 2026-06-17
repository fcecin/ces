# cesweb deploy

Run the cesweb gateway behind nginx on a box. cesweb is a read-only client of a
CES server (on this box or anywhere), so deploying here never touches the CES
install (`/opt/ces`). `deploy.sh` is additive: it ships the app + a release
`cesh` to `/opt/cesweb`, installs the systemd unit + nginx site, restarts cesweb,
and reloads nginx.

The fronted CES server must have its rpc port + file store enabled
(`rpc_port != 0`, `file_store_max_bytes > 0`) — and compute, if you use
`/dev/dial`. Otherwise file pages 502 with "no file service".

## Architecture

```
browser ──HTTPS :443──> nginx ──127.0.0.1:8088──> cesweb (Node) ──> cesh ──> CES
          TLS, :80→301   proxy + WS upgrade        gateway, systemd  spawns
```

- **nginx** (apt): TLS on :443 (Let's Encrypt), :80 → :443; reverse-proxies the
  loopback gateway; forwards the WebSocket upgrade on `/dev/dial`; per-IP caps.
- **cesweb**: the Node gateway, loopback only, behind nginx. systemd unit.
- **cesh**: a release build (`-q` / `--server-key`) in `/opt/cesweb`, separate
  from any CES install.

`cesweb.service` and `nginx-cesweb.conf` are **templates** — `deploy.sh` renders
`@@DOMAIN@@` / `@@CESHOST@@` from env at ship time, so they stay generic.

## Config (env for deploy.sh)

- `HOST` (required) — ssh target, e.g. `root@server`
- `DOMAIN` (required) — public hostname (nginx `server_name` + TLS cert)
- `CESHOST` (optional) — the CES server cesweb fronts; default = `DOMAIN`
  (co-located). To front a CES you don't run, set this to it.
- `SKIP_BUILD=1` — skip the release rebuild (JS/nginx-only changes)

To front several servers (or any), edit `CESWEB_ALLOW_HOSTS` in the unit (empty =
open). When it isn't pinned to one host, the home page switches to the
`/<host>/<path>` form automatically.

## The gateway wallet

`/opt/cesweb/wallet.txt` is the key cesweb pays file reads with — a `"00"`/`"01"`
+ 64-hex line. Two choices:

- The fronted server's **own** key (only if you run that CES): reads are free
  (bottomless account), never 402. Trade-off: RCE in cesweb exposes that key.
- A **dedicated funded** key: the norm when you don't run the CES. Users keep it
  topped up with `cesh transfer`; the home page shows its balance + the command.

## One-time box setup

```bash
ssh $HOST 'apt-get update && apt-get install -y nodejs nginx certbot python3-certbot-nginx'
ssh $HOST 'umask 077; printf "00%s\n" "<64-hex-ed25519-private>" > /opt/cesweb/wallet.txt'
ssh $HOST 'ufw allow 80,443/tcp'
HOST=$HOST DOMAIN=your.public.host bash deploy.sh
ssh $HOST 'certbot --nginx -d your.public.host'   # issue the cert, then re-run deploy.sh
```

## Redeploy

```bash
HOST=root@server DOMAIN=your.public.host bash deploy.sh
SKIP_BUILD=1 HOST=root@server DOMAIN=your.public.host bash deploy.sh
```

## Add content

```bash
cesh ... -r /opt/cesweb/wallet.txt file put <file> /p/site/<name> --deposit 1000000000
# → https://your.public.host/p/site/<name>
```
