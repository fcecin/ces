---
title: Servers
summary: How to select a server (--server), find its rpc port (--rpc-port, ping), and read its info
order: 3
---

Each command talks to one server. A server has two UDP ports:

- The main port (default 53830) for the ledger: transfers, queries, assets.
- The rpc port for the services: files, compute, think, mail, dial.

## Select a server

- `$CESH_SERVER`, or `--server host:port`. The default is `localhost:53830`.
  `cesh bootstrap` sets `CESH_SERVER` to the public server
  `ces.pubcom.org:53830` in a new shell.
- The rpc port: the server announces it, and `file`, `compute`, `think` and
  `mail` use it. Give `--rpc-port N` only to use another port. `dial` needs
  `--rpc-port`.

`cesh --server host:port ping` shows the server's public key and its rpc
port. The ping is free.

Example for the public server:

```
cesh --server ces.pubcom.org:53830 think hello
```

## Server info

- `cesh ping`: free. The handshake, the server key and the rpc port.
- `cesh server-info`: paid. The fees, the counts of accounts and assets,
  and the version.
- `cesh peer-info <id> <server>`: free. One slot of the server's peer table.

## When a server does not answer

cesh tries `--tries` times (default 3), then prints
`Connect failed: no reply from <address> (UDP, 3 tries)`. Check the address
and the port. A server can also be down.
