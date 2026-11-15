---
title: The cesh manual
summary: What cesh is, how this manual works, and where to start
order: 0
---

cesh is the wallet and command line of CES. CES is a network of sovereign
ledgers: each server keeps its own accounts, files and programs, and anyone
can run a server. A key is the same identity on every server.

Each command of cesh signs with a key of your wallet and talks to one server.
The server charges a small fee for most signed operations.

## How to read this manual

- `cesh man` prints the list of pages, one line each.
- `cesh man <page>` prints a page, for example `cesh man files/rent` or
  `cesh man rent`.
- `cesh man <command>` prints the help of a command, for example
  `cesh man transfer`.
- `cesh man --search <word>` finds the pages that contain a word.
- `cesh man --serve <port>` serves this manual to a browser on
  `http://127.0.0.1:<port>/`.

## Where to start

- New here? Run `cesh bootstrap`. It makes a wallet if you have none, connects
  to `ces.pubcom.org`, mines credits until you press Ctrl+C, and opens a shell
  where cesh uses that server.
- [Credits](basics/credits.md): the unit of money, and raw units.
- [Keys and the wallet](basics/keys.md): `@0`, `-a`, and where keys live.
- [Servers](basics/servers.md): `--server`, `--rpc-port`, and `ping`.
- [Errors](basics/errors.md): what each error code means and what to do.
- [Send credits](money/transfer.md): the most common operation.
