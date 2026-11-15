---
title: Keys and the wallet
summary: Where cesh finds keys, what @0 and -a mean, and how to make, add, list and export keys
order: 2
---

A key pair is an identity. Its public key (64 hex characters) is the account
address on every server. The private key signs operations. cesh never sends a
private key to a server.

## The wallet

cesh loads keys from the first of these that it finds:

1. `-r PATH` or `--wallet PATH`: a wallet file.
2. `$CESH_WALLET`: the keys inline, separated by colons (the format that
   `cesh keys export` prints). It is not a path.
3. `~/.cesh/CESH_WALLET`.

## Select a key

- `@0`, `@1`, ...: the keys of the wallet, by index from 0.
- `-a <key>` or `--actor <key>`: the key that signs the command. It takes
  `@N` or a public key in hex. The default actor is `@0`.
- Where a command takes a destination, `@N` means the public key of that
  wallet key.

Example: `cesh -a @1 transfer @0 100000000` sends 1 credit from the second
key of the wallet to the first.

## Commands

| Command | What it does |
| --- | --- |
| `cesh keys list` | List the keys of the wallet (private keys masked) |
| `cesh keys gen N -w PATH` | Make N new keys and save them to the wallet file |
| `cesh keys add <privkey> -w PATH` | Add an existing private key to the wallet file |
| `cesh keys export` | Print a `CESH_WALLET=...` line with all keys |

Without `-w`, `keys gen` prints the new keys and does not save them.

## Safety

A private key gives full control of its accounts on every server. Do not put
a private key in a chat, a file on CES, or a command line that others see.
