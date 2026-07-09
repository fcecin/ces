# lang/ — CesVM language playground

Example programs for the cesc toolchain (the casm assembler and the
cesl language), plus a one-command local devnet to run them on.

```bash
./devnet.sh up                  # local no-PoW ces server + funded wallet
./run.sh answer.casm            # compile, deploy as an asset, CES_RUN_ASSET
./run.sh vault.cesl --input 0500000000000000 --allowance 500
./run.sh cruncher.cesl          # 399 bytes: deploys as a bundle
./devnet.sh down

./build.sh                      # just compile every example into build/
```

Examples, simplest first:

| file | shows |
|---|---|
| `examples/answer.casm` | output cells, term |
| `examples/countdown.casm` | registers, labels, a loop |
| `examples/greet.casm` | `.alloc`, `.string`, byte output |
| `examples/add.cesl` | expressions, top-level return |
| `examples/fib.cesl` | variables, while, checked arithmetic |
| `examples/vault.cesl` | input, require, a paid syscall + allowance |
| `examples/cruncher.cesl` | subroutines, dynamic region indexing, multi-cell output, bundle deployment (>210 bytes) |
| `examples/hook_gate.cesl` | account hook (gate): `invoke_kind`, event descriptor, accept/reject |
| `examples/hook_watch.cesl` | account hook (watch): screen-then-`refill` to record |

Full manual: `docs/cesl.md`. Short references:
`include/ces/lang/casm.h` and `include/ces/lang/cesl.h`.
Programs past 210 bytes deploy as bundles: `cesc --bundle` writes the
chunk, key-table, and boot blocks plus a manifest (see
`include/ces/lang/bundle.h`), and `cesh asset deploy-bundle NAME DIR
--days N` creates every asset in one command. run.sh does both
automatically.

Everything generated (compiled binaries, the devnet workspace, keys,
ledger) lands in `lang/build/`, which is gitignored. The devnet wallet
is `@0` = you, `@1` = the server key acting as bottomless donor; state
persists across `up`/`down`, delete `lang/build/devnet` to reset.
