---
title: Compute
summary: How to launch, list, inspect and stop a Lua program, what it costs, and the program account
order: 4
---

A program is a Lua file in the file store. A server with compute can run it
as an instance, a sandboxed process with its own pid.

## Run a program from your disk

A program runs from the file store, not from your disk. `compute launch`
takes a path on the server.

1. Upload it with a deposit: `cesh file put hello.lua hello.lua --deposit 100000000`
   (1 credit). The bare name `hello.lua` is `/h/<your key>/hello.lua`.
2. Start it: `cesh compute launch hello.lua`. It prints the pid.
3. Keep it alive: the file balance pays each second. Read the balance with
   `cesh file stat hello.lua` now and again later to see how fast it goes
   down, and add credits with `cesh file deposit hello.lua <raw>`.

## Commands

| Command | What it does | Who |
| --- | --- | --- |
| `cesh compute launch <path>` | Start a new instance of the source file; prints its pid | Owner of the file |
| `cesh compute ps` | List your running instances | Signer |
| `cesh compute stat <pid>` | Uptime, CPU, memory, ports and the program key of an instance | Anyone |
| `cesh compute instances <path>` | The pids that run a source file | Anyone |
| `cesh compute kill <pid>` | Stop an instance | Owner |

## What it costs

- The source file's balance pays each second the program runs: a slot fee,
  CPU time and memory.
- `launch` needs 15 minutes of that cost in the balance, else it fails with
  `CES_ERROR_COMPUTE_FUND_TOO_LOW`. Use `cesh file deposit <path> <raw>`.
- When the balance is gone, the server stops the program. When the source
  file is deleted, its instances stop.
- A program ends itself with `ces.exit()`.

## The program account

Each file has a program key. The file's balance is the account of that key,
so credits sent to the program key (`ces.program_pubkey()` in Lua) go to the
file balance. A program pays its own work from that account, and it can sign
its own operations with that key.

## The sandbox

Programs are LuaJIT with `base`, `string`, `table`, `math` and `bit`. There is
no `os`, `io`, `require`, `load` or `debug`. The API is the global `ces`. A
program that serves must end with `ces.run()`.
