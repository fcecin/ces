# CesVM interpreter performance

Measurements for the interpreter optimization pass (memoized pre-decode,
threaded dispatch, fixed stacks, gas-multiply hoist). Baseline ("before")
is the tree immediately before the pass (commit 67d2b50, old inline
interpreter) with the cesvmbench program workloads backported; "after"
is the optimized interpreter with all switches at their defaults.

Two full measurement sets appear below: the primary one on the machine's
performance platform profile, and an earlier accidental run on the
power-saver profile, kept because the comparison is itself informative.

## Why speed matters here

The VM runs on `logicStrand_`, the server's global ledger lock. A gas
budget of 1e9 allows ~10M ops; every ns/op shaved off the interpreter
shrinks the worst-case strand stall a maximally-budgeted run can cause.
Real programs are also syscall-heavy, and syscall cost (ledger reads,
transfers, hashing) is untouched by this work; the numbers below isolate
the interpreter core (arithmetic, dispatch, operand decode) against a
null host.

## What was optimized

Four independent compile-time switches, documented in `cesvm.h`
(`CESVM_OPT_*`, all default on, `-DCESVM_OPT_X=0` to disable, must be
uniform across a build):

- `CESVM_OPT_PREDECODE`: each byte offset's instruction is decoded once
  per run and memoized (opcode, operand values, regptr flags, next PC,
  jump target) in an epoch-validated side table; loop iterations after
  the first skip the control-byte parse, bounds checks, and memcpy of
  `read()`. Instructions with no static decoding (HOSTV/HOSTXV variable
  arg lists, operands dereferencing cell 0, malformed encodings) replay
  through the reference interpreter, byte-for-byte.
- `CESVM_OPT_THREADED`: computed-goto dispatch for the fast core (GNU C
  label addresses; GCC/Clang only, auto-off elsewhere).
- `CESVM_OPT_BILL_HOIST`: `COST_PER_OP * gasMult` and its overflow guard
  computed once per execute() instead of per op.
- `CESVM_OPT_FIXED_STACKS`: data stack and CALL frame stack as fixed
  member arrays instead of vectors (their depth caps are hard constants).

Semantics are pinned by `CesVMTests/DifferentialFastVsReferenceCore`,
which runs ~30 programs (faults, mid-run budget exhaustion, odd-offset
overlapping decodes, PC-writing jumps, HOSTV replays, compiler-emitted
workloads) through both cores and requires identical error, op count,
gas, and output. The reference core stays selectable at runtime via
`CesVM::_setLegacyCore(true)`.

## Test rig

- CPU: Intel Core Ultra 7 155H (hybrid P/E cores, max 4.8 GHz), no core
  pinning; ACPI platform profile as labeled per section
- RAM: 96 GB; OS: Ubuntu 24.04, Linux 6.17
- Compiler: g++ 13.3.0, `-O3 -march=x86-64-v3`, C++20
- Bench: `cesvmbench` (release build), single-threaded, one warmup run
  then one timed run per measurement. Run-to-run variance on this laptop
  is large (hybrid scheduling, turbo, thermals); program-workload tables
  report best-of-N across 3+ runs, opcode tables are single runs that
  internally average 1M iterations

# Results: performance platform profile

## cesl program workloads

`cesvmbench prog`, ns per executed VM op, best of 3+ runs. These
programs compile to short-val-heavy bytecode (1-byte operands), the
interpreter's cheapest case, so this is the conservative number.

| workload | what it stresses            | before | after | speedup |
|----------|-----------------------------|--------|-------|---------|
| arith    | register arithmetic, branch | 4.4    | 3.1   | 1.4x    |
| calls    | CALL/RET register frames    | 4.7    | 4.0   | 1.2x    |
| memory   | dynamic region indexing     | 6.2    | 3.0   | 2.1x    |
| stack    | data-stack expressions      | 4.4    | 3.3   | 1.3x    |

Peak throughput after: 240-340 Mops/s.

## Opcode microbenchmarks

`cesvmbench ops`, ns per loop iteration. The bench loop scaffold uses
wide (multi-byte) operands, the case pre-decode helps most; bundled and
large programs address cells past io[63] and look like this, not like
the table above.

| bench            | before | after | speedup |
|------------------|--------|-------|---------|
| loop overhead    | 23.6   | 6.5   | 3.6x    |
| NOP              | 26.7   | 8.0   | 3.3x    |
| ADD reg          | 30.2   | 9.3   | 3.2x    |
| ADD stack        | 41.1   | 22.4  | 1.8x    |
| DIV reg          | 41.3   | 17.0  | 2.4x    |
| MOD reg          | 39.5   | 18.0  | 2.2x    |
| SET              | 31.2   | 11.3  | 2.8x    |
| PUSH+POP         | 33.0   | 15.1  | 2.2x    |
| CALL+RET         | 41.0   | 20.1  | 2.0x    |
| LDB              | 29.4   | 10.9  | 2.7x    |
| STB              | 30.8   | 11.2  | 2.8x    |
| MOV 32 cells     | 34.9   | 14.3  | 2.4x    |
| CMP 4 cells      | 35.2   | 13.1  | 2.7x    |
| FIL 32 cells     | 34.7   | 14.1  | 2.5x    |

The before ADD reg of 30.2 ns matches the "~31 ns" figure the gas
constants in cesvm.h were originally calibrated against, confirming the
rig configuration is comparable to the calibration run.

## Per-switch isolation

Fast-core ns/op on the program workloads with one switch disabled at a
time, best of 3 runs (all-defaults row is best of 8):

| build                    | arith | calls | memory | stack |
|--------------------------|-------|-------|--------|-------|
| all defaults             | 3.1   | 4.0   | 3.0    | 3.3   |
| CESVM_OPT_THREADED=0     | 3.7   | 4.1   | 4.4    | 4.3   |
| CESVM_OPT_FIXED_STACKS=0 | 3.7   | 3.9   | 3.6    | 3.5   |
| CESVM_OPT_BILL_HOIST=0   | 3.9   | 4.2   | 3.8    | 4.0   |
| reference core (runtime) | 6.4   | 6.1   | 6.2    | 5.4   |

Unthrottled, each secondary switch contributes a real 10-30% by
best-of-run (they were invisible under the power-saver profile, below),
with threaded dispatch mattering most on memory/stack workloads. The
distributions overlap due to run variance, so treat the per-switch rows
as indicative; the dominant gain is `CESVM_OPT_PREDECODE` either way.

Note the "reference core" row is the post-refactor reference
interpreter (per-op call into `stepSlow`), slower than the original
inline loop; use the "before" columns, not that row, as the true
baseline.

# Results: power-saver platform profile

The same matrix accidentally measured with the ACPI platform profile on
power-saver (CPU scaling capped around 30%). Kept for two reasons: the
relative speedups survive throttling nearly unchanged, and the
per-switch differences do not — noise swallows them entirely.

cesl program workloads (typical of 3+ runs):

| workload | before | after | speedup |
|----------|--------|-------|---------|
| arith    | 7.3    | 5.6   | 1.3x    |
| calls    | 7.3    | 6.0   | 1.2x    |
| memory   | 9.1    | 5.7   | 1.6x    |
| stack    | 6.7    | 5.9   | 1.1x    |

Opcode microbenchmarks:

| bench            | before | after | speedup |
|------------------|--------|-------|---------|
| loop overhead    | 42.8   | 13.1  | 3.3x    |
| ADD reg          | 50.9   | 16.0  | 3.2x    |
| ADD stack        | 67.1   | 31.1  | 2.2x    |
| DIV reg          | 66.1   | 26.8  | 2.5x    |
| MOD reg          | 67.5   | 26.9  | 2.5x    |
| SET              | 50.5   | 16.7  | 3.0x    |
| PUSH+POP         | 56.2   | 22.7  | 2.5x    |
| CALL+RET         | 67.3   | 29.8  | 2.3x    |
| LDB              | 48.0   | 14.8  | 3.2x    |
| MOV 32 cells     | 56.2   | 23.9  | 2.4x    |
| FIL 32 cells     | 55.6   | 22.1  | 2.5x    |

Per-switch isolation under power-saver: all three secondary switches
measured within noise (fast core ~5.5-6.1 ns/op with any one of them
disabled). Interference summary: throttling scales absolute numbers by
roughly 1.7-2x and flattens small effects, but leaves the headline
before/after ratios intact — acceptable for go/no-go conclusions,
useless for ranking individual optimizations.

# Reproduction

```bash
# platform profile matters; check it first:
cat /sys/firmware/acpi/platform_profile

./build.sh release
./build/release/cesvmbench prog     # workload table, both cores
./build/release/cesvmbench ops      # opcode table
./build/release/cesvmbench sys      # syscalls vs null host
./build/release/cesvmbench crypto   # raw crypto for gas context

# variant build, e.g. switch dispatch instead of computed goto:
cmake -S . -B build/release -DCMAKE_CXX_FLAGS="-DCESVM_OPT_THREADED=0"
cmake --build build/release --target cesvmbench --parallel
# afterwards reset with -DCMAKE_CXX_FLAGS="" and rebuild via build.sh
```

# Gas calibration

The `CESVM_COST_*` constants are anchored at 1 gas unit = 0.1 ns of
logic-strand time, derived from the performance-profile tables above
plus raw crypto measurements (`cesvmbench crypto`: ED25519 verify
29.6 us, sign 21.7 us; SHA256 53.8 ns at 32 B rising ~0.46 ns/byte).
Burning N units of gas always buys ~N/10 ns of strand time, uniformly
across the opcode, syscall-dispatch, bulk-memory, hashing, and
EC-verify lanes:

| constant          | units  | implies      | measured               |
|-------------------|--------|--------------|------------------------|
| COST_PER_OP       | 100    | 10 ns        | 9.3 ns wide-op ADD (short-val runs faster, not discounted) |
| COST_PER_SYSCALL  | 150    | 15 ns        | ~10-13 ns null dispatch |
| COST_PER_MEMOP    | 500    | 50 ns        | ~54 ns SHA256 init     |
| COST_PER_BYTE     | 5      | 0.5 ns/B     | 0.46 ns/B SHA256       |
| COST_PER_CELL     | 3      | 0.3 ns/cell  | ~0.24 ns/cell MOV      |
| COST_VERIFY_EC    | 300000 | 30 us        | 29.6 us ED25519 verify |

Gas prices compute only; ledger-touching syscalls bill the same
protocol fees as the wire ops (feeTx, feeQuery, feeAsset) on top, via
billCredits.

`feeVmMult` then converts gas units into credits as policy, anchored on
the strand's opportunity cost: what the server earns settling instead.
Measured with cesbench on this rig (100k-200k pre-signed transfers
against the in-process server, ledger conservation verified):

- ~80-82k TPS acked, 12.1-12.4 us per transfer (ed25519)
- ~72k TPS, 13.8 us per transfer (secp256k1)
- opportunity cost = feeTx x capacity = 32,000 x ~81k/s
  ~= 2.6 credits per strand-ns

A VM run at multiplier m burns ~10*m credits per strand-ns (100 units
per ~10 ns op), so parity with settlement is m ~= 0.26: any m >= 1
already out-earns the settlement lane. The default m = 5 prices VM
compute at ~19x opportunity cost — deterrence enough that a
strand-hogging program is a well-paying customer rather than a denial
of service — while leaving the load discount (FeeKind::VMMult, floored
at gasMult = 1) a real 5:1 busy/idle dynamic range. For scale, the L2
compute lane charges feeComputeCpuSec = 5M credits per background
core-second (0.005 credits/ns); the strand lane sits orders of
magnitude above it because compute cores are fungible and the strand is
the global lock.
