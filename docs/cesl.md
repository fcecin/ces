# cesl - the CesVM programming language

cesl is a small imperative language that compiles to CesVM bytecode.
CesVM programs live inside CES assets and execute on the server,
atomically with the ledger, via `CES_RUN_ASSET`. cesl targets that
machine honestly: one integer type, checked arithmetic by default,
statically allocated variables, and non-reentrant functions. This
manual also covers casm (the textual assembler for the same VM), the
cesc compiler CLI, and bundle deployment for programs larger than one
asset.

Companion material: `lang/` in the repo root holds runnable examples
(simplest first) and a one-command local devnet. The authoritative
short references live in the headers: `include/ces/lang/cesl.h`,
`include/ces/lang/casm.h`, `include/ces/lang/bundle.h`, and the VM
itself in `include/ces/cesvm.h`.

```
// hello: deploy, run, get 14 back
return 2 + 3 * 4;
```

```bash
cd lang
./devnet.sh up
./run.sh add.cesl
```

## 1. Execution model

A cesl program is bytecode stored in an asset. Anyone who can sign a
`CES_RUN_ASSET` op can run it, supplying:

- a gas **budget** (credits, prepaid; the unspent part is refunded),
- an **allowance** (a cap on how much of the caller's balance the
  program may spend through syscalls; default unlimited),
- up to 1024 bytes of **input**.

The program runs on the server's logic strand, serialized with all
other ledger operations. Every mutation it makes goes through an undo
log: if the program crashes (overflow, failed require, out of gas,
segfault), everything rolls back and the caller pays gas used plus a
crash fee. If it terminates normally, mutations commit and up to 1024
bytes of **output** return to the caller.

The machine is a Harvard design. Code (up to 8 KB) is separate from
data: 1024 cells of 8 bytes each (`io[0..1023]`). cesl manages the
cells for you; casm exposes them directly. There is no heap and no
stack-relative addressing: every variable is a statically allocated
cell, decided at compile time. This is why functions are non-reentrant
and recursion is a compile error.

## 2. Program shape

Top-level statements are the program; execution starts at the first
one and an implicit `term` ends it. `fn` definitions may appear
anywhere at top level (before or after use) and are emitted after the
top-level code. `fn` inside a block is an error.

```
const FEE = 2 * PRICE_UNIT;   // compile-time constant
let counter = 0;              // global cell
let key[4];                   // 4-cell region (32 bytes)

fn clamp(v, hi) {
  if (v > hi) { return hi; }
  return v;
}

copy(key, caller_key, 4);
return clamp(input_len, 64);  // top level: writes output, terminates
```

Comments are `//` to end of line. Identifiers are `[A-Za-z_][A-Za-z0-9_]*`.
Number literals are decimal or `0x` hex. There are no negative
literals; unary minus is an operator (`-5` wraps to two's complement).

## 3. Values

There is exactly one value type: the unsigned 64-bit integer. Signed
values (account balances are int64) are the same bits; use the signed
builtins (`slt`, `sgt`, `sge`, `sle`, `sar`) when order or shifting
must respect the sign bit. Booleans are integers: 0 is false, anything
else is true; comparison and logical operators produce 0 or 1.

## 4. Variables, constants, regions

```
let x;             // one cell, uninitialized reads as 0
let y = expr;      // initialized
let buf[27];       // region: 27 contiguous cells (216 bytes)
const K = 3 * 7;   // compile-time constant (initializer must fold)
```

`let` allocates a fresh cell (or contiguous cells) from the machine's
scratch space for the lifetime of the program; block scoping controls
name visibility, not storage. Region sizes must be constant
expressions. Redefinition in the same scope is an error; reserved
names (keywords, builtins, syscalls) cannot be shadowed.

A bare region name is a value: the index of its first cell (a
pointer). `buf[i]` reads or writes cell i of the region; a constant
index is bounds-checked at compile time and compiles to a direct
access, a dynamic index compiles to computed addressing with **no
bounds check** (out-of-range access reads or clobbers other cells, or
segfaults the VM past cell 1023). `peek(addr)` and `poke(addr, v)` are
the raw equivalents for computed cell addresses.

## 5. Expressions and operators

Precedence, tightest first; all binary operators are left-associative:

| level | operators | notes |
|---|---|---|
| unary | `!` `~` `-` | logical not, bitwise not, negate (wraps) |
| multiplicative | `*` `/` `%` `*%` | `*` checked; `*%` wraps; `/ %` unsigned, trap on 0 |
| additive | `+` `-` `+%` `-%` | `+ -` checked; `+% -%` wrap |
| shift | `<<` `>>` | logical; a shift count >= 64 halts the VM |
| relational | `<` `>` `<=` `>=` | unsigned |
| equality | `==` `!=` | |
| bit and | `&` | |
| bit xor | `^` | |
| bit or | `\|` | |
| logical and | `&&` | short-circuit, yields 0/1 |
| logical or | `\|\|` | short-circuit, yields 0/1 |

**Checked arithmetic is the default.** `+ - *` halt the VM with
`CESVM_OVERFLOW` when the mathematical result does not fit u64
(including `a - b` with `b > a`). The run aborts and rolls back: for
money code this is what you want. The `%`-suffixed forms wrap mod 2^64
for intentional modular arithmetic. Division or modulo by zero halts
with `CESVM_DIVZERO`.

`&&` and `||` evaluate the right side only when needed, so a syscall
or function call on the right does not execute when the left side
decides the result.

Function-call arguments and syscall arguments are evaluated left to
right, each read at its own textual position.

Constant expressions (const initializers, region sizes, constant
indices) are folded at compile time with the same semantics: a folded
overflow or division by zero is a compile error.

## 6. Statements

```
let / const                       declarations (section 4)
x = expr;                         assign to a variable
region[expr] = expr;              store into a region
if (expr) { ... }                 braces mandatory
if (expr) { ... } else if ...     else-if chains
while (expr) { ... }              break; continue;
return expr;   return;            see below
require(expr);                    abort the run if expr is falsy
abort();                          abort the run unconditionally
expr;                             evaluate and discard (e.g. a call)
```

`return` inside a function returns its value to the caller. `return
expr` at **top level** writes the value into the first output cell,
sets the output length to 8, and terminates: the value becomes the
8-byte program result. Bare `return;` at top level just terminates.
For richer results write the `output` region and `output_len`
directly:

```
output[0] = a;
output[1] = b;
output_len = 16;
```

`require(cond)` compiles to one `ASSERT` opcode; a falsy condition
halts the VM with `CESVM_ABORT` and rolls back the run. It is the
canonical guard for money code.

Memory statements:

```
copy(dst, src, n);        // copy n cells (region names are pointers)
fill(dst, v, n);          // set n cells to v
poke(addr, v);            // store v at computed cell address
setb(byteoff, v);         // store low byte of v at byte offset
emit_string(region, "text");  // bake a string into region cells
```

Byte offsets address the cell array as 8192 bytes, little-endian
within each cell; byte offset of cell c is `c * 8`.

## 7. Functions

```
fn name(p1, p2) { ... }
```

Functions are top-level, take up to a few dozen u64 parameters (each
is a statically allocated cell), and return one u64 (0 if control
falls off the end). Calls may appear anywhere in an expression;
forward references are fine.

**Recursion is a compile error**, direct or mutual: locals and
parameters live in fixed cells, so a second simultaneous activation of
a function would alias the first. The compiler builds the call graph
and rejects cycles. (The VM itself supports call depth 256; hand-write
casm with an explicit data-stack discipline if you truly need
recursion.)

Under the hood a call snapshots all 16 VM registers and `ret` restores
them, so registers are automatically callee-saved and `r` carries the
return value; nothing about this leaks into cesl semantics.

## 8. Value builtins

| builtin | meaning |
|---|---|
| `peek(addr)` | read the cell at computed address |
| `getb(byteoff)` | read one byte |
| `memcmp(a, b, n)` | 1 if n cells at a and b are equal, else 0 |
| `slt/sgt/sge/sle(a, b)` | signed (int64) comparisons |
| `sar(a, b)` | arithmetic (sign-preserving) shift right |
| `random()` | 64 random bits (server-side PRNG) |
| `now()` | current time, microseconds since epoch |

## 9. Syscalls

Syscall builtins mirror the CesVM syscall ABI one to one (see
`cesvm.h` for authoritative per-call documentation). Pointer-typed
parameters take a region (or any expression yielding a cell index);
value-typed parameters take any expression.

| builtin | args |
|---|---|
| `read_account(pfx)` | pfx: 1-cell account prefix; yields balance, nonce lands in `arg1` |
| `transfer(dest, amt)` | dest: 4-cell key; spends the caller's allowance |
| `deposit(amt)` | caller -> program owner; allowance-bound |
| `withdraw(amt)` | program owner -> caller |
| `owner_transfer(dest, amt)` | program owner pays |
| `read_asset(key, owner_out, content_out)` | balance/price land in `arg3`/io[8] |
| `create_asset(key, content, days)` | |
| `create_asset_random(content, days, key_out)` | |
| `create_asset_range(count, days, key_out)` | atomic N account-owned cells at a random prefix; cell 0 holds `count` |
| `create_asset_managed(key, content, days)` | caller pays, program owns |
| `update_asset(key, content)` | |
| `update_asset_meta(key, owner, price)` | |
| `fund_asset(key, days)` | |
| `buy_asset(key, max_price)` | allowance-bound |
| `give_asset(key, owner)` | |
| `hash(ptr, len, out)` | SHA-256, byte length |
| `verify_sig(ptr, len, sig, pubkey)` | yields 1/0 |
| `cross_transfer(dest, amt, server)` | |
| `load_code(key)` | append an asset's 210 bytes to the code space |
| `send_client(id, ptr, len)` | push to a connected client |
| `schedule(key, budget, allowance, in_ptr, in_len, time_us)` | future run |
| `rpc(host, hostlen, port, filehead, followup, budget, tag)` | |
| `refill(n)` | account hooks: draw up to `n` more gas from the account (sidecar-capped); yields the amount granted |
| `read_alias(id, off, len, dest)` | windowed read of an alias's value image into cells at `dest`; yields `len` |
| `write_alias(id, off, len, src)` | patch bytes into an alias as the run's programOwner principal |
| `load_code_alias(id)` | append an alias's inline code area to the code space; yields the code offset |
| `schedule_alias(id, budget, allowance, in_ptr, in_len, time_us)` | future run of an alias's inline program |

Each builtin dispatches with abort-on-error semantics: a failing
syscall halts the run (`CESVM_ABORT`) and rolls back. Each also has a
`try_` variant (`try_transfer(...)`) that never aborts and yields the
CES error code instead (0 = success), for programs that want to branch
on failure. The plain variant's value is the syscall's R result
(balance for `read_account`, 1/0 for `verify_sig`, and so on).

Spending syscalls (`transfer`, `deposit`, `buy_asset`,
`cross_transfer`) draw from the caller's account and are capped by the
run's allowance; `withdraw` and `owner_transfer` draw from the program
owner's account, who consented by deploying the code.

## 10. Predeclared names

| name | kind | meaning |
|---|---|---|
| `input[128]` | region | caller-supplied input bytes |
| `output[128]` | region | program result buffer |
| `caller_key[4]` | region | caller's 32-byte public key |
| `self_key[4]` | region | this program's asset key |
| `input_len` | read-only | input length in bytes |
| `output_len` | writable | output length in bytes (set by you) |
| `budget_start` | read-only | initial gas budget |
| `gas_left` | read-only | remaining gas, current to the last op |
| `allowance_left` | read-only | remaining spend allowance |
| `start_time` | read-only | run start, microseconds since epoch |
| `r`, `s` | read-only | VM result / status registers |
| `arg0..arg3` | read-only | syscall argument/result cells |
| `PRICE_UNIT` | const | 100000000 (8-decimal credit unit) |
| `invoke_kind` | read-only | which event invoked this run (see below) |
| `INVOKE_DIRECT`, `INVOKE_SCHEDULED` | const | direct `CES_RUN_ASSET` / scheduled run |
| `INVOKE_XFER_IN`, `INVOKE_XFER_OUT`, `INVOKE_XFER_VM` | const | account-hook transfer events |
| `INVOKE_SETTLE_IN`, `INVOKE_SETTLE_OUT` | const | account-hook cross-transfer events |

## 10a. Account hooks

An account can attach a program that runs when a ledger event touches it: set
the account's alias to a hook type pointing at the trigger asset's key. A
**gate** (`ALIAS_OP_HOOK_GATE`) runs before an incoming transfer commits and
accepts (clean return) or rejects (`require` fails / `abort`) - a courtesy
signal to the sender; it must be immutable-or-self-owned and runs on the free
grant only (no `refill`). A **watch** (`ALIAS_OP_HOOK_WATCH`) runs after the
transfer commits, purely to observe/record, and may `refill` to spend past the
grant, capped by the sidecar's refill ceiling.

Read `invoke_kind` to see which event fired, and the event descriptor from the
`input` region:

| cell | meaning |
|---|---|
| `input[0..3]` | counterparty pubkey (the other account) |
| `input[4]` | amount |
| `input[5]` | this account's balance at fire time (pre for a gate, post for a watch) |

A run that is not a hook reads `invoke_kind == INVOKE_DIRECT`. An inbound
transfer worth less than the cost of screening it fires no hook at all (the
dust floor). Examples: `lang/examples/hook_gate.cesl`, `hook_watch.cesl`.

`gas_left` lets a program bail out gracefully (`require(gas_left >
50000);`) before a hard out-of-gas abort. `arg1`/`arg3` expose
secondary syscall results (nonce after `read_account`, asset balance
after `read_asset`).

## 11. Gas and cost

Every VM instruction costs gas (about 100 units for a simple op, more
for syscalls, signature checks, and per-cell/per-byte work; see the
`CESVM_COST_*` constants in `cesvm.h`), multiplied by the server's gas
multiplier and drawn from the prepaid budget. Ledger-mutating syscalls
additionally bill the protocol fee of the equivalent wire op (feeTx,
feeAsset rent, feeQuery). Unused budget is refunded; a crashed run
forfeits a crash fee. Code size is money twice: bytes occupy asset
space (rent) and ops burn gas every run.

## 12. Deployment

`cesc` compiles source to bytecode:

```bash
cesc prog.cesl                  # writes prog.bin
cesc prog.cesl --hex            # hex to stdout
cesc prog.cesl --boot           # enforce + pad to the 210-byte boot block
cesc prog.cesl --bundle out/    # multi-asset bundle for programs > 210 bytes
cesc prog.casm                  # same CLI assembles casm
```

A program up to 210 bytes is one asset: create it with the `--boot`
content and run it (`cesh asset create NAME --hexcontent HEX --days N`,
`cesh asset run NAME --budget B [--input HEX] [--allowance A]`).

A larger program (up to 8 KB) deploys as a **bundle**: the body is
split into 210-byte chunk assets which `SYS_LOAD_CODE` reassembles
contiguously at run time; chunk keys live in a chain of key-table
assets; a boot-loader asset holds one root key, loads everything, and
jumps into the body. `cesc --bundle` computes the whole set offline
with deterministic keys (sha256 of a tag, `--salt`, index, and body)
and writes the blocks plus a `manifest.txt`; then one command deploys
it all:

```bash
cesh asset deploy-bundle NAME out/ --days N
```

creates every chunk and table asset at its manifest key and the boot
loader last, under NAME. Chunk and table keys are content-derived, so
re-deploying the same bundle reuses the blocks already on the ledger
(only a fresh boot asset is created). `lang/run.sh` automates compile
plus deploy. Each run of a bundled program pays a query fee per table
read and per chunk load on top of gas.

## 13. casm - the assembler

casm is the 1:1 textual form of the instruction set: one mnemonic per
opcode, one line per instruction. cesl and casm are siblings; both
compile through the same backend (`VmProgram`), and cesl never
generates casm.

```
; comment                  # comment
name:                      label
.equ NAME value            named constant
.alloc NAME count          allocate scratch cells; NAME = first cell
.at NAME cell              bind NAME to a fixed cell
.string NAME "text"        bake bytes into cells at NAME

    set g0, 10             ; io[8] = 10 (bare symbol = value)
    add [g0], [g1]         ; R = contents of g0 + contents of g1
    jt [r], label          ; branch on contents of R
```

Operands: a bare number/symbol is an immediate; `[x]` reads cell x at
run time; `sym+3` / `sym-3` displace. Register aliases: `pc r s sys
a0-a3 g0-g7` (cells 0..15). Protocol cells by name: `input`, `output`,
`input_len`, `output_len`, `budget`, `start_time`, `caller_key`,
`self_key`, `allowance`, `gas_left`.

Mnemonics are the opcode names lowercase: `set add sub mul div mod or
and xor shl shr sar andl orl eq ne gt lt ge le slt sgt sge sle addx
subx mulx not lnot neg inc dec mov cmp fil ldb stb push pop dup jmp jf
jt call callr jmpr ret require nop term abort host hostx hostv
hostxv`. A `.s` suffix emits the stack-mode variant (operands popped
from the data stack): `add.s`, `slt.s`, `jf.s label`, `call.s`.
Syscalls dispatch by enum name: `hostxv TRANSFER, dest, 100` (hostxv
aborts on error, hostv leaves the code in `s`).

Subroutines: `call` saves all 16 registers (128-byte frame, separate
from the data stack, depth 256) and jumps; `ret v` restores them and
puts v in `r`. Convention: arguments in `g0..g7`, return value in `r`,
everything else comes back automatically. Memory cells are not saved:
they are shared across frames (which is what makes naive recursion
wrong).

## 14. Errors

A run ends in one of the `CesVMError` codes (`cesvm.h`): `0` OK,
`OVERFLOW` (checked arithmetic wrapped), `ABORT` (require/abort/failed
syscall), `DIVZERO`, `BUDGET` (out of gas), `SEGFAULT` (bad address,
stack over/underflow), `OPLIMIT`, and friends. Anything nonzero rolled
back. Compile-time errors from cesc carry `line N:` positions.

## 15. Limits

| limit | value |
|---|---|
| code space | 8192 bytes (one 210-byte boot block + loaded chunks) |
| single-asset program | 210 bytes |
| data cells | 1024 x 8 bytes (io[0..1023]) |
| program-usable scratch | cells 16..751 |
| input / output | 1024 bytes each |
| data stack | 1024 values |
| call depth | 256 frames |
| expression complexity | 12 pending operands per statement (compiler temps) |
| jump range | 16-bit code addresses |

## 16. How it compiles (internals)

Both frontends drive `VmProgram` (`include/ces/util/vmprogram.h`), the
C++ builder that owns instruction encoding, label resolution, and cell
allocation; `buildBytes()` emits the final bytecode. The cesl compiler
is a recursive-descent parser that emits during parsing: no AST, no
IR. Expressions evaluate on the VM's data stack via the stack-mode
opcodes (one operand-free byte per operator); variables bump-allocate
cells (hottest first: cells 16..63 encode in one operand byte);
functions ride the hardware register-frame CALL/RET; a pure evaluator
folds constant expressions; a call-graph pass rejects recursion. For
bundles the body is compiled with a code-base offset of 210 so every
jump target is correct at its final address, then split at arbitrary
byte boundaries (chunks reassemble contiguously, so instructions may
straddle chunks).
