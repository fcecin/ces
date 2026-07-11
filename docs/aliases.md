# Aliases: account memory cells

The alias is CES's third ledger type, peer to Account and Asset. An alias is
a server-allocated, id-keyed, account-owned memory cell: 1 KiB of ledger RAM
bound 1:1 to an account, with a second account optionally granted write
access, readable by anyone, patchable byte-by-byte, and executable. It is the
shared-memory and actor primitive: cells, grants, hooks, and rent compose
into mailboxes, message-passing meshes, and autonomous per-account programs
without any further protocol vocabulary.

Everything below is implemented and tested. Sources: `include/ces/alias.h`
(layout + constants), `src/ceslib/server.cpp` (ops, hooks, VM host),
`include/ces/cesvm.h` (syscall ABI), tests in `tests/test_alias.cpp`,
`tests/test_alias_layout.cpp`, `tests/test_alias_vm.cpp`,
`tests/test_account_hooks.cpp`.

## 1. The cell

### 1.1 Layout

The ledger row is a boost flat-map entry of exactly 1024 bytes:

```
entry (1024) = id key (4) + value image (1020)

value image, zero padding anywhere:
  offset  0  owner    HashPrefix (8)   server-set at create; never writable
  offset  8  editor   HashPrefix (8)   granted writer (all-zero = no grant)
  offset 16  op       uint16 (2)       system op code; little-endian in the
                                       image on all supported targets
  offset 18  content  uint8[1002]      payload; meaning defined by op
```

All sizes and offsets are constexprs in `alias.h` (`ALIAS_ENTRY_BYTES`,
`ALIAS_VALUE_BYTES`, `ALIAS_OFF_OWNER/EDITOR/OP/CONTENT`,
`ALIAS_CONTENT_BYTES`); no call site carries literal math. The physical
layout is pinned by static_asserts in `tests/test_alias_layout.cpp`; drift
there is a protocol break.

The 1024-byte entry is the most a fixed CES_* UDP op can carry: a whole-value
`CES_SET_ALIAS` patch is 1138 bytes on the wire, inside MINX's 1280-byte
payload ceiling. Growing the cell would require chunked RUDP.

### 1.2 Identity properties

- The id is a server-allocated uint32, monotonic, allocated by the generator
  cell at id 0 (system-owned, op `ALIAS_OP_SYSTEM`, undeletable, never
  billed). Ids are NEVER reused: a deleted cell's id dangles safely forever
  (any reference to it fails `ALIAS_NOT_FOUND`; it can never resolve to a
  stranger's cell). Programs may therefore bake ids into code as stable
  capabilities.
- One alias per account, both directions stored: `Account.aliasId` (0 =
  none) points at the cell; `Alias.owner` points back. The alias dies with
  the account.
- Not tradeable, not transferable, no per-cell balance. The account is the
  anchor; the cell is part of the account.

### 1.3 Discovery

The account -> alias link is exposed everywhere a client or program can read
an account:

- Wire: `CES_UNSIGNED_QUERY_ACCOUNT_RESULT.aliasId` (0 = none).
- VM: `SYS_READ_ACCOUNT` writes `io[6] = aliasId`.

So any pubkey resolves to its cell with existing reads: pubkey -> 8-byte
prefix -> account -> aliasId -> cell. The one cell discoverable from nothing
but a server's identity is the server account's own alias (the "root alias"):
every client holds the server pubkey from the bind/reply path, making that
cell a natural self-description slot, service directory, or root actor. The
server account is bottomless and uncounted, so its cell's rent self-pays.

## 2. Ownership: owner and editor

Two principals per cell, with asymmetric powers:

- The OWNER (the account the cell is attached to) controls the envelope:
  the `editor` grant, the `op` code, deletion, and all of content. The owner
  pays the cell's daily rent. The owner may never rewrite the `owner` field
  itself (server-set at create).
- The EDITOR (any single other account, by prefix) may write CONTENT only,
  never the header. All-zero = no grant. The owner grants, rotates, and
  revokes by patching the editor field.

The 8-byte editor prefix is sound as an authorization field because account
prefixes are first-come-first-served unique: the account map stores a 24-byte
key tail that authenticates the one full key owning the prefix, and a
different pubkey with the same prefix can never register (`prefixTaken`).

Exactly ONE editor, deliberately. A cell has at most one writer per trust
domain, which makes write races across trust boundaries impossible at L1:
message-passing between distrusting parties, shared memory within one
domain. Untrusted bidirectional collaboration is a PAIR of cells, each side
hosting (and paying rent on) the half the other writes: the vostro/reserve
correspondent-banking shape at the memory layer. Reads are public, so a lane
needs only its writer granted. N-writer blackboards belong above L1,
mediated by a program that owns the board.

The owner CAN write content but conventionally does not on cells used as
inbound lanes: the owner's write capability is the master key (reset a
wedged mailbox, rotate a dead editor, wipe, delete), not a second lane.

## 3. Wire operations

### 3.1 CES_SET_ALIAS: patch write

Signed. The write is a PATCH over the value image:

```
originId (32) serverId (8) reqNonce (4)
aliasId (u32)   0 = my own alias (created zeroed on first use)
                N = any cell I own or edit
offset  (u16)   image byte offset
len     (u16) + len payload bytes
```

Rules, all enforced server-side, reject-whole on any violation:

- Nobody writes `owner` (bytes 0..7): `CES_ERROR_BAD_INPUT`.
- Bounds: `offset + len <= 1020` else `CES_ERROR_BAD_INPUT`.
- Floors: the owner writes from `ALIAS_PATCH_MIN_OWNER` (8); an editor from
  `ALIAS_PATCH_MIN_EDITOR` (18, content only). Under-floor:
  `CES_ERROR_NOT_OWNER`. A signer who is neither owner nor editor:
  `CES_ERROR_NOT_OWNER`. Missing nonzero target: `CES_ERROR_ALIAS_NOT_FOUND`.
- Create-on-first-use: `aliasId = 0` with no live alias allocates a fresh id
  (zeroed image, owner stamped, account link set) and applies the patch.
  Editors cannot create cells (a nonexistent cell has no editor). The id is
  stable across patches; DELETE is the only id drop/rotate.
- Hook re-validation: if the RESULTING image has a pointer-hook op
  (`ALIAS_OP_HOOK_GATE/WATCH`), the trigger asset named by content[0..32)
  must exist and be immutable or owned by the SIGNER (owner or editor,
  whoever is patching): `CES_ERROR_HOOK_TARGET` otherwise. This runs on
  every patch that leaves a pointer-hook op in place, so an editor cannot
  repoint an installed hook at code the account did not commit to.
- Fee: the SIGNER pays one day of `feeAlias` per patch (anti-spam floor;
  editors pay for their own writes; the owner keeps paying rent).
- Returns the target/created id.

### 3.2 CES_QUERY_ALIAS: windowed read

Unsigned, free (main-port ticket rules only). `(aliasId, offset, len)` over
the image; returns the bytes and a found flag. Out-of-bounds windows and
unknown ids return found = 0 (no partial/clamped reads). The whole image is
public, header included. `offset/len` exist so readers (and editor-side
code) can skip the 18-byte header or fetch a single field.

### 3.3 CES_DELETE_ALIAS

Signed, owner only, own alias only. Erases the cell and clears
`Account.aliasId`. Charges `feeQuery`. A later create mints a NEW id.

### 3.4 CES_RUN_ALIAS: public invocation

Signed. The alias-id twin of `CES_RUN_ASSET`: `(aliasId, budget, allowance,
time, input)`. The target cell must have op `ALIAS_OP_INLINE_PROGRAM`
(explicit opt-in to public invocation); otherwise `CES_ERROR_BAD_INPUT`
(`CES_ERROR_ALIAS_NOT_FOUND` for a dead id), with the reserved budget
refunded since nothing ran.

The run boots the cell's inline code area with:

- caller = the signer (pays gas; `allowance` caps caller-side debits),
- self = all-zero (no boot asset),
- programOwner = the cell's OWNER (consented code, section 5).

Nonceless dedup and future-time scheduling work exactly as in
`CES_RUN_ASSET` (a future `time` enqueues a prepaid scheduled run; the op is
re-checked at fire time). Result carries rcode, vmError, budgetUsed,
allowanceUsed, output (up to 1024 bytes).

## 4. Executable cells

### 4.1 Op vocabulary

```
0x0000 ALIAS_OP_NONE               raw bytes (default; render as hex)
0x0001 ALIAS_OP_STRING             UTF-8 text
0x0010 ALIAS_OP_HOOK_GATE          pointer hook: content[0..32) = trigger
                                   asset key, content[32..40) = refill
                                   ceiling (u64 LE)
0x0011 ALIAS_OP_HOOK_WATCH         pointer hook, watch form
0x0012 ALIAS_OP_INLINE_HOOK_GATE   inline hook: content IS the code
0x0013 ALIAS_OP_INLINE_HOOK_WATCH  inline hook, watch form
0x0014 ALIAS_OP_INLINE_PROGRAM     inline code, publicly invocable
                                   (CES_RUN_ALIAS / SYS_SCHEDULE_ALIAS),
                                   never deposit-fired
0xFFFF ALIAS_OP_SYSTEM             reserved (the id-0 generator cell)
```

`op` is the owner's declared trust envelope: only the owner sets it, and it
determines what the content means and who may be running it. One cell, one
role: a program cell is not simultaneously a label; a gate is not a watch.

### 4.2 Inline layout

For the three `ALIAS_OP_INLINE_*` ops the content splits into:

```
content[0 .. 994)      code area (ALIAS_INLINE_CODE_BYTES)
content[994 .. 1002)   refill ceiling, u64 LE (image offset
                       ALIAS_OFF_INLINE_CEILING = 1012)
```

The code area is ALWAYS loaded whole and zero-padded, so `SYS_LOAD_CODE*`
landing offsets are link-time constants regardless of the program's real
length (a boot from a cell puts the first loaded block at 994). 994 bytes is
about 5x an asset boot block; larger programs chain into asset chunks with
`SYS_LOAD_CODE` exactly like asset boots do. A patch replaces code
atomically: there is no torn-deploy window, unlike multi-asset bundles.

The ceiling trailer is the hook refill cap (section 4.3), meaningful for
`INLINE_HOOK_WATCH`; forced to 0 for gates.

### 4.3 Account hooks (gate / watch)

Hooks are deposit-triggered runs of the account's cell, in two forms
(pointer: cell names a trigger asset; inline: cell holds the code) and two
classes:

- GATE runs BEFORE the credit and may reject it (clean TERM = accept;
  abort/fault/out-of-gas = reject, surfacing `CES_ERROR_HOOK_REJECTED` to
  the sender). Fail-closed: a rotted pointer target rejects.
- WATCH runs AFTER the transfer commits. Fail-open: its outcome never blocks
  delivery.

Fire points: local transfer in (`INVOKE_HOOK_XFER_IN`) and out
(`INVOKE_HOOK_XFER_OUT`), and a program's `SYS_TRANSFER` crediting a hooked
account (`INVOKE_HOOK_XFER_VM`, deferred until the crediting run commits,
watch-only). Class matching spans both forms: a WATCH fire point matches
`HOOK_WATCH` and `INLINE_HOOK_WATCH`; `INLINE_PROGRAM` cells never fire as
hooks. Hooks never fire from inside a hook (no cascades). Transfers below
the free grant fire nothing (the dust floor: screening must cost less than
the amount screened).

Execution economics: the run gets a free gas grant (`hookFreeGrant`,
minimum-compute at live rates, debited from no one) with the hooked account
as caller and allowance 0 (a hook cannot spend its account through the
caller lane). A WATCH may `SYS_REFILL` additional gas, funded by the hooked
account, capped by the cell's ceiling (trailer for inline, content[32..40)
for pointer). GATES run as PURE PREDICATES: ceiling forced 0 and no
principal, so a gate has no money side effect at all; that purity is what
makes the composed sequence (out-gate + in-gate + transfer) atomic without
any enclosing journal. The event descriptor arrives in io[INPUT]:
counterparty pubkey (32), amount (u64 LE), account balance at fire time
(u64 LE; pre-mutation for a gate, post for a watch).

Pointer-hook install/patch validation: the trigger asset must be immutable
or owned by the setter, checked on every patch that results in a pointer
hook op (see 3.1). Inline hooks need no such check: the code is in the cell
and only the owner (or a deliberately granted editor) can put it there.

## 5. The identity model: three principals per run

Every VM run carries three typed identities, each with an honest all-zero
sentinel, never overloaded:

```
caller        account        who invoked me; pays gas; allowance binds
                             caller-side debits. Always real.
self          asset key | 0  the boot asset: the identity that holds
                             deposits, owns managed assets, and anchors
                             asset-owned chains. ZERO for alias code: no
                             boot asset, so the asset-custody syscalls
                             (SYS_DEPOSIT/WITHDRAW/CREATE_ASSET_MANAGED)
                             error; the program's funds are its account's,
                             reached through the principal.
programOwner  account | 0    the consenting principal: the account the run
                             ACTS AS for the allowance-exempt syscalls
                             (SYS_OWNER_TRANSFER, SYS_WITHDRAW,
                             SYS_DEPOSIT, asset write auth) and for alias
                             writes. ZERO = no principal: those syscalls
                             no-op and alias writes are rejected.
```

Preloaded, informational copies for the program (authorization always reads
the host-side fields, never io):

```
io[756..759]  caller pubkey (32 bytes)
io[760..763]  self asset key (32 bytes; all-zero = alias program)
io[1023]      programOwner prefix (8 bytes; all-zero = no principal)
io[1022]      invoke kind (CesVMInvoke)
```

`self == 0` doubles as the run's type tag: programs and syscalls branch on
one comparison to know they are cell-hosted. The all-zero ASSET KEY is
reserved at creation (`CES_ERROR_BAD_INPUT` from every create path) so the
sentinel is unmintable.

The principal is derived from CONSENT to the code, never from who invoked
it and never from who authored it:

- Inline cell code: principal = the cell's owner. Patching code into your
  own cell is consent to that exact bytecode.
- Pointer WATCH whose trigger the hooked account owns AT FIRE TIME:
  principal = the hooked account (owning the code is the same consent).
- Pointer hook on someone else's immutable asset: NO principal. Installing
  a stranger's code grants it the ceiling, never the authority to act as
  you.
- Every GATE: NO principal (purity).
- `CES_RUN_ASSET`: principal = the boot asset's owner (pre-existing
  semantics: deploying the asset is consent; the dice house pattern).
- `CES_RUN_ALIAS` / `SYS_SCHEDULE_ALIAS` fires: principal = the cell's
  owner, whoever invoked it. Any caller pokes the actor; the actor acts as
  its account.
- No cell or consenting asset in the invocation path = no principal: the
  run can spend only its caller (allowance-bounded) and write nothing.

Invoke kinds added for cells: `INVOKE_DIRECT_ALIAS` (3, CES_RUN_ALIAS) and
`INVOKE_SCHEDULED_ALIAS` (4, SYS_SCHEDULE_ALIAS fire).

## 6. VM syscalls

```
25 SYS_READ_ALIAS    io[4]=alias id, io[5]=offset, io[6]=len,
                     io[7]=dest cell ptr
                     -> R=len, S=OK / ALIAS_NOT_FOUND (incl. out-of-bounds
                     window) / BAD_INPUT. Public read; bills feeQuery.

26 SYS_WRITE_ALIAS   io[4]=alias id, io[5]=offset, io[6]=len,
                     io[7]=src cell ptr
                     -> S=OK / NOT_OWNER (no principal, no grant, or an
                     under-floor offset; wire parity) / BAD_INPUT (bounds) /
                     ALIAS_NOT_FOUND / HOOK_TARGET (pointer-hook
                     re-validation, principal as setter).
                     Acts as programOwner; owner floor 8, editor floor 18.
                     Cannot create cells. Bills feeAlias (one upfront day,
                     wire parity). Atomic: joins the run's undo log, so an
                     aborted run reverts its writes; committed writes are
                     re-journaled and flushed with the run.

27 SYS_LOAD_CODE_ALIAS io[4]=alias id
                     -> R=code offset, S=OK / ALIAS_NOT_FOUND.
                     Appends the target cell's WHOLE code area (994 bytes,
                     zero-padded) to the code buffer; CESVM_CODEFULL past
                     8 KiB. Bills feeQuery. Linking, not calling: the loaded
                     code runs under the current run's identities. Does not
                     interpret the target's op; loading a data cell as code
                     is the caller's bug.

28 SYS_SCHEDULE_ALIAS io[4]=alias id, io[5]=budget, io[6]=child_allowance,
                     io[7]=input ptr, io[8]=input len, io[9]=time_us
                     -> S=OK / ALIAS_NOT_FOUND / BAD_INPUT (target not an
                     INLINE_PROGRAM) / QUEUE_FULL / ALLOWANCE_EXCEEDED.
                     Same billing and allowance-carve contract as
                     SYS_SCHEDULE (hosting cost by delay; the parent's
                     allowance is decremented by child_allowance, refunded
                     if the queue rejects; the enqueue itself is undone if
                     the parent later aborts).
```

Also extended: `SYS_READ_ACCOUNT` now writes `io[6] = aliasId` (0 = none),
completing the pubkey -> account -> cell chase from inside the VM.

VmProgram wrappers: `sysReadAlias`, `sysWriteAlias`, `sysLoadCodeAlias`,
`sysScheduleAlias` (hostx semantics: failure aborts; use `hostv` to observe
S instead).

## 7. Scheduling and the async call

`SYS_SCHEDULE_ALIAS` (or a future-time `CES_RUN_ALIAS`) is the
alias-to-alias async call: A's program enqueues a future run of B's cell
with input bytes and a carved allowance. The fired child boots B's code area
with principal = B (consented code), self = 0, invoke kind
`INVOKE_SCHEDULED_ALIAS`, gas debited from the SCHEDULING account at fire
time (or prepaid for the wire future-time form).

The target must be `ALIAS_OP_INLINE_PROGRAM` at queue time (syscall) AND at
fire time: a cell that was deleted or repurposed in between is skipped, like
a scheduled asset run whose asset died. A prepaid future-time run whose
target dies before firing burns its budget (same policy as assets: the
reservation paid for the slot, and there is no one to run for).

There is deliberately NO synchronous call between programs. Trusted sync
composition is `SYS_LOAD_CODE`/`SYS_LOAD_CODE_ALIAS` linking (callee shares
your io, gas, undo scope, identities). Untrusted composition is
message-passing: write the counterparty's granted cell, ring the doorbell
(a transfer, which fires their watch), read their reply lane. Sync effectful
calls into untrusted code would require nested undo scopes and import
re-entrancy, the largest smart-contract bug class; CES is immune by
construction and stays that way.

## 8. Economics

- Rent: the owner account pays `feeAlias` per day (daily maintenance;
  default `ALIAS_BYTES x MEMORY_PRICE`, the same per-byte-day price as
  every ledger row). Owner cannot pay, or owner account gone: the cell is
  reclaimed and the link cleared. No per-cell balance; the account is the
  funding source.
- `feeAlias` again as a per-patch anti-spam day, charged to the SIGNER of a
  wire patch or the BUDGET of a VM write.
- `feeQuery` per VM read/load; the unsigned wire read is free.
- `CES_RUN_ALIAS` gas: budget reserved upfront from the caller, unused
  refunded, including on load failures (nothing ran = full refund); the
  usual crash fee on non-abort faults; refill charges land on the hooked
  account for hook runs.
- Structures price per edge: one cell = one account (64 B row) + one alias
  (1024 B row) of rent per day. A ring of N costs N edges; abandoned
  structure decays out by rent death. Nothing is garbage-collected; it is
  priced.

## 9. Sharp edges (read before granting or opting in)

- An editor grant on an INLINE cell is FULL DELEGATION of the account. The
  code area and the ceiling trailer are content, so the editor can rewrite
  the program that runs with the owner as principal (allowance-exempt spend is
  unbounded by design). Grant editors on data cells freely; grant one on a
  program cell only when "this key may reprogram my agent" is the intent.
- `ALIAS_OP_INLINE_PROGRAM` is a public run surface with your principal:
  anyone can invoke it with arbitrary input, and the code decides what the
  principal does (exactly like deploying an asset program that calls
  SYS_OWNER_TRANSFER; the dice-house contract). Your code is the whole
  gate; write it accordingly.
- `op` is the trust envelope and only the owner can move it; but WATCH
  hooks may rewrite their own cell (principal = owner), including op.
  Self-modifying agents are a feature; a buggy one can seal or repurpose
  its own cell.
- There is no trustless alias. The owner key can always delete or starve
  the cell, so "trust the code, not the keyholder" is impossible here in
  the strong sense; what holds is "this id never lies" (ids are never
  reused, so replacement is always visible as death, not mutation). Code
  that must be trustless lives in an IMMUTABLE ASSET; cells can point at
  it (pointer hooks) or load it.
- Prefix grants name accounts, not people: whoever holds the editor
  account's key holds the grant. Rotation is one owner patch.
- The all-zero sentinels are load-bearing: zero asset key is unmintable,
  zero principal means the run acts as no one, zero editor means no grant.
  Never treat
  them as values.

## 10. Patterns

- Mailbox pair (untrusted duplex): A hosts cell_A with editor = B; B hosts
  cell_B with editor = A. Each side writes the other's cell and reads its
  own. Doorbell: a minimal transfer to the reader fires their WATCH (the
  transfer is the interrupt, and it pays its own gas via refill).
- Ring: N accounts, each granting editorship to its predecessor: a bounded
  queue of registers, a token ring with signed, serialized, audit-trailed
  hops.
- Root alias: the server account's own cell; discoverable from the server
  pubkey alone; the ledger's MOTD, service directory, or (operator's
  choice) root actor with the bottomless principal.
- Agent + heap: one account's cell holds the program; N sibling accounts
  (keys held by the same operator) hold data cells granting the agent
  editorship. In-degree costs a cell; out-degree is free.

## 11. Toolchain

- `cesc file.cesl|file.casm --alias` compiles/validates against the
  994-byte inline code area and pads to it. Deploy the emitted bytes as one
  patch at the content offset, with the op:
  `cesh alias write 16 --hexcontent <op_le_hex><code_hex>` or op and code
  in separate patches.
- `cesh alias write <offset> [--id N] --content|--hexcontent` raw patch;
  `cesh alias read <id> [offset] [len]` raw window (quiet mode emits raw
  bytes); `cesh alias run <id> --budget N [--allowance N] [--input hex]
  [--nonceless]`; `cesh alias rm`. cesh is deliberately structure-blind:
  offsets come from this document, not from CLI sugar.

## 12. Test map

- `test_alias_layout.cpp`: the physical image, offsets, constexpr
  cross-pins, serializer round trip.
- `test_alias.cpp`: patch semantics (create/edit/rotate/delete, floors,
  bounds, grants, revocation, strangers), generator behavior, rent and
  reclaim, wire round trip and windowed reads.
- `test_account_hooks.cpp`: pointer gates/watches end to end, set-time
  target validation, refill ceilings, dust floor, conservation.
- `test_alias_vm.cpp`: identity preloads, the mailbox watch write, gate
  purity (reject and accept paths), owned-pointer-watch principal, foreign
  foreign immutable code running principal-less, editor hook-repoint
  re-validation,
  abort/revert of cell writes, ungranted-principal rejection, schedule
  fire-time re-check and dead-target abort, load-code linking, budget
  refund on load failure, aliasId discovery on both read surfaces.
- `test_persistence.cpp`: cell + editor grant + VM-written bytes across
  snapshot/reload; generator counter survival.
- `test_cesh_e2e.cpp`: raw write/read round trip, partial patches, quiet
  raw-byte output.
