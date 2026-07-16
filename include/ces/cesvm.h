#pragma once

/**
 * CesVM — Server-side bytecode VM for CES.
 *
 * Based on GVM (github.com/FluxBP/gvm). Executes bytecode stored in
 * asset cells. The HOST instruction dispatches CES I/O operations
 * (read/write accounts, assets, send UDP) based on a syscall number
 * in register io[3].
 *
 * Programs are invoked via CES_RUN_ASSET. The caller provides:
 *   - Asset key (which program to run)
 *   - Credit budget (max credits to burn)
 *   - Input data (arbitrary bytes, available to the program)
 *
 * The program runs on the logic strand, serialized with all other
 * CES operations. It can read any account/asset, write assets owned
 * by the caller, transfer credits from the caller, and send UDP
 * packets. All mutations are charged to the caller's budget.
 *
 * Architecture:
 *   - Harvard: code (read-only, up to 8KB) and data (io[], 8KB) are separate
 *   - Code starts as the 210-byte asset content, grows via SYS_LOAD_CODE
 *   - 59 opcodes (35 GVM core + RND, TIME, MOV, LDB, STB, CMP, FIL,
 *     HOSTX, ABORT, JMPR, CALLR, HOSTV, HOSTXV, SAR, LNOT, SLT, SGT,
 *     SGE, SLE, ADDX, SUBX, MULX, ASSERT, DUP)
 *   - 16 registers: PC, R, S, SYSCALL, ARG0-3, GPR0-7
 *   - CALL/RET save/restore all 16 registers (128-byte frame)
 *   - Write syscalls execute real mutations via host callbacks
 *   - Atomicity (rollback on error) is the server's responsibility via undo log
 *
 * Syscall convention (HOST/HOSTX instruction):
 *   io[3] = syscall number
 *   io[4..8] = arguments (syscall-specific)
 *   R (io[1]) = data return value (syscall-specific, unchanged if no data)
 *   S (io[2]) = CES error code (0 = CES_OK, nonzero = failure)
 *   HOST: executes syscall, program checks S to decide what to do
 *   HOSTX: executes syscall, aborts VM (CESVM_ABORT) if S != 0
 *
 * Syscalls (dense range 0..22; see CesVMSyscall enum below for the
 * authoritative IDs and per-call ABI doc):
 *   0  NOP                  S=ok
 *   1  READ_ACCOUNT         io[4]=prefix_ptr → R=balance, io[5]=nonce, io[6]=aliasId (0 = none), S=ok
 *   2  TRANSFER             io[4]=dest_key_ptr, io[5]=amount → S=error_code
 *   3  READ_ASSET           io[4]=key_ptr, io[5]=owner_out, io[6]=content_out → io[7]=balance (raw u16: bits 0..12 days, bit 13 immut, bit 14 aowned, bit 15 priv), io[8]=price, S=ok/ASSET_NOT_FOUND
 *   4  CREATE_ASSET_RANDOM  io[4]=content_ptr, io[5]=days, io[6]=key_out_ptr → S=ok
 *   5  UPDATE_ASSET         io[4]=key_ptr, io[5]=content_ptr → S=error_code
 *   6  FUND_ASSET           io[4]=key_ptr, io[5]=days → S=error_code
 *   7  BUY_ASSET            io[4]=key_ptr, io[5]=max_price → S=error_code
 *   8  GIVE_ASSET           io[4]=key_ptr, io[5]=new_owner_ptr → S=error_code
 *   9  SEND_UDP             DISABLED (returns S=DISABLED). Use SEND_CLIENT instead.
 *  10  HASH                 io[4]=data_ptr, io[5]=len, io[6]=out_ptr → S=ok
 *  11  VERIFY_SIG           io[4]=data_ptr, io[5]=data_len, io[6]=sig_ptr, io[7]=pubkey_ptr → R=1/0, S=ok
 *  12  CROSS_TRANSFER       io[4]=dest_key_ptr, io[5]=amount, io[6]=server_ptr → S=ok (buffered)
 *  13  LOAD_CODE            io[4]=key_ptr → R=code_offset, S=ok/ASSET_NOT_FOUND
 *  14  CREATE_ASSET         io[4]=key_ptr, io[5]=content_ptr, io[6]=days → S=ok/ASSET_EXISTS
 *  15  SEND_CLIENT          io[4]=account_prefix_ptr, io[5]=data_ptr, io[6]=data_len → R=sent(1/0), S=ok
 *  16  SCHEDULE             io[4]=asset_key_ptr, io[5]=budget, io[6]=child_allowance, io[7]=input_ptr, io[8]=input_len, io[9]=time_us → S=ok/QUEUE_FULL/ALLOWANCE_EXCEEDED (parent's allowance decremented by child_allowance on success)
 *  17  CREATE_ASSET_MANAGED io[4]=key_ptr, io[5]=content_ptr, io[6]=days → S=ok/ASSET_EXISTS
 *  18  RPC                  io[4..10] = host cell, host len, port, file head, followup program, followup budget, followup tag → S=ok/queue code (see SYS_RPC enum doc)
 *  19  OWNER_TRANSFER       io[4]=dest_key_ptr, io[5]=amount → S=error_code (drains programOwner, not caller)
 *  20  DEPOSIT              io[4]=amount → S=error_code (caller → programOwner)
 *  21  WITHDRAW             io[4]=amount → S=error_code (programOwner → caller)
 *  22  UPDATE_ASSET_META    io[4]=key_ptr, io[5]=new_owner_ptr, io[6]=new_price → S=error_code (owner/price only, content untouched)
 *  25  READ_ALIAS           io[4]=alias_id, io[5]=offset, io[6]=len, io[7]=dest_ptr → R=len, S=ok/ALIAS_NOT_FOUND/BAD_INPUT (public windowed read of the value image)
 *  26  WRITE_ALIAS          io[4]=alias_id, io[5]=offset, io[6]=len, io[7]=src_ptr → S=error_code (patch as programOwner: owner floor 8, editor floor 18; principal-less runs always NOT_OWNER)
 *  27  LOAD_CODE_ALIAS      io[4]=alias_id → R=code_offset, S=ok/ALIAS_NOT_FOUND (appends the whole ALIAS_INLINE_CODE_BYTES area)
 *  28  SCHEDULE_ALIAS       io[4]=alias_id, io[5]=budget, io[6]=child_allowance, io[7]=input_ptr, io[8]=input_len, io[9]=time_us → S=ok/QUEUE_FULL/ALLOWANCE_EXCEEDED/ALIAS_NOT_FOUND (target must be ALIAS_OP_INLINE_PROGRAM)
 *
 * Preloaded io locations (read-only context, set before execution):
 *   io[752]        = input length (bytes)
 *   io[754]        = initial budget (credits)
 *   io[755]        = start time (microseconds since epoch)
 *   io[756..759]   = caller public key (32 bytes)
 *   io[760..763]   = self asset key (32 bytes; all-zero = alias program:
 *                    no boot asset, asset-custody syscalls disabled)
 *   io[892..1019]  = input data (up to 1024 bytes)
 *   io[1023]       = programOwner account prefix (8 bytes; all-zero = no
 *                    principal: allowance-exempt syscalls no-op, alias
 *                    writes rejected)
 *
 * Program-writable io locations:
 *   io[753]        = output length (bytes, set by program)
 *   io[764..891]   = output data (up to 1024 bytes)
 *
 * Memory layout (io[0..1023], 8KB):
 *   [0..15]      Registers (PC, R, S, SYSCALL, ARG0-3, GPR0-7)
 *   [16..751]    Program memory (736 cells = 5888 bytes)
 *   [752..763]   Preloaded context (see above)
 *   [764..891]   Output data (128 cells = 1024 bytes)
 *   [892..1019]  Input data (128 cells = 1024 bytes)
 *   [1020..1023] Reserved
 *
 * Pointers in syscalls refer to io memory offsets where byte data
 * is packed into uint64_t cells (8 bytes per cell, little-endian).
 */

#include <ces/types.h>
#include <ces/asset.h>
#include <ces/account.h>
#include <ces/feemult.h>

#include <minx/types.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

// ============================================================================
// Interpreter optimization switches
// ============================================================================
// Each is independently toggleable at compile time (-DCESVM_OPT_X=0) and must
// be set identically for every TU in a build (they change the CesVM class
// layout). Defaults: everything on; THREADED auto-detects GNU C.
//
//   CESVM_OPT_PREDECODE    Memoized operand pre-decode (the fast core). Each
//                          byte offset's instruction is decoded once and
//                          cached in a side table (epoch-validated per
//                          execute(), extended on SYS_LOAD_CODE growth).
//                          Anything the fast core cannot statically decode —
//                          HOSTV/HOSTXV variable arg lists, operands that
//                          dereference cell 0 (the mid-instruction PC),
//                          truncated or invalid encodings — replays through
//                          the reference interpreter (stepSlow), so
//                          observable semantics are identical by
//                          construction. 0 = always run the reference core.
//   CESVM_OPT_THREADED     Computed-goto dispatch for the fast core (GNU C
//                          label-address extension; GCC/Clang only,
//                          auto-off elsewhere). No effect when
//                          CESVM_OPT_PREDECODE=0.
//   CESVM_OPT_BILL_HOIST   Precompute COST_PER_OP * gasMult once per
//                          execute() instead of overflow-guarding the
//                          multiply on every op. Pure C++.
//   CESVM_OPT_FIXED_STACKS Data stack and CALL frame stack as fixed member
//                          arrays (their depth caps are hard constants)
//                          instead of std::vectors. Pure C++.
//
// The runtime hook CesVM::_setLegacyCore(true) forces the reference core on
// one instance (used by the differential test and by cesvmbench to measure
// the fast core against the reference in a single binary).

#ifndef CESVM_OPT_PREDECODE
#define CESVM_OPT_PREDECODE 1
#endif

#ifndef CESVM_OPT_THREADED
#if defined(__GNUC__) || defined(__clang__)
#define CESVM_OPT_THREADED 1
#else
#define CESVM_OPT_THREADED 0
#endif
#endif
#if CESVM_OPT_THREADED && !(defined(__GNUC__) || defined(__clang__))
#undef CESVM_OPT_THREADED
#define CESVM_OPT_THREADED 0
#endif

#ifndef CESVM_OPT_BILL_HOIST
#define CESVM_OPT_BILL_HOIST 1
#endif

// The one switch whose "off" position has a real use case rather than
// being a fallback. On: the data stack and CALL frame stack live inline
// in the object, growing sizeof(CesVM) by ~40 KB (8 KB stack + 32 KB
// frames) on top of the 8 KB io_ array that is inline in every
// configuration; worth ~10-20% on arith/memory workloads. Fine for the
// current usage (one stack-local CesVM per run on logicStrand_). Off:
// both revert to vectors and the object is ~8.5 KB again -- flip this
// for any embedding that holds many CesVM objects alive at once.
#ifndef CESVM_OPT_FIXED_STACKS
#define CESVM_OPT_FIXED_STACKS 1
#endif

namespace ces {

// GVM error codes
enum CesVMError : uint64_t {
  CESVM_OK         = 0,
  CESVM_OPCODE     = 1,
  CESVM_CODESIZE   = 2,
  CESVM_DIVZERO    = 3,
  CESVM_OPLIMIT    = 4,
  CESVM_UNDERFLOW  = 5,
  CESVM_RET        = 6,
  CESVM_SEGFAULT   = 7,
  CESVM_NEGNUM     = 8,    // tombstoned; ADD/SUB/MUL all wrap silently now
                            // (programs check via CMP before the op)
  // CES-specific
  CESVM_BUDGET     = 9,   // credit budget exhausted
  CESVM_SYSCALL    = 10,  // invalid syscall number
  CESVM_AUTH       = 11,  // not authorized (e.g. write to non-owned asset)
  CESVM_CODEFULL   = 12,  // code space exhausted (SYS_LOAD_CODE)
  CESVM_ABORT      = 13,  // program aborted (OP_HOSTX on S!=0, OP_ABORT, or OP_ASSERT)
  CESVM_HOST       = 14,  // host callback or VM infrastructure threw
  CESVM_OVERFLOW   = 15,  // checked arithmetic (ADDX/SUBX/MULX) wrapped
};

// Syscall numbers, dense range 0..22.
enum CesVMSyscall : uint64_t {
  SYS_NOP            = 0,
  SYS_READ_ACCOUNT   = 1,
  SYS_TRANSFER       = 2,
  SYS_READ_ASSET     = 3,
  SYS_CREATE_ASSET_RANDOM = 4,
  SYS_UPDATE_ASSET   = 5,
  SYS_FUND_ASSET     = 6,
  SYS_BUY_ASSET      = 7,
  SYS_GIVE_ASSET     = 8,
  SYS_SEND_UDP       = 9,  // tombstoned: returns CES_ERROR_DISABLED
  SYS_HASH           = 10,
  SYS_VERIFY_SIG     = 11,
  SYS_CROSS_TRANSFER       = 12,
  SYS_LOAD_CODE            = 13,
  SYS_CREATE_ASSET         = 14,
  SYS_SEND_CLIENT          = 15,
  SYS_SCHEDULE             = 16,
  SYS_CREATE_ASSET_MANAGED = 17, // caller pays, boot asset owns
  // SYS_RPC — MINX/RUDP stream call to an external service.
  // The caller pre-writes the request body into a cesh file (typically
  // pre-allocated with extra capacity to receive the response), passes
  // its head key to SYS_RPC, and the dispatcher:
  //   - Reads header.fileSize bytes from the file chain as the request.
  //   - Builds a signed envelope: [u32 BE body_len][body][u64 BE time_us]
  //     [32 sender_key][32 sha256(body||time||key)][65 signature]
  //   - Opens an outbound Rudp channel on the server's dedicated rpcMinx_,
  //     writes the envelope via asio::async_write on a RudpStream, reads
  //     a [u32 BE body_len][body] response.
  //   - Writes the response bytes back into the SAME file chain, updating
  //     header.fileSize to the response length (bounded by chain capacity;
  //     excess response bytes are silently truncated).
  //   - Schedules a followup VM program via scheduleRun with a 48-byte
  //     input: [u32 tag][u32 status][u32 wire_body_len][u32 bytes_written]
  //     [32 file_head_key].
  //
  // io layout:
  //   io[4]  = host cell ptr     (cell index of ASCII host/IP bytes)
  //   io[5]  = host length       (bytes, max 255)
  //   io[6]  = port              (u16)
  //   io[7]  = file_head cell    (cell index of a 32-byte cesh file head)
  //   io[8]  = followup cell     (cell index of a 32-byte followup VM asset)
  //   io[9]  = followup budget   (u64)
  //   io[10] = followup tag      (u32)
  //
  // Returns CES_OK in S() on successful queue; CES_ERROR_DISABLED if
  // the server was started with rpcPort == 0; error codes from the
  // file auth / materialization checks otherwise.
  SYS_RPC             = 18,
  // SYS_OWNER_TRANSFER — same shape as SYS_TRANSFER (io[4]=dest cell ptr,
  // io[5]=amount), but the source account is programOwner, not the
  // caller. The caller still pays the protocol fee (feeTx) because they
  // invoked the syscall — only the value-bearing transfer is debited
  // from programOwner. NO allowance check applies: this is an unbounded
  // spend of programOwner, gated only by the bytecode reaching this
  // instruction. See the programOwner field doc (this file) for the
  // capability/security model and the /b/dice gating pattern. Returns
  // CES_ERROR_ORIGIN_NOT_FOUND if programOwner has no account (e.g. an
  // asset-owned chain, or a run with programOwner deliberately empty),
  // or CES_ERROR_INSUFFICIENT_BALANCE if the owner can't cover it.
  SYS_OWNER_TRANSFER  = 19,
  // SYS_DEPOSIT — caller -> programOwner. Convenience for the common
  // "user funds the asset's owner" pattern (deposits, bets, payments
  // for an asset's service). io[4] = amount; both endpoints are
  // implicit, so no dest pubkey is needed in io memory or input.
  // Allowance-bound (caller is spending their own credits). Returns
  // CES_ERROR_ORIGIN_NOT_FOUND if the owner has no account.
  SYS_DEPOSIT         = 20,
  // SYS_WITHDRAW — programOwner -> caller. Convenience for the
  // "asset pays its caller" pattern (refunds, payouts, faucets).
  // io[4] = amount. NOT allowance-bound: an unbounded spend of
  // programOwner, so the bytecode alone stands between it and a drain.
  // The bytecode MUST reach this only on a path it authorized (in a
  // faucet: only after the service was actually rendered / paid for).
  // /b/dice pays 2*bet here but only after a hostx SYS_DEPOSIT proved
  // the bet cleared; a plain (non-aborting) collect would let an
  // underfunded caller win house money for free. See the programOwner
  // field doc for the full model. Returns CES_ERROR_ORIGIN_NOT_FOUND or
  // CES_ERROR_INSUFFICIENT_BALANCE per host.withdraw.
  SYS_WITHDRAW        = 21,
  // SYS_UPDATE_ASSET_META — set owner+price on an existing asset
  // without touching content. io[4] = key_ptr, io[5] = new_owner_ptr
  // (8-byte HashPrefix), io[6] = new_price (uint32). Auth via
  // checkAssetWriteAuth (caller, programOwner, or self-asset-key for
  // asset-owned chains). Bills feeTx, not feeAsset — matches the wire
  // CES_UPDATE_ASSET_META fee tier (cheaper than full content update).
  SYS_UPDATE_ASSET_META = 22,
  // SYS_REFILL — top up this run's gas budget past the free grant, funded by
  // the caller account (used by account hooks: the trigger spends its own
  // account's money to do work bigger than the free grant, e.g. write
  // history). io[4] = requested gas credits. Returns the amount actually
  // granted in R (0 if refill is disabled or the sidecar ceiling / balance is
  // exhausted); never aborts. The caller is charged post-run for gas consumed
  // past the free grant, outside the undo log so a crash still pays for the
  // strand time it used. No-op (grants 0) outside a run whose host set a
  // refill ceiling. See local/account_hooks_design.md.
  SYS_REFILL          = 23,
  // SYS_CREATE_ASSET_RANGE — atomically create N account-owned assets at a
  // fresh random 24-byte prefix, keyed prefix||0 .. prefix||(N-1) (last 8 bytes
  // a native index). Cell 0's content carries uint32_t N at bytes 0..3; all
  // cells are otherwise zero. The prefix is opaque entropy, no type tag, and
  // the whole batch is collision-checked: any pre-existing target key abandons
  // the batch (creating nothing) and retries a fresh prefix. io[4]=N, io[5]=days,
  // io[6]=cell index where the 32-byte handle (cell-0 key) is written. Bills N
  // asset creations. This is the bare array primitive; sequence membership is
  // metadata held by the owner (all cells share one owner), not read from keys.
  SYS_CREATE_ASSET_RANGE = 24,
  // SYS_READ_ALIAS — public windowed read of an alias's value image
  // (owner|editor|op|content; see alias.h layout constants). io[4]=alias id,
  // io[5]=offset, io[6]=len, io[7]=dest cell ptr. R=len, S=ok /
  // ALIAS_NOT_FOUND (also for an out-of-bounds window) / BAD_INPUT.
  // Bills feeQuery.
  SYS_READ_ALIAS      = 25,
  // SYS_WRITE_ALIAS — patch bytes into an alias's value image, acting as the
  // run's programOwner principal (the owner of the cell or asset that
  // carries this code, when that owner consented to it; see docs/aliases.md
  // section 5). Same
  // floors as the wire op: owner from ALIAS_PATCH_MIN_OWNER, editor from
  // ALIAS_PATCH_MIN_EDITOR. A principal-less run (empty programOwner: any
  // gate, a foreign-code hook, bare CES_RUN_ASSET) always gets NOT_OWNER —
  // no consenting principal, no write authority; the same emptiness keeps
  // gates pure. io[4]=alias id,
  // io[5]=offset, io[6]=len, io[7]=src cell ptr. S=error_code. Bills
  // feeAlias (one upfront day, wire parity). Undo-log atomic.
  SYS_WRITE_ALIAS     = 26,
  // SYS_LOAD_CODE_ALIAS — append an alias's whole inline code area
  // (ALIAS_INLINE_CODE_BYTES, zero-padded so load bases are link-time
  // constants) to the code buffer. io[4]=alias id. R=code offset, S=ok /
  // ALIAS_NOT_FOUND. Bills feeQuery. The loaded code runs under the current
  // run's identities (linking, not calling).
  SYS_LOAD_CODE_ALIAS = 27,
  // SYS_SCHEDULE_ALIAS — enqueue a future run of an alias's inline program
  // (the async alias-to-alias call). Same ABI as SYS_SCHEDULE with io[4] =
  // alias id instead of an asset key ptr. The target must be
  // ALIAS_OP_INLINE_PROGRAM at queue AND fire time; the fired run gets
  // self = 0 and programOwner = the cell's owner (consented code).
  SYS_SCHEDULE_ALIAS  = 28,
  // SYS_L2_CALL — paid, reliable call into an in-CES (L2) service, routed by
  // an 8-byte discriminator: the first 8 bytes of sha256(built-in mount name),
  // treated as a flat byte array (endian-independent, never a native int).
  // io[4] = discriminator cell (the 8 bytes = one io cell)
  // io[5] = value            (u64, burned from caller on accept)
  // io[6] = blob cell        (provider-ABI payload, opaque to core)
  // io[7] = blob len         (bytes)
  // io[8] = followup cell    (32-byte followup VM asset key; 0 = fire-and-forget)
  // io[9] = followup budget  (u64)
  // io[10]= followup tag     (u32)
  // The syscall OWNS the burn: a synchronous reject (unmounted discriminator,
  // queue full) returns a code and burns nothing; CES_OK atomically burns
  // `value` and enqueues a persistent call. Settlement is delivery-based and
  // core-owned: delivered -> mint payee; not-delivered (no-handler / timeout)
  // -> refund payer. Resolution schedules a followup run (invokeKind =
  // INVOKE_L2_RETURN, input [tag][outcome]) unless followup cell is zero.
  SYS_L2_CALL         = 29,
};

// Invocation kind — which entry path started this run. Preloaded into
// io[CESVM_IO_INVOKE_KIND] from host.invokeKind so a program can dispatch on
// how it was invoked. This is the universal VM invocation-context ABI: every
// entry path stamps its value here; hooks are the first extension of it.
//
// APPEND-ONLY. Never renumber or reuse a value: a program built against an
// older ABI treats an unrecognized kind as INVOKE_DIRECT semantics (read
// io[INPUT] as opaque) or, for a gate, default-rejects. INVOKE_DIRECT = 0 so
// zero-initialized io already means "direct call" with no migration.
//
// The hook subrange (16+) carries an event descriptor in io[INPUT] (which is
// free on a hook, there being no user-supplied input): counterparty pubkey,
// amount, resulting balance. Reserved values below are real fill-sites (a named
// event, a fire-site, a descriptor), not placeholders: wiring one later is
// "stamp the value + fill the descriptor", never an ABI break. Full model:
// local/account_hooks_design.md.
enum CesVMInvoke : uint64_t {
  INVOKE_DIRECT        = 0,   // CES_RUN_ASSET (also the zero-init default).
  INVOKE_SCHEDULED     = 1,   // SYS_SCHEDULE fire.
  INVOKE_AUTOEXEC      = 2,   // boot autoexec.
  INVOKE_DIRECT_ALIAS  = 3,   // CES_RUN_ALIAS (public inline-program run).
  INVOKE_SCHEDULED_ALIAS = 4, // SYS_SCHEDULE_ALIAS fire.
  INVOKE_L2_RETURN     = 5,   // SYS_L2_CALL resolution (delivered / refunded).

  // Account-hook subrange.
  INVOKE_HOOK_XFER_IN  = 16,  // a local transfer credited this account.
  INVOKE_HOOK_XFER_OUT = 17,  // this account sent a local transfer.
  INVOKE_HOOK_XFER_VM  = 18,  // a program's SYS_TRANSFER credited this account
                              // (deferred, never nested).

  // Reserved: real events, not yet wired. See the design doc.
  INVOKE_HOOK_MINT      = 32, // PoW mint credited this account.
  INVOKE_HOOK_ASSET_BUY = 33, // CES_BUY_ASSET paid this account (asset owner).
  // Cross-transfer settlement events, for complete transaction histories.
  // Both WATCH-ONLY: a landed cross already committed on the origin so it
  // cannot be gated (SETTLE_IN), and outbound gating is a porous soft
  // guardrail not worth the settlement path (SETTLE_OUT). Fire points are on
  // the settlement path (the dest credit / the crossTransfer origin debit),
  // NOT the exempt transfer(Open) path.
  INVOKE_HOOK_SETTLE_IN  = 34, // a cross transfer landed on this account.
  INVOKE_HOOK_SETTLE_OUT = 35, // this account sent a cross transfer.
};

// Opcode numbers (one byte each). Exposed here as the single source of
// truth: cesvm.cpp's parser, the VmProgram builder (include/ces/vmprogram.h),
// and every test file that checks bytecode bytes directly all pull from
// this header instead of maintaining their own local copies. When a new
// opcode lands it goes here and nowhere else needs to change.
//
// The high bit (0x80) of an opcode byte is the STACK modifier: OR it
// with any opcode that has a stack variant (ADD, SUB, MUL, DIV, MOD, OR,
// AND, ANDL, XOR, NOT, LNOT, SHL, SHR, SAR, EQ, NE, GT, LT, GE, LE, NEG,
// ORL, JF, JT, LDB, STB, RND, TIME, CALL, SLT, SGT, SGE, SLE, ADDX,
// SUBX, MULX, ASSERT) to pop operands from the stack instead of reading
// them from the instruction stream.
enum CesVMOpcode : uint8_t {
  OP_NOP   = 0,  OP_TERM  = 1,  OP_SET   = 2,  OP_JMP   = 3,
  OP_ADD   = 4,  OP_SUB   = 5,  OP_MUL   = 6,  OP_DIV   = 7,
  OP_MOD   = 8,  OP_OR    = 9,  OP_ANDL  = 10, OP_XOR   = 11,
  OP_NOT   = 12, OP_SHL   = 13, OP_SHR   = 14, OP_INC   = 15,
  OP_DEC   = 16, OP_PUSH  = 17, OP_POP   = 18, OP_AND   = 19,
  OP_HOST  = 20, OP_VPUSH = 21, OP_VPOP  = 22, OP_CALL  = 23,
  OP_RET   = 24, OP_JF    = 25, OP_JT    = 26, OP_EQ    = 27,
  OP_NE    = 28, OP_GT    = 29, OP_LT    = 30, OP_GE    = 31,
  OP_LE    = 32, OP_NEG   = 33, OP_ORL   = 34, OP_RND   = 35,
  OP_TIME  = 36, OP_MOV   = 37, OP_LDB   = 38, OP_STB   = 39,
  OP_CMP   = 40, OP_FIL   = 41, OP_HOSTX = 42, OP_ABORT = 43,
  // Indirect variants of JMP / CALL. The original OP_JMP and OP_CALL
  // read their target as a 2-byte literal via read(true), which means
  // the destination is baked into the code at build time. These
  // variants read a regular operand (via read()), so the target can
  // be a cell index that gets dereferenced at runtime. Needed for
  // SYS_LOAD_CODE + call-into-loaded-block patterns where the loaded
  // code's offset isn't known until runtime.
  OP_JMPR  = 44, OP_CALLR = 45,
  // Variadic syscall dispatch. Reads (syscall_num, arg_count, arg0..)
  // inline and populates io[3] + io[4..4+arg_count-1] in one opcode,
  // then calls hostCall. OP_HOSTXV additionally promotes a nonzero S
  // on return to CESVM_ABORT, matching OP_HOSTX's semantics.
  OP_HOSTV = 46, OP_HOSTXV = 47,
  // Arithmetic shift right: sign-extends (preserves the high bit), unlike
  // logical SHR (zero-fill). Use for signed values such as int64_t balances.
  OP_SAR   = 48,
  // Logical NOT (!x). Distinct from OP_NOT (bitwise ~x) and OP_NEG (arithmetic).
  OP_LNOT  = 49,
  // Signed comparisons: operands reinterpreted as two's-complement
  // int64. The GT/LT/GE/LE family is unsigned and reads the sign bit
  // as magnitude; these are correct for signed values such as account
  // balances.
  OP_SLT   = 50, OP_SGT   = 51, OP_SGE   = 52, OP_SLE   = 53,
  // Checked unsigned arithmetic: identical to ADD/SUB/MUL except a
  // wrap (add/mul overflow, sub borrow) halts with CESVM_OVERFLOW
  // instead of producing a wrapped value. Intended as the default for
  // money math; the wrapping forms remain for intentional mod-2^64 use.
  OP_ADDX  = 54, OP_SUBX  = 55, OP_MULX  = 56,
  // Abort (CESVM_ABORT) if the operand is falsy (0). One-opcode form
  // of the jt-over-abort guard idiom; complements OP_HOSTX, which is
  // the same contract for syscall status.
  OP_ASSERT = 57,
  // Duplicate the top of the data stack. Stack-only by nature (no
  // register form); used when a stack-scheduled value feeds two
  // consumers, since stack-mode ops pop their operands.
  OP_DUP   = 58,
};

// Named cell indices for the 16 registers. Useful anywhere a cell
// index is expected — e.g. `set(Imm(R_CELL), Imm(42))` writes 42 to R,
// or `set(Imm(destCell), Ref(R_CELL))` stores the current R value
// into destCell. The register names match the ABI doc comment at
// the top of this file.
static constexpr uint64_t CESVM_CELL_PC       = 0;
static constexpr uint64_t CESVM_CELL_R        = 1;
static constexpr uint64_t CESVM_CELL_S        = 2;
static constexpr uint64_t CESVM_CELL_SYSCALL  = 3;
static constexpr uint64_t CESVM_CELL_ARG0     = 4;
static constexpr uint64_t CESVM_CELL_ARG1     = 5;
static constexpr uint64_t CESVM_CELL_ARG2     = 6;
static constexpr uint64_t CESVM_CELL_ARG3     = 7;
static constexpr uint64_t CESVM_CELL_GPR0     = 8;
static constexpr uint64_t CESVM_CELL_GPR1     = 9;
static constexpr uint64_t CESVM_CELL_GPR2     = 10;
static constexpr uint64_t CESVM_CELL_GPR3     = 11;
static constexpr uint64_t CESVM_CELL_GPR4     = 12;
static constexpr uint64_t CESVM_CELL_GPR5     = 13;
static constexpr uint64_t CESVM_CELL_GPR6     = 14;
static constexpr uint64_t CESVM_CELL_GPR7     = 15;

// Operand control-byte encoding bits (see cesvm.cpp's read() function).
// SHORT_VAL means "the low 6 bits of the control byte ARE the value";
// absent, the low 6 bits are the number of LE payload bytes that follow.
// REG_PTR wraps either form with "the resulting value is a cell index —
// dereference it to get the real value."
static constexpr uint8_t CESVM_OP_STACK = 0x80;
static constexpr uint8_t CESVM_REG_PTR  = 0x80;
static constexpr uint8_t CESVM_SHORT_VAL = 0x40;
static constexpr uint8_t CESVM_MAX_SHORT_VAL = 0x3F;  // 6 bits = 0..63

static constexpr uint64_t CESVM_IO_SIZE = 1024;
static constexpr uint64_t CESVM_REG_SIZE = 16;
static constexpr uint64_t CESVM_MAX_CODE = 8192;
static constexpr uint64_t CESVM_CODE_BLOCK = 210;

// Caps on the data stack (OP_PUSH) and call/context stack (OP_CALL register
// frames). The GVM core leaves both unbounded; without a cap a push loop
// exhausts server memory faster than the gas budget halts it. Overflow is
// promoted to CESVM_SEGFAULT, triggering the undo-log rollback.
static constexpr uint64_t CESVM_MAX_STACK_DEPTH = 1024;
static constexpr uint64_t CESVM_MAX_CALL_DEPTH  = 256;

// Upper bound on OP_HOSTV / OP_HOSTXV argument count; a larger count promotes
// to CESVM_SEGFAULT before any io slot is touched. 16 fills io[4..19].
static constexpr uint64_t CESVM_MAX_HOSTV_ARGS = 16;

// ============================================================================
// Memory layout
// ============================================================================
//
// io[0..1023] is a flat uint64_t cell array with a byte-overlay view via
// OP_LDB / OP_STB. Cells are 8-byte aligned; stored multi-byte integers are
// little-endian. Cells are untyped: a hash and a balance are indistinguishable
// at the ISA level.
//
// The address space is divided into five bands. The short-val operand
// encoding (control byte SHORT_VAL | 6-bit value) reaches io[0..63] in a
// single byte; io[64] and up need a wide operand (2+ bytes), so the low 64
// cells are the scarce resource.
//
//   io[0..15]  ── REGISTERS (16 cells, short-encoded)
//                PC=io[0], R=io[1], S=io[2], SYSCALL=io[3],
//                ARG0..3=io[4..7], GPR0..7=io[8..15].
//                Syscall arguments flow through ARG0..3 and GPR0..3;
//                bigger syscalls spill into GPR4..7.
//
//   io[16..63] ── LOW REGION / SCRATCH (48 cells, short-encoded)
//                The program's working memory for values it references
//                often. CONVENTIONS (not enforced by the VM):
//
//                   io[16..23] ── Hash slots (two 4-cell = 32-byte
//                                 slots). Typical use: io[16..19] for
//                                 a "destination key" argument, io[20..23]
//                                 for a "source key" argument.
//                   io[24..31] ── Syscall argument staging. When a
//                                 program needs to compose a multi-arg
//                                 syscall, build the args here so each
//                                 OP_SET into the io[4..10] slot region
//                                 uses short-encoded sources.
//                   io[32..47] ── General scratch. Loop counters,
//                                 temporaries, computed addresses.
//                   io[48..63] ── Free. Reserved for future conventions.
//
//                Programs that copy their inputs from io[CESVM_IO_INPUT]
//                (the high region) down into this low band can then
//                address them at short-encoded (1-byte) operand cost.
//
//   io[64..751] ── WIDE PROGRAM MEMORY (688 cells = 5504 bytes)
//                 Readable and writable by the program, but every
//                 reference costs a wide operand. Use for large scratch
//                 buffers, content blocks, and anything too big for
//                 the low region.
//
//   io[752..891] ── PRELOADED CONTEXT (140 cells, wide-encoded)
//                  Filled by execute() before the program runs.
//                  Programs typically copy the parts they need down
//                  into the low region and work from there rather than
//                  touching this band directly. Documented slots:
//
//     io[752]        = input length (bytes, preloaded)
//     io[753]        = output length (bytes, program writes this)
//     io[754]        = initial budget (credits, preloaded)
//     io[755]        = start time (microseconds since epoch, preloaded)
//     io[756..759]   = caller public key (32 bytes = 4 cells, preloaded)
//     io[760..763]   = self asset key (32 bytes = 4 cells, preloaded)
//     io[764..891]   = output data buffer (128 cells, program writes)
//
//   io[892..1023] ── INPUT + RESERVED (132 cells)
//     io[892..1019]  = input data (128 cells, preloaded)
//     io[1020]       = remaining caller-debit allowance (syscall-synced)
//     io[1021]       = remaining gas budget (op-synced — see bill())
//     io[1022..1023] = reserved
//
// ----------------------------------------------------------------------------
// Preloaded context lives in the high region, not the low one
// ----------------------------------------------------------------------------
//
// The ~140 preloaded cells (caller/self key, input and output buffers) would
// fill io[0..63] and leave no short-encoded scratch for the program. Instead
// they sit high; a program OP_MOVs the few cells it needs into the low region
// at startup and works against the short-encoded copies. The VmProgram
// builder's copyFromInput() / copyCallerKeyTo() / copySelfKeyTo() wrap this.
//
// ----------------------------------------------------------------------------
// Invariant: execute() never writes io[16..63]
// ----------------------------------------------------------------------------
//
// execute() writes only io[0..15] (registers) and the preloaded context in
// io[752..1023]. The low scratch region io[16..63] belongs to the program.
// New preloaded values go in the high region or the io[1023] reserve (io[1022]
// is now the invocation kind), never the low region, which would clobber
// programs relying on it as scratch.
// ============================================================================
static constexpr uint64_t CESVM_IO_INPUT_LEN  = 752;
static constexpr uint64_t CESVM_IO_OUTPUT_LEN = 753;
static constexpr uint64_t CESVM_IO_BUDGET     = 754;
static constexpr uint64_t CESVM_IO_START_TIME = 755;
static constexpr uint64_t CESVM_IO_CALLER_KEY = 756;
static constexpr uint64_t CESVM_IO_SELF_KEY   = 760;
static constexpr uint64_t CESVM_IO_OUTPUT     = 764;
static constexpr uint64_t CESVM_IO_INPUT      = 892;
static constexpr uint64_t CESVM_IO_ALLOWANCE  = 1020;
// Gas budget remaining — programs can read this to bail gracefully
// before running out of budget mid-operation. Mirrored by bill() after
// every op, so the value is always current as of the last instruction
// that successfully billed. Symmetric with CESVM_IO_ALLOWANCE but
// updated at op granularity instead of syscall granularity because
// budget is consumed by every op, not just syscalls.
static constexpr uint64_t CESVM_IO_BUDGET_REMAINING = 1021;
// Invocation kind: which entry path started this run (a CesVMInvoke value).
// execute() preloads it from host.invokeKind. Zero-init means INVOKE_DIRECT,
// so a program that never reads this cell behaves exactly as before. Programs
// that do read it dispatch on how they were invoked (direct call, scheduled,
// autoexec, account hook). See CesVMInvoke.
static constexpr uint64_t CESVM_IO_INVOKE_KIND = 1022;
// The run's programOwner principal (8-byte account prefix; all-zero = no
// principal). Informational copy for the program; authorization always reads
// the host-side field, never this cell.
static constexpr uint64_t CESVM_IO_PROGRAM_OWNER = 1023;
static constexpr uint64_t CESVM_MAX_INPUT     = 1024;
static constexpr uint64_t CESVM_MAX_OUTPUT    = 1024;

// SYS_CREATE_ASSET_RANGE: max cells per atomic range, and collision retries.
// The 24-byte prefix carries 2^192 entropy, so one attempt effectively always
// wins; retries only guard the astronomically rare collision.
static constexpr uint64_t CESVM_MAX_ASSET_RANGE     = 256;
static constexpr uint64_t CESVM_ASSET_RANGE_RETRIES = 4;

// --- Gas cost constants ---
// Anchor: 1 gas unit = 0.1 ns of logic-strand time, measured on a release
// build with cesvmbench (methodology and full tables: docs/cesvm-perf.md).
// Every constant below is its measured wall cost expressed in that unit,
// so gas is uniform across opcodes, syscall dispatch, bulk memory, hashing,
// and EC verify: burning N units always buys ~N/10 ns of strand time.
// Ledger mutations inside syscalls are NOT priced here; they bill the same
// protocol fees as the wire ops (feeTx, feeQuery, ...) via billCredits.
//
// Cost per VM instruction in gas units (~10 ns: wide-operand dispatch;
// short-val code runs faster and is deliberately not discounted)
static constexpr uint64_t CESVM_COST_PER_OP = 100;
// Cost per syscall (dispatch + host vtable, on top of per-op cost; ~15 ns)
static constexpr uint64_t CESVM_COST_PER_SYSCALL = 150;
// Cost for compute-only syscalls (HASH init, no ledger I/O; ~50 ns)
static constexpr uint64_t CESVM_COST_PER_MEMOP = 500;
// Per-cell cost for variable-length memory opcodes (MOV, CMP, FIL; ~0.24 ns)
static constexpr uint64_t CESVM_COST_PER_CELL = 3;
// Per-byte cost for variable-length data processing (HASH, VERIFY_SIG;
// SHA256 measures ~0.46 ns/byte)
static constexpr uint64_t CESVM_COST_PER_BYTE = 5;
// EC signature verification cost (ED25519 verify measures ~30 us)
static constexpr uint64_t CESVM_COST_VERIFY_EC = 300000;
// Fixed penalty on VM crash (deducted from refund, not from budget)
static constexpr uint64_t CESVM_CRASH_FEE = 1000000;
// Cost to schedule a delayed runAsset (base + per second of hosting)
static constexpr uint64_t CESVM_SCHEDULE_BASE_COST = CESVM_COST_PER_OP * 100;  // 10000
static constexpr uint64_t CESVM_SCHEDULE_PER_SEC = CESVM_COST_PER_OP;           // 100

// Account-hook free grant = MINIMUM COMPUTE: the fixed gas budget every trigger
// run starts with, sized as N instructions + M asset reads (not as a fraction
// of any fee), converted to a credit budget at the live gasMult so a screen
// always fits regardless of load. Too small to compute with (a screen, not a
// program), so it is non-launderable via self-transfer no matter the nominal
// credits. At stock fees this lands ~1.1x feeTx (screening an event costs about
// a transaction). See local/account_hooks_design.md.
//   grant = OPS*COST_PER_OP*gasMult + READS*(COST_PER_SYSCALL*gasMult + feeQuery)
static constexpr uint64_t CESVM_HOOK_GRANT_OPS   = 50;
static constexpr uint64_t CESVM_HOOK_GRANT_READS = 4;

struct CesVMResult {
  uint64_t error = CESVM_OK;
  uint64_t opsExecuted = 0;
  uint64_t budgetUsed = 0;
  ces::Bytes output;
};

// The execution environment provided by the CES server. Virtual interface;
// the VM dispatches every syscall through these methods. Production: see
// CesServerVmHost in src/ceslib/server.cpp — overrides every method with
// real ledger mutations. Default implementations throw std::logic_error so
// any uncovered method becomes loud rather than silent. Tests that only
// need data members (allowance, callerKey, ...) can default-construct;
// tests that need behavior subclass and override.
//
// Atomicity is the server's job, via an undo log outside the VM.
class CesVMHost {
public:
  virtual ~CesVMHost() = default;

  // Throws std::logic_error("CesVMHost: <name> not implemented"). Every
  // default virtual delegates here; production override or per-test
  // subclass replaces them.
  [[noreturn]] static void notImpl(const char* name) {
    throw std::logic_error(std::string("CesVMHost: ") + name + " not implemented");
  }

  // ---- Reads ---------------------------------------------------------------
  virtual int64_t  readAccountBalance(const HashPrefix&)
  { notImpl("readAccountBalance"); }
  virtual uint32_t readAccountNonce  (const HashPrefix&)
  { notImpl("readAccountNonce"); }
  virtual uint32_t readAccountAliasId(const HashPrefix&)
  { notImpl("readAccountAliasId"); }
  virtual bool     readAsset(const minx::Hash&, HashPrefix&, AssetData&,
                             uint16_t&, uint32_t&)
  { notImpl("readAsset"); }
  // Windowed read of an alias's value image into `dest` (len bytes at
  // offset). Returns false for an unknown id or an out-of-bounds window.
  // Backs SYS_READ_ALIAS and SYS_LOAD_CODE_ALIAS.
  virtual bool     readAlias(uint32_t /*id*/, uint32_t /*offset*/,
                             uint32_t /*len*/, uint8_t* /*dest*/)
  { notImpl("readAlias"); }

  // ---- Writes — return CES_OK on success, error code otherwise ------------
  virtual uint8_t  transfer       (const minx::Hash&, uint64_t)
  { notImpl("transfer"); }
  // Same credit path as `transfer`, but the source is programOwner, not
  // the caller. NO allowance check (unbounded spend of programOwner);
  // bytecode-gated. See the programOwner field doc. Backs SYS_OWNER_TRANSFER.
  virtual uint8_t  ownerTransfer  (const minx::Hash&, uint64_t)
  { notImpl("ownerTransfer"); }
  // caller -> programOwner. Allowance-bound. Backs SYS_DEPOSIT.
  virtual uint8_t  deposit        (uint64_t)              { notImpl("deposit"); }
  // programOwner -> caller. NO allowance check (unbounded spend of
  // programOwner); bytecode-gated. See the programOwner field doc.
  // Backs SYS_WITHDRAW.
  virtual uint8_t  withdraw       (uint64_t)              { notImpl("withdraw"); }
  // Grant up to `requested` gas credits, funded by the caller account, bounded
  // by the refill ceiling and the account balance. Returns the amount granted;
  // the VM adds it to its budget. Default 0 (refill disabled). Backs
  // SYS_REFILL. The host tracks the running total in `refilledTotal` so
  // executeVmRun can charge for gas consumed past the free grant.
  virtual uint64_t refillGas      (uint64_t /*requested*/) { return 0; }
  virtual uint8_t  createAsset    (const minx::Hash&, const AssetData&, uint16_t)
  { notImpl("createAsset"); }
  // Caller pays, boot asset owns.
  virtual uint8_t  createAssetManaged(const minx::Hash&, const AssetData&, uint16_t)
  { notImpl("createAssetManaged"); }
  // Atomically create `n` account-owned assets keyed by the given first key
  // with its last 8 bytes overwritten 0..n-1 (LE). Returns CES_ERROR_ASSET_EXISTS
  // creating nothing if any target key exists (caller retries a fresh prefix);
  // CES_OK on success. Cell 0's content carries uint32_t n at bytes 0..3.
  virtual uint8_t  createAssetRange(const minx::Hash&, uint32_t, uint16_t)
  { notImpl("createAssetRange"); }
  virtual uint8_t  updateAsset    (const minx::Hash&, const AssetData&)
  { notImpl("updateAsset"); }
  // Owner+price-only update; content untouched. Backs SYS_UPDATE_ASSET_META.
  virtual uint8_t  updateAssetMeta(const minx::Hash&, const HashPrefix&, uint32_t)
  { notImpl("updateAssetMeta"); }
  virtual uint8_t  fundAsset      (const minx::Hash&, uint16_t)
  { notImpl("fundAsset"); }
  virtual uint8_t  buyAsset       (const minx::Hash&, uint64_t)
  { notImpl("buyAsset"); }
  virtual uint8_t  giveAsset      (const minx::Hash&, const HashPrefix&)
  { notImpl("giveAsset"); }
  // Patch an alias's value image as the run's programOwner principal (see
  // SYS_WRITE_ALIAS). Returns a CES error code.
  virtual uint8_t  writeAlias     (uint32_t /*id*/, uint32_t /*offset*/,
                                   const uint8_t*, uint32_t /*len*/)
  { notImpl("writeAlias"); }
  // Schedule a future runAsset. `allowance` is the per-run caller-debit cap
  // the future run will see — the syscall handler snapshots `host.allowance`
  // at queue time so the child inherits the parent's remaining headroom.
  virtual uint8_t  schedule       (const minx::Hash&, uint64_t /*budget*/,
                                   uint64_t /*allowance*/,
                                   const uint8_t*, size_t, uint64_t /*time_us*/)
  { notImpl("schedule"); }
  // Schedule a future run of an alias's inline program (SYS_SCHEDULE_ALIAS).
  virtual uint8_t  scheduleAlias  (uint32_t /*aliasId*/, uint64_t /*budget*/,
                                   uint64_t /*allowance*/,
                                   const uint8_t*, size_t, uint64_t /*time_us*/)
  { notImpl("scheduleAlias"); }
  // SYS_RPC — fire-and-forget MINX/RUDP stream call. The dispatcher reads
  // the request body from the cesh file at `fileHeadKey`, signs a footer
  // envelope (see the SYS_RPC enum comment), ships it to (host, port) on
  // the server's dedicated rpcMinx_, reads the response, writes it back
  // into the same file, and schedules a followup VM run with the outcome.
  // Returns a CES error code for the queue result (CES_OK = queued; the
  // actual call outcome arrives later via the followup).
  virtual uint8_t  rpc            (const std::string&, uint16_t,
                                   const minx::Hash&, const minx::Hash&,
                                   uint64_t, uint32_t)
  { notImpl("rpc"); }

  // SYS_L2_CALL — route to an in-CES (L2) built-in by 8-byte discriminator,
  // burn `value` from the caller on accept, enqueue a persistent call, and
  // settle on delivery (delivered -> mint payee; no-handler / timeout ->
  // refund payer). Zero followupKey = fire-and-forget. Returns the queue
  // result (CES_OK = accepted + burned; reject codes burn nothing).
  virtual uint8_t  l2call         (const uint8_t* /*discriminator8*/,
                                   uint64_t /*value*/,
                                   const uint8_t*, size_t /*blob*/,
                                   const minx::Hash& /*followupKey*/,
                                   uint64_t /*followupBudget*/,
                                   uint32_t /*followupTag*/)
  { notImpl("l2call"); }

  // ---- Caller debit chokepoint --------------------------------------------
  // For *spending* (transfer amounts, asset purchase prices, cross-transfer
  // amounts). Allowance-bound: the user signed an `allowance` value when
  // invoking CES_RUN_ASSET, and these debits collectively cannot exceed it.
  // Returns:
  //   CES_OK                          on success
  //   CES_ERROR_ORIGIN_NOT_FOUND      caller account is gone
  //   CES_ERROR_INSUFFICIENT_BALANCE  caller exists but lacks the credits
  //   CES_ERROR_ALLOWANCE_EXCEEDED    debit would exceed `allowance`
  // Used internally by `transfer`, `crossTransfer`, `buyAsset`. Undo-log
  // tracked under CES_RUN_ASSET. *Protocol fees* (feeTx, feeQuery,
  // feeAsset rent, etc.) do NOT go through this entry — they're billed
  // against the run's `budget` (pre-paid at CES_RUN_ASSET time); see
  // CesVM::billCredits.
  virtual uint8_t  debitCaller    (uint64_t)            { notImpl("debitCaller"); }

  // ---- Deferred side-effects ----------------------------------------------
  // Server buffers in CES_RUN_ASSET path; fires immediately in the
  // scheduled-run path.
  virtual void     sendUdp        (const std::string&, uint16_t,
                                   const uint8_t*, size_t)
  { notImpl("sendUdp"); }
  // Returns CES_OK on successful queue-and-debit, or a specific error:
  // CES_ERROR_UNKNOWN_PEER (no reachable peer for `server`),
  // CES_ERROR_QUEUE_FULL (settlement client backpressure),
  // or whatever debitCaller surfaced (INSUFFICIENT_BALANCE, ALLOWANCE_EXCEEDED,
  // ORIGIN_NOT_FOUND). Programs branch on the result; SYS_CROSS_TRANSFER
  // mirrors it into S.
  virtual uint8_t  crossTransfer  (const minx::Hash&, uint64_t,
                                   const std::string&)
  { notImpl("crossTransfer"); }

  // Push to connected client (APPLICATION message via presence cache).
  // Returns true if client was found and message sent.
  virtual bool     sendClient     (const HashPrefix&, const uint8_t*, size_t)
  { notImpl("sendClient"); }

  // ---- Crypto -------------------------------------------------------------
  virtual bool     verifySig      (const uint8_t*, size_t,
                                   const uint8_t*, const uint8_t*)
  { notImpl("verifySig"); }

  // ============================================================================
  // Per-run context (data members; populated before execute()).
  // ============================================================================

  // Per-operation protocol fees, populated from CesConfig at construction.
  // Syscall handlers bill these so the gas-billed compute cost stays separate
  // from the ledger-mutation fee that the VM and the UDP path must agree on.
  uint64_t feeQuery     = 0;
  uint64_t feeTx        = 0;
  uint64_t feeAsset     = 0;
  uint64_t feeAccount   = 0;
  uint64_t feeAlias    = 0;   // per-patch upfront day (SYS_WRITE_ALIAS)
  uint64_t feeSendClient = 0;  // no UDP equivalent — see CesServerVmHost ctor

  // Inputs for the per-day attenuated prepay-cost math (CREATE/FUND asset).
  // feeAssetRaw is the undiscounted feeAsset; assetRentMultBp is the current
  // AssetRent multiplier in basis points 0..10000. SYS_FUND_ASSET /
  // SYS_CREATE_ASSET* compute total cost inline using these plus
  // kPrepaidDiscountWindowDays — no extra hooks needed.
  uint64_t feeAssetRaw      = 0;
  uint16_t assetRentMultBp  = 10000;

  // Per-run cap on total caller-account debit through `debitCaller`. Initial
  // value is mirrored into io[CESVM_IO_ALLOWANCE] at execute() entry and is
  // decremented (and re-synced into io memory after every syscall) as the run
  // progresses, so VM programs can branch on remaining allowance. The default
  // (UINT64_MAX) is the "no enforcement" sentinel — set explicitly by callers
  // who want to cap how much a gateway program can spend on their behalf.
  // Gas budget is *not* counted here; it has its own cap (`budget`).
  uint64_t allowance = std::numeric_limits<uint64_t>::max();

  // Refill (SYS_REFILL). `refillCeiling` caps how much gas the run may draw
  // from the caller account past the free grant (0 = refill disabled).
  // `refilledTotal` is the running granted total, read by executeVmRun to
  // charge the caller for gas consumed past the free grant.
  uint64_t refillCeiling = 0;
  uint64_t refilledTotal = 0;

  // Which entry path started this run (a CesVMInvoke value). execute()
  // preloads it into io[CESVM_IO_INVOKE_KIND]. Default INVOKE_DIRECT so the
  // wire CES_RUN_ASSET path needs no change; scheduled/autoexec/hook paths set
  // it explicitly.
  uint64_t invokeKind = INVOKE_DIRECT;

  // Context
  minx::Hash callerKey;
  minx::Hash selfAssetKey;      // the asset being executed (boot cell)
  // The account this run may spend from WITHOUT an allowance check:
  // SYS_OWNER_TRANSFER and SYS_WITHDRAW debit it, SYS_DEPOSIT credits
  // it, and checkAssetWriteAuth lets the run rewrite its assets. It is a
  // CAPABILITY (a consenting principal), not merely a provenance record,
  // even though today it happens to equal the boot asset's current owner.
  //
  // SECURITY: this is a loaded gun. Any code path that reaches an
  // allowance-exempt syscall spends this account, and the caller may be
  // a stranger. The safety model is that the bytecode gates those
  // syscalls itself; the field is only sound when the party it names has
  // genuinely consented to this exact bytecode. In CES_RUN_ASSET that
  // holds because deploying the asset IS the consent, and the deployer
  // wrote the gate. /b/dice (buildDiceVmProgram in server.cpp) is the
  // reference: it collects the bet with a hostx (abort-on-failure)
  // SYS_DEPOSIT before it can ever reach the SYS_WITHDRAW payout, so an
  // underfunded caller aborts the run instead of winning house money.
  //
  // A future caller that runs bytecode the named account did NOT consent
  // to (e.g. an account-attached hook pointing at a stranger's program)
  // MUST leave this empty; a zero prefix finds no account, so every
  // allowance-exempt syscall no-ops and the run can only spend the
  // caller via the allowance-bounded path.
  HashPrefix programOwner{};
  ces::Bytes input;
};

class CesVM {
public:
  CesVM();

  // Execute bytecode with the given host environment and credit budget.
  // gasMult: server-configured multiplier applied to all gas costs.
  CesVMResult execute(const ces::Bytes& code,
                      CesVMHost& host, uint64_t budget,
                      uint64_t gasMult = 1);

  // Test/bench hook: force the reference (non-predecoded) interpreter core
  // on this instance. The reference core defines the semantics; the fast
  // core must match it observably. No effect when CESVM_OPT_PREDECODE=0
  // (the reference core is all there is).
  void _setLegacyCore(bool legacy) { legacyCore_ = legacy; }

private:
  // GVM core
  uint64_t io_[CESVM_IO_SIZE];

#if CESVM_OPT_FIXED_STACKS
  // Both stacks have hard depth caps, so fixed member arrays beat vectors
  // (no capacity checks or heap traffic on the hot push/pop path). Contents
  // above the length watermark are never read.
  uint64_t stackBuf_[CESVM_MAX_STACK_DEPTH];
  uint32_t stackLen_ = 0;
  std::array<uint64_t, CESVM_REG_SIZE> ctxBuf_[CESVM_MAX_CALL_DEPTH];
  uint32_t ctxLen_ = 0;
#else
  std::vector<uint64_t> stack_;
  std::vector<std::array<uint64_t, CESVM_REG_SIZE>> context_;
#endif

  // Named register refs
  uint64_t& PC() { return io_[0]; }
  uint64_t& R()  { return io_[1]; }
  uint64_t& S()  { return io_[2]; }

  // Operand decoding (from GVM)
  uint64_t read(bool jumpSkipControl = false);

  uint64_t& get(uint64_t index) {
    if (index < CESVM_IO_SIZE) {
      return io_[index];
    }
    term_ = CESVM_SEGFAULT;
    return R();
  }

  // Hard cap on the data stack to close the "push in a tight loop and
  // burn server memory faster than the gas budget can stop it" DoS
  // vector. Overflow is promoted to CESVM_SEGFAULT, which the server's
  // undo log rolls back the same as any other VM crash.
  void push(uint64_t v) {
#if CESVM_OPT_FIXED_STACKS
    if (stackLen_ >= CESVM_MAX_STACK_DEPTH) {
      term_ = CESVM_SEGFAULT;
      return;
    }
    stackBuf_[stackLen_++] = v;
#else
    if (stack_.size() >= CESVM_MAX_STACK_DEPTH) {
      term_ = CESVM_SEGFAULT;
      return;
    }
    stack_.push_back(v);
#endif
  }

  uint64_t pop() {
#if CESVM_OPT_FIXED_STACKS
    if (stackLen_ == 0) {
      term_ = CESVM_UNDERFLOW;
      return 0;
    }
    return stackBuf_[--stackLen_];
#else
    if (stack_.empty()) {
      term_ = CESVM_UNDERFLOW;
      return 0;
    }
    uint64_t v = stack_.back();
    stack_.pop_back();
    return v;
#endif
  }

  void stackClear() {
#if CESVM_OPT_FIXED_STACKS
    stackLen_ = 0;
#else
    stack_.clear();
#endif
  }

  // CALL frame stack. ctxPush snapshots the 16 registers (including the
  // already-advanced PC = return address); false means the call-depth cap
  // was hit and CESVM_SEGFAULT is set. ctxRestorePop restores the caller's
  // registers and drops the frame.
  bool ctxPush() {
#if CESVM_OPT_FIXED_STACKS
    if (ctxLen_ >= CESVM_MAX_CALL_DEPTH) {
      term_ = CESVM_SEGFAULT;
      return false;
    }
    std::memcpy(ctxBuf_[ctxLen_++].data(), &io_[0],
                sizeof(uint64_t) * CESVM_REG_SIZE);
#else
    if (context_.size() >= CESVM_MAX_CALL_DEPTH) {
      term_ = CESVM_SEGFAULT;
      return false;
    }
    std::array<uint64_t, CESVM_REG_SIZE> regs;
    std::memcpy(regs.data(), &io_[0], sizeof(uint64_t) * CESVM_REG_SIZE);
    context_.push_back(regs);
#endif
    return true;
  }

  bool ctxEmpty() const {
#if CESVM_OPT_FIXED_STACKS
    return ctxLen_ == 0;
#else
    return context_.empty();
#endif
  }

  void ctxRestorePop() {
#if CESVM_OPT_FIXED_STACKS
    std::memcpy(&io_[0], ctxBuf_[--ctxLen_].data(),
                sizeof(uint64_t) * CESVM_REG_SIZE);
#else
    std::memcpy(&io_[0], context_.back().data(),
                sizeof(uint64_t) * CESVM_REG_SIZE);
    context_.pop_back();
#endif
  }

  void ctxClear() {
#if CESVM_OPT_FIXED_STACKS
    ctxLen_ = 0;
#else
    context_.clear();
#endif
  }

  // CES syscall dispatch
  void hostCall(CesVMHost& host);

  // Interpreter cores. stepSlow executes exactly one instruction at PC
  // (base per-op cost already billed by the caller) and is the reference
  // semantics; runLegacy loops it. runFast is the predecoded core, which
  // dispatches anything it can't fast-path back through stepSlow.
  void stepSlow(CesVMHost& host);
  void runLegacy(CesVMHost& host, CesVMResult& result);
#if CESVM_OPT_PREDECODE
  struct Decoded {
    uint32_t epoch = 0;   // valid iff == epoch_
    uint16_t h = 0;       // fast-handler index (0 = replay via stepSlow)
    uint8_t  regptr = 0;  // bit i: operand i is a cell dereference
    uint8_t  nops = 0;
    uint16_t nextPc = 0;  // byte offset after the full instruction
    uint16_t target = 0;  // JMP/CALL/JF/JT literal jump target
    uint64_t val[3] = {}; // operand immediates / static cell indices
  };
  void decodeAt(uint64_t pc, Decoded& d);
  void runFast(CesVMHost& host, CesVMResult& result);
  std::vector<Decoded> dtab_; // indexed by byte offset; lazily decoded
  uint32_t epoch_ = 0;        // bumped per execute(); validates dtab_ entries
#endif
  bool legacyCore_ = false;

  // Billing: deduct cost from budget, set CESVM_BUDGET on insufficient funds.
  // Returns true if budget was sufficient, false if execution should stop.
  bool bill(uint64_t cost);
  // Overflow-safe bill(a * b): rejects if the multiplication would wrap.
  bool billMul(uint64_t a, uint64_t b);
  // Bill raw credits against the budget without applying gasMult — used
  // for protocol fees (feeTx, feeQuery, etc.) which are denominated in
  // credits already, not in gas units. Same halt semantics as bill().
  bool billCredits(uint64_t raw);

  // The per-op base cost, billed once per instruction by both cores.
  // With CESVM_OPT_BILL_HOIST the COST_PER_OP * gasMult product (and its
  // overflow guard, which halts as budget-exhausted, matching bill()) is
  // computed once per execute() instead of per op.
  bool billOp() {
#if CESVM_OPT_BILL_HOIST
    if (opCostOvf_ || opCost_ > budget_ - budgetUsed_) {
      term_ = CESVM_BUDGET;
      io_[CESVM_IO_BUDGET_REMAINING] = 0;
      return false;
    }
    budgetUsed_ += opCost_;
    io_[CESVM_IO_BUDGET_REMAINING] = budget_ - budgetUsed_;
    return true;
#else
    return bill(CESVM_COST_PER_OP);
#endif
  }

  // Helper: read bytes from io memory at offset into a buffer
  void readIoBytes(uint64_t ioOffset, uint8_t* out, size_t len);
  // Helper: write bytes to io memory at offset
  void writeIoBytes(uint64_t ioOffset, const uint8_t* data, size_t len);

  uint64_t term_ = 0;
  uint64_t budget_ = 0;
  uint64_t budgetUsed_ = 0;
  uint64_t gasMult_ = 1;
  uint64_t opCost_ = CESVM_COST_PER_OP;
  bool opCostOvf_ = false;
  ces::Bytes code_;  // mutable code buffer (grows via SYS_LOAD_CODE)
  std::mt19937_64 rng_;
};

} // namespace ces
