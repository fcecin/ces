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
 *   - 50 opcodes (35 GVM core + RND, TIME, MOV, LDB, STB, CMP, FIL,
 *     HOSTX, ABORT, JMPR, CALLR, HOSTV, HOSTXV, SAR, LNOT)
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
 *   1  READ_ACCOUNT         io[4]=prefix_ptr → R=balance, io[5]=nonce, S=ok
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
 *
 * Preloaded io locations (read-only context, set before execution):
 *   io[752]        = input length (bytes)
 *   io[754]        = initial budget (credits)
 *   io[755]        = start time (microseconds since epoch)
 *   io[756..759]   = caller public key (32 bytes)
 *   io[760..763]   = self asset key (32 bytes)
 *   io[892..1019]  = input data (up to 1024 bytes)
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

#include <cstdint>
#include <functional>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

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
  CESVM_ABORT      = 13,  // program aborted (OP_HOSTX on S!=0, or OP_ABORT)
  CESVM_HOST       = 14,  // host callback or VM infrastructure threw
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
  // io[5]=amount), but the source account is the program's owner
  // (vmHost.programOwner), not the caller. The caller still pays the
  // protocol fee (feeTx) because they invoked the syscall — only the
  // value-bearing transfer is debited from the owner. No allowance check
  // applies; the asset's owner deployed the bytecode and consented to
  // whatever it does. Returns CES_ERROR_ORIGIN_NOT_FOUND if the program
  // owner has no account (e.g. asset-owned chain), or
  // CES_ERROR_INSUFFICIENT_BALANCE if the owner can't cover the amount.
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
  // io[4] = amount. NOT allowance-bound — the asset's owner consented
  // to the bytecode by deploying it. Returns CES_ERROR_ORIGIN_NOT_FOUND
  // or CES_ERROR_INSUFFICIENT_BALANCE per host.withdraw.
  SYS_WITHDRAW        = 21,
  // SYS_UPDATE_ASSET_META — set owner+price on an existing asset
  // without touching content. io[4] = key_ptr, io[5] = new_owner_ptr
  // (8-byte HashPrefix), io[6] = new_price (uint32). Auth via
  // checkAssetWriteAuth (caller, programOwner, or self-asset-key for
  // asset-owned chains). Bills feeTx, not feeAsset — matches the wire
  // CES_UPDATE_ASSET_META fee tier (cheaper than full content update).
  SYS_UPDATE_ASSET_META = 22,
};

// Opcode numbers (one byte each). Exposed here as the single source of
// truth: cesvm.cpp's parser, the VmProgram builder (include/ces/vmprogram.h),
// and every test file that checks bytecode bytes directly all pull from
// this header instead of maintaining their own local copies. When a new
// opcode lands it goes here and nowhere else needs to change.
//
// The high bit (0x80) of an opcode byte is the STACK modifier: OR it
// with any opcode that has a stack variant (ADD, SUB, MUL, DIV, MOD, OR,
// ANDL, XOR, NOT, LNOT, SHL, SHR, SAR, EQ, NE, GT, LT, GE, LE, NEG, ORL,
// JF, JT, LDB, STB, RND, TIME, CALL) to pop operands from the stack
// instead of reading them from the instruction stream.
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
//                (the high region) down into this low band get the rest
//                of the program for free at short-encoded cost.
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
// New preloaded values go in the high region or the io[1022..1023] reserve,
// never the low region, which would clobber programs relying on it as scratch.
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
static constexpr uint64_t CESVM_MAX_INPUT     = 1024;
static constexpr uint64_t CESVM_MAX_OUTPUT    = 1024;

// --- Gas cost constants (benchmarked on release build, 1M iterations) ---
// Baseline: ADD reg ≈ 31 ns. 1 unit ≈ 0.31 ns.
//
// Cost per VM instruction in credits
static constexpr uint64_t CESVM_COST_PER_OP = 100;
// Cost per syscall (dispatch + host callback, on top of per-op cost)
static constexpr uint64_t CESVM_COST_PER_SYSCALL = 150;
// Cost for compute-only syscalls (HASH init, no ledger I/O)
static constexpr uint64_t CESVM_COST_PER_MEMOP = 300;
// Per-cell cost for variable-length memory opcodes (MOV, CMP, FIL)
static constexpr uint64_t CESVM_COST_PER_CELL = 1;
// Per-byte cost for variable-length data processing (HASH, VERIFY_SIG)
static constexpr uint64_t CESVM_COST_PER_BYTE = 1;
// EC signature verification cost (~1000x baseline op)
static constexpr uint64_t CESVM_COST_VERIFY_EC = 100000;
// Fixed penalty on VM crash (deducted from refund, not from budget)
static constexpr uint64_t CESVM_CRASH_FEE = 1000000;
// Cost to schedule a delayed runAsset (base + per second of hosting)
static constexpr uint64_t CESVM_SCHEDULE_BASE_COST = CESVM_COST_PER_OP * 100;  // 10000
static constexpr uint64_t CESVM_SCHEDULE_PER_SEC = CESVM_COST_PER_OP;           // 100

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
  virtual bool     readAsset(const minx::Hash&, HashPrefix&, AssetData&,
                             uint16_t&, uint32_t&)
  { notImpl("readAsset"); }

  // ---- Writes — return CES_OK on success, error code otherwise ------------
  virtual uint8_t  transfer       (const minx::Hash&, uint64_t)
  { notImpl("transfer"); }
  // Same credit path as `transfer`, but the source is the program's
  // owner (programOwner), not the caller. No allowance check.
  virtual uint8_t  ownerTransfer  (const minx::Hash&, uint64_t)
  { notImpl("ownerTransfer"); }
  // caller -> programOwner. Allowance-bound. Backs SYS_DEPOSIT.
  virtual uint8_t  deposit        (uint64_t)              { notImpl("deposit"); }
  // programOwner -> caller. No allowance check. Backs SYS_WITHDRAW.
  virtual uint8_t  withdraw       (uint64_t)              { notImpl("withdraw"); }
  virtual uint8_t  createAsset    (const minx::Hash&, const AssetData&, uint16_t)
  { notImpl("createAsset"); }
  // Caller pays, boot asset owns.
  virtual uint8_t  createAssetManaged(const minx::Hash&, const AssetData&, uint16_t)
  { notImpl("createAssetManaged"); }
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
  // Schedule a future runAsset. `allowance` is the per-run caller-debit cap
  // the future run will see — the syscall handler snapshots `host.allowance`
  // at queue time so the child inherits the parent's remaining headroom.
  virtual uint8_t  schedule       (const minx::Hash&, uint64_t /*budget*/,
                                   uint64_t /*allowance*/,
                                   const uint8_t*, size_t, uint64_t /*time_us*/)
  { notImpl("schedule"); }
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

  // Context
  minx::Hash callerKey;
  minx::Hash selfAssetKey;      // the asset being executed (boot cell)
  HashPrefix programOwner{};    // owner of the boot cell (program author auth)
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

private:
  // GVM core
  uint64_t io_[CESVM_IO_SIZE];
  std::vector<uint64_t> stack_;
  std::vector<std::array<uint64_t, CESVM_REG_SIZE>> context_;

  // Named register refs
  uint64_t& PC() { return io_[0]; }
  uint64_t& R()  { return io_[1]; }
  uint64_t& S()  { return io_[2]; }

  // Operand decoding (from GVM)
  uint64_t read(bool jumpSkipControl = false);
  uint64_t& get(uint64_t index);
  void push(uint64_t v);
  uint64_t pop();

  // CES syscall dispatch
  void hostCall(CesVMHost& host);

  // Billing: deduct cost from budget, set CESVM_BUDGET on insufficient funds.
  // Returns true if budget was sufficient, false if execution should stop.
  bool bill(uint64_t cost);
  // Overflow-safe bill(a * b): rejects if the multiplication would wrap.
  bool billMul(uint64_t a, uint64_t b);
  // Bill raw credits against the budget without applying gasMult — used
  // for protocol fees (feeTx, feeQuery, etc.) which are denominated in
  // credits already, not in gas units. Same halt semantics as bill().
  bool billCredits(uint64_t raw);

  // Helper: read bytes from io memory at offset into a buffer
  void readIoBytes(uint64_t ioOffset, uint8_t* out, size_t len);
  // Helper: write bytes to io memory at offset
  void writeIoBytes(uint64_t ioOffset, const uint8_t* data, size_t len);

  uint64_t term_ = 0;
  uint64_t budget_ = 0;
  uint64_t budgetUsed_ = 0;
  uint64_t gasMult_ = 1;
  ces::Bytes code_;  // mutable code buffer (grows via SYS_LOAD_CODE)
  std::mt19937_64 rng_;
};

} // namespace ces
