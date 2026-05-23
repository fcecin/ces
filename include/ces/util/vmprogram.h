#pragma once

/**
 * vmprogram.h — C++ builder for CesVM bytecode programs.
 *
 * A fluent API that emits bytecode for the GVM-based CesVM used by
 * CES_RUN_ASSET. Test authors and program writers use this instead of
 * hand-packing opcode bytes and operand control-byte encodings, turning
 * that mechanical work into compile-checked C++.
 *
 * The builder:
 *
 *   - Exposes one method per VM opcode, with C++ types instead of raw
 *     bytes. Misspellings become compile errors.
 *
 *   - Auto-encodes operands in the shortest valid control-byte form.
 *     Small immediates use the 1-byte SHORT_VAL encoding; larger
 *     values use the multi-byte wide form (1..8 payload bytes LE).
 *
 *   - Handles labels with forward-reference patching. A label is
 *     declared, referenced by branch/call instructions as many times
 *     as needed, and placed at its target by place(label). The build
 *     step resolves all pending references in one pass.
 *
 *   - Offers structured control flow on top of labels: lambda-bodied
 *     ifThen / ifThenElse that allocate and place their own labels,
 *     with merge-jmp elision when the then-body terminates (the
 *     emitted bytecode matches a hand-written branch).
 *
 *   - Manages scratch-cell layout via a tiny bump allocator. Programs
 *     ask for typed Regions (allocHash, allocContent, …) instead of
 *     typing magic cell numbers; two regions in the same program are
 *     guaranteed non-overlapping. allocAt() is the escape hatch for
 *     protocol-fixed addresses.
 *
 *   - Provides typed syscall wrappers for the host-dispatch family,
 *     plus pair-bundle helpers (loadCodeAndCall, readAndUpdateAsset)
 *     that bake safety contracts and ABI quirks into a single call.
 *
 *   - Provides convenience helpers for common patterns: copying cells
 *     out of preloaded regions (caller key, self key, input), writing
 *     byte sequences (e.g. "127.0.0.1") into io memory, byte-level
 *     ldb/stb addressed by (cell, byteOffset).
 *
 *   - Builds into either a 210-byte AssetData (the boot code block of
 *     a CES asset) via buildBootBlock(), or a flexible byte vector
 *     via buildBytes() if the program is larger than one block. The
 *     CesVM code limit is 8 KB.
 *
 * Example — a minimal "ext_call rudp" gateway program:
 *
 *   VmProgram pgm;
 *   Region fileHead = pgm.allocHash();   // 4 cells of scratch
 *   pgm.copyFromInput(fileHead, 0);      // 0 = input cell offset
 *   pgm.term();
 *   AssetData code = pgm.buildBootBlock();
 *
 * Threading / lifetime: VmProgram is a plain builder object with no
 * external state. It is not thread-safe; construct one per building
 * session and throw it away.
 */

#include <ces/asset.h>
#include <ces/cesvm.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace ces {

// ---------------------------------------------------------------------------
// Operand helpers
// ---------------------------------------------------------------------------
//
// The CesVM's read() function decodes each operand into a uint64_t by
// combining:
//   - A control byte whose bits say "short form vs. wide form" and
//     "raw value vs. dereference via io[value]".
//   - Optional 1..8 payload bytes (for wide form only).
//
// VmVal wraps the triplet (numeric value, dereference flag) the builder
// needs to emit one operand. Opcodes interpret the final value
// differently — OP_SET's first operand is a cell index to write into,
// OP_ADD's operands are literal values to add, OP_MOV's operands are
// (dst cell, src cell, count) — but the wire encoding is uniform, so
// the VmVal struct is enough to represent every operand.

struct VmVal {
  uint64_t value = 0;
  bool deref = false;  // if true, emit with the REG_PTR bit set (io[value])
};

// Immediate value. The emitted operand decodes to exactly `v`, whatever
// the surrounding opcode does with it.
inline VmVal Imm(uint64_t v) { return {v, false}; }

// Dereference through a cell. The emitted operand reads cell `c` at
// runtime and uses that cell's contents as the operand value.
inline VmVal Ref(uint64_t c) { return {c, true}; }

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------
//
// A VmLabel is an opaque handle into the builder's internal label table.
// Declare one with VmProgram::label(), place it at its intended code
// offset with VmProgram::place(l), and reference it from jumps and
// calls. References emit a 2-byte placeholder that build-time
// resolution patches with the resolved offset. Forward references are
// fine; unplaced labels at build time are a build error.

struct VmLabel {
  size_t id;
  bool operator==(const VmLabel& o) const { return id == o.id; }
};

// ---------------------------------------------------------------------------
// Region — a typed handle for a contiguous range of scratch cells
// ---------------------------------------------------------------------------
//
// CesVM's data plane (`io_`) has 1024 cells. Cells 0..15 are named
// registers (PC, R, S, …, GPR0..7); cells 752..1023 are protocol-fixed
// (context, output, input, allowance, budget remaining); cells
// 16..751 are 736 cells of free-form scratch shared across the
// program. Bytecode lives in a separate buffer (`code_` in CesVM), not
// overlaid on io[], so a program can use any subrange of cells 16..751 as
// scratch without overwriting its own bytecode.
//
// VmProgram ships a tiny bump allocator over that 736-cell range so
// programs don't pick magic cell numbers by hand. Each `alloc(N)` (or
// the typed shortcuts `allocHash`, `allocHashPrefix`, `allocContent`,
// `allocCell`) returns a Region with a stable first-cell index and a
// count. Two regions allocated in the same program are guaranteed
// non-overlapping. The allocator has no notion of free/release — it's
// strictly bump-up, matching the program-as-straight-line shape that
// VmProgram targets. Programs that share data with the outside world
// at fixed addresses (or that need backwards-compatibility with
// existing layouts) can use `allocAt(cell, count)` to anchor a
// Region at a specific cell without moving the bump cursor.
//
// Region implicitly converts to VmVal as Imm(cell), so it slots
// directly into existing typed syscall structs whose `*Cell` fields
// are VmVal-typed cell indices. Helpers that take raw cell indices
// (ldbFromCell, stbInCell, the copy* family) gain Region overloads
// for fluency.

struct Region {
  uint64_t cell  = 0;  // first cell index in the region
  uint64_t count = 0;  // number of cells

  // Implicit conversion to a VmVal: "the cell index where this region
  // starts, as an immediate." Lets a Region pass for any VmVal-typed
  // parameter expecting a cell-index pointer.
  operator VmVal() const { return Imm(cell); }
};

// ---------------------------------------------------------------------------
// VmProgram — the builder
// ---------------------------------------------------------------------------
//
// The builder is register-style: every binary-op method takes two VmVal
// operands and writes the result to R. CesVM's ISA also has stack-mode
// variants (the opcode OR'd with the STACK bit 0x80, popping and pushing
// the data stack), but the builder does not expose them for arithmetic.
// The host C++ already does the operand scheduling that stack mode exists
// to help a hand-coder with. push() and pop() remain exposed for parking
// a value across a syscall that clobbers R; hand-write raw bytes if you
// genuinely need stack-composed bytecode.

class VmProgram {
public:
  VmProgram();
  ~VmProgram() = default;

  VmProgram(const VmProgram&) = delete;
  VmProgram& operator=(const VmProgram&) = delete;
  VmProgram(VmProgram&&) = default;
  VmProgram& operator=(VmProgram&&) = default;

  // =========================================================================
  // Low-level opcode methods
  //
  // One method per GVM / CesVM opcode, named after the opcode in
  // lower_snake_case. Operand types match the decoded shape; binary ops
  // take two VmVal operands, ternary ops (mov/cmp/fil) take three, and
  // so on. The dst/src distinction is documented per method.
  //
  // These methods can be chained and each returns *this for fluent
  // composition.
  // =========================================================================

  // --- Control flow + meta ---

  // No-op (1 gas unit).
  VmProgram& nop();
  // Terminate normally. Sets PC to UINT64_MAX, which ends execution.
  VmProgram& term();
  // Abort. Ends execution with CESVM_ABORT.
  VmProgram& abort();
  // Unconditional jump to `target`.
  VmProgram& jmp(VmLabel target);
  // Jump to `target` if `cond` is falsy (0).
  VmProgram& jf(VmVal cond, VmLabel target);
  // Jump to `target` if `cond` is truthy (nonzero).
  VmProgram& jt(VmVal cond, VmLabel target);
  // Call `target`. Saves all 16 registers (128-byte frame); RET restores.
  VmProgram& call(VmLabel target);
  // Return from a call, writing `retVal` into R before restoring regs.
  // For top-level returns (no enclosing call), the program ends with
  // CESVM_RET, which the VM treats as a crash.
  VmProgram& ret(VmVal retVal);

  // Indirect jump and call: the target is a runtime value computed by
  // the program, not a compile-time label. Typical use: after
  // SYS_LOAD_CODE writes the loaded block's offset into R, jmpr(Ref(
  // CESVM_CELL_R)) jumps into the freshly-loaded code. OP_JMPR /
  // OP_CALLR take a single operand that gets dereferenced by the
  // VM's regular operand decoder (so Imm(offset) jumps to that
  // literal address, Ref(cell) jumps to io[cell]).
  VmProgram& jmpr(VmVal target);
  VmProgram& callr(VmVal target);

  // --- Host dispatch ---

  // Call the host, ignoring S (status). Use host() for "best-effort"
  // syscalls where the program will inspect S manually.
  VmProgram& host();
  // Call the host and abort the program if S is nonzero on return.
  // This is the common case — use hostx() unless you explicitly want
  // to handle a failing syscall.
  VmProgram& hostx();

  // --- Data movement ---

  // io[dst] = src. dst is interpreted as a cell index to write into;
  // src is interpreted as the value to store (so src = Imm(v) stores
  // the literal, src = Ref(c) stores io[c]). dst can itself be a Ref
  // (writing through a pointer stored in a cell).
  VmProgram& set(VmVal dst, VmVal src);

  // Copy `count` cells from io[src..] to io[dst..]. See also copy()
  // below for the common all-literal case.
  VmProgram& mov(VmVal dst, VmVal src, VmVal count);

  // Compare: R() = 1 if io[a..a+count-1] == io[b..b+count-1], else 0.
  VmProgram& cmp(VmVal a, VmVal b, VmVal count);

  // Fill: io[dst..dst+count-1] = val.
  VmProgram& fil(VmVal dst, VmVal val, VmVal count);

  // Load/store byte — io's byte-level view. LDB reads one byte at
  // `byteOffset` into R; STB writes the low byte of `val` at
  // `byteOffset`.
  VmProgram& ldb(VmVal byteOffset);
  VmProgram& stb(VmVal byteOffset, VmVal val);

  // Increment / decrement a cell in place.
  VmProgram& inc(VmVal cell);
  VmProgram& dec(VmVal cell);

  // --- Arithmetic / logic (two-operand, result in R) ---

  VmProgram& add(VmVal a, VmVal b);
  VmProgram& sub(VmVal a, VmVal b);
  VmProgram& mul(VmVal a, VmVal b);
  VmProgram& div(VmVal a, VmVal b);
  VmProgram& mod(VmVal a, VmVal b);
  VmProgram& or_(VmVal a, VmVal b);
  VmProgram& and_(VmVal a, VmVal b);
  VmProgram& xor_(VmVal a, VmVal b);
  // Bitwise complement (~x). For boolean-flip use lnot().
  VmProgram& not_(VmVal a);
  // Logical NOT (!x): 0 → 1, anything else → 0.
  VmProgram& lnot(VmVal a);
  // Arithmetic two's-complement negate (-x).
  VmProgram& neg(VmVal a);
  VmProgram& shl(VmVal a, VmVal b);
  VmProgram& shr(VmVal a, VmVal b);
  // Arithmetic shift right: signed >> (preserves sign bit). Use for
  // negative values; SHR is logical/zero-fill.
  VmProgram& sar(VmVal a, VmVal b);
  VmProgram& andl(VmVal a, VmVal b);  // logical AND (!!a && !!b)
  VmProgram& orl(VmVal a, VmVal b);   // logical OR
  VmProgram& eq(VmVal a, VmVal b);
  VmProgram& ne(VmVal a, VmVal b);
  VmProgram& gt(VmVal a, VmVal b);
  VmProgram& lt(VmVal a, VmVal b);
  VmProgram& ge(VmVal a, VmVal b);
  VmProgram& le(VmVal a, VmVal b);

  // --- Stack ---

  VmProgram& push(VmVal v);
  VmProgram& pop(VmVal cell);

  // --- Miscellaneous ---

  // Write a 64-bit random number to R.
  VmProgram& rnd();
  // Write current time (microseconds since epoch) to R.
  VmProgram& time();

  // =========================================================================
  // Label management
  // =========================================================================

  // Create a fresh label. The label can be referenced immediately (for
  // forward jumps) and placed later via place().
  VmLabel label();

  // Place a label at the current code offset. A label can only be
  // placed once; placing twice is a build error.
  VmProgram& place(VmLabel l);

  // =========================================================================
  // Structured control flow
  // =========================================================================
  //
  // Lambda-bodied if-then[-else] that allocates and places its own
  // labels. The body callable is invoked with `*this`, so it can emit
  // any further instructions (including nested ifs, syscalls, jumps to
  // outer labels — closures-by-reference make outer labels visible).
  //
  // ifThenElse emits the canonical shape:
  //   jf(cond, elseL); <thenBody>; jmp(endL); place(elseL); <elseBody>; place(endL)
  // with one optimization: if the then-body's last emitted opcode is
  // OP_TERM or OP_ABORT, the merge `jmp(endL)` is elided as dead code
  // (execution can never reach it). This keeps the lambda form
  // bytecode-equal to a hand-written branch where both arms terminate.

  template<class ThenBody>
  VmProgram& ifThen(VmVal cond, ThenBody&& body) {
    VmLabel endL = label();
    jf(cond, endL);
    std::forward<ThenBody>(body)(*this);
    place(endL);
    return *this;
  }

  template<class ThenBody, class ElseBody>
  VmProgram& ifThenElse(VmVal cond,
                         ThenBody&& thenBody,
                         ElseBody&& elseBody) {
    VmLabel elseL = label();
    VmLabel endL  = label();
    jf(cond, elseL);
    lastWasTerminator_ = false;  // jf emits non-terminator OP_JF
    std::forward<ThenBody>(thenBody)(*this);
    if (!lastWasTerminator_) jmp(endL);
    place(elseL);
    std::forward<ElseBody>(elseBody)(*this);
    place(endL);
    return *this;
  }

  // =========================================================================
  // Scratch region allocator
  // =========================================================================

  // Allocate `count` contiguous cells from the scratch range and
  // return a Region. Throws if the bump cursor would overflow the
  // scratch range (cells 16..751 by default).
  Region alloc(uint64_t count);

  // Typed shortcuts for the most common region sizes. Equivalent to
  // alloc(N) with N matching the protocol object's cell footprint.
  Region allocHash()       { return alloc(4); }   // 32-byte hash
  Region allocHashPrefix() { return alloc(1); }   // 8-byte HashPrefix
  Region allocContent()    { return alloc(27); }  // 210-byte AssetData (round up to 27 cells)
  Region allocCell()       { return alloc(1); }   // single 8-byte cell

  // Anchor a region at a fixed cell index without bumping the cursor.
  // Use when the program needs a region at a protocol-fixed location
  // (e.g. CESVM_IO_INPUT range), or when bridging to legacy code that
  // hard-coded cells. The caller takes responsibility for ensuring
  // the anchored range doesn't collide with allocator-managed cells.
  Region allocAt(uint64_t cell, uint64_t count) const {
    return Region{cell, count};
  }

  // Set the starting cell for the bump allocator. Default is
  // CESVM_REG_SIZE (16) — the first cell past the registers. Calling
  // this AFTER allocations have happened simply moves the cursor;
  // previously returned regions remain valid (and may now overlap
  // future allocations, which is the caller's problem).
  void setScratchBase(uint64_t cell) { scratchTop_ = cell; }

  // =========================================================================
  // High-level convenience helpers
  // =========================================================================

  // Copy `count` cells from io[srcCell..] to io[dstCell..]. Shortcut
  // for mov(Imm(dst), Imm(src), Imm(count)) — the common all-literal
  // case that appears in almost every test program.
  VmProgram& copy(uint64_t dstCell, uint64_t srcCell, uint64_t count);

  // Preloaded-context copy helpers. Every gateway program starts by
  // copying some of its inputs out of the high-region preloaded cells
  // (CESVM_IO_INPUT, CESVM_IO_CALLER_KEY, CESVM_IO_SELF_KEY) into the
  // low region where short-encoded access is cheap. These wrap the
  // copy() call with the right source offset so callers don't have
  // to remember the high-region constants.

  // Copy `count` cells from io[CESVM_IO_INPUT + inputCellOffset..]
  // to io[dstCell..]. `inputCellOffset` is a count of u64 cells from
  // the start of the input region, NOT bytes. Each cell is 8 bytes.
  VmProgram& copyFromInput(uint64_t dstCell, uint64_t inputCellOffset,
                            uint64_t count);

  // Region-typed overload. The destination region's `count` is the
  // number of cells copied; `dst.cell` is where they land.
  VmProgram& copyFromInput(Region dst, uint64_t inputCellOffset) {
    return copyFromInput(dst.cell, inputCellOffset, dst.count);
  }

  // Copy the caller public key (4 cells = 32 bytes) from the
  // preloaded io[CESVM_IO_CALLER_KEY..] region to io[dstCell..].
  VmProgram& copyCallerKeyTo(uint64_t dstCell);
  VmProgram& copyCallerKeyTo(Region dst) { return copyCallerKeyTo(dst.cell); }

  // Copy the self asset key (4 cells = 32 bytes) from the preloaded
  // io[CESVM_IO_SELF_KEY..] region to io[dstCell..]. Typically used
  // by counter programs that need to read/write their own asset.
  VmProgram& copySelfKeyTo(uint64_t dstCell);
  VmProgram& copySelfKeyTo(Region dst) { return copySelfKeyTo(dst.cell); }

  // Output-write helpers. The "return a value" pattern at the end of
  // a test program is a set of io[CESVM_IO_OUTPUT_LEN] + a write into
  // io[CESVM_IO_OUTPUT..]. These helpers collapse the pair into a
  // single builder call.

  // Write a single value to io[CESVM_IO_OUTPUT] and set
  // io[CESVM_IO_OUTPUT_LEN] to `byteLen`. `value` can be an
  // Imm for a literal, Ref for a dereference from another cell.
  // Single-cell values only; for multi-cell outputs use copy()
  // into io[CESVM_IO_OUTPUT..] and then set the length directly.
  VmProgram& setOutput(VmVal value, uint64_t byteLen);

  // Multi-cell output: copy `count` cells from io[srcCell..] into
  // io[CESVM_IO_OUTPUT..] and set io[CESVM_IO_OUTPUT_LEN] to
  // `byteLen`. Useful when the program assembled a multi-byte result
  // in scratch space and wants to return it verbatim.
  VmProgram& setOutputBytes(uint64_t srcCell, uint64_t count,
                             uint64_t byteLen);

  // Byte-level cell addressing. CesVM's LDB/STB operate on byte offsets
  // into io memory, computed as `cellIndex * 8 + byteInCell`. These helpers
  // compute that offset so call sites don't hand-roll the arithmetic.

  // Returns the byte offset of the `byteOffsetInCell`-th byte inside
  // the cell at `cellIndex`. Little-endian byte order within the cell.
  // Constexpr so it can appear in constant expressions.
  static constexpr uint64_t byteInCell(uint64_t cellIndex,
                                        uint64_t byteOffsetInCell) {
    return cellIndex * 8 + byteOffsetInCell;
  }

  // Load the `byteOffsetInCell`-th byte of the cell at `cellIndex`
  // into R. Equivalent to `ldb(Imm(byteInCell(cellIndex,
  // byteOffsetInCell)))` but reads more naturally at call sites.
  VmProgram& ldbFromCell(uint64_t cellIndex, uint64_t byteOffsetInCell);
  VmProgram& ldbFromCell(Region region, uint64_t byteOffsetInCell) {
    return ldbFromCell(region.cell, byteOffsetInCell);
  }

  // Store the low byte of `val` at the `byteOffsetInCell`-th byte of
  // the cell at `cellIndex`.
  VmProgram& stbInCell(uint64_t cellIndex, uint64_t byteOffsetInCell,
                        VmVal val);
  VmProgram& stbInCell(Region region, uint64_t byteOffsetInCell, VmVal val) {
    return stbInCell(region.cell, byteOffsetInCell, val);
  }

  // Load a library asset's code block and call into it in one
  // emission. `keyPtr` is passed through to SYS_LOAD_CODE as
  // io[4], so it should be a cell index holding a 32-byte hash (or
  // a Ref() to such a cell). After SYS_LOAD_CODE populates R with
  // the loaded block's offset, a CALLR through R transfers control
  // to the freshly-loaded code. Emitting the two back-to-back guarantees
  // R is not clobbered between the load and the call.
  //
  // The loaded code should end in OP_RET to return to the
  // instruction after this emission. Use loadCodeAndJmp() instead
  // if the loaded code ends in TERM and execution should not
  // return.
  VmProgram& loadCodeAndCall(VmVal keyPtr);

  // Same as loadCodeAndCall but emits OP_JMPR instead of OP_CALLR —
  // no context save, no return. Used when the loaded code is a
  // self-contained program that ends in TERM.
  VmProgram& loadCodeAndJmp(VmVal keyPtr);

  // Read-modify-write idiom for an existing asset. Issues
  // SYS_READ_ASSET to load content into the caller-supplied `content`
  // region, invokes `body` to mutate the buffer, then issues
  // SYS_UPDATE_ASSET to write the (potentially modified) content
  // back. The owner-out scratch cell is allocated internally from the
  // bump allocator (one cell, placed past whatever has already been
  // allocated); balance and price land in io[7]/io[8] per the
  // SYS_READ_ASSET ABI.
  //
  // `content` is typically the result of `allocContent()` (27 cells,
  // enough for a 210-byte AssetData). `keyPtr` is a VmVal — pass a
  // Region (auto-converts to Imm(cell)), an Imm/Ref directly, or
  // anything else compatible.
  //
  // Both syscalls use hostx semantics — failure aborts the program.
  // `body` is invoked with `*this`, so it can emit any further bytecode
  // (including nested syscalls or control flow); closures-by-reference
  // make outer state visible.
  template<class Body>
  VmProgram& readAndUpdateAsset(VmVal keyPtr,
                                 Region content,
                                 Body&& body) {
    Region ownerOut = allocHashPrefix();
    sysReadAsset({
      .keyPtr         = keyPtr,
      .ownerOutCell   = ownerOut,
      .contentOutCell = content,
    });
    std::forward<Body>(body)(*this);
    sysUpdateAsset({.keyPtr = keyPtr, .contentPtr = content});
    return *this;
  }

  // Embed raw bytes into consecutive io cells starting at `dstCell`,
  // via a sequence of OP_SET instructions. Bytes are packed little-
  // endian eight per cell; any trailing bytes in the final cell are
  // zero. `bytes` is copied at build time; it does not have to
  // outlive this call.
  //
  // Cost-wise this emits one OP_SET per 8 bytes. A 9-byte string like
  // "127.0.0.1" takes two OP_SETs.
  VmProgram& writeBytesToIo(uint64_t dstCell, const uint8_t* bytes, size_t len);

  // Same, taking a string view.
  VmProgram& writeBytesToIo(uint64_t dstCell, std::string_view s);

  // =========================================================================
  // Typed syscall wrappers
  //
  // One method per commonly-used syscall. Each wrapper lowers to a
  // single OP_HOSTXV (the compact variadic host-dispatch opcode) with
  // the syscall number and the args populated into io[4..4+N-1] in the
  // order the cesvm.cpp dispatcher reads them. Wrappers always use the
  // hostx variant — failure aborts the program.
  //
  // Callers supply per-argument VmVals so they can pass either
  // literals or dereferences as appropriate; Region implicitly
  // converts to Imm(cell) so allocator-managed regions slot in
  // directly.
  //
  // For syscalls without a dedicated wrapper below, use the generic
  // syscall() method (which emits an OP_SET chain + OP_HOSTX, suitable
  // for non-sequential slot patterns), or hostv()/hostxv() to dispatch
  // by number, or set up the io slots manually with set() + hostx().
  // =========================================================================

  // SYS_READ_ACCOUNT — reads balance into R and nonce into io[5].
  // Only one input: a cell pointer to the 8-byte HashPrefix.
  struct ReadAccountArgs {
    VmVal prefixPtr;  // io[4]
  };
  VmProgram& sysReadAccount(ReadAccountArgs a);

  // SYS_TRANSFER — transfer credits from caller to dest.
  struct TransferArgs {
    VmVal destKeyPtr;  // io[4] — cell index of a 32-byte hash
    VmVal amount;      // io[5] — uint64 credits
  };
  VmProgram& sysTransfer(TransferArgs a);

  // SYS_OWNER_TRANSFER — same shape as sysTransfer, but the source is
  // the program's owner (the asset that holds the bytecode being
  // executed), not the caller. Caller still pays the protocol fee.
  // Use for "house pays out" / "faucet" / "refund" patterns where the
  // program's deployer has consented to disburse from its own account
  // by virtue of deploying the bytecode.
  using OwnerTransferArgs = TransferArgs;
  VmProgram& sysOwnerTransfer(OwnerTransferArgs a);

  // SYS_DEPOSIT — caller -> programOwner. Convenience for the common
  // "pay the asset's owner" pattern. Source/dest are both implicit, so
  // the only argument is the amount. Allowance-bound.
  struct DepositArgs {
    VmVal amount;  // io[4]
  };
  VmProgram& sysDeposit(DepositArgs a);

  // SYS_WITHDRAW — programOwner -> caller. Symmetric convenience for
  // "asset pays its caller". Same shape: only amount, no dest. NOT
  // allowance-bound (the asset's owner consented to the bytecode).
  using WithdrawArgs = DepositArgs;
  VmProgram& sysWithdraw(WithdrawArgs a);

  // SYS_READ_ASSET — read asset content and metadata. Three input
  // slots at io[4..6] (key, owner-out cell-index, content-out
  // cell-index); balance and price are written directly by the
  // syscall into io[7] and io[8] respectively.
  struct ReadAssetArgs {
    VmVal keyPtr;         // io[4] — cell index of a 32-byte hash
    VmVal ownerOutCell;   // io[5] — cell index where owner (HashPrefix) is written
    VmVal contentOutCell; // io[6] — cell index where content (AssetData) is written
  };
  VmProgram& sysReadAsset(ReadAssetArgs a);

  // SYS_CREATE_ASSET_RANDOM — create a new asset with a fresh random key.
  struct CreateAssetRandomArgs {
    VmVal contentPtr;  // io[4] — cell index of asset content
    VmVal days;        // io[5] — lifetime in days
    VmVal keyOutPtr;   // io[6] — cell index where the new key is written
  };
  VmProgram& sysCreateAssetRandom(CreateAssetRandomArgs a);

  // SYS_CREATE_ASSET — create an asset with a caller-specified key.
  struct CreateAssetArgs {
    VmVal keyPtr;     // io[4] — cell index of a 32-byte hash
    VmVal contentPtr; // io[5] — cell index of asset content
    VmVal days;       // io[6] — lifetime in days
  };
  VmProgram& sysCreateAsset(CreateAssetArgs a);

  // SYS_CREATE_ASSET_MANAGED — like CREATE_ASSET, but the created
  // asset is owned by the running program's boot cell (asset-owned),
  // not by the runner. Used by gateway programs that want to manage
  // their own state.
  using CreateAssetManagedArgs = CreateAssetArgs;
  VmProgram& sysCreateAssetManaged(CreateAssetManagedArgs a);

  // SYS_UPDATE_ASSET — overwrite the content of an existing asset.
  struct UpdateAssetArgs {
    VmVal keyPtr;     // io[4]
    VmVal contentPtr; // io[5]
  };
  VmProgram& sysUpdateAsset(UpdateAssetArgs a);

  // SYS_UPDATE_ASSET_META — set owner+price without touching content.
  // Lets a program list its asset for sale, drop the price, or hand off
  // ownership in a single op (cheaper than UPDATE_ASSET).
  struct UpdateAssetMetaArgs {
    VmVal keyPtr;      // io[4]
    VmVal newOwnerPtr; // io[5] — cell index of an 8-byte HashPrefix
    VmVal newPrice;    // io[6] — new price (0 = remove from sale)
  };
  VmProgram& sysUpdateAssetMeta(UpdateAssetMetaArgs a);

  // SYS_FUND_ASSET — extend the lifetime of an existing asset.
  struct FundAssetArgs {
    VmVal keyPtr; // io[4]
    VmVal days;   // io[5]
  };
  VmProgram& sysFundAsset(FundAssetArgs a);

  // SYS_BUY_ASSET — purchase an asset from its current owner.
  struct BuyAssetArgs {
    VmVal keyPtr;   // io[4]
    VmVal maxPrice; // io[5]
  };
  VmProgram& sysBuyAsset(BuyAssetArgs a);

  // SYS_GIVE_ASSET — transfer ownership to a new account.
  struct GiveAssetArgs {
    VmVal keyPtr;      // io[4]
    VmVal newOwnerPtr; // io[5] — cell index of an 8-byte HashPrefix
  };
  VmProgram& sysGiveAsset(GiveAssetArgs a);

  // SYS_HASH — compute SHA-256 of a byte range.
  struct HashArgs {
    VmVal dataPtr; // io[4] — cell index of input bytes
    VmVal len;     // io[5] — length in bytes
    VmVal outPtr;  // io[6] — cell index for 32-byte output
  };
  VmProgram& sysHash(HashArgs a);

  // SYS_VERIFY_SIG — verify a signature. On return, R holds 1 (valid)
  // or 0 (invalid); S holds CES_OK regardless.
  struct VerifySigArgs {
    VmVal dataPtr;
    VmVal dataLen;
    VmVal sigPtr;
    VmVal pubkeyPtr;
  };
  VmProgram& sysVerifySig(VerifySigArgs a);

  // SYS_CROSS_TRANSFER — send credits to an account on another peer
  // server. Deferred: the actual network send happens at commit time.
  struct CrossTransferArgs {
    VmVal destKeyPtr; // io[4]
    VmVal amount;     // io[5]
    VmVal serverPtr;  // io[6] — cell index of the peer server address string
  };
  VmProgram& sysCrossTransfer(CrossTransferArgs a);

  // SYS_LOAD_CODE — append a library asset's code block to the
  // running program's code buffer. On return, R holds the offset of
  // the loaded block, which can then be targeted by jmpr()/callr()
  // via Ref(CESVM_CELL_R).
  struct LoadCodeArgs {
    VmVal keyPtr; // io[4]
  };
  VmProgram& sysLoadCode(LoadCodeArgs a);

  // SYS_SEND_CLIENT — push an application message to a currently-
  // connected client. R holds 1 on successful push, 0 otherwise.
  struct SendClientArgs {
    VmVal clientIdPtr; // io[4] — cell index of 8-byte HashPrefix
    VmVal dataPtr;     // io[5] — cell index of payload bytes
    VmVal dataLen;     // io[6] — length in bytes
  };
  VmProgram& sysSendClient(SendClientArgs a);

  // SYS_SCHEDULE — queue a future runAsset for a different program.
  // The parent passes an explicit `childAllowance` and the syscall
  // decrements the parent's remaining allowance by that amount before
  // handing it off (returns CES_ERROR_ALLOWANCE_EXCEEDED if the parent
  // can't cover it), so a child run cannot exceed its parent's headroom.
  struct ScheduleArgs {
    VmVal assetKeyPtr;    // io[4]
    VmVal budget;         // io[5]
    VmVal childAllowance; // io[6]
    VmVal inputPtr;       // io[7]
    VmVal inputLen;       // io[8]
    VmVal timeUs;         // io[9] — wall clock microseconds (0 = next tick)
  };
  VmProgram& sysSchedule(ScheduleArgs a);

  // SYS_RPC — MINX/RUDP stream call to an external service. The
  // request body comes from a pre-allocated cesh file (the caller
  // must have written the body via cesh's ramfileWrite/ramfileResize
  // helpers, typically with extra capacity so the response has
  // room to land in the same file). The followup VM program is
  // scheduled on completion with a 48-byte input describing the
  // result. See SYS_RPC in cesvm.h for the full io layout and
  // wire protocol.
  struct RpcArgs {
    VmVal hostCell;      // io[4] — cell index of ASCII host string
    VmVal hostLen;       // io[5] — host string length in bytes
    VmVal port;          // io[6] — destination UDP port (u16)
    VmVal fileHead;      // io[7] — cell holding 32-byte cesh file head key
    VmVal followup;      // io[8] — cell holding 32-byte followup asset key
    VmVal budget;        // io[9] — followup VM gas budget
    VmVal tag;           // io[10] — followup input tag (u32)
  };
  VmProgram& sysRpc(RpcArgs args);

  // Generic syscall dispatch. Populates io[3] with `syscallNum`, then
  // emits OP_SET for each (slot, value) pair in `slots`, then OP_HOSTX.
  // Use this for one-off tests where adding a typed wrapper above is
  // overkill.
  VmProgram& syscall(
    uint64_t syscallNum,
    std::initializer_list<std::pair<uint64_t, VmVal>> slots);

  // Variadic syscall dispatch — emits a single OP_HOSTV / OP_HOSTXV
  // opcode that populates io[3] with `syscallNum` and io[4..4+N-1]
  // with the args (in the order given). More compact than the equivalent
  // OP_SET chain; gas cost is identical.
  //
  // Use `hostxv()` for the common "abort if the syscall's S register
  // is nonzero on return" semantics (matches OP_HOSTX). Use `hostv()`
  // if the caller wants to inspect S manually after the dispatch.
  //
  // The args.size() must be <= CESVM_MAX_HOSTV_ARGS (currently 16);
  // builder time enforces this so a program that overflows can't be
  // built. The VM also checks at runtime and returns CESVM_SEGFAULT
  // if a hand-crafted byte sequence exceeds the cap.
  VmProgram& hostv(uint64_t syscallNum,
                    std::initializer_list<VmVal> args);
  VmProgram& hostxv(uint64_t syscallNum,
                     std::initializer_list<VmVal> args);

  // =========================================================================
  // Build-out
  // =========================================================================

  // Current code size in bytes. Grows as opcodes are appended.
  size_t size() const { return code_.size(); }

  // Build into a 210-byte AssetData boot block — the deployment shape
  // for code that lives in a single asset's content cell. Throws if:
  //   - any label was referenced but never placed.
  //   - the code is larger than AssetData::size() (210 bytes).
  // The output is zero-padded to the full 210 bytes.
  AssetData buildBootBlock();

  // Build into a byte vector of the minimum needed size. The
  // in-memory shape used for direct CesVM execution and for chained
  // library code (loaded via SYS_LOAD_CODE). Throws if any label was
  // referenced but never placed, or if the code is larger than
  // CESVM_MAX_CODE (8192 bytes).
  ces::Bytes buildBytes();

private:
  // Raw bytecode accumulator.
  ces::Bytes code_;

  // Labels: index == label id. Value is either an offset into code_
  // (if placed) or UINT64_MAX (if still unplaced).
  std::vector<uint64_t> labels_;

  // Forward-reference patch sites. Each record says "at `offset` in
  // code_, there are two bytes that should be overwritten with the
  // little-endian offset of labels_[labelId] when build-out runs."
  struct Reloc {
    size_t offset;
    size_t labelId;
  };
  std::vector<Reloc> relocs_;

  // Tracks whether the most recent emitted opcode was OP_TERM or
  // OP_ABORT. Used by ifThenElse to elide an unreachable merge jmp
  // when the then-body ends in a terminator. Updated only inside
  // emitOpcode(), so operand bytes pushed via emitVal/emitLabelRef
  // never affect the flag (an operand byte that happens to equal
  // OP_TERM by coincidence cannot trigger a false positive).
  bool lastWasTerminator_ = false;

  // Bump cursor for the scratch region allocator. Initialized to the
  // first cell past the named registers; advances by alloc() each
  // time a region is requested. allocAt() does not move it.
  uint64_t scratchTop_ = CESVM_REG_SIZE;

  // --- Internal emit helpers ---

  void emitByte(uint8_t b);
  void emitOpcode(uint8_t op);
  // Emit one operand in the shortest control-byte form that fits.
  void emitVal(VmVal v);
  // Emit a 2-byte label reference placeholder and record a reloc.
  void emitLabelRef(VmLabel l);

  // Resolve all pending relocs against the labels table, or throw if
  // any label is unplaced.
  void resolveLabelsOrThrow();
};

// Exception type for builder errors. Catch std::runtime_error to be
// transport-agnostic.
class VmProgramError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

} // namespace ces
