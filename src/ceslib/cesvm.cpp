/**
 * CesVM implementation.
 * GVM core (github.com/FluxBP/gvm) adapted for CES server-side execution.
 */

#include <ces/alias.h>
#include <ces/cesvm.h>
#include <ces/keys.h>

#include <minx/types.h>
#include <minx/blog.h>

#include <algorithm>
#include <cstring>
#include <array>
#include <random>

#include <cryptopp/sha.h>

LOG_MODULE("cesvm");

namespace ces {

// Opcode numbers, operand encoding bits, and stack caps now live in
// cesvm.h as the single source of truth. Keep short local aliases for
// the bits that show up a lot in this file so the parser stays
// readable.
static constexpr uint8_t STACK         = CESVM_OP_STACK;
static constexpr uint8_t REG_PTR       = CESVM_REG_PTR;
static constexpr uint8_t SHORT_VAL     = CESVM_SHORT_VAL;
static constexpr uint8_t MAX_SHORT_VAL = CESVM_MAX_SHORT_VAL;

// Plain unit conversion for the SYS_SCHEDULE gas formula.
static constexpr uint64_t US_PER_SEC = 1'000'000;

CesVM::CesVM() : rng_(std::random_device{}()) {
  std::memset(io_, 0, sizeof(io_));
}

CesVMResult CesVM::execute(const ces::Bytes& code,
                           CesVMHost& host, uint64_t budget,
                           uint64_t gasMult) {
  CesVMResult result;
  std::memset(io_, 0, sizeof(io_));
  stackClear();
  ctxClear();
  term_ = CESVM_OK;
  budget_ = budget;
  budgetUsed_ = 0;
  gasMult_ = gasMult ? gasMult : 1;

  // Copy initial code into mutable code buffer. An oversize input is a
  // hard error (CESVM_CODESIZE) rather than a silent truncate — a
  // program whose tail got chopped would fail in subtle ways further
  // along, far from the actual cause.
  if (code.size() > CESVM_MAX_CODE) {
    result.error = CESVM_CODESIZE;
    return result;
  }
  code_ = code;

  // Preload immutable context into fixed io memory locations
  size_t inputLen = std::min(host.input.size(), size_t(CESVM_MAX_INPUT));
  io_[CESVM_IO_INPUT_LEN] = inputLen;
  io_[CESVM_IO_OUTPUT_LEN] = 0;
  io_[CESVM_IO_BUDGET] = budget;
  io_[CESVM_IO_START_TIME] = static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
  io_[CESVM_IO_ALLOWANCE] = host.allowance;
  io_[CESVM_IO_BUDGET_REMAINING] = budget;
  io_[CESVM_IO_INVOKE_KIND] = host.invokeKind;
  writeIoBytes(CESVM_IO_CALLER_KEY, host.callerKey.data(), KEY_SIZE);
  writeIoBytes(CESVM_IO_SELF_KEY, host.selfAssetKey.data(), KEY_SIZE);
  writeIoBytes(CESVM_IO_PROGRAM_OWNER, host.programOwner.data(),
               host.programOwner.size());
  if (inputLen > 0)
    writeIoBytes(CESVM_IO_INPUT, host.input.data(), inputLen);

  // Per-op gas precompute (see billOp): an overflowing COST_PER_OP*gasMult
  // matches bill()'s overflow guard -- halt as budget-exhausted on the
  // first op.
  opCostOvf_ = CESVM_COST_PER_OP >
               std::numeric_limits<uint64_t>::max() / gasMult_;
  opCost_ = opCostOvf_ ? 0 : CESVM_COST_PER_OP * gasMult_;

#if CESVM_OPT_PREDECODE
  if (legacyCore_) runLegacy(host, result);
  else             runFast(host, result);
#else
  runLegacy(host, result);
#endif

  result.error = term_;
  result.budgetUsed = budgetUsed_;

  // Read output from fixed io location
  size_t outLen = std::min(io_[CESVM_IO_OUTPUT_LEN], uint64_t(CESVM_MAX_OUTPUT));
  if (outLen > 0) {
    result.output.resize(outLen);
    readIoBytes(CESVM_IO_OUTPUT, result.output.data(), outLen);
  }

  return result;
}

// --- Reference interpreter core ---

void CesVM::runLegacy(CesVMHost& host, CesVMResult& result) {
  while (!term_ && PC() < code_.size()) {
    result.opsExecuted++;
    if (!billOp()) { PC()++; break; }
    stepSlow(host);
  }
}

// Execute exactly one instruction at PC. The base per-op cost has already
// been billed by the caller (runLegacy or the fast core's dispatch);
// variable extra costs (HOSTV's per-arg writes, MOV/CMP/FIL per-cell) are
// billed here. This switch is the reference semantics: the fast core must
// match it observably, and replays through it anything it does not
// fast-path.
void CesVM::stepSlow(CesVMHost& host) {
  uint64_t op1, op2;
  uint8_t opcode = code_[PC()++];

    switch (opcode) {
    case OP_NOP:
      break;
    case OP_TERM:
      PC() = UINT64_MAX;
      break;
    case OP_SET:
      op1 = read();
      op2 = read();
      get(op1) = op2;
      break;
    case OP_JMP:
      op1 = read(true);
      PC() = op1;
      break;
    case OP_ADD:
      op1 = read(); op2 = read(); R() = op1 + op2; break;
    case OP_ADD | STACK:
      op2 = pop(); op1 = pop(); push(op1 + op2); break;
    case OP_SUB:
      // Two's-complement subtraction. Wraps silently on underflow
      // (consistent with ADD/MUL/NEG); programs that need to detect
      // "would go negative" branch on a CMP first.
      op1 = read(); op2 = read();
      R() = op1 - op2;
      break;
    case OP_SUB | STACK:
      op2 = pop(); op1 = pop();
      push(op1 - op2);
      break;
    case OP_MUL:
      op1 = read(); op2 = read(); R() = op1 * op2; break;
    case OP_MUL | STACK:
      op2 = pop(); op1 = pop(); push(op1 * op2); break;
    case OP_DIV:
      op1 = read(); op2 = read();
      if (op2) R() = op1 / op2; else term_ = CESVM_DIVZERO;
      break;
    case OP_DIV | STACK:
      op2 = pop(); op1 = pop();
      if (op2) push(op1 / op2); else term_ = CESVM_DIVZERO;
      break;
    case OP_MOD:
      op1 = read(); op2 = read();
      if (op2) R() = op1 % op2; else term_ = CESVM_DIVZERO;
      break;
    case OP_MOD | STACK:
      op2 = pop(); op1 = pop();
      if (op2) push(op1 % op2); else term_ = CESVM_DIVZERO;
      break;
    case OP_OR:
      op1 = read(); op2 = read(); R() = op1 | op2; break;
    case OP_OR | STACK:
      op2 = pop(); op1 = pop(); push(op1 | op2); break;
    case OP_ANDL:
      op1 = read(); op2 = read(); R() = op1 && op2; break;
    case OP_ANDL | STACK:
      op2 = pop(); op1 = pop(); push(op1 && op2); break;
    case OP_XOR:
      op1 = read(); op2 = read(); R() = op1 ^ op2; break;
    case OP_XOR | STACK:
      op2 = pop(); op1 = pop(); push(op1 ^ op2); break;
    case OP_NOT:
      // Bitwise complement (per x86/ARM/MIPS convention: NOT = ~x).
      op1 = read(); R() = ~op1; break;
    case OP_NOT | STACK:
      op1 = pop(); push(~op1); break;
    case OP_LNOT:
      // Logical NOT: 0 → 1, anything else → 0.
      op1 = read(); R() = !op1; break;
    case OP_LNOT | STACK:
      op1 = pop(); push(!op1); break;
    case OP_SHL:
      op1 = read(); op2 = read();
      // Shifting a uint64_t by >= 64 bits is UB per [expr.shift]/1.
      // Reject attacker bytecode that would trigger it.
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      R() = op1 << op2; break;
    case OP_SHL | STACK:
      op2 = pop(); op1 = pop();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      push(op1 << op2); break;
    case OP_SHR:
      op1 = read(); op2 = read();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      R() = op1 >> op2; break;
    case OP_SHR | STACK:
      op2 = pop(); op1 = pop();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      push(op1 >> op2); break;
    case OP_SAR:
      // Arithmetic shift right — preserves the sign bit. C++20 guarantees
      // signed `>>` is arithmetic (P0907R4); same UB rule for op2 >= 64
      // applies as in SHR/SHL.
      op1 = read(); op2 = read();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      R() = static_cast<uint64_t>(static_cast<int64_t>(op1) >>
                                  static_cast<int>(op2)); break;
    case OP_SAR | STACK:
      op2 = pop(); op1 = pop();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      push(static_cast<uint64_t>(static_cast<int64_t>(op1) >>
                                 static_cast<int>(op2))); break;
    case OP_INC:
      op1 = read(); ++get(op1); break;
    case OP_DEC:
      op1 = read(); --get(op1); break;
    case OP_PUSH:
      op1 = read(); push(op1); break;
    case OP_POP:
      op1 = read(); get(op1) = pop(); break;
    case OP_AND:
      op1 = read(); op2 = read(); R() = op1 & op2; break;
    case OP_AND | STACK:
      op2 = pop(); op1 = pop(); push(op1 & op2); break;
    case OP_HOST:
      hostCall(host);
      break;
    case OP_HOSTX:
      hostCall(host);
      if (!term_ && S() != 0) term_ = CESVM_ABORT;
      break;
    case OP_ABORT:
      term_ = CESVM_ABORT;
      break;
    case OP_VPUSH:
      op1 = read(); op2 = read();
      ++get(op1); get(get(op1)) = op2;
      break;
    case OP_VPOP:
      op1 = read(); op2 = read();
      get(op2) = get(op1); --get(op1);
      break;
    case OP_CALL: {
      op1 = read(true);
      // Hard cap on call depth to close a stack-recursion DoS vector
      // analogous to the data-stack cap in push(). 256 frames is plenty
      // for any realistic program; deeper recursion almost always
      // indicates a bug.
      if (!ctxPush()) break;
      PC() = op1;
      break;
    }
    case OP_CALL | STACK: {
      // Stack form: target popped from the data stack instead of read
      // inline. Equivalent to OP_CALLR for a runtime-computed target,
      // but consumes the value off the stack rather than dereferencing
      // a cell. Same call-depth cap as OP_CALL.
      op1 = pop();
      if (!ctxPush()) break;
      PC() = op1;
      break;
    }
    case OP_JMPR:
      // Indirect JMP: target comes from a regular operand, so it can
      // be dereferenced through a cell (e.g. R after SYS_LOAD_CODE
      // wrote the loaded block's offset there).
      op1 = read();
      PC() = op1;
      break;
    case OP_CALLR: {
      // Indirect CALL: same shape as OP_CALL but the target is a
      // runtime value. See OP_JMPR.
      op1 = read();
      if (!ctxPush()) break;
      PC() = op1;
      break;
    }
    case OP_HOSTV:
    case OP_HOSTXV: {
      // Variadic syscall dispatch. Reads (syscall_num, arg_count,
      // arg0, arg1, ...) inline, populates io[3] = syscall_num and
      // io[4..4+N-1] = args, then calls hostCall. OP_HOSTXV
      // additionally promotes a nonzero S on return to CESVM_ABORT.
      //
      // Two-phase execution: read and validate all args into a local
      // buffer first, then commit to io. This means a truncated or
      // malformed arg stream (which would set term_ = CESVM_CODESIZE
      // mid-read) can't leave io half-populated in a state the
      // syscall would see as half-filled.
      uint64_t syscallNum = read();
      if (term_) break;
      uint64_t argCount = read();
      if (term_) break;
      if (argCount > CESVM_MAX_HOSTV_ARGS) {
        term_ = CESVM_SEGFAULT;
        break;
      }
      // Bill the equivalent of (argCount + 1) OP_SETs up front: one
      // for the io[3] syscall-num write, N for the arg writes. Same
      // total gas as the old OP_SET × (N+1) + OP_HOSTX pattern would
      // have charged, so HOSTV saves bytecode without discounting
      // gas.
      if (!bill(CESVM_COST_PER_OP * (argCount + 1))) break;
      uint64_t argBuf[CESVM_MAX_HOSTV_ARGS];
      for (uint64_t i = 0; i < argCount; ++i) {
        argBuf[i] = read();
        if (term_) break;
      }
      if (term_) break;
      // Commit: all reads succeeded, now populate io slots atomically
      // (no partial state on parser failure).
      io_[3] = syscallNum;
      for (uint64_t i = 0; i < argCount; ++i) {
        io_[4 + i] = argBuf[i];
      }
      hostCall(host);
      if (opcode == OP_HOSTXV && !term_ && S() != 0) {
        term_ = CESVM_ABORT;
      }
      break;
    }
    case OP_RET: {
      op1 = read();
      if (ctxEmpty()) { term_ = CESVM_RET; break; }
      ctxRestorePop();
      R() = op1;
      break;
    }
    case OP_JF:
      op1 = read();
      if (!op1) { PC() = read(true); }
      else { PC() += 2; }
      break;
    case OP_JF | STACK:
      op1 = pop();
      if (!op1) { PC() = read(true); }
      else { PC() += 2; }
      break;
    case OP_JT:
      op1 = read();
      if (op1) { PC() = read(true); }
      else { PC() += 2; }
      break;
    case OP_JT | STACK:
      op1 = pop();
      if (op1) { PC() = read(true); }
      else { PC() += 2; }
      break;
    case OP_EQ:
      op1 = read(); op2 = read(); R() = op1 == op2; break;
    case OP_EQ | STACK:
      op2 = pop(); op1 = pop(); push(op1 == op2); break;
    case OP_NE:
      op1 = read(); op2 = read(); R() = op1 != op2; break;
    case OP_NE | STACK:
      op2 = pop(); op1 = pop(); push(op1 != op2); break;
    case OP_GT:
      op1 = read(); op2 = read(); R() = op1 > op2; break;
    case OP_GT | STACK:
      op2 = pop(); op1 = pop(); push(op1 > op2); break;
    case OP_LT:
      op1 = read(); op2 = read(); R() = op1 < op2; break;
    case OP_LT | STACK:
      op2 = pop(); op1 = pop(); push(op1 < op2); break;
    case OP_GE:
      op1 = read(); op2 = read(); R() = op1 >= op2; break;
    case OP_GE | STACK:
      op2 = pop(); op1 = pop(); push(op1 >= op2); break;
    case OP_LE:
      op1 = read(); op2 = read(); R() = op1 <= op2; break;
    case OP_LE | STACK:
      op2 = pop(); op1 = pop(); push(op1 <= op2); break;
    case OP_SLT:
      op1 = read(); op2 = read();
      R() = static_cast<int64_t>(op1) < static_cast<int64_t>(op2); break;
    case OP_SLT | STACK:
      op2 = pop(); op1 = pop();
      push(static_cast<int64_t>(op1) < static_cast<int64_t>(op2)); break;
    case OP_SGT:
      op1 = read(); op2 = read();
      R() = static_cast<int64_t>(op1) > static_cast<int64_t>(op2); break;
    case OP_SGT | STACK:
      op2 = pop(); op1 = pop();
      push(static_cast<int64_t>(op1) > static_cast<int64_t>(op2)); break;
    case OP_SGE:
      op1 = read(); op2 = read();
      R() = static_cast<int64_t>(op1) >= static_cast<int64_t>(op2); break;
    case OP_SGE | STACK:
      op2 = pop(); op1 = pop();
      push(static_cast<int64_t>(op1) >= static_cast<int64_t>(op2)); break;
    case OP_SLE:
      op1 = read(); op2 = read();
      R() = static_cast<int64_t>(op1) <= static_cast<int64_t>(op2); break;
    case OP_SLE | STACK:
      op2 = pop(); op1 = pop();
      push(static_cast<int64_t>(op1) <= static_cast<int64_t>(op2)); break;
    case OP_ADDX:
      // Checked unsigned add: a wrap halts with CESVM_OVERFLOW instead
      // of producing a mod-2^64 result. Same shape for SUBX/MULX below.
      op1 = read(); op2 = read();
      if (op1 > UINT64_MAX - op2) { term_ = CESVM_OVERFLOW; break; }
      R() = op1 + op2; break;
    case OP_ADDX | STACK:
      op2 = pop(); op1 = pop();
      if (op1 > UINT64_MAX - op2) { term_ = CESVM_OVERFLOW; break; }
      push(op1 + op2); break;
    case OP_SUBX:
      op1 = read(); op2 = read();
      if (op2 > op1) { term_ = CESVM_OVERFLOW; break; }
      R() = op1 - op2; break;
    case OP_SUBX | STACK:
      op2 = pop(); op1 = pop();
      if (op2 > op1) { term_ = CESVM_OVERFLOW; break; }
      push(op1 - op2); break;
    case OP_MULX:
      op1 = read(); op2 = read();
      if (op2 != 0 && op1 > UINT64_MAX / op2) { term_ = CESVM_OVERFLOW; break; }
      R() = op1 * op2; break;
    case OP_MULX | STACK:
      op2 = pop(); op1 = pop();
      if (op2 != 0 && op1 > UINT64_MAX / op2) { term_ = CESVM_OVERFLOW; break; }
      push(op1 * op2); break;
    case OP_ASSERT:
      op1 = read();
      if (!op1) term_ = CESVM_ABORT;
      break;
    case OP_ASSERT | STACK:
      op1 = pop();
      // pop() on an empty stack already set CESVM_UNDERFLOW and
      // returned 0; do not misreport that crash as an assert failure.
      if (!op1 && !term_) term_ = CESVM_ABORT;
      break;
    case OP_DUP:
      // pop-then-push-twice inherits the existing edge semantics: empty
      // stack halts with CESVM_UNDERFLOW via pop(), a stack at cap
      // halts with CESVM_SEGFAULT on the second push().
      op1 = pop();
      push(op1);
      push(op1);
      break;
    case OP_NEG:
      // Arithmetic two's-complement negate. Wraps at 0 (NEG of 0 is 0;
      // NEG of INT64_MIN is itself — that's the well-known x86 quirk
      // and we replicate it: -x = 0 - x mod 2^64).
      op1 = read();
      R() = static_cast<uint64_t>(0) - op1;
      break;
    case OP_NEG | STACK:
      op1 = pop();
      push(static_cast<uint64_t>(0) - op1);
      break;
    case OP_ORL:
      op1 = read(); op2 = read(); R() = op1 || op2; break;
    case OP_ORL | STACK:
      op2 = pop(); op1 = pop(); push(op1 || op2); break;
    case OP_RND:
      R() = rng_();
      break;
    case OP_RND | STACK:
      push(rng_());
      break;
    case OP_TIME:
      R() = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count());
      break;
    case OP_TIME | STACK:
      push(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count()));
      break;
    case OP_MOV: {
      // MOV dst, src, count — copy count cells from io[src] to io[dst]
      op1 = read(); // dst
      op2 = read(); // src
      uint64_t cnt = read(); // count
      if (cnt > CESVM_IO_SIZE ||
          op1 > CESVM_IO_SIZE - cnt || op2 > CESVM_IO_SIZE - cnt) {
        term_ = CESVM_SEGFAULT; break;
      }
      if (!billMul(cnt, CESVM_COST_PER_CELL)) break;
      std::memmove(&io_[op1], &io_[op2], cnt * sizeof(uint64_t));
      break;
    }
    case OP_LDB: {
      // LDB — R = byte at byte_offset (read from io as byte array)
      op1 = read(); // byte offset
      auto* base = reinterpret_cast<uint8_t*>(io_);
      if (op1 >= CESVM_IO_SIZE * sizeof(uint64_t)) {
        term_ = CESVM_SEGFAULT; break;
      }
      R() = base[op1];
      break;
    }
    case OP_LDB | STACK: {
      op1 = pop();
      auto* base = reinterpret_cast<uint8_t*>(io_);
      if (op1 >= CESVM_IO_SIZE * sizeof(uint64_t)) {
        term_ = CESVM_SEGFAULT; break;
      }
      push(base[op1]);
      break;
    }
    case OP_STB: {
      // STB — store low byte of value at byte_offset
      op1 = read(); // byte offset
      op2 = read(); // value (low byte used)
      auto* base = reinterpret_cast<uint8_t*>(io_);
      if (op1 >= CESVM_IO_SIZE * sizeof(uint64_t)) {
        term_ = CESVM_SEGFAULT; break;
      }
      base[op1] = static_cast<uint8_t>(op2 & 0xFF);
      break;
    }
    case OP_STB | STACK: {
      op2 = pop(); // value
      op1 = pop(); // byte offset
      auto* base = reinterpret_cast<uint8_t*>(io_);
      if (op1 >= CESVM_IO_SIZE * sizeof(uint64_t)) {
        term_ = CESVM_SEGFAULT; break;
      }
      base[op1] = static_cast<uint8_t>(op2 & 0xFF);
      break;
    }
    case OP_CMP: {
      // CMP a, b, count → R = 1 if io[a..a+count-1] == io[b..b+count-1]
      op1 = read(); // a (cell offset)
      op2 = read(); // b (cell offset)
      uint64_t cnt = read();
      if (cnt > CESVM_IO_SIZE ||
          op1 > CESVM_IO_SIZE - cnt || op2 > CESVM_IO_SIZE - cnt) {
        term_ = CESVM_SEGFAULT; break;
      }
      if (!billMul(cnt, CESVM_COST_PER_CELL)) break;
      R() = (std::memcmp(&io_[op1], &io_[op2], cnt * sizeof(uint64_t)) == 0) ? 1 : 0;
      break;
    }
    case OP_FIL: {
      // FIL dst, val, count → fill io[dst..dst+count-1] with val
      op1 = read(); // dst (cell offset)
      op2 = read(); // value (uint64_t)
      uint64_t cnt = read();
      if (cnt > CESVM_IO_SIZE || op1 > CESVM_IO_SIZE - cnt) {
        term_ = CESVM_SEGFAULT; break;
      }
      if (!billMul(cnt, CESVM_COST_PER_CELL)) break;
      for (uint64_t i = 0; i < cnt; ++i)
        io_[op1 + i] = op2;
      break;
    }
    default:
      term_ = CESVM_OPCODE;
    }
}

#if CESVM_OPT_PREDECODE

// ============================================================================
// Fast interpreter core: memoized operand pre-decode plus (optionally)
// computed-goto dispatch. See the CESVM_OPT_* block in cesvm.h for the
// contract. stepSlow defines the semantics; instructions this core cannot
// statically decode (variadic HOSTV/HOSTXV, operands dereferencing cell 0,
// any encoding anomaly) keep h = H_SLOW and replay through stepSlow --
// same bytes, same faults, same side effects.
// ============================================================================

// Dense fast-handler indices. The X-macro keeps the enum and the threaded
// dispatch table in lockstep; H_SLOW must stay first (a zero-initialized
// Decoded dispatches to it, and decodeAt leaves h = H_SLOW on any anomaly).
#define CESVM_FAST_HANDLERS(X) \
  X(SLOW) X(NOP) X(TERM) X(SET) X(JMP) X(INC) X(DEC) X(PUSH) X(POP) \
  X(HOST) X(HOSTX) X(ABORT) X(VPUSH) X(VPOP) X(CALL) X(CALL_S) X(CALLR) \
  X(JMPR) X(RET) X(JF) X(JF_S) X(JT) X(JT_S) X(DUP) X(RND) X(RND_S) \
  X(TIME) X(TIME_S) X(MOV) X(CMP) X(FIL) X(LDB) X(LDB_S) X(STB) X(STB_S) \
  X(ADD) X(ADD_S) X(SUB) X(SUB_S) X(MUL) X(MUL_S) X(DIV) X(DIV_S) \
  X(MOD) X(MOD_S) X(OR) X(OR_S) X(AND) X(AND_S) X(XOR) X(XOR_S) \
  X(ANDL) X(ANDL_S) X(ORL) X(ORL_S) X(NOT) X(NOT_S) X(LNOT) X(LNOT_S) \
  X(NEG) X(NEG_S) X(SHL) X(SHL_S) X(SHR) X(SHR_S) X(SAR) X(SAR_S) \
  X(EQ) X(EQ_S) X(NE) X(NE_S) X(GT) X(GT_S) X(LT) X(LT_S) X(GE) X(GE_S) \
  X(LE) X(LE_S) X(SLT) X(SLT_S) X(SGT) X(SGT_S) X(SGE) X(SGE_S) \
  X(SLE) X(SLE_S) X(ADDX) X(ADDX_S) X(SUBX) X(SUBX_S) X(MULX) X(MULX_S) \
  X(ASSERT) X(ASSERT_S)

enum : uint16_t {
#define X(n) H_##n,
  CESVM_FAST_HANDLERS(X)
#undef X
  H_COUNT
};

// Static per-opcode decode plan: fast handler, inline operand count, and
// whether a 2-byte literal jump target follows the operands (the
// read(true) form). H_SLOW rows never reach decodeAt's operand walk.
struct FastOpInfo {
  uint16_t h = H_SLOW;
  uint8_t nops = 0;
  bool jumpTail = false;
};

static constexpr std::array<FastOpInfo, 256> kFastOpInfo = [] {
  std::array<FastOpInfo, 256> t{};
  auto op = [&](uint8_t code, uint16_t h, uint8_t nops, bool tail = false) {
    t[code] = {h, nops, tail};
  };
  op(OP_NOP,   H_NOP,   0);       op(OP_TERM,  H_TERM,  0);
  op(OP_SET,   H_SET,   2);       op(OP_JMP,   H_JMP,   0, true);
  op(OP_ADD,   H_ADD,   2);       op(OP_SUB,   H_SUB,   2);
  op(OP_MUL,   H_MUL,   2);       op(OP_DIV,   H_DIV,   2);
  op(OP_MOD,   H_MOD,   2);       op(OP_OR,    H_OR,    2);
  op(OP_ANDL,  H_ANDL,  2);       op(OP_XOR,   H_XOR,   2);
  op(OP_NOT,   H_NOT,   1);       op(OP_SHL,   H_SHL,   2);
  op(OP_SHR,   H_SHR,   2);       op(OP_INC,   H_INC,   1);
  op(OP_DEC,   H_DEC,   1);       op(OP_PUSH,  H_PUSH,  1);
  op(OP_POP,   H_POP,   1);       op(OP_AND,   H_AND,   2);
  op(OP_HOST,  H_HOST,  0);       op(OP_VPUSH, H_VPUSH, 2);
  op(OP_VPOP,  H_VPOP,  2);       op(OP_CALL,  H_CALL,  0, true);
  op(OP_RET,   H_RET,   1);       op(OP_JF,    H_JF,    1, true);
  op(OP_JT,    H_JT,    1, true); op(OP_EQ,    H_EQ,    2);
  op(OP_NE,    H_NE,    2);       op(OP_GT,    H_GT,    2);
  op(OP_LT,    H_LT,    2);       op(OP_GE,    H_GE,    2);
  op(OP_LE,    H_LE,    2);       op(OP_NEG,   H_NEG,   1);
  op(OP_ORL,   H_ORL,   2);       op(OP_RND,   H_RND,   0);
  op(OP_TIME,  H_TIME,  0);       op(OP_MOV,   H_MOV,   3);
  op(OP_LDB,   H_LDB,   1);       op(OP_STB,   H_STB,   2);
  op(OP_CMP,   H_CMP,   3);       op(OP_FIL,   H_FIL,   3);
  op(OP_HOSTX, H_HOSTX, 0);       op(OP_ABORT, H_ABORT, 0);
  op(OP_JMPR,  H_JMPR,  1);       op(OP_CALLR, H_CALLR, 1);
  // OP_HOSTV / OP_HOSTXV stay H_SLOW: their operand count is a runtime
  // value, so there is nothing static to pre-decode.
  op(OP_SAR,   H_SAR,   2);       op(OP_LNOT,  H_LNOT,  1);
  op(OP_SLT,   H_SLT,   2);       op(OP_SGT,   H_SGT,   2);
  op(OP_SGE,   H_SGE,   2);       op(OP_SLE,   H_SLE,   2);
  op(OP_ADDX,  H_ADDX,  2);       op(OP_SUBX,  H_SUBX,  2);
  op(OP_MULX,  H_MULX,  2);       op(OP_ASSERT, H_ASSERT, 1);
  op(OP_DUP,   H_DUP,   0);
  // Stack variants: operands come off the data stack, so no inline
  // operands; JF/JT keep their literal jump tail.
  auto sop = [&](uint8_t code, uint16_t h, bool tail = false) {
    t[code | STACK] = {h, 0, tail};
  };
  sop(OP_ADD, H_ADD_S);   sop(OP_SUB, H_SUB_S);   sop(OP_MUL, H_MUL_S);
  sop(OP_DIV, H_DIV_S);   sop(OP_MOD, H_MOD_S);   sop(OP_OR, H_OR_S);
  sop(OP_ANDL, H_ANDL_S); sop(OP_XOR, H_XOR_S);   sop(OP_NOT, H_NOT_S);
  sop(OP_SHL, H_SHL_S);   sop(OP_SHR, H_SHR_S);   sop(OP_AND, H_AND_S);
  sop(OP_CALL, H_CALL_S); sop(OP_JF, H_JF_S, true); sop(OP_JT, H_JT_S, true);
  sop(OP_EQ, H_EQ_S);     sop(OP_NE, H_NE_S);     sop(OP_GT, H_GT_S);
  sop(OP_LT, H_LT_S);     sop(OP_GE, H_GE_S);     sop(OP_LE, H_LE_S);
  sop(OP_NEG, H_NEG_S);   sop(OP_ORL, H_ORL_S);   sop(OP_RND, H_RND_S);
  sop(OP_TIME, H_TIME_S); sop(OP_LDB, H_LDB_S);   sop(OP_STB, H_STB_S);
  sop(OP_SAR, H_SAR_S);   sop(OP_LNOT, H_LNOT_S); sop(OP_SLT, H_SLT_S);
  sop(OP_SGT, H_SGT_S);   sop(OP_SGE, H_SGE_S);   sop(OP_SLE, H_SLE_S);
  sop(OP_ADDX, H_ADDX_S); sop(OP_SUBX, H_SUBX_S); sop(OP_MULX, H_MULX_S);
  sop(OP_ASSERT, H_ASSERT_S);
  return t;
}();

// Decode the instruction at pc0 into d, mirroring read() byte for byte.
// Any anomaly (truncation, oversized payload width, PC-dereferencing
// operand) leaves h = H_SLOW so execution replays through stepSlow and
// faults (or behaves) exactly as the reference core would.
void CesVM::decodeAt(uint64_t pc0, Decoded& d) {
  d.epoch = epoch_;
  d.h = H_SLOW;
  d.regptr = 0;
  const FastOpInfo& info = kFastOpInfo[code_[pc0]];
  if (info.h == H_SLOW) return;
  const size_t size = code_.size();
  uint64_t p = pc0 + 1;
  for (uint8_t i = 0; i < info.nops; ++i) {
    if (p >= size) return;
    uint8_t control = code_[p++];
    uint8_t v = control & MAX_SHORT_VAL;
    uint64_t val;
    if (control & SHORT_VAL) {
      val = v;
    } else {
      if (v > sizeof(val)) return;
      if (v > size || p > size - v) return;
      val = 0;
      std::memcpy(&val, &code_[p], v);
      p += v;
    }
    if (control & REG_PTR) {
      // A dereference of cell 0 observes the mid-instruction PC, which
      // the fast core does not materialize per-operand.
      if (val == 0) return;
      d.regptr |= static_cast<uint8_t>(1u << i);
    }
    d.val[i] = val;
  }
  if (info.jumpTail) {
    if (p + 2 > size) return;
    d.target = static_cast<uint16_t>(code_[p] |
                                     (static_cast<uint16_t>(code_[p + 1]) << 8));
    p += 2;
  }
  d.nextPc = static_cast<uint16_t>(p);
  d.nops = info.nops;
  d.h = info.h;
}

void CesVM::runFast(CesVMHost& host, CesVMResult& result) {
  if (++epoch_ == 0) {  // epoch wrap: hard-invalidate the whole table
    dtab_.clear();
    epoch_ = 1;
  }
  if (dtab_.size() < code_.size()) dtab_.resize(code_.size());

  uint64_t pc = 0;
  const Decoded* d = nullptr;
  uint64_t a = 0, b = 0, c = 0;

// Operand i: pre-decoded immediate, or a cell dereference through get()
// (which bounds-checks and faults exactly like the reference core).
#define VMOP(i) ((d->regptr & (1u << (i))) ? get(d->val[i]) : d->val[i])

#if CESVM_OPT_THREADED
// Label-as-value jump table + computed goto: a deliberate GCC/Clang extension
// (the threaded-dispatch fast core). Both constructs are non-ISO, so -Wpedantic
// flags them; suppress it just for this dispatch prologue rather than dropping
// the flag for the whole lib.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
  static const void* const kTbl[] = {
#define X(n) &&VL_##n,
    CESVM_FAST_HANDLERS(X)
#undef X
  };
#define VM_TARGET(n) VL_##n:
#define VM_NEXT      goto vm_dispatch

vm_dispatch:
  if (term_) return;
  pc = io_[0];
  if (pc >= code_.size()) return;
  if (pc >= dtab_.size()) dtab_.resize(code_.size());  // SYS_LOAD_CODE grew
  d = &dtab_[pc];
  if (d->epoch != epoch_) decodeAt(pc, dtab_[pc]);
  ++result.opsExecuted;
  if (!billOp()) { io_[0] = pc + 1; return; }
  io_[0] = d->nextPc;
  goto *kTbl[d->h];
#pragma GCC diagnostic pop
#else
#define VM_TARGET(n) case H_##n:
#define VM_NEXT      continue

  for (;;) {
    if (term_) return;
    pc = io_[0];
    if (pc >= code_.size()) return;
    if (pc >= dtab_.size()) dtab_.resize(code_.size());  // SYS_LOAD_CODE grew
    d = &dtab_[pc];
    if (d->epoch != epoch_) decodeAt(pc, dtab_[pc]);
    ++result.opsExecuted;
    if (!billOp()) { io_[0] = pc + 1; return; }
    io_[0] = d->nextPc;
    switch (d->h) {
#endif

  VM_TARGET(SLOW) {
    // Replay through the reference interpreter: reset PC to the opcode
    // byte (the base cost is already billed) and run one instruction.
    io_[0] = pc;
    stepSlow(host);
  } VM_NEXT;

  VM_TARGET(NOP) VM_NEXT;

  VM_TARGET(TERM) { io_[0] = UINT64_MAX; } VM_NEXT;

  VM_TARGET(SET) { a = VMOP(0); b = VMOP(1); get(a) = b; } VM_NEXT;

  VM_TARGET(JMP) { io_[0] = d->target; } VM_NEXT;

  VM_TARGET(INC) { a = VMOP(0); ++get(a); } VM_NEXT;

  VM_TARGET(DEC) { a = VMOP(0); --get(a); } VM_NEXT;

  VM_TARGET(PUSH) { a = VMOP(0); push(a); } VM_NEXT;

  VM_TARGET(POP) { a = VMOP(0); get(a) = pop(); } VM_NEXT;

  VM_TARGET(HOST) { hostCall(host); } VM_NEXT;

  VM_TARGET(HOSTX) {
    hostCall(host);
    if (!term_ && S() != 0) term_ = CESVM_ABORT;
  } VM_NEXT;

  VM_TARGET(ABORT) { term_ = CESVM_ABORT; } VM_NEXT;

  VM_TARGET(VPUSH) {
    a = VMOP(0); b = VMOP(1);
    ++get(a); get(get(a)) = b;
  } VM_NEXT;

  VM_TARGET(VPOP) {
    a = VMOP(0); b = VMOP(1);
    get(b) = get(a); --get(a);
  } VM_NEXT;

  // ctxPush snapshots the registers with PC = nextPc (the return
  // address); on depth-cap failure it sets CESVM_SEGFAULT and the
  // dispatch check exits.
  VM_TARGET(CALL) { if (ctxPush()) io_[0] = d->target; } VM_NEXT;

  VM_TARGET(CALL_S) { a = pop(); if (ctxPush()) io_[0] = a; } VM_NEXT;

  VM_TARGET(CALLR) { a = VMOP(0); if (ctxPush()) io_[0] = a; } VM_NEXT;

  VM_TARGET(JMPR) { a = VMOP(0); io_[0] = a; } VM_NEXT;

  VM_TARGET(RET) {
    a = VMOP(0);
    if (ctxEmpty()) { term_ = CESVM_RET; }
    else { ctxRestorePop(); R() = a; }
  } VM_NEXT;

  VM_TARGET(JF)   { a = VMOP(0); if (!a) io_[0] = d->target; } VM_NEXT;
  VM_TARGET(JF_S) { a = pop();   if (!a) io_[0] = d->target; } VM_NEXT;
  VM_TARGET(JT)   { a = VMOP(0); if (a)  io_[0] = d->target; } VM_NEXT;
  VM_TARGET(JT_S) { a = pop();   if (a)  io_[0] = d->target; } VM_NEXT;

  VM_TARGET(DUP) { a = pop(); push(a); push(a); } VM_NEXT;

  VM_TARGET(RND)   { R() = rng_(); } VM_NEXT;
  VM_TARGET(RND_S) { push(rng_()); } VM_NEXT;

  VM_TARGET(TIME) {
    R() = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
  } VM_NEXT;

  VM_TARGET(TIME_S) {
    push(static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count()));
  } VM_NEXT;

  VM_TARGET(MOV) {
    a = VMOP(0); b = VMOP(1); c = VMOP(2);
    if (c > CESVM_IO_SIZE ||
        a > CESVM_IO_SIZE - c || b > CESVM_IO_SIZE - c) {
      term_ = CESVM_SEGFAULT;
    } else if (billMul(c, CESVM_COST_PER_CELL)) {
      std::memmove(&io_[a], &io_[b], c * sizeof(uint64_t));
    }
  } VM_NEXT;

  VM_TARGET(CMP) {
    a = VMOP(0); b = VMOP(1); c = VMOP(2);
    if (c > CESVM_IO_SIZE ||
        a > CESVM_IO_SIZE - c || b > CESVM_IO_SIZE - c) {
      term_ = CESVM_SEGFAULT;
    } else if (billMul(c, CESVM_COST_PER_CELL)) {
      R() = (std::memcmp(&io_[a], &io_[b], c * sizeof(uint64_t)) == 0) ? 1 : 0;
    }
  } VM_NEXT;

  VM_TARGET(FIL) {
    a = VMOP(0); b = VMOP(1); c = VMOP(2);
    if (c > CESVM_IO_SIZE || a > CESVM_IO_SIZE - c) {
      term_ = CESVM_SEGFAULT;
    } else if (billMul(c, CESVM_COST_PER_CELL)) {
      for (uint64_t i = 0; i < c; ++i)
        io_[a + i] = b;
    }
  } VM_NEXT;

  VM_TARGET(LDB) {
    a = VMOP(0);
    if (a >= CESVM_IO_SIZE * sizeof(uint64_t)) term_ = CESVM_SEGFAULT;
    else R() = reinterpret_cast<uint8_t*>(io_)[a];
  } VM_NEXT;

  VM_TARGET(LDB_S) {
    a = pop();
    if (a >= CESVM_IO_SIZE * sizeof(uint64_t)) term_ = CESVM_SEGFAULT;
    else push(reinterpret_cast<uint8_t*>(io_)[a]);
  } VM_NEXT;

  VM_TARGET(STB) {
    a = VMOP(0); b = VMOP(1);
    if (a >= CESVM_IO_SIZE * sizeof(uint64_t)) term_ = CESVM_SEGFAULT;
    else reinterpret_cast<uint8_t*>(io_)[a] = static_cast<uint8_t>(b & 0xFF);
  } VM_NEXT;

  VM_TARGET(STB_S) {
    b = pop(); a = pop();  // value first, offset second (matches stepSlow)
    if (a >= CESVM_IO_SIZE * sizeof(uint64_t)) term_ = CESVM_SEGFAULT;
    else reinterpret_cast<uint8_t*>(io_)[a] = static_cast<uint8_t>(b & 0xFF);
  } VM_NEXT;

// Two-operand ops with register and stack forms and no extra checks.
#define VM_BIN(NAME, EXPR) \
  VM_TARGET(NAME)      { a = VMOP(0); b = VMOP(1); R() = (EXPR); } VM_NEXT; \
  VM_TARGET(NAME##_S)  { b = pop(); a = pop(); push(EXPR); } VM_NEXT;

  VM_BIN(ADD, a + b)
  VM_BIN(SUB, a - b)
  VM_BIN(MUL, a * b)
  VM_BIN(OR,  a | b)
  VM_BIN(AND, a & b)
  VM_BIN(XOR, a ^ b)
  VM_BIN(ANDL, a && b)
  VM_BIN(ORL,  a || b)
  VM_BIN(EQ, a == b)
  VM_BIN(NE, a != b)
  VM_BIN(GT, a > b)
  VM_BIN(LT, a < b)
  VM_BIN(GE, a >= b)
  VM_BIN(LE, a <= b)
  VM_BIN(SLT, static_cast<int64_t>(a) <  static_cast<int64_t>(b))
  VM_BIN(SGT, static_cast<int64_t>(a) >  static_cast<int64_t>(b))
  VM_BIN(SGE, static_cast<int64_t>(a) >= static_cast<int64_t>(b))
  VM_BIN(SLE, static_cast<int64_t>(a) <= static_cast<int64_t>(b))
#undef VM_BIN

  VM_TARGET(DIV) {
    a = VMOP(0); b = VMOP(1);
    if (b) R() = a / b; else term_ = CESVM_DIVZERO;
  } VM_NEXT;

  VM_TARGET(DIV_S) {
    b = pop(); a = pop();
    if (b) push(a / b); else term_ = CESVM_DIVZERO;
  } VM_NEXT;

  VM_TARGET(MOD) {
    a = VMOP(0); b = VMOP(1);
    if (b) R() = a % b; else term_ = CESVM_DIVZERO;
  } VM_NEXT;

  VM_TARGET(MOD_S) {
    b = pop(); a = pop();
    if (b) push(a % b); else term_ = CESVM_DIVZERO;
  } VM_NEXT;

  VM_TARGET(SHL) {
    a = VMOP(0); b = VMOP(1);
    if (b >= 64) term_ = CESVM_SEGFAULT; else R() = a << b;
  } VM_NEXT;

  VM_TARGET(SHL_S) {
    b = pop(); a = pop();
    if (b >= 64) term_ = CESVM_SEGFAULT; else push(a << b);
  } VM_NEXT;

  VM_TARGET(SHR) {
    a = VMOP(0); b = VMOP(1);
    if (b >= 64) term_ = CESVM_SEGFAULT; else R() = a >> b;
  } VM_NEXT;

  VM_TARGET(SHR_S) {
    b = pop(); a = pop();
    if (b >= 64) term_ = CESVM_SEGFAULT; else push(a >> b);
  } VM_NEXT;

  VM_TARGET(SAR) {
    a = VMOP(0); b = VMOP(1);
    if (b >= 64) term_ = CESVM_SEGFAULT;
    else R() = static_cast<uint64_t>(static_cast<int64_t>(a) >>
                                     static_cast<int>(b));
  } VM_NEXT;

  VM_TARGET(SAR_S) {
    b = pop(); a = pop();
    if (b >= 64) term_ = CESVM_SEGFAULT;
    else push(static_cast<uint64_t>(static_cast<int64_t>(a) >>
                                    static_cast<int>(b)));
  } VM_NEXT;

  VM_TARGET(NOT)    { a = VMOP(0); R() = ~a; } VM_NEXT;
  VM_TARGET(NOT_S)  { a = pop(); push(~a); } VM_NEXT;
  VM_TARGET(LNOT)   { a = VMOP(0); R() = !a; } VM_NEXT;
  VM_TARGET(LNOT_S) { a = pop(); push(!a); } VM_NEXT;
  VM_TARGET(NEG)    { a = VMOP(0); R() = static_cast<uint64_t>(0) - a; } VM_NEXT;
  VM_TARGET(NEG_S)  { a = pop(); push(static_cast<uint64_t>(0) - a); } VM_NEXT;

  VM_TARGET(ADDX) {
    a = VMOP(0); b = VMOP(1);
    if (a > UINT64_MAX - b) term_ = CESVM_OVERFLOW; else R() = a + b;
  } VM_NEXT;

  VM_TARGET(ADDX_S) {
    b = pop(); a = pop();
    if (a > UINT64_MAX - b) term_ = CESVM_OVERFLOW; else push(a + b);
  } VM_NEXT;

  VM_TARGET(SUBX) {
    a = VMOP(0); b = VMOP(1);
    if (b > a) term_ = CESVM_OVERFLOW; else R() = a - b;
  } VM_NEXT;

  VM_TARGET(SUBX_S) {
    b = pop(); a = pop();
    if (b > a) term_ = CESVM_OVERFLOW; else push(a - b);
  } VM_NEXT;

  VM_TARGET(MULX) {
    a = VMOP(0); b = VMOP(1);
    if (b != 0 && a > UINT64_MAX / b) term_ = CESVM_OVERFLOW;
    else R() = a * b;
  } VM_NEXT;

  VM_TARGET(MULX_S) {
    b = pop(); a = pop();
    if (b != 0 && a > UINT64_MAX / b) term_ = CESVM_OVERFLOW;
    else push(a * b);
  } VM_NEXT;

  VM_TARGET(ASSERT) {
    a = VMOP(0);
    if (!a) term_ = CESVM_ABORT;
  } VM_NEXT;

  VM_TARGET(ASSERT_S) {
    a = pop();
    // pop() on an empty stack already set CESVM_UNDERFLOW; do not
    // misreport that crash as an assert failure.
    if (!a && !term_) term_ = CESVM_ABORT;
  } VM_NEXT;

#if !CESVM_OPT_THREADED
    default:
      // Unreachable: decodeAt only emits indices with handlers. A loud
      // halt beats a silent no-op if table and handlers ever diverge.
      term_ = CESVM_HOST;
      VM_NEXT;
    }
  }
#endif

#undef VM_TARGET
#undef VM_NEXT
#undef VMOP
}

#endif  // CESVM_OPT_PREDECODE

// --- GVM operand decoding ---

uint64_t CesVM::read(bool jumpSkipControl) {
  if (PC() >= code_.size()) {
    term_ = CESVM_CODESIZE;
    return 0;
  }
  uint8_t control;
  if (jumpSkipControl)
    control = 2; // 2-byte address
  else
    control = code_[PC()++];

  uint8_t v = control & MAX_SHORT_VAL;
  bool regptr = control & REG_PTR;
  bool shortval = control & SHORT_VAL;
  uint64_t val;
  if (shortval) {
    val = v;
  } else {
    val = 0;
    // v comes from attacker bytecode (low 6 bits = 0..63). Reject
    // anything that wouldn't fit in a uint64_t — otherwise the memcpy
    // below would write past `val` on the stack.
    if (v > sizeof(val)) {
      term_ = CESVM_OPCODE;
      return 0;
    }
    if (v > code_.size() || PC() > code_.size() - v) {
      term_ = CESVM_CODESIZE;
      return 0;
    }
    std::memcpy(&val, &code_[PC()], v);
    PC() += v;
  }
  if (regptr)
    val = get(val);
  return val;
}

bool CesVM::bill(uint64_t cost) {
  // Overflow guard on cost * gasMult_, symmetric with billMul(). An absurd
  // feeVmMult could otherwise wrap a real cost to a small value and underbill;
  // on wrap, halt as budget-exhausted. (gasMult_ is forced >= 1 in execute().)
  if (gasMult_ != 0 && cost > std::numeric_limits<uint64_t>::max() / gasMult_) {
    term_ = CESVM_BUDGET;
    io_[CESVM_IO_BUDGET_REMAINING] = 0;
    return false;
  }
  cost *= gasMult_;
  // Use cost <= budget_ - budgetUsed_ to avoid uint64_t overflow on the
  // sum. Equivalent to (budgetUsed_ + cost > budget_) when no wrap.
  if (cost > budget_ - budgetUsed_) {
    term_ = CESVM_BUDGET;
    io_[CESVM_IO_BUDGET_REMAINING] = 0;  // mirror reflects exhausted state
    return false;
  }
  budgetUsed_ += cost;
  // Mirror the remaining budget into io[CESVM_IO_BUDGET_REMAINING] so
  // programs can read their current gas headroom mid-run and bail
  // gracefully before a hard CESVM_BUDGET abort. Symmetric with the
  // allowance mirror in hostCall, but updated at op granularity
  // because budget is consumed by every op, not just by syscalls.
  io_[CESVM_IO_BUDGET_REMAINING] = budget_ - budgetUsed_;
  return true;
}

bool CesVM::billCredits(uint64_t raw) {
  if (raw > budget_ - budgetUsed_) {
    term_ = CESVM_BUDGET;
    io_[CESVM_IO_BUDGET_REMAINING] = 0;
    return false;
  }
  budgetUsed_ += raw;
  io_[CESVM_IO_BUDGET_REMAINING] = budget_ - budgetUsed_;
  return true;
}

bool CesVM::billMul(uint64_t a, uint64_t b) {
  // Overflow-safe bill(a * b). Covers the case where attacker bytecode
  // supplies huge `a` (e.g. OP_MOV cnt) to make a*b wrap to a small
  // value that slips past bill()'s budget check.
  if (b != 0 && a > UINT64_MAX / b) {
    term_ = CESVM_BUDGET;
    return false;
  }
  return bill(a * b);
}

// --- IO memory byte helpers ---

void CesVM::readIoBytes(uint64_t ioOffset, uint8_t* out, size_t len) {
  // io is uint64_t cells; bytes are packed little-endian
  size_t totalBytes = CESVM_IO_SIZE * sizeof(uint64_t);
  if (ioOffset > UINT64_MAX / sizeof(uint64_t)) {
    term_ = CESVM_SEGFAULT;
    return;
  }
  size_t byteOffset = ioOffset * sizeof(uint64_t);
  if (len > totalBytes || byteOffset > totalBytes - len) {
    term_ = CESVM_SEGFAULT;
    return;
  }
  std::memcpy(out, reinterpret_cast<uint8_t*>(io_) + byteOffset, len);
}

void CesVM::writeIoBytes(uint64_t ioOffset, const uint8_t* data, size_t len) {
  size_t totalBytes = CESVM_IO_SIZE * sizeof(uint64_t);
  if (ioOffset > UINT64_MAX / sizeof(uint64_t)) {
    term_ = CESVM_SEGFAULT;
    return;
  }
  size_t byteOffset = ioOffset * sizeof(uint64_t);
  if (len > totalBytes || byteOffset > totalBytes - len) {
    term_ = CESVM_SEGFAULT;
    return;
  }
  std::memcpy(reinterpret_cast<uint8_t*>(io_) + byteOffset, data, len);
}

// --- CES syscall dispatch ---

void CesVM::hostCall(CesVMHost& host) {
  uint64_t syscall = io_[3]; // SYSCALL register

  switch (syscall) {
  case SYS_NOP:
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    S() = CES_OK;
    break;

  case SYS_READ_ACCOUNT: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    HashPrefix id;
    readIoBytes(io_[4], id.data(), id.size());
    if (term_) return;
    if (!billCredits(host.feeQuery)) return;
    R() = static_cast<uint64_t>(host.readAccountBalance(id));
    io_[5] = host.readAccountNonce(id);
    io_[6] = host.readAccountAliasId(id);   // 0 = no alias
    S() = CES_OK;
    break;
  }

  case SYS_TRANSFER: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash dest;
    readIoBytes(io_[4], dest.data(), dest.size());
    if (term_) return;
    // Protocol fee comes out of the run's pre-paid budget, not the
    // user's allowance. Halts the VM (CESVM_BUDGET) if budget is
    // insufficient — symmetric with how bill() handles gas exhaustion.
    if (!billCredits(host.feeTx)) return;
    S() = host.transfer(dest, io_[5]);
    break;
  }

  case SYS_OWNER_TRANSFER: {
    // Same shape as SYS_TRANSFER, but debits the program's owner instead
    // of the caller. Protocol fee still comes from the caller's budget —
    // they invoked the syscall.
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash dest;
    readIoBytes(io_[4], dest.data(), dest.size());
    if (term_) return;
    if (!billCredits(host.feeTx)) return;
    S() = host.ownerTransfer(dest, io_[5]);
    break;
  }

  case SYS_DEPOSIT: {
    // caller -> programOwner. Both endpoints implicit; io[4] = amount.
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    if (!billCredits(host.feeTx)) return;
    S() = host.deposit(io_[4]);
    break;
  }

  case SYS_WITHDRAW: {
    // programOwner -> caller. Both endpoints implicit; io[4] = amount.
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    if (!billCredits(host.feeTx)) return;
    S() = host.withdraw(io_[4]);
    break;
  }

  case SYS_READ_ASSET: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash key;
    readIoBytes(io_[4], key.data(), key.size());
    if (term_) return;
    if (!billCredits(host.feeQuery)) return;
    HashPrefix owner;
    AssetData content;
    uint16_t balance = 0;
    uint32_t price = 0;
    if (host.readAsset(key, owner, content, balance, price)) {
      // Inputs are contiguous at io[4..6] so OP_HOSTXV can populate
      // them without padding; outputs land at io[7] (balance) and
      // io[8] (price), past the input range.
      writeIoBytes(io_[5], owner.data(), owner.size());
      writeIoBytes(io_[6], content.data(), content.size());
      io_[7] = balance;
      io_[8] = price;
      S() = CES_OK;
    } else {
      S() = CES_ERROR_ASSET_NOT_FOUND;
    }
    break;
  }

  case SYS_CREATE_ASSET_RANDOM: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    AssetData content{};
    readIoBytes(io_[4], content.data(), CESVM_CODE_BLOCK);
    if (term_) return;
    uint16_t days = static_cast<uint16_t>(io_[5]);
    // Asset rent is protocol overhead (paying for slot occupancy),
    // not user spending — bill from budget. Prepaid days run through
    // the attenuation helper so deep funding can't lock in a low rate.
    uint32_t totalDays = 2u + assetDays(days);
    if (!billCredits(computePrepayCost(host.feeAssetRaw, host.assetRentMultBp, totalDays, 0))) return;
    minx::Hash newKey;
    for (auto& b : newKey) b = static_cast<uint8_t>(rng_());
    S() = host.createAsset(newKey, content, days);
    if (S() == CES_OK)
      writeIoBytes(io_[6], newKey.data(), newKey.size());
    break;
  }

  case SYS_CREATE_ASSET_RANGE: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    uint64_t n = io_[4];
    if (n == 0 || n > CESVM_MAX_ASSET_RANGE) {
      S() = CES_ERROR_BAD_INPUT;
      break;
    }
    // Gas scales with the cells created: this base plus one per extra cell.
    if (n > 1 && !bill(CESVM_COST_PER_SYSCALL * (n - 1))) return;
    uint16_t days = static_cast<uint16_t>(io_[5]);
    uint64_t per = computePrepayCost(host.feeAssetRaw, host.assetRentMultBp,
                                     2u + assetDays(days), 0);
    if (!billCredits(per * n)) return;
    // Fresh 24-byte entropy prefix, index suffix zeroed (cell 0). Retry a new
    // prefix on the astronomically rare collision; the host creates nothing on
    // collision so the retry is clean.
    minx::Hash firstKey{};
    uint8_t rc = CES_ERROR_ASSET_EXISTS;
    for (uint64_t attempt = 0; attempt < CESVM_ASSET_RANGE_RETRIES; ++attempt) {
      for (int i = 0; i < 24; ++i) firstKey[i] = static_cast<uint8_t>(rng_());
      for (int i = 24; i < 32; ++i) firstKey[i] = 0;
      rc = host.createAssetRange(firstKey, static_cast<uint32_t>(n), days);
      if (rc != CES_ERROR_ASSET_EXISTS) break;
    }
    S() = rc;
    if (rc == CES_OK) writeIoBytes(io_[6], firstKey.data(), firstKey.size());
    break;
  }

  case SYS_UPDATE_ASSET: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash key;
    readIoBytes(io_[4], key.data(), key.size());
    if (term_) return;
    AssetData content{};
    readIoBytes(io_[5], content.data(), CESVM_CODE_BLOCK);
    if (term_) return;
    if (!billCredits(host.feeAsset)) return;
    S() = host.updateAsset(key, content);
    break;
  }

  case SYS_UPDATE_ASSET_META: {
    // Owner+price update with no content I/O — bills feeTx (cheaper tier),
    // matching CES_UPDATE_ASSET_META on the wire.
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash key;
    readIoBytes(io_[4], key.data(), key.size());
    if (term_) return;
    HashPrefix newOwner;
    readIoBytes(io_[5], newOwner.data(), newOwner.size());
    if (term_) return;
    if (!billCredits(host.feeTx)) return;
    S() = host.updateAssetMeta(key, newOwner, static_cast<uint32_t>(io_[6]));
    break;
  }

  case SYS_REFILL: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    // Grow this run's budget by what the host grants (bounded host-side by the
    // refill ceiling and the caller's balance). The caller is charged post-run
    // for gas actually consumed past the free grant (executeVmRun), not for the
    // grant itself, so unused refill costs nothing.
    uint64_t granted = host.refillGas(io_[4]);
    budget_ += granted;
    io_[CESVM_IO_BUDGET_REMAINING] = budget_ - budgetUsed_;
    R() = granted;
    S() = CES_OK;
    break;
  }

  case SYS_READ_ALIAS: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    // io[4]=alias id, io[5]=offset, io[6]=len, io[7]=dest cell ptr
    uint32_t aliasId = static_cast<uint32_t>(io_[4]);
    uint64_t off = io_[5];
    uint64_t len = io_[6];
    if (off > ALIAS_VALUE_BYTES || len > ALIAS_VALUE_BYTES ||
        off + len > ALIAS_VALUE_BYTES) {
      S() = CES_ERROR_BAD_INPUT;
      break;
    }
    if (!billCredits(host.feeQuery)) return;
    ces::Bytes tmp(len);
    if (!host.readAlias(aliasId, static_cast<uint32_t>(off),
                        static_cast<uint32_t>(len), tmp.data())) {
      S() = CES_ERROR_ALIAS_NOT_FOUND;
      break;
    }
    if (len > 0) {
      writeIoBytes(io_[7], tmp.data(), len);
      if (term_) return;
    }
    R() = len;
    S() = CES_OK;
    break;
  }

  case SYS_WRITE_ALIAS: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    // io[4]=alias id, io[5]=offset, io[6]=len, io[7]=src cell ptr
    uint32_t aliasId = static_cast<uint32_t>(io_[4]);
    uint64_t off = io_[5];
    uint64_t len = io_[6];
    if (off > ALIAS_VALUE_BYTES || len > ALIAS_VALUE_BYTES ||
        off + len > ALIAS_VALUE_BYTES) {
      S() = CES_ERROR_BAD_INPUT;
      break;
    }
    ces::Bytes tmp(len);
    if (len > 0) {
      readIoBytes(io_[7], tmp.data(), len);
      if (term_) return;
    }
    if (!billCredits(host.feeAlias)) return;
    S() = host.writeAlias(aliasId, static_cast<uint32_t>(off), tmp.data(),
                          static_cast<uint32_t>(len));
    break;
  }

  case SYS_LOAD_CODE_ALIAS: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    if (code_.size() + ALIAS_INLINE_CODE_BYTES > CESVM_MAX_CODE) {
      term_ = CESVM_CODEFULL;
      return;
    }
    uint32_t aliasId = static_cast<uint32_t>(io_[4]);
    if (!billCredits(host.feeQuery)) return;
    uint64_t offset = code_.size();
    code_.resize(offset + ALIAS_INLINE_CODE_BYTES);
    if (!host.readAlias(aliasId, ALIAS_OFF_CONTENT, ALIAS_INLINE_CODE_BYTES,
                        &code_[offset])) {
      code_.resize(offset);
      S() = CES_ERROR_ALIAS_NOT_FOUND;
      break;
    }
    R() = offset;
    S() = CES_OK;
    break;
  }

  case SYS_SCHEDULE_ALIAS: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    // io[4]=alias id, io[5]=budget, io[6]=child_allowance,
    // io[7]=input_ptr, io[8]=input_len, io[9]=time_us
    // Same billing and allowance carve as SYS_SCHEDULE.
    uint32_t aliasId = static_cast<uint32_t>(io_[4]);
    uint64_t childBudget = io_[5];
    uint64_t childAllowance = io_[6];
    size_t inputLen = std::min(io_[8], uint64_t(CESVM_MAX_INPUT));
    ces::Bytes input(inputLen);
    if (inputLen > 0) {
      readIoBytes(io_[7], input.data(), inputLen);
      if (term_) return;
    }
    uint64_t time_us = io_[9];
    uint64_t now = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    uint64_t duration = (time_us > now) ? (time_us - now) : 0;
    uint64_t hostingCost = CESVM_SCHEDULE_BASE_COST +
                           CESVM_SCHEDULE_PER_SEC * duration / US_PER_SEC;
    if (!bill(hostingCost)) return;
    if (host.allowance != std::numeric_limits<uint64_t>::max()) {
      if (childAllowance > host.allowance) {
        S() = CES_ERROR_ALLOWANCE_EXCEEDED;
        break;
      }
      host.allowance -= childAllowance;
    }
    S() = host.scheduleAlias(aliasId, childBudget, childAllowance,
                             input.data(), inputLen, time_us);
    if (S() != CES_OK &&
        host.allowance != std::numeric_limits<uint64_t>::max()) {
      host.allowance += childAllowance;
    }
    break;
  }

  case SYS_FUND_ASSET: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash key;
    readIoBytes(io_[4], key.data(), key.size());
    if (term_) return;
    uint16_t days = static_cast<uint16_t>(io_[5]);
    // Read existing days off the asset to drive correct attenuation.
    HashPrefix _o; AssetData _c; uint16_t _bal = 0; uint32_t _p = 0;
    uint32_t held = host.readAsset(key, _o, _c, _bal, _p)
                      ? assetDays(_bal) : 0u;
    // The day field caps at 0x0FFF, and VmHost::fundAsset clamps the grant
    // to it -- so bill only for the days actually granted, not the full
    // request (mirrors the wire fundAsset fix; otherwise funding a near-cap
    // asset overcharges for days it never receives).
    uint32_t granted = std::min<uint32_t>(0x0FFF, held + days) - held;
    if (!billCredits(host.feeTx + computePrepayCost(host.feeAssetRaw,
                                             host.assetRentMultBp,
                                             granted, held))) return;
    S() = host.fundAsset(key, days);
    break;
  }

  case SYS_BUY_ASSET: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash key;
    readIoBytes(io_[4], key.data(), key.size());
    if (term_) return;
    if (!billCredits(host.feeTx)) return;
    // Purchase price stays allowance-bound — it's spending toward the
    // seller, not protocol overhead.
    S() = host.buyAsset(key, io_[5]);
    break;
  }

  case SYS_GIVE_ASSET: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash key;
    readIoBytes(io_[4], key.data(), key.size());
    if (term_) return;
    HashPrefix newOwner;
    readIoBytes(io_[5], newOwner.data(), newOwner.size());
    if (term_) return;
    if (!billCredits(host.feeTx)) return;
    S() = host.giveAsset(key, newOwner);
    break;
  }

  case SYS_SEND_UDP: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    // Disabled: raw UDP is insecure. Use SYS_SEND_CLIENT instead.
    S() = CES_ERROR_DISABLED;
    break;
    // Original implementation (kept for potential future re-enabling):
    // char addrBuf[64] = {};
    // readIoBytes(io_[4], reinterpret_cast<uint8_t*>(addrBuf), 63);
    // if (term_) return;
    // uint16_t port = static_cast<uint16_t>(io_[5]);
    // size_t dataLen = std::min(io_[7], uint64_t(minx::MAX_DATA_SIZE));
    // ces::Bytes data(dataLen);
    // readIoBytes(io_[6], data.data(), dataLen);
    // if (term_) return;
    // host.sendUdp(addrBuf, port, data.data(), dataLen);
    // S() = CES_OK;
    // break;
  }

  case SYS_HASH: {
    if (!bill(CESVM_COST_PER_MEMOP)) return;
    uint64_t dataOff = io_[4];
    uint64_t len = std::min(io_[5], uint64_t(CESVM_MAX_CODE));
    uint64_t outOff = io_[6];
    size_t totalBytes = CESVM_IO_SIZE * sizeof(uint64_t);
    // dataOff/outOff are attacker-controlled cell indices; the subsequent
    // "* sizeof(uint64_t)" must not wrap, and neither may the "+ len" sum.
    if (dataOff > UINT64_MAX / sizeof(uint64_t) ||
        outOff  > UINT64_MAX / sizeof(uint64_t)) {
      term_ = CESVM_SEGFAULT; return;
    }
    size_t dataByte = dataOff * sizeof(uint64_t);
    size_t outByte  = outOff  * sizeof(uint64_t);
    if (len > totalBytes || dataByte > totalBytes - len ||
        outByte > totalBytes - sizeof(minx::Hash)) {
      term_ = CESVM_SEGFAULT; return;
    }
    if (!billMul(len, CESVM_COST_PER_BYTE)) return;
    auto* base = reinterpret_cast<uint8_t*>(io_);
    CryptoPP::SHA256().CalculateDigest(base + outByte, base + dataByte, len);
    S() = CES_OK;
    break;
  }

  case SYS_VERIFY_SIG: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    uint64_t dataLen = std::min(io_[5], uint64_t(minx::MAX_DATA_SIZE));
    if (!bill(dataLen * CESVM_COST_PER_BYTE + CESVM_COST_VERIFY_EC)) return;
    ces::Bytes data(dataLen);
    readIoBytes(io_[4], data.data(), dataLen);
    if (term_) return;
    uint8_t sig[SIG_SIZE];
    readIoBytes(io_[6], sig, SIG_SIZE);
    if (term_) return;
    uint8_t pubkey[KEY_SIZE];
    readIoBytes(io_[7], pubkey, KEY_SIZE);
    if (term_) return;
    R() = host.verifySig(data.data(), dataLen, sig, pubkey) ? 1 : 0;
    S() = CES_OK;
    break;
  }

  case SYS_CROSS_TRANSFER: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash dest;
    readIoBytes(io_[4], dest.data(), dest.size());
    if (term_) return;
    char addrBuf[64] = {};
    readIoBytes(io_[6], reinterpret_cast<uint8_t*>(addrBuf), 63);
    if (term_) return;
    if (!billCredits(host.feeTx)) return;
    // Cross-transfer amount stays allowance-bound (it's spending). The
    // host validates peer + queue + debit synchronously and returns a
    // proper code; only the network dispatch is deferred to commit.
    S() = host.crossTransfer(dest, io_[5], addrBuf);
    break;
  }

  case SYS_CREATE_ASSET: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash key;
    readIoBytes(io_[4], key.data(), key.size());
    if (term_) return;
    AssetData content{};
    readIoBytes(io_[5], content.data(), CESVM_CODE_BLOCK);
    if (term_) return;
    uint16_t days = static_cast<uint16_t>(io_[6]);
    if (!billCredits(computePrepayCost(host.feeAssetRaw, host.assetRentMultBp, 2u + assetDays(days), 0))) return;
    S() = host.createAsset(key, content, days);
    break;
  }

  case SYS_LOAD_CODE: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    if (code_.size() + CESVM_CODE_BLOCK > CESVM_MAX_CODE) {
      term_ = CESVM_CODEFULL;
      return;
    }
    minx::Hash key;
    readIoBytes(io_[4], key.data(), key.size());
    if (term_) return;
    if (!billCredits(host.feeQuery)) return;
    HashPrefix owner;
    AssetData content;
    uint16_t balance = 0;
    uint32_t price = 0;
    if (!host.readAsset(key, owner, content, balance, price)) {
      S() = CES_ERROR_ASSET_NOT_FOUND;
      break;
    }
    uint64_t offset = code_.size();
    code_.resize(code_.size() + CESVM_CODE_BLOCK);
    std::memcpy(&code_[offset], content.data(), CESVM_CODE_BLOCK);
    R() = offset;
    S() = CES_OK;
    break;
  }

  case SYS_SEND_CLIENT: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    // io[4] = account prefix ptr, io[5] = data ptr, io[6] = data len
    HashPrefix clientId;
    readIoBytes(io_[4], clientId.data(), clientId.size());
    if (term_) return;
    size_t dataLen = std::min(io_[6], uint64_t(minx::MAX_DATA_SIZE));
    ces::Bytes data(dataLen);
    readIoBytes(io_[5], data.data(), dataLen);
    if (term_) return;
    if (!billCredits(host.feeSendClient)) return;
    R() = host.sendClient(clientId, data.data(), dataLen) ? 1 : 0;
    S() = CES_OK;
    break;
  }

  case SYS_SCHEDULE: {
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    // io[4]=asset_key_ptr, io[5]=budget, io[6]=child_allowance,
    // io[7]=input_ptr, io[8]=input_len, io[9]=time_us
    minx::Hash assetKey;
    readIoBytes(io_[4], assetKey.data(), assetKey.size());
    if (term_) return;
    uint64_t childBudget = io_[5];
    uint64_t childAllowance = io_[6];
    size_t inputLen = std::min(io_[8], uint64_t(CESVM_MAX_INPUT));
    ces::Bytes input(inputLen);
    if (inputLen > 0) {
      readIoBytes(io_[7], input.data(), inputLen);
      if (term_) return;
    }
    uint64_t time_us = io_[9];
    // Compute hosting cost: base + per_us * duration
    uint64_t now = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    uint64_t duration = (time_us > now) ? (time_us - now) : 0;
    uint64_t hostingCost = CESVM_SCHEDULE_BASE_COST +
                           CESVM_SCHEDULE_PER_SEC * duration / US_PER_SEC;
    if (!bill(hostingCost)) return;
    // Decrement parent's allowance by the child's allotment. UINT64_MAX
    // sentinel means "no enforcement"; we treat any childAllowance as
    // ≤ UINT64_MAX and pass it through unchanged in that case (the child
    // also gets the unbounded sentinel only when both parent and request
    // are UINT64_MAX). Otherwise the parent must have ≥ childAllowance
    // remaining or this fails ALLOWANCE_EXCEEDED — and once we accept,
    // the parent loses that headroom for any subsequent SYS_SCHEDULE or
    // direct spend in this run.
    //
    // NOTE: allowance bounds caller-account *debits* (transfers/fees), NOT
    // gas — childBudget is intentionally not carved here. See review F2: the
    // lack of any spawned-gas exposure bound is a design gap, not bounded by
    // conflating it with the debit allowance.
    if (host.allowance != std::numeric_limits<uint64_t>::max()) {
      if (childAllowance > host.allowance) {
        S() = CES_ERROR_ALLOWANCE_EXCEEDED;
        break;
      }
      host.allowance -= childAllowance;
    }
    S() = host.schedule(assetKey, childBudget, childAllowance,
                         input.data(), inputLen, time_us);
    // If schedule rejected, refund the parent's allowance so we don't
    // burn headroom on a no-op.
    if (S() != CES_OK &&
        host.allowance != std::numeric_limits<uint64_t>::max()) {
      host.allowance += childAllowance;
    }
    break;
  }

  case SYS_CREATE_ASSET_MANAGED: {
    // Like SYS_CREATE_ASSET but the created asset is owned by the boot asset
    // (asset-owned), not by the runner. Caller pays, program owns.
    // io[4]=key_ptr, io[5]=content_ptr, io[6]=days
    if (!bill(CESVM_COST_PER_SYSCALL)) return;
    minx::Hash key;
    readIoBytes(io_[4], key.data(), key.size());
    if (term_) return;
    AssetData content{};
    readIoBytes(io_[5], content.data(), CESVM_CODE_BLOCK);
    if (term_) return;
    uint16_t days = static_cast<uint16_t>(io_[6]);
    if (!billCredits(computePrepayCost(host.feeAssetRaw, host.assetRentMultBp, 2u + assetDays(days), 0))) return;
    S() = host.createAssetManaged(key, content, days);
    break;
  }

  case SYS_RPC: {
    // MINX/RUDP stream call. See SYS_RPC in cesvm.h for the io layout
    // and wire protocol. Returns CES_OK (queued), CES_ERROR_DISABLED
    // (rpcPort == 0 on this server), or an upfront validation error.
    // Actual call outcome arrives later via the scheduled followup.
    if (!bill(CESVM_COST_PER_SYSCALL)) return;

    // Host string (max 255 bytes).
    uint64_t hostLen = io_[5];
    // Wire field caps host string at 255 bytes; reject before doing any
    // I/O. BAD_INPUT, not INTERNAL — the program supplied a too-long
    // hostname, the server is fine.
    if (hostLen > 255) { S() = CES_ERROR_BAD_INPUT; break; }
    std::string hostStr(hostLen, '\0');
    if (hostLen > 0) {
      readIoBytes(io_[4], reinterpret_cast<uint8_t*>(hostStr.data()),
                  hostLen);
      if (term_) return;
    }

    uint16_t port = static_cast<uint16_t>(io_[6]);

    minx::Hash fileHeadKey;
    readIoBytes(io_[7], fileHeadKey.data(), fileHeadKey.size());
    if (term_) return;

    minx::Hash followupKey;
    readIoBytes(io_[8], followupKey.data(), followupKey.size());
    if (term_) return;

    uint64_t followupBudget = io_[9];
    uint32_t followupTag = static_cast<uint32_t>(io_[10]);

    S() = host.rpc(hostStr, port, fileHeadKey, followupKey,
                    followupBudget, followupTag);
    break;
  }

  case SYS_L2_CALL: {
    // Paid, reliable call into an in-CES (L2) built-in. See SYS_L2_CALL in
    // cesvm.h for the io layout. The syscall owns the burn: a synchronous
    // reject burns nothing; CES_OK burns `value` and enqueues. Settlement is
    // delivery-based and resolved later via a followup run (INVOKE_L2_RETURN).
    if (!bill(CESVM_COST_PER_SYSCALL)) return;

    // Discriminator: 8 raw bytes (sha256 of the built-in name, truncated),
    // matched as a flat array so routing is endian-independent.
    uint8_t disc[8];
    readIoBytes(io_[4], disc, sizeof(disc));
    if (term_) return;

    uint64_t value = io_[5];

    // Provider-ABI blob, opaque to core. Bounded to keep the inline path small.
    constexpr uint64_t kMaxL2Blob = 1024;
    uint64_t blobLen = io_[7];
    if (blobLen > kMaxL2Blob) { S() = CES_ERROR_BAD_INPUT; break; }
    std::vector<uint8_t> blob(blobLen);
    if (blobLen > 0) {
      readIoBytes(io_[6], blob.data(), blobLen);
      if (term_) return;
    }

    minx::Hash followupKey;
    readIoBytes(io_[8], followupKey.data(), followupKey.size());
    if (term_) return;

    uint64_t followupBudget = io_[9];
    uint32_t followupTag = static_cast<uint32_t>(io_[10]);

    S() = host.l2call(disc, value, blob.data(), blob.size(),
                      followupKey, followupBudget, followupTag);
    break;
  }

  default:
    term_ = CESVM_SYSCALL;
  }

  // Mirror remaining allowance back into io memory so VM programs can read
  // their per-run spending headroom (and branch on it) the same way they
  // read the initial budget from io[CESVM_IO_BUDGET].
  io_[CESVM_IO_ALLOWANCE] = host.allowance;
}

} // namespace ces
