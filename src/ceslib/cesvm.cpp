/**
 * CesVM implementation.
 * GVM core (github.com/FluxBP/gvm) adapted for CES server-side execution.
 */

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
  stack_.clear();
  context_.clear();
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
  writeIoBytes(CESVM_IO_CALLER_KEY, host.callerKey.data(), KEY_SIZE);
  writeIoBytes(CESVM_IO_SELF_KEY, host.selfAssetKey.data(), KEY_SIZE);
  if (inputLen > 0)
    writeIoBytes(CESVM_IO_INPUT, host.input.data(), inputLen);

  uint64_t op1, op2;
  while (!term_ && PC() < code_.size()) {
    result.opsExecuted++;

    uint8_t opcode = code_[PC()++];

    switch (opcode) {
    case OP_NOP:
      if (!bill(CESVM_COST_PER_OP)) break;
      break;
    case OP_TERM:
      if (!bill(CESVM_COST_PER_OP)) break;
      PC() = UINT64_MAX;
      break;
    case OP_SET:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read();
      op2 = read();
      get(op1) = op2;
      break;
    case OP_JMP:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(true);
      PC() = op1;
      break;
    case OP_ADD:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 + op2; break;
    case OP_ADD | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 + op2); break;
    case OP_SUB:
      // Two's-complement subtraction. Wraps silently on underflow
      // (consistent with ADD/MUL/NEG); programs that need to detect
      // "would go negative" branch on a CMP first.
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read();
      R() = op1 - op2;
      break;
    case OP_SUB | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop();
      push(op1 - op2);
      break;
    case OP_MUL:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 * op2; break;
    case OP_MUL | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 * op2); break;
    case OP_DIV:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read();
      if (op2) R() = op1 / op2; else term_ = CESVM_DIVZERO;
      break;
    case OP_DIV | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop();
      if (op2) push(op1 / op2); else term_ = CESVM_DIVZERO;
      break;
    case OP_MOD:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read();
      if (op2) R() = op1 % op2; else term_ = CESVM_DIVZERO;
      break;
    case OP_MOD | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop();
      if (op2) push(op1 % op2); else term_ = CESVM_DIVZERO;
      break;
    case OP_OR:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 | op2; break;
    case OP_OR | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 | op2); break;
    case OP_ANDL:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 && op2; break;
    case OP_ANDL | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 && op2); break;
    case OP_XOR:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 ^ op2; break;
    case OP_XOR | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 ^ op2); break;
    case OP_NOT:
      // Bitwise complement (per x86/ARM/MIPS convention: NOT = ~x).
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); R() = ~op1; break;
    case OP_NOT | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = pop(); push(~op1); break;
    case OP_LNOT:
      // Logical NOT: 0 → 1, anything else → 0.
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); R() = !op1; break;
    case OP_LNOT | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = pop(); push(!op1); break;
    case OP_SHL:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read();
      // Shifting a uint64_t by >= 64 bits is UB per [expr.shift]/1.
      // Reject attacker bytecode that would trigger it.
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      R() = op1 << op2; break;
    case OP_SHL | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      push(op1 << op2); break;
    case OP_SHR:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      R() = op1 >> op2; break;
    case OP_SHR | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      push(op1 >> op2); break;
    case OP_SAR:
      // Arithmetic shift right — preserves the sign bit. C++20 guarantees
      // signed `>>` is arithmetic (P0907R4); same UB rule for op2 >= 64
      // applies as in SHR/SHL.
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      R() = static_cast<uint64_t>(static_cast<int64_t>(op1) >>
                                  static_cast<int>(op2)); break;
    case OP_SAR | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop();
      if (op2 >= 64) { term_ = CESVM_SEGFAULT; break; }
      push(static_cast<uint64_t>(static_cast<int64_t>(op1) >>
                                 static_cast<int>(op2))); break;
    case OP_INC:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); ++get(op1); break;
    case OP_DEC:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); --get(op1); break;
    case OP_PUSH:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); push(op1); break;
    case OP_POP:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); get(op1) = pop(); break;
    case OP_AND:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 & op2; break;
    case OP_AND | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 & op2); break;
    case OP_HOST:
      if (!bill(CESVM_COST_PER_OP)) break;
      hostCall(host);
      break;
    case OP_HOSTX:
      if (!bill(CESVM_COST_PER_OP)) break;
      hostCall(host);
      if (!term_ && S() != 0) term_ = CESVM_ABORT;
      break;
    case OP_ABORT:
      if (!bill(CESVM_COST_PER_OP)) break;
      term_ = CESVM_ABORT;
      break;
    case OP_VPUSH:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read();
      ++get(op1); get(get(op1)) = op2;
      break;
    case OP_VPOP:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read();
      get(op2) = get(op1); --get(op1);
      break;
    case OP_CALL: {
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(true);
      // Hard cap on call depth to close a stack-recursion DoS vector
      // analogous to the data-stack cap in push(). 256 frames is plenty
      // for any realistic program; deeper recursion almost always
      // indicates a bug.
      if (context_.size() >= CESVM_MAX_CALL_DEPTH) {
        term_ = CESVM_SEGFAULT;
        break;
      }
      std::array<uint64_t, CESVM_REG_SIZE> regs;
      std::memcpy(regs.data(), &io_[0], sizeof(uint64_t) * CESVM_REG_SIZE);
      context_.push_back(regs);
      PC() = op1;
      break;
    }
    case OP_CALL | STACK: {
      // Stack form: target popped from the data stack instead of read
      // inline. Equivalent to OP_CALLR for a runtime-computed target,
      // but consumes the value off the stack rather than dereferencing
      // a cell. Same call-depth cap as OP_CALL.
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = pop();
      if (context_.size() >= CESVM_MAX_CALL_DEPTH) {
        term_ = CESVM_SEGFAULT;
        break;
      }
      std::array<uint64_t, CESVM_REG_SIZE> regs;
      std::memcpy(regs.data(), &io_[0], sizeof(uint64_t) * CESVM_REG_SIZE);
      context_.push_back(regs);
      PC() = op1;
      break;
    }
    case OP_JMPR:
      // Indirect JMP: target comes from a regular operand, so it can
      // be dereferenced through a cell (e.g. R after SYS_LOAD_CODE
      // wrote the loaded block's offset there).
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read();
      PC() = op1;
      break;
    case OP_CALLR: {
      // Indirect CALL: same shape as OP_CALL but the target is a
      // runtime value. See OP_JMPR.
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read();
      if (context_.size() >= CESVM_MAX_CALL_DEPTH) {
        term_ = CESVM_SEGFAULT;
        break;
      }
      std::array<uint64_t, CESVM_REG_SIZE> regs;
      std::memcpy(regs.data(), &io_[0], sizeof(uint64_t) * CESVM_REG_SIZE);
      context_.push_back(regs);
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
      if (!bill(CESVM_COST_PER_OP)) break;
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
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read();
      if (context_.empty()) { term_ = CESVM_RET; break; }
      std::memcpy(&io_[0], context_.back().data(),
                  sizeof(uint64_t) * CESVM_REG_SIZE);
      context_.pop_back();
      R() = op1;
      break;
    }
    case OP_JF:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read();
      if (!op1) { PC() = read(true); }
      else { PC() += 2; }
      break;
    case OP_JF | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = pop();
      if (!op1) { PC() = read(true); }
      else { PC() += 2; }
      break;
    case OP_JT:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read();
      if (op1) { PC() = read(true); }
      else { PC() += 2; }
      break;
    case OP_JT | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = pop();
      if (op1) { PC() = read(true); }
      else { PC() += 2; }
      break;
    case OP_EQ:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 == op2; break;
    case OP_EQ | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 == op2); break;
    case OP_NE:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 != op2; break;
    case OP_NE | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 != op2); break;
    case OP_GT:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 > op2; break;
    case OP_GT | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 > op2); break;
    case OP_LT:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 < op2; break;
    case OP_LT | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 < op2); break;
    case OP_GE:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 >= op2; break;
    case OP_GE | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 >= op2); break;
    case OP_LE:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 <= op2; break;
    case OP_LE | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 <= op2); break;
    case OP_NEG:
      // Arithmetic two's-complement negate. Wraps at 0 (NEG of 0 is 0;
      // NEG of INT64_MIN is itself — that's the well-known x86 quirk
      // and we replicate it: -x = 0 - x mod 2^64).
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read();
      R() = static_cast<uint64_t>(0) - op1;
      break;
    case OP_NEG | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = pop();
      push(static_cast<uint64_t>(0) - op1);
      break;
    case OP_ORL:
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = read(); op2 = read(); R() = op1 || op2; break;
    case OP_ORL | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      op2 = pop(); op1 = pop(); push(op1 || op2); break;
    case OP_RND:
      if (!bill(CESVM_COST_PER_OP)) break;
      R() = rng_();
      break;
    case OP_RND | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      push(rng_());
      break;
    case OP_TIME:
      if (!bill(CESVM_COST_PER_OP)) break;
      R() = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count());
      break;
    case OP_TIME | STACK:
      if (!bill(CESVM_COST_PER_OP)) break;
      push(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count()));
      break;
    case OP_MOV: {
      if (!bill(CESVM_COST_PER_OP)) break;
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
      if (!bill(CESVM_COST_PER_OP)) break;
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
      if (!bill(CESVM_COST_PER_OP)) break;
      op1 = pop();
      auto* base = reinterpret_cast<uint8_t*>(io_);
      if (op1 >= CESVM_IO_SIZE * sizeof(uint64_t)) {
        term_ = CESVM_SEGFAULT; break;
      }
      push(base[op1]);
      break;
    }
    case OP_STB: {
      if (!bill(CESVM_COST_PER_OP)) break;
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
      if (!bill(CESVM_COST_PER_OP)) break;
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
      if (!bill(CESVM_COST_PER_OP)) break;
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
      if (!bill(CESVM_COST_PER_OP)) break;
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

    if (term_) break;
  }

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
    // below would scribble past `val` on the stack.
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

uint64_t& CesVM::get(uint64_t index) {
  if (index < CESVM_IO_SIZE) {
    return io_[index];
  }
  term_ = CESVM_SEGFAULT;
  return R();
}

void CesVM::push(uint64_t v) {
  // Hard cap on the data stack to close the "push in a tight loop and
  // burn server memory faster than the gas budget can stop it" DoS
  // vector. Overflow is promoted to CESVM_SEGFAULT, which the server's
  // undo log rolls back the same as any other VM crash.
  if (stack_.size() >= CESVM_MAX_STACK_DEPTH) {
    term_ = CESVM_SEGFAULT;
    return;
  }
  stack_.push_back(v);
}

uint64_t CesVM::pop() {
  if (stack_.empty()) {
    term_ = CESVM_UNDERFLOW;
    return 0;
  }
  uint64_t v = stack_.back();
  stack_.pop_back();
  return v;
}

bool CesVM::bill(uint64_t cost) {
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
    // The day field caps at 0x1FFF, and VmHost::fundAsset clamps the grant
    // to it — so bill only for the days actually granted, not the full
    // request (mirrors the wire fundAsset fix; otherwise funding a near-cap
    // asset overcharges for days it never receives).
    uint32_t granted = std::min<uint32_t>(0x1FFF, held + days) - held;
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

  default:
    term_ = CESVM_SYSCALL;
  }

  // Mirror remaining allowance back into io memory so VM programs can read
  // their per-run spending headroom (and branch on it) the same way they
  // read the initial budget from io[CESVM_IO_BUDGET].
  io_[CESVM_IO_ALLOWANCE] = host.allowance;
}

} // namespace ces
