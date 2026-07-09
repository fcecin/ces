#pragma once

/**
 * casm.h — textual assembler for CesVM bytecode.
 *
 * Maps 1:1 onto the CesVM ISA via the VmProgram builder: every mnemonic
 * is one opcode, every operand is one Imm/Ref control-byte operand.
 * Input is line-oriented text; output is deployable bytecode.
 *
 * Line shape (one instruction, label, or directive per line):
 *
 *   ; comment                     # comment
 *   name:                         label definition (targets jmp/call/jf/jt)
 *   .equ NAME value               named constant
 *   .alloc NAME count             allocate `count` scratch cells (bump
 *                                 allocator, cells 16..751); NAME = first cell
 *   .at NAME cell                 bind NAME to a fixed cell index
 *   .string NAME "text"           emit SETs packing the bytes into cells
 *                                 at NAME (little-endian, 8 per cell)
 *
 * Operands:
 *
 *   42, 0x2A, -5                  immediate value (Imm); -5 wraps to u64
 *   name, name+3                  symbol (register alias, .equ/.alloc/.at),
 *                                 optionally displaced by a constant
 *   [x]                           dereference (Ref): the operand value is
 *                                 read from cell x at runtime; x is any of
 *                                 the immediate forms above
 *
 * Register aliases (cells 0..15): pc r s sys a0 a1 a2 a3 g0..g7.
 * Protocol cells: input_len output_len budget start_time caller_key
 * self_key output input allowance gas_left.
 *
 * Mnemonics are the CesVMOpcode names in lowercase (set, add, mov, jf,
 * hostxv, require, dup, ...). A `.s` suffix emits the stack-mode variant
 * (operands popped from the data stack): add.s, slt.s, assert.s, jf.s,
 * jt.s, call.s. `hostv NAME, args...` / `hostxv NAME, args...` dispatch a
 * syscall by enum name (TRANSFER, READ_ACCOUNT, ...) or number.
 *
 * Example:
 *
 *   .alloc dest 4
 *       mov dest, caller_key, 4     ; dest = caller pubkey
 *       hostxv TRANSFER, dest, 100  ; send 100 credits back to caller
 *       set output_len, 8
 *       set output, [r]
 *       term
 */

#include <ces/buffer.h>

#include <stdexcept>
#include <string>
#include <string_view>

namespace ces {

// Errors carry "line N: <what>" messages.
class CasmError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

// Assemble CesVM assembly text into bytecode. Throws CasmError on any
// lexical, syntactic, or semantic error. The result is the flexible
// byte-vector shape (VmProgram::buildBytes); callers deploying a boot
// block enforce the 210-byte limit themselves. codeBase relocates all
// label targets for code that runs at a nonzero address (a bundle body
// entered at 210; see lang/bundle.h); the byte length is identical for
// any base.
ces::Bytes casmAssemble(std::string_view source, uint64_t codeBase = 0);

} // namespace ces
