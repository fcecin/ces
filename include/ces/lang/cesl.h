#pragma once

/**
 * cesl.h — compiler for cesl, the CesVM transaction-script language.
 *
 * cesl is a small, single-type (u64) imperative language that compiles
 * to CesVM bytecode through the VmProgram builder. It targets the
 * machine honestly: variables are statically allocated io cells,
 * functions are non-reentrant (recursion is a compile error), and
 * arithmetic is checked by default (a wrap halts the VM with
 * CESVM_OVERFLOW; wrapping operators exist for intentional mod-2^64
 * math). Expressions are evaluated on the VM data stack via the
 * stack-mode opcodes.
 *
 * Program shape: top-level statements are the program (run from PC 0,
 * implicit final `term`); `fn` definitions may appear anywhere at top
 * level and are emitted after it.
 *
 *   const FEE = 2 * PRICE_UNIT;     // compile-time constant (folded)
 *   let counter = 0;                // global cell
 *   let key[4];                     // 4-cell region (32 bytes)
 *
 *   fn clamp(v, hi) {
 *     if (v > hi) { return hi; }
 *     return v;
 *   }
 *
 *   copy(key, caller_key, 4);
 *   require(deposit(FEE) == 0);
 *   return clamp(input_len, 64);    // top level: writes output, terms
 *
 * Statements: let, assignment (`x = e;`, `region[i] = e;`), if/else,
 * while, break, continue, return, require(e), abort(), expression
 * statements, and the memory builtins poke(addr, v), setb(byteoff, v),
 * copy(dst, src, n), fill(dst, v, n), emit_string(region, "text").
 *
 * Expressions: u64 literals (decimal, 0x hex), variables, region names
 * (the value is the region's first cell index), region[i], function
 * calls, and operators by C precedence:
 *   unary        ! ~ -
 *   multiplicative * / % *%
 *   additive     + - +% -%
 *   shift        << >>
 *   relational   < > <= >=          (unsigned)
 *   equality     == !=
 *   bitwise      & ^ |
 *   logical      && ||              (short-circuit, yield 0/1)
 * `+ - *` are checked; `+% -% *%` wrap. Signed helpers are builtins:
 * slt/sgt/sge/sle(a, b) and sar(a, b).
 *
 * Value builtins: peek(addr), getb(byteoff), memcmp(a, b, n),
 * random(), now().
 *
 * Syscall builtins mirror the CesVM syscall ABI (cesvm.h) one to one;
 * pointer-typed parameters take a region (or any expression yielding a
 * cell index). Each dispatches via hostxv (failure aborts the program)
 * and yields the syscall's R value:
 *   read_account(pfx) transfer(dest, amt) deposit(amt) withdraw(amt)
 *   owner_transfer(dest, amt) read_asset(key, owner_out, content_out)
 *   create_asset(key, content, days) create_asset_random(content, days,
 *   key_out) create_asset_range(count, days, key_out)
 *   create_asset_managed(key, content, days)
 *   update_asset(key, content) update_asset_meta(key, owner, price)
 *   fund_asset(key, days) buy_asset(key, max_price)
 *   give_asset(key, owner) hash(ptr, len, out)
 *   verify_sig(ptr, len, sig, pubkey) cross_transfer(dest, amt, server)
 *   load_code(key) send_client(id, ptr, len)
 *   schedule(key, budget, allowance, in_ptr, in_len, time_us)
 *   rpc(host, hostlen, port, filehead, followup, budget, tag)
 * Each also has a try_ variant (try_transfer, ...) that dispatches via
 * hostv and yields S (the CES error code) instead of aborting.
 *
 * Predeclared names:
 *   regions   input[128] output[128] caller_key[4] self_key[4]
 *   read-only r s arg0 arg1 arg2 arg3 input_len budget_start
 *             start_time allowance_left gas_left
 *   writable  output_len
 *   const     PRICE_UNIT
 */

#include <ces/buffer.h>

#include <stdexcept>
#include <string>
#include <string_view>

namespace ces {

// Errors carry "line N: <what>" messages.
class CeslError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

// Compile cesl source into CesVM bytecode. Throws CeslError on any
// lexical, syntactic, or semantic error (including recursion and
// constant-expression overflow). The result is the flexible byte-vector
// shape (VmProgram::buildBytes); boot-block deployment enforces the
// 210-byte limit at the call site. codeBase relocates all label targets
// for code that runs at a nonzero address (a bundle body entered at
// 210; see lang/bundle.h); the byte length is identical for any base.
ces::Bytes ceslCompile(std::string_view source, uint64_t codeBase = 0);

} // namespace ces
