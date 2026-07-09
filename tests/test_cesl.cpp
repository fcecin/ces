/**
 * test_cesl.cpp — tests for the cesl compiler (include/ces/lang/cesl.h):
 * expressions (checked vs wrapping), control flow, short-circuit logic,
 * functions and the recursion ban, regions, const folding, builtins,
 * and syscall dispatch.
 */

#include <boost/test/unit_test.hpp>

#include <ces/cesvm.h>
#include <ces/lang/cesl.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

using namespace ces;

namespace {

struct RunResult {
  uint64_t error;
  ces::Bytes output;

  uint64_t outU64() const {
    uint64_t v = 0;
    for (size_t i = 0; i < 8 && i < output.size(); ++i)
      v |= static_cast<uint64_t>(output[i]) << (8 * i);
    return v;
  }
};

RunResult runSrc(const std::string& src, CesVMHost& host) {
  CesVM vm;
  auto code = ceslCompile(src);
  auto r = vm.execute(code, host, 10'000'000);
  return {r.error, r.output};
}

RunResult runSrc(const std::string& src) {
  CesVMHost host;
  return runSrc(src, host);
}

} // namespace

BOOST_AUTO_TEST_SUITE(CeslTests)

BOOST_AUTO_TEST_CASE(ArithmeticAndPrecedence) {
  auto r = runSrc("return 2 + 3 * 4;");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 14u);

  auto p = runSrc("return (2 + 3) * 4 - 1;");
  BOOST_CHECK_EQUAL(p.outU64(), 19u);

  auto b = runSrc("return (5 > 3) + (2 == 2) + (7 & 3) + (1 << 4);");
  BOOST_CHECK_EQUAL(b.outU64(), 1u + 1u + 3u + 16u);
}

BOOST_AUTO_TEST_CASE(CheckedVersusWrapping) {
  auto wrap = runSrc("let a = 0 -% 1; return a +% 1;");
  BOOST_CHECK_EQUAL(wrap.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(wrap.outU64(), 0u);

  auto over = runSrc("let a = 0 -% 1; return a + 1;");
  BOOST_CHECK_EQUAL(over.error, static_cast<uint64_t>(CESVM_OVERFLOW));

  auto under = runSrc("return 3 - 5;");
  BOOST_CHECK_EQUAL(under.error, static_cast<uint64_t>(CESVM_OVERFLOW));
}

BOOST_AUTO_TEST_CASE(WhileLoopAndBreakContinue) {
  auto r = runSrc(R"(
    let i = 0;
    let sum = 0;
    while (i < 10) {
      i = i + 1;
      sum = sum + i;
    }
    return sum;
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 55u);

  auto bc = runSrc(R"(
    let i = 0;
    let odd_sum = 0;
    while (1) {
      i = i + 1;
      if (i > 9) { break; }
      if ((i & 1) == 0) { continue; }
      odd_sum = odd_sum + i;
    }
    return odd_sum;
  )");
  BOOST_CHECK_EQUAL(bc.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(bc.outU64(), 25u);  // 1+3+5+7+9
}

BOOST_AUTO_TEST_CASE(FunctionsAndElseIfChain) {
  auto r = runSrc(R"(
    fn classify(x) {
      if (x < 10) { return 1; }
      else if (x < 100) { return 2; }
      else { return 3; }
    }
    fn add3(a, b, c) { return a + b + c; }
    return classify(50) * 100 + add3(add3(1, 1, 1), 2, 0);
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 205u);
}

BOOST_AUTO_TEST_CASE(ShortCircuitSkipsSideEffects) {
  auto r = runSrc(R"(
    let g = 0;
    fn bump() { g = g + 1; return 1; }
    let x = 0 && bump();
    let y = 1 || bump();
    let z = 1 && bump();
    return g * 100 + x * 10 + y + z;
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  // bump ran exactly once (the && with a truthy lhs); x=0, y=1, z=1.
  BOOST_CHECK_EQUAL(r.outU64(), 102u);
}

BOOST_AUTO_TEST_CASE(RecursionIsRejected) {
  BOOST_CHECK_THROW(ceslCompile("fn f() { return f(); } return f();"),
                    CeslError);
  BOOST_CHECK_THROW(
    ceslCompile("fn f() { return g(); } fn g() { return f(); } return f();"),
    CeslError);
}

BOOST_AUTO_TEST_CASE(RequireAndAbort) {
  auto ok = runSrc("require(1 < 2); return 5;");
  BOOST_CHECK_EQUAL(ok.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(ok.outU64(), 5u);

  auto bad = runSrc("require(2 < 1); return 5;");
  BOOST_CHECK_EQUAL(bad.error, static_cast<uint64_t>(CESVM_ABORT));

  auto ab = runSrc("abort();");
  BOOST_CHECK_EQUAL(ab.error, static_cast<uint64_t>(CESVM_ABORT));
}

BOOST_AUTO_TEST_CASE(RegionsStaticAndDynamicIndex) {
  auto r = runSrc(R"(
    let arr[4];
    arr[0] = 7;
    let i = 3;
    arr[i] = 9;
    let j = 0;
    return arr[j] + arr[3];
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 16u);

  BOOST_CHECK_THROW(ceslCompile("let a[2]; a[2] = 1;"), CeslError);
}

BOOST_AUTO_TEST_CASE(ConstFolding) {
  auto r = runSrc(R"(
    const HALF = PRICE_UNIT / 2;
    const K = 2 * HALF;
    return K / PRICE_UNIT;
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 1u);

  BOOST_CHECK_THROW(ceslCompile("const X = 1 - 2;"), CeslError);
  BOOST_CHECK_THROW(ceslCompile("let v = 1; const X = v + 1;"), CeslError);
  // Runtime shifts >= 64 fault the VM; the fold must reject, not yield 0.
  BOOST_CHECK_THROW(ceslCompile("const X = 1 << 64;"), CeslError);
}

BOOST_AUTO_TEST_CASE(MemoryBuiltins) {
  auto r = runSrc(R"(
    let buf[4];
    copy(buf, caller_key, 4);
    let same = memcmp(buf, caller_key, 4);
    fill(buf, 3, 4);
    let p = peek(buf);
    let z[1];
    setb(z * 8, 65);
    let byte = getb(z * 8);
    return same * 1000 + p * 100 + byte;
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 1000u + 300u + 65u);
}

BOOST_AUTO_TEST_CASE(SignedBuiltins) {
  auto r = runSrc("return slt(0 -% 5, 3) * 10 + sgt(3, 0 -% 5);");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 11u);
}

BOOST_AUTO_TEST_CASE(SyscallBuiltins) {
  struct H : CesVMHost {
    uint64_t deposited = 0;
    uint8_t rc = CES_OK;
    uint8_t deposit(uint64_t amt) override {
      deposited += amt;
      return rc;
    }
  };

  H ok;
  auto r = runSrc("deposit(5); deposit(7); return 1;", ok);
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(ok.deposited, 12u);

  // try_ variant yields S without aborting.
  H soft;
  soft.rc = 7;
  auto t = runSrc("return try_deposit(5);", soft);
  BOOST_CHECK_EQUAL(t.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(t.outU64(), 7u);

  // non-try variant aborts on a failing syscall.
  H hard;
  hard.rc = 7;
  auto a = runSrc("deposit(5); return 1;", hard);
  BOOST_CHECK_EQUAL(a.error, static_cast<uint64_t>(CESVM_ABORT));
}

BOOST_AUTO_TEST_CASE(PredeclaredContext) {
  CesVMHost host;
  host.input = {1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0};
  CesVM vm;
  auto code = ceslCompile("return input_len * 100 + input[0] + input[1];");
  auto r = vm.execute(code, host, 1'000'000);
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  uint64_t v = 0;
  for (size_t i = 0; i < 8; ++i)
    v |= static_cast<uint64_t>(r.output[i]) << (8 * i);
  BOOST_CHECK_EQUAL(v, 1600u + 1u + 9u);
}

// The compiler's temp cells are one shared runtime pool across all
// call frames. An operand landed in a temp before a later argument (or
// RHS) runs would be clobbered when that expression calls a function
// whose body uses temps itself. Pins the stack-until-consumed emission
// for dynamic-index assignment, poke, and multi-operand builtins.
BOOST_AUTO_TEST_CASE(TempsSurviveCalleeFrames) {
  // clobber() performs a dynamic region store, which uses the first
  // two temp cells inside the callee frame.
  const std::string clobberFn =
    "fn clobber(ret) { let a[2]; let i = 0; a[i] = 77; return ret; }\n";

  auto dyn = runSrc(clobberFn +
    "let arr[4]; let j = 1;\n"
    "arr[j] = clobber(5);\n"
    "return arr[1];\n");
  BOOST_CHECK_EQUAL(dyn.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(dyn.outU64(), 5u);

  auto pk = runSrc(clobberFn +
    "let arr[4];\n"
    "poke(arr + 2, clobber(5));\n"
    "return arr[2];\n");
  BOOST_CHECK_EQUAL(pk.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(pk.outU64(), 5u);

  // Both region operands are non-trivial (base + 0), so they are
  // materialized in temps; the count argument's call must not corrupt
  // them (clobber's a[] holds 77,0 while arr/arr2 hold 9,9).
  auto mc = runSrc(clobberFn +
    "let arr[2]; let arr2[2];\n"
    "fill(arr, 9, 2); fill(arr2, 9, 2);\n"
    "return memcmp(arr + 0, arr2 + 0, clobber(2));\n");
  BOOST_CHECK_EQUAL(mc.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(mc.outU64(), 1u);
}

// Arguments are evaluated left to right at their textual position: a
// variable argument is read before later arguments run, so a later
// argument's function call mutating that variable does not affect the
// value already captured.
BOOST_AUTO_TEST_CASE(ArgumentsReadAtTheirPosition) {
  struct H : CesVMHost {
    uint64_t lastBudget = 0;
    uint64_t lastDeposit = 0;
    uint8_t schedule(const minx::Hash&, uint64_t budget, uint64_t,
                     const uint8_t*, size_t, uint64_t) override {
      lastBudget = budget;
      return CES_OK;
    }
    uint8_t deposit(uint64_t amt) override {
      lastDeposit = amt;
      return CES_OK;
    }
  } host;

  // schedule(key, budget, ...): budget is a variable that a later
  // argument's call mutates; the host must see the value from before
  // the call (left-to-right evaluation at textual position).
  auto r = runSrc(
    "let x = 5;\n"
    "fn bump() { x = 99; return 0; }\n"
    "let key[4];\n"
    "schedule(key, x, 0, 0, 0, bump());\n"
    "return x;\n",
    host);
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 99u);      // bump ran
  BOOST_CHECK_EQUAL(host.lastBudget, 5u);  // pre-bump value captured

  H h2;
  auto v = runSrc("let x = 5;\ndeposit(x);\nreturn 1;\n", h2);
  BOOST_CHECK_EQUAL(v.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(h2.lastDeposit, 5u);
}

BOOST_AUTO_TEST_CASE(CompileErrors) {
  BOOST_CHECK_THROW(ceslCompile("return x;"), CeslError);           // unknown
  BOOST_CHECK_THROW(ceslCompile("break;"), CeslError);              // no loop
  BOOST_CHECK_THROW(ceslCompile("input_len = 1;"), CeslError);      // read-only
  BOOST_CHECK_THROW(ceslCompile("let transfer = 1;"), CeslError);   // reserved
  BOOST_CHECK_THROW(ceslCompile("let a = 1; let a = 2;"), CeslError);
  BOOST_CHECK_THROW(ceslCompile("fn f(a) {} return f();"), CeslError);
  BOOST_CHECK_THROW(ceslCompile("if (1) { fn g() {} }"), CeslError);
}

// Every syscall in the table compiles at its declared arity (catches a wrong
// SYS_num / argc typo), and wrong arity is rejected. Compile-only: no host.
BOOST_AUTO_TEST_CASE(AllSyscallsCompile) {
  const char* calls[] = {
      "read_account(0)", "transfer(0,0)", "read_asset(0,0,0)",
      "create_asset_random(0,0,0)", "update_asset(0,0)", "fund_asset(0,0)",
      "buy_asset(0,0)", "give_asset(0,0)", "hash(0,0,0)", "verify_sig(0,0,0,0)",
      "cross_transfer(0,0,0)", "load_code(0)", "create_asset(0,0,0)",
      "send_client(0,0,0)", "schedule(0,0,0,0,0,0)", "create_asset_managed(0,0,0)",
      "rpc(0,0,0,0,0,0,0)", "owner_transfer(0,0)", "deposit(0)", "withdraw(0)",
      "update_asset_meta(0,0,0)", "refill(0)",
  };
  for (const char* c : calls) {
    std::string src = std::string(c) + "; return 0;";
    BOOST_CHECK_NO_THROW(ceslCompile(src));               // plain form
    BOOST_CHECK_NO_THROW(ceslCompile("try_" + src));      // try_ form
  }
  // Wrong arity is a compile error.
  BOOST_CHECK_THROW(ceslCompile("refill(0,0); return 0;"), CeslError);
  BOOST_CHECK_THROW(ceslCompile("transfer(0); return 0;"), CeslError);
}

// The refill syscall grows the run's gas budget and yields the granted amount.
BOOST_AUTO_TEST_CASE(RefillSyscallGrantsBudget) {
  struct RefillHost : CesVMHost {
    uint64_t refillGas(uint64_t requested) override { return requested / 2; }
  } host;
  // The host halves the request; the plain form yields R = the granted amount.
  auto r = runSrc("return refill(1000);", host);
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 500u);
}

// A cesl gate reads its invocation kind and event descriptor: accept only an
// inbound transfer of at least 50, reading the amount from input[4].
BOOST_AUTO_TEST_CASE(HookInvocationContext) {
  CesVMHost host;
  host.invokeKind = INVOKE_HOOK_XFER_IN;
  host.input.assign(48, 0);
  host.input[32] = 100;   // amount = input[4] = 100 (LE byte 0 of the cell)

  auto accept = runSrc(
      "require(invoke_kind == INVOKE_XFER_IN);\n"
      "require(input[4] >= 50);\n"
      "return input[4];\n", host);
  BOOST_CHECK_EQUAL(accept.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(accept.outU64(), 100u);

  // Wrong kind rejects (require aborts).
  host.invokeKind = INVOKE_HOOK_XFER_OUT;
  auto reject = runSrc("require(invoke_kind == INVOKE_XFER_IN); return 1;", host);
  BOOST_CHECK_EQUAL(reject.error, static_cast<uint64_t>(CESVM_ABORT));
}

// Every shipped lang/examples/*.cesl compiles - pins the demos (incl. the hook
// examples) against language drift. Add a line here when you add an example.
BOOST_AUTO_TEST_CASE(ShippedExamplesCompile) {
  const std::string dir = std::string(CES_SOURCE_DIR) + "/lang/examples/";
  const char* files[] = {
      "add.cesl", "fib.cesl", "vault.cesl", "cruncher.cesl",
      "hook_gate.cesl", "hook_watch.cesl",
  };
  for (const char* f : files) {
    std::ifstream in(dir + f);
    std::stringstream ss;
    ss << in.rdbuf();
    std::string src = ss.str();
    BOOST_REQUIRE_MESSAGE(!src.empty(), std::string("missing example: ") + f);
    try {
      ceslCompile(src);
    } catch (const std::exception& e) {
      BOOST_ERROR(std::string(f) + " failed to compile: " + e.what());
    }
  }
}

BOOST_AUTO_TEST_SUITE_END()
