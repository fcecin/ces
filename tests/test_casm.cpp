/**
 * test_casm.cpp — tests for the casm textual assembler
 * (include/ces/lang/casm.h): operand forms, labels, directives, stack
 * suffix, syscall dispatch by name, and error reporting.
 */

#include <boost/test/unit_test.hpp>

#include <ces/cesvm.h>
#include <ces/lang/casm.h>

#include <cstdint>
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
  auto code = casmAssemble(src);
  auto r = vm.execute(code, host, 1'000'000);
  return {r.error, r.output};
}

RunResult runSrc(const std::string& src) {
  CesVMHost host;
  return runSrc(src, host);
}

} // namespace

BOOST_AUTO_TEST_SUITE(CasmTests)

BOOST_AUTO_TEST_CASE(OutputAndComments) {
  auto r = runSrc(R"(
    ; write 42 to the program output
    set output_len, 8   # trailing comment
    set output, 42
    term
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 42u);
}

BOOST_AUTO_TEST_CASE(LabelsAndLoop) {
  // sum 5+4+3+2+1 via a jt-terminated countdown
  auto r = runSrc(R"(
    set g0, 5
    set g1, 0
loop:
    add [g1], [g0]
    set g1, [r]
    dec g0
    jt [g0], loop
    set output_len, 8
    set output, [g1]
    term
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 15u);
}

BOOST_AUTO_TEST_CASE(DirectivesAllocEquString) {
  auto r = runSrc(R"(
    .alloc buf 2
    .equ answer 40+2
    .string buf, "hi"
    set output_len, 2
    mov output, buf, 1
    set g0, answer
    term
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(r.output.size(), 2u);
  BOOST_CHECK_EQUAL(r.output[0], 'h');
  BOOST_CHECK_EQUAL(r.output[1], 'i');
}

BOOST_AUTO_TEST_CASE(StackSuffixForms) {
  auto r = runSrc(R"(
    push 7
    dup
    add.s
    pop g2
    set output_len, 8
    set output, [g2]
    term
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 14u);
}

BOOST_AUTO_TEST_CASE(StackConditionalJump) {
  auto r = runSrc(R"(
    push 0
    jf.s skip
    abort
skip:
    set output_len, 8
    set output, 9
    term
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 9u);
}

BOOST_AUTO_TEST_CASE(CheckedAndSignedMnemonics) {
  auto over = runSrc("addx -1, 1\nterm\n");
  BOOST_CHECK_EQUAL(over.error, static_cast<uint64_t>(CESVM_OVERFLOW));

  auto r = runSrc(R"(
    slt -5, 3
    set output_len, 8
    set output, [r]
    term
  )");
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(r.outU64(), 1u);
}

BOOST_AUTO_TEST_CASE(RequireMnemonic) {
  auto ok = runSrc("require 1\nterm\n");
  BOOST_CHECK_EQUAL(ok.error, static_cast<uint64_t>(CESVM_OK));
  auto bad = runSrc("require 0\nterm\n");
  BOOST_CHECK_EQUAL(bad.error, static_cast<uint64_t>(CESVM_ABORT));
}

BOOST_AUTO_TEST_CASE(SyscallByName) {
  struct H : CesVMHost {
    uint64_t deposited = 0;
    uint8_t deposit(uint64_t amt) override {
      deposited += amt;
      return CES_OK;
    }
  } host;
  auto r = runSrc("hostxv DEPOSIT, 100\nterm\n", host);
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(host.deposited, 100u);
}

BOOST_AUTO_TEST_CASE(ErrorsCarryLineNumbers) {
  BOOST_CHECK_THROW(casmAssemble("nop\nfrobnicate 1\n"), CasmError);
  try {
    casmAssemble("nop\nfrobnicate 1\n");
  } catch (const CasmError& e) {
    BOOST_CHECK(std::string(e.what()).find("line 2") != std::string::npos);
  }
  // referenced but undefined label
  BOOST_CHECK_THROW(casmAssemble("jmp nowhere\nterm\n"), CasmError);
  // wrong operand count
  BOOST_CHECK_THROW(casmAssemble("set 1\n"), CasmError);
  // stack form with operands
  BOOST_CHECK_THROW(casmAssemble("add.s 1, 2\n"), CasmError);
  // unknown symbol
  BOOST_CHECK_THROW(casmAssemble("set g0, bogus\n"), CasmError);
  // duplicate label
  BOOST_CHECK_THROW(casmAssemble("a:\na:\nterm\n"), CasmError);
}

BOOST_AUTO_TEST_SUITE_END()
