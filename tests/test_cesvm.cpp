/**
 * Unit tests for the CesVM (server-side bytecode VM).
 */

#include "test_common.h"
#include <ces/autoexec.h>
#include <ces/buffer.h>
#include <ces/cesvm.h>
#include <ces/util/vmprogram.h>
#include <cryptopp/sha.h>
#include <future>
#include <ces/util/ctrlc.h>
#include <ces/protocol.h>

using namespace ces;

// Opcodes, STACK, SHORT_VAL, and REG_PTR constants live in cesvm.h
// now — this file used to duplicate them and drifted once already.
// Local `sv`/`rp` helpers stay because the bytecode-comparison tests
// read more naturally with them.
static uint8_t sv(uint8_t val) {
  return static_cast<uint8_t>(CESVM_SHORT_VAL | (val & CESVM_MAX_SHORT_VAL));
}
static uint8_t rp(uint8_t val) {
  return static_cast<uint8_t>(CESVM_REG_PTR | CESVM_SHORT_VAL |
                               (val & CESVM_MAX_SHORT_VAL));
}
static constexpr uint8_t STACK = CESVM_OP_STACK;

// Helper: encode a 2-byte little-endian VM operand.
static void push2(ces::Bytes& code, uint16_t val) {
  code.push_back(2); // control: 2 bytes follow
  ces::Buffer::putLE<uint16_t>(code, val);
}

// Helper: encode an 8-byte little-endian VM operand.
static void push8(ces::Bytes& code, uint64_t val) {
  code.push_back(8); // control: 8 bytes follow
  ces::Buffer::putLE<uint64_t>(code, val);
}

// Minimal host that does nothing — reads return zero/false, writes succeed.
// Subclass of CesVMHost so calls go through the vtable just like the
// production CesServer::VmHost.
struct NullVmHost : CesVMHost {
  int64_t  readAccountBalance(const HashPrefix&) override { return 0; }
  uint32_t readAccountNonce  (const HashPrefix&) override { return 0; }
  bool     readAsset(const minx::Hash&, HashPrefix&, AssetData&,
                     uint16_t&, uint32_t&) override { return false; }
  uint8_t  transfer    (const minx::Hash&, uint64_t)              override { return CES_OK; }
  uint8_t  createAsset (const minx::Hash&, const AssetData&, uint16_t) override { return CES_OK; }
  uint8_t  updateAsset (const minx::Hash&, const AssetData&)      override { return CES_OK; }
  uint8_t  fundAsset   (const minx::Hash&, uint16_t)              override { return CES_OK; }
  uint8_t  buyAsset    (const minx::Hash&, uint64_t)              override { return CES_OK; }
  uint8_t  giveAsset   (const minx::Hash&, const HashPrefix&)     override { return CES_OK; }
  void     sendUdp     (const std::string&, uint16_t, const uint8_t*, size_t) override {}
  uint8_t  crossTransfer(const minx::Hash&, uint64_t, const std::string&)     override { return CES_OK; }
  bool     sendClient  (const HashPrefix&, const uint8_t*, size_t) override { return false; }
  uint8_t  schedule    (const minx::Hash&, uint64_t, uint64_t,
                        const uint8_t*, size_t, uint64_t) override { return CES_OK; }
  uint8_t  debitCaller (uint64_t) override                                    { return CES_OK; }
  bool     verifySig   (const uint8_t*, size_t, const uint8_t*, const uint8_t*) override { return false; }
};

static NullVmHost makeNullHost() {
  NullVmHost host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  return host;
}

BOOST_AUTO_TEST_SUITE(CesVMTests)

// --- Basic execution ---

BOOST_AUTO_TEST_CASE(EmptyProgram) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code;
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  BOOST_CHECK_EQUAL(result.opsExecuted, 0);
}

BOOST_AUTO_TEST_CASE(TermInstruction) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {OP_TERM};
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  BOOST_CHECK_EQUAL(result.opsExecuted, 1);
}

BOOST_AUTO_TEST_CASE(NopThenTerm) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {OP_NOP, OP_NOP, OP_NOP, OP_TERM};
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  BOOST_CHECK_EQUAL(result.opsExecuted, 4);
}

// --- Arithmetic ---

BOOST_AUTO_TEST_CASE(AddRegisters) {
  CesVM vm;
  auto host = makeNullHost();
  // SET io[8] = 10, SET io[9] = 20, ADD io[8] io[9] → R=30, TERM
  ces::Bytes code = {
    OP_SET, sv(8), sv(10),   // io[8] = 10
    OP_SET, sv(9), sv(20),   // io[9] = 20
    OP_ADD, sv(8), sv(9),    // R = io[8] + io[9] = 30
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(AddStack) {
  CesVM vm;
  auto host = makeNullHost();
  // PUSH 10, PUSH 20, ADD|STACK → stack top = 30
  ces::Bytes code = {
    OP_PUSH, sv(10),
    OP_PUSH, sv(20),
    static_cast<uint8_t>(OP_ADD | STACK),
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(MulStack) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_PUSH, sv(7),
    OP_PUSH, sv(6),
    static_cast<uint8_t>(OP_MUL | STACK),
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  // 7 * 6 = 42 on stack top
}

BOOST_AUTO_TEST_CASE(DivByZero) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_PUSH, sv(10),
    OP_PUSH, sv(0),
    static_cast<uint8_t>(OP_DIV | STACK),
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_DIVZERO);
}

// --- Control flow ---

BOOST_AUTO_TEST_CASE(Jump) {
  CesVM vm;
  auto host = makeNullHost();
  // JMP to address 5, skip the invalid opcode at 3
  ces::Bytes code = {
    OP_JMP, 0x05, 0x00,     // JMP to 5
    0xFF,                     // invalid opcode (should be skipped)
    0xFF,
    OP_TERM                   // address 5
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(ConditionalJumpTrue) {
  CesVM vm;
  auto host = makeNullHost();
  // SET R=1, JT R addr:7 → jumps to TERM at 7
  ces::Bytes code = {
    OP_SET, sv(1), sv(1),     // R = 1
    OP_JT, sv(1), 0x09, 0x00, // JT R, addr=9
    0xFF,                      // skipped
    0xFF,
    OP_TERM                    // address 9
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(ConditionalJumpFalse) {
  CesVM vm;
  auto host = makeNullHost();
  // SET R=0, JT R addr:skip → falls through to TERM
  ces::Bytes code = {
    OP_SET, sv(1), sv(0),     // R = 0
    OP_JT, sv(1), 0xFF, 0x00, // JT R, addr=255 (bad, should not jump)
    OP_TERM                    // falls through here
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- Budget enforcement ---

BOOST_AUTO_TEST_CASE(BudgetExhaustion) {
  CesVM vm;
  auto host = makeNullHost();
  // Infinite loop: JMP 0
  ces::Bytes code = {
    OP_JMP, 0x00, 0x00
  };
  auto result = vm.execute(code, host, 500);
  BOOST_CHECK_EQUAL(result.error, CESVM_BUDGET);
  // 5 JMPs billed at 100 each = 500, 6th can't bill
  BOOST_CHECK_EQUAL(result.budgetUsed, 500);
}

// --- Stack operations ---

BOOST_AUTO_TEST_CASE(StackUnderflow) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    static_cast<uint8_t>(OP_ADD | STACK), // pop from empty stack
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_UNDERFLOW);
}

BOOST_AUTO_TEST_CASE(PushPop) {
  CesVM vm;
  auto host = makeNullHost();
  // PUSH 42, POP into io[8] → io[8] = 42
  ces::Bytes code = {
    OP_PUSH, sv(42),
    OP_POP, sv(8),
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- CALL/RET ---

BOOST_AUTO_TEST_CASE(CallAndReturn) {
  CesVM vm;
  auto host = makeNullHost();
  // CALL addr:5, TERM (return lands here after RET)
  // addr 5: RET 42
  ces::Bytes code = {
    OP_CALL, 0x05, 0x00,    // CALL addr=5
    OP_TERM,                  // return lands here
    0xFF,                     // padding
    OP_RET, sv(42),           // addr 5: RET 42
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- HOST/Syscall ---

BOOST_AUTO_TEST_CASE(SyscallNop) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_NOP),
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// Helper: build code to read io[offset] where offset > 63
// Uses io[9] as temp: SET io[9]=offset, PUSH io[io[9]]
static void pushIoIndirect(ces::Bytes& code, uint16_t offset) {
  code.push_back(OP_SET);
  code.push_back(sv(9));
  push2(code, offset);
  code.push_back(OP_PUSH);
  code.push_back(rp(9));
}

BOOST_AUTO_TEST_CASE(PreloadedInputLen) {
  CesVM vm;
  auto host = makeNullHost();
  host.input = {0x41, 0x42, 0x43};
  ces::Bytes code;
  pushIoIndirect(code, CESVM_IO_INPUT_LEN);
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(PreloadedInputData) {
  CesVM vm;
  auto host = makeNullHost();
  host.input = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
  ces::Bytes code;
  pushIoIndirect(code, CESVM_IO_INPUT);
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(PreloadedBudget) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code;
  pushIoIndirect(code, CESVM_IO_BUDGET);
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 5000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(PreloadedStartTime) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code;
  pushIoIndirect(code, CESVM_IO_START_TIME);
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 5000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(SyscallTransfer) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_TRANSFER),
    OP_SET, sv(4), sv(16),    // dest key at io[16]
    OP_SET, sv(5), sv(42),    // amount = 42
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(SyscallCreateAssetRandom) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_CREATE_ASSET_RANDOM),
    OP_SET, sv(4), sv(64),    // content at io[64]
    OP_SET, sv(5), sv(30),    // 30 days
    OP_SET, sv(6), sv(96),    // write new key to io[96]
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(InvalidSyscall) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_SET, sv(3), sv(99),  // invalid syscall
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SYSCALL);
}

BOOST_AUTO_TEST_CASE(InvalidOpcode) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {0xFF};
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OPCODE);
}

// --- Segfault ---

BOOST_AUTO_TEST_CASE(Segfault) {
  CesVM vm;
  auto host = makeNullHost();
  // SET io[9999] = 1 → out of bounds
  ces::Bytes code;
  code.push_back(OP_SET);
  push2(code, 9999);
  code.push_back(sv(1));
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

// --- Loop with budget ---

BOOST_AUTO_TEST_CASE(LoopCountsDown) {
  CesVM vm;
  auto host = makeNullHost();
  // io[8] = 5, loop: DEC io[8], JT io[8] loop, TERM. After the loop exits,
  // io[8] must be 0 — that's the *reason* the loop exits. opsExecuted==12
  // alone doesn't prove the JT is honouring the counter; a broken jump that
  // misreads the condition could hit 12 ops by a different path and pass.
  // Copy io[8] into output so the assertion can see the final counter value.
  ces::Bytes code = {
    OP_SET, sv(8), sv(5),     // addr 0: io[8] = 5
    OP_DEC, sv(8),            // addr 3: --io[8]
    OP_JT, rp(8), 0x03, 0x00, // addr 5: if io[8] != 0, jump to 3
  };
  code.push_back(OP_MOV);
  push2(code, CESVM_IO_OUTPUT);
  code.push_back(sv(8));
  code.push_back(sv(1));
  code.push_back(OP_SET);
  push2(code, CESVM_IO_OUTPUT_LEN);
  code.push_back(sv(8));
  code.push_back(OP_TERM);

  auto result = vm.execute(code, host, 10000000);
  BOOST_REQUIRE_EQUAL(result.error, CESVM_OK);
  // 1 SET + 5*(DEC+JT) + (MOV + SET + TERM) = 14 ops (was 12 without the
  // output stanza; the counter-cheat guard below is what actually matters).
  BOOST_CHECK_EQUAL(result.opsExecuted, 14);

  BOOST_REQUIRE_EQUAL(result.output.size(), 8u);
  uint64_t counter = 0;
  for (int i = 0; i < 8; ++i)
    counter |= static_cast<uint64_t>(result.output[i]) << (8 * i);
  BOOST_CHECK_EQUAL(counter, 0u);
}

// --- Output via fixed io region ---

BOOST_AUTO_TEST_CASE(OutputViaIo) {
  CesVM vm;
  auto host = makeNullHost();
  // Write 42 to io[CESVM_IO_OUTPUT] (first cell of output region)
  // Set io[CESVM_IO_OUTPUT_LEN] = 8 (1 cell = 8 bytes)
  ces::Bytes code;
  // SET io[764] = 42 — need 2-byte encoding for 764
  code.push_back(OP_SET);
  push2(code, CESVM_IO_OUTPUT);   // dst = 764
  code.push_back(sv(42));          // value = 42
  code.push_back(OP_SET);
  push2(code, CESVM_IO_OUTPUT_LEN); // dst = 753
  code.push_back(sv(8));            // 8 bytes
  code.push_back(OP_TERM);

  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  BOOST_CHECK_EQUAL(result.output.size(), 8);
  BOOST_CHECK_EQUAL(result.output[0], 42);
}

BOOST_AUTO_TEST_CASE(OutputEmptyByDefault) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {OP_TERM};
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  BOOST_CHECK(result.output.empty());
}

// --- Cross-transfer (not yet implemented, placeholder) ---

// SyscallGetCaller removed — caller key is preloaded at CESVM_IO_CALLER_KEY

// --- Memory operations ---

BOOST_AUTO_TEST_CASE(MovCells) {
  CesVM vm;
  auto host = makeNullHost();
  // SET io[20] = 42, MOV dst=30 src=20 count=1, check io[30]==42
  ces::Bytes code = {
    OP_SET, sv(20), sv(42),
    OP_MOV, sv(30), sv(20), sv(1),  // copy 1 cell from io[20] to io[30]
    OP_PUSH, rp(30),
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(MovMultipleCells) {
  CesVM vm;
  auto host = makeNullHost();
  // Set io[20..23] = 1,2,3,4 then MOV 4 cells to io[30..33]
  ces::Bytes code = {
    OP_SET, sv(20), sv(1),
    OP_SET, sv(21), sv(2),
    OP_SET, sv(22), sv(3),
    OP_SET, sv(23), sv(4),
    OP_MOV, sv(30), sv(20), sv(4),
    OP_PUSH, rp(32),  // should be 3
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(LoadByte) {
  CesVM vm;
  auto host = makeNullHost();
  // io[3] = 42. Byte offset = 3*8 = 24. LDB 24 → R = 42
  ces::Bytes code = {
    OP_SET, sv(3), sv(42),
    OP_LDB, sv(24),       // byte 24 = first byte of io[3]
    // R should be 42
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(StoreByte) {
  CesVM vm;
  auto host = makeNullHost();
  // STB byte 24 = 99, LDB byte 24 → R = 99
  ces::Bytes code = {
    OP_STB, sv(24), sv(99),
    OP_LDB, sv(24),
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(LoadByteStack) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_STB, sv(24), sv(77),
    OP_PUSH, sv(24),
    static_cast<uint8_t>(OP_LDB | STACK),
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(CmpEqual) {
  CesVM vm;
  auto host = makeNullHost();
  // Set io[8] and io[10] to same value, CMP → R=1
  ces::Bytes code = {
    OP_SET, sv(8), sv(42),
    OP_SET, sv(10), sv(42),
    OP_CMP, sv(8), sv(10), sv(1),  // compare 1 cell at io[8] vs io[10]
    // R should be 1 (equal)
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(CmpNotEqual) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_SET, sv(8), sv(42),
    OP_SET, sv(10), sv(99),
    OP_CMP, sv(8), sv(10), sv(1),  // compare 1 cell
    // R should be 0 (not equal)
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(CmpMultipleCells) {
  CesVM vm;
  auto host = makeNullHost();
  // Set io[8..10] and io[16..18] to same values, compare 3 cells
  ces::Bytes code = {
    OP_SET, sv(8), sv(11),
    OP_SET, sv(9), sv(22),
    OP_SET, sv(10), sv(33),
    OP_SET, sv(16), sv(11),
    OP_SET, sv(17), sv(22),
    OP_SET, sv(18), sv(33),
    OP_CMP, sv(8), sv(16), sv(3),  // compare 3 cells
    // R should be 1 (equal)
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(CmpSegfault) {
  CesVM vm;
  auto host = makeNullHost();
  // CMP with count that overflows io memory
  ces::Bytes code = {
    OP_CMP, sv(8), sv(10),
  };
  push2(code, 2000); // 2000 cells > CESVM_IO_SIZE
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

BOOST_AUTO_TEST_CASE(FilBasic) {
  CesVM vm;
  auto host = makeNullHost();
  // FIL io[8..9] with value 7, then check io[8] and io[9]
  ces::Bytes code = {
    OP_FIL, sv(8), sv(7), sv(2),   // fill 2 cells at io[8] with 7
    OP_EQ, rp(8), sv(7),           // R = (io[8] == 7)
    OP_JF, sv(0),                  // jump to 0 (infinite loop) if false — won't happen
    OP_EQ, rp(9), sv(7),           // R = (io[9] == 7)
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(FilSegfault) {
  CesVM vm;
  auto host = makeNullHost();
  // FIL with count that overflows io memory
  ces::Bytes code = {
    OP_FIL, sv(8), sv(0),
  };
  push2(code, 2000); // 2000 cells > CESVM_IO_SIZE
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

// --- Attacker-bytecode overflow regressions ---
// All four tests encode attack inputs that used to reach OOB memory access
// in the server process. They trip the overflow-safe bounds checks added
// in the Phase 2 sweep; if a future edit re-introduces the
// `A + B > LIMIT` pattern, these tests fail instead of silently becoming
// memory corruption.

BOOST_AUTO_TEST_CASE(MovBoundsOverflow) {
  CesVM vm;
  auto host = makeNullHost();
  // dst near UINT64_MAX with a small count. Pre-fix, `op1 + cnt` wraps
  // to ~0 and `> CESVM_IO_SIZE` is false → memmove runs with op1 near
  // UINT64_MAX and writes past the io_ array.
  ces::Bytes code = {OP_MOV};
  push8(code, UINT64_MAX - 2);  // dst
  code.push_back(sv(0));         // src
  code.push_back(sv(3));         // cnt
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

BOOST_AUTO_TEST_CASE(SysHashDataOffOverflow) {
  CesVM vm;
  auto host = makeNullHost();
  // dataOff * 8 wraps: attacker sets io[4] to (UINT64_MAX / 8) + 1 so the
  // pre-fix `dataByte = dataOff * sizeof(uint64_t)` wraps to a small in-
  // bounds-looking value, slipping past the length check; SHA256 then
  // reads OOB.
  ces::Bytes code;
  code.insert(code.end(), {OP_SET, sv(5), sv(8)});   // len = 8
  code.insert(code.end(), {OP_SET, sv(6), sv(20)});  // outOff
  code.push_back(OP_SET);
  code.push_back(sv(4));
  push8(code, (UINT64_MAX / sizeof(uint64_t)) + 1);  // dataOff
  code.insert(code.end(), {OP_SET, sv(3), sv(SYS_HASH)});
  code.push_back(OP_HOST);
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

BOOST_AUTO_TEST_CASE(ReadIoBytesOffsetOverflow) {
  CesVM vm;
  auto host = makeNullHost();
  // SYS_SEND_CLIENT reads its clientId via readIoBytes(io[4], ...). If
  // io[4] is huge, `ioOffset * sizeof(uint64_t)` wraps and the
  // "+ len" bounds check passes on the wrapped value.
  ces::Bytes code;
  code.insert(code.end(), {OP_SET, sv(6), sv(0)});   // dataLen = 0
  code.insert(code.end(), {OP_SET, sv(5), sv(16)});  // dataPtr (unused)
  code.push_back(OP_SET);
  code.push_back(sv(4));
  push8(code, (UINT64_MAX / sizeof(uint64_t)) + 1);  // clientPtr
  code.insert(code.end(), {OP_SET, sv(3), sv(SYS_SEND_CLIENT)});
  code.push_back(OP_HOST);
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

BOOST_AUTO_TEST_CASE(ReadWideFormOversize) {
  CesVM vm;
  auto host = makeNullHost();
  // Wide-form operand with v=9: legit encoders cap at 8 (fits uint64_t),
  // but raw bytecode is untrusted. Pre-fix, `memcpy(&val, code+PC, 9)`
  // scribbles one byte past `val` on the stack.
  ces::Bytes code = {OP_SET};
  code.push_back(9); // control: wide form, v = 9 bytes
  for (int i = 0; i < 9; ++i) code.push_back(0);
  code.push_back(sv(0));  // second operand
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OPCODE);
}

BOOST_AUTO_TEST_CASE(ShlOversizeShiftRejected) {
  CesVM vm;
  auto host = makeNullHost();
  // op1 = 1 (short form), op2 = 64 (wide form, 1 byte). Shifting
  // uint64_t by >= 64 bits is UB per [expr.shift]/1; pre-fix the VM
  // would execute the shift and let the compiler decide what happens.
  ces::Bytes code = {
    OP_SHL, sv(1),
    /*op2 wide form*/ 1, 64,
    OP_TERM,
  };
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

BOOST_AUTO_TEST_CASE(ShrOversizeShiftRejected) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_SHR, sv(1),
    /*op2 wide form*/ 1, 64,
    OP_TERM,
  };
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

// SAR is the signed/arithmetic right-shift counterpart of SHR. SHR on a
// negative value (high bit set) zero-fills the sign bit and produces a
// huge positive number; SAR sign-extends and produces the right negative
// answer. Compare both on the same input.
BOOST_AUTO_TEST_CASE(SarSignExtendsVsShr) {
  CesVM vm;
  auto host = makeNullHost();
  // io[8] = -2 (= 0xFFFFFFFF_FFFFFFFE). SHR 1 → 0x7FFFFFFF_FFFFFFFF (huge).
  // SAR 1 → -1 (= 0xFFFFFFFF_FFFFFFFF). Stash both into the output buffer
  // so we can read them back as cells. The `rp()` operands dereference —
  // `sv(8)` would be the literal value 8, not the contents of cell 8.
  ces::Bytes code = {
    OP_SET, sv(8), /*wide -2 = 8 bytes*/ 8,
            0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    OP_SHR, rp(8), sv(1),                         // R = io[8] >> 1 (logical)
    OP_SET, sv(9), rp(1),                         // io[9] = R
    OP_SAR, rp(8), sv(1),                         // R = io[8] >> 1 (arithmetic)
    OP_SET, sv(10), rp(1),                        // io[10] = R
    OP_MOV, /*dst wide*/ 2,
            static_cast<uint8_t>(CESVM_IO_OUTPUT & 0xFF),
            static_cast<uint8_t>((CESVM_IO_OUTPUT >> 8) & 0xFF),
            sv(9), sv(2),                         // copy 2 cells starting io[9]
    OP_SET, /*dst wide*/ 2,
            static_cast<uint8_t>(CESVM_IO_OUTPUT_LEN & 0xFF),
            static_cast<uint8_t>((CESVM_IO_OUTPUT_LEN >> 8) & 0xFF),
            sv(16),
    OP_TERM,
  };
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, CESVM_OK);
  BOOST_REQUIRE_EQUAL(result.output.size(), 16u);

  uint64_t shrVal = 0, sarVal = 0;
  std::memcpy(&shrVal, result.output.data(),     8);
  std::memcpy(&sarVal, result.output.data() + 8, 8);
  BOOST_CHECK_EQUAL(shrVal, 0x7FFFFFFFFFFFFFFFull);    // logical: huge positive
  BOOST_CHECK_EQUAL(static_cast<int64_t>(sarVal), -1); // arithmetic: -1
}

// Protocol-fee billing: every state-mutating syscall debits a per-op
// fee from the run's budget on top of the gas cost. These tests pin the
// fee category each syscall picks (Tx vs Query vs Asset vs SendClient)
// so a future copy-paste mistake of "billCredits(host.feeAsset)" where
// "billCredits(host.feeTx)" was intended would surface as a test
// regression instead of mispriced production traffic.
namespace {

// Subclass with non-zero fees and pass-through stubs for the syscalls
// being measured. Each test runs a tiny program that issues exactly one
// syscall, then asserts the budget delta matches gas+fee.
struct FeeMeasureHost : NullVmHost {
  FeeMeasureHost() {
    feeQuery       = 1000;   // distinct values so a wrong category is loud
    feeTx          = 2000;
    feeAsset       = 4000;
    feeAccount     = 8000;
    feeSendClient  = 16000;
    feeAssetRaw    = 4000;
    assetRentMultBp = 10000;
  }
  uint8_t transfer       (const minx::Hash&, uint64_t)              override { return CES_OK; }
  uint8_t ownerTransfer  (const minx::Hash&, uint64_t)              override { return CES_OK; }
  uint8_t deposit        (uint64_t)                                  override { return CES_OK; }
  uint8_t withdraw       (uint64_t)                                  override { return CES_OK; }
  uint8_t fundAsset      (const minx::Hash&, uint16_t)              override { return CES_OK; }
  uint8_t buyAsset       (const minx::Hash&, uint64_t)              override { return CES_OK; }
  uint8_t giveAsset      (const minx::Hash&, const HashPrefix&)     override { return CES_OK; }
  uint8_t updateAssetMeta(const minx::Hash&, const HashPrefix&,
                          uint32_t)                                  override { return CES_OK; }
  uint8_t debitCaller    (uint64_t)                                  override { return CES_OK; }
};

// Run a single-syscall program with `gasMult = 1` so gas costs are
// readable directly in budget units, returns the budgetUsed.
static uint64_t feeProbe(uint8_t syscall,
                         ces::Bytes argSetup = {}) {
  CesVM vm;
  FeeMeasureHost host;
  ces::Bytes code = {OP_SET, sv(3), sv(syscall)};
  code.insert(code.end(), argSetup.begin(), argSetup.end());
  code.push_back(OP_HOST);
  code.push_back(OP_TERM);
  auto r = vm.execute(code, host, /*budget=*/100'000, /*gasMult=*/1);
  BOOST_REQUIRE_EQUAL(r.error, CESVM_OK);
  return r.budgetUsed;
}

} // namespace

BOOST_AUTO_TEST_CASE(FeeBillingTransferUsesFeeTx) {
  // SYS_TRANSFER bills feeTx (not feeAsset). Setup: write a key into
  // io[16..19] (zero is fine), io[5]=amount=0. Gas: SET (×3) + HOST +
  // TERM + SYS_TRANSFER dispatch = 5*COST_PER_OP + COST_PER_SYSCALL.
  // Fee: feeTx (2000).
  ces::Bytes setup = {
    OP_SET, sv(4), sv(16),  // dest_key_ptr (cell with zeros — host stub)
    OP_SET, sv(5), sv(0),   // amount = 0
  };
  uint64_t used = feeProbe(SYS_TRANSFER, setup);
  uint64_t expectedGas = 5 * CESVM_COST_PER_OP + CESVM_COST_PER_SYSCALL;
  BOOST_CHECK_EQUAL(used, expectedGas + /*feeTx=*/2000u);
}

BOOST_AUTO_TEST_CASE(FeeBillingDepositUsesFeeTx) {
  // SYS_DEPOSIT bills feeTx, no key reads. Gas: SET (×2) + HOST + TERM
  // + SYSCALL.
  ces::Bytes setup = { OP_SET, sv(4), sv(0) };
  uint64_t used = feeProbe(SYS_DEPOSIT, setup);
  uint64_t expectedGas = 4 * CESVM_COST_PER_OP + CESVM_COST_PER_SYSCALL;
  BOOST_CHECK_EQUAL(used, expectedGas + /*feeTx=*/2000u);
}

BOOST_AUTO_TEST_CASE(FeeBillingUpdateAssetMetaUsesFeeTx) {
  // META change bills feeTx (cheaper tier than full UPDATE_ASSET).
  ces::Bytes setup = {
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(20),  // new owner ptr
    OP_SET, sv(6), sv(0),   // new price = 0
  };
  uint64_t used = feeProbe(SYS_UPDATE_ASSET_META, setup);
  uint64_t expectedGas = 6 * CESVM_COST_PER_OP + CESVM_COST_PER_SYSCALL;
  BOOST_CHECK_EQUAL(used, expectedGas + /*feeTx=*/2000u);
}

// NEG / NOT / LNOT — match x86/ARM/MIPS convention: NEG is arithmetic
// negate (-x), NOT is bitwise complement (~x), LNOT is logical not (!x).
// All four results land in io[9..12] for the output copy.
BOOST_AUTO_TEST_CASE(NegNotLnotSemantics) {
  CesVM vm;
  auto host = makeNullHost();
  // io[8] = 5. NEG → -5. NOT → ~5. LNOT(5) → 0. LNOT(literal 0) → 1.
  ces::Bytes code = {
    OP_SET, sv(8),  sv(5),
    OP_NEG,  rp(8),                  // R = -5
    OP_SET, sv(9),  rp(1),           // io[9] = R
    OP_NOT,  rp(8),                  // R = ~5
    OP_SET, sv(10), rp(1),           // io[10] = R
    OP_LNOT, rp(8),                  // R = !5 = 0
    OP_SET, sv(11), rp(1),           // io[11] = R
    OP_LNOT, sv(0),                  // R = !0 = 1 (literal 0 source)
    OP_SET, sv(12), rp(1),           // io[12] = R
    OP_MOV, /*dst wide*/ 2,
            static_cast<uint8_t>(CESVM_IO_OUTPUT & 0xFF),
            static_cast<uint8_t>((CESVM_IO_OUTPUT >> 8) & 0xFF),
            sv(9), sv(4),            // copy 4 cells from io[9]
    OP_SET, /*dst wide*/ 2,
            static_cast<uint8_t>(CESVM_IO_OUTPUT_LEN & 0xFF),
            static_cast<uint8_t>((CESVM_IO_OUTPUT_LEN >> 8) & 0xFF),
            sv(32),
    OP_TERM,
  };
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, CESVM_OK);
  BOOST_REQUIRE_EQUAL(result.output.size(), 32u);

  uint64_t neg = 0, bnot = 0, lnot5 = 0, lnot0 = 0;
  std::memcpy(&neg,   result.output.data() +  0, 8);
  std::memcpy(&bnot,  result.output.data() +  8, 8);
  std::memcpy(&lnot5, result.output.data() + 16, 8);
  std::memcpy(&lnot0, result.output.data() + 24, 8);
  BOOST_CHECK_EQUAL(static_cast<int64_t>(neg), -5);
  BOOST_CHECK_EQUAL(bnot, ~uint64_t(5));
  BOOST_CHECK_EQUAL(lnot5, 0u);
  BOOST_CHECK_EQUAL(lnot0, 1u);
}

BOOST_AUTO_TEST_CASE(SarOversizeShiftRejected) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_SAR, sv(1),
    /*op2 wide form*/ 1, 64,
    OP_TERM,
  };
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

BOOST_AUTO_TEST_CASE(SyscallHash) {
  CesVM vm;
  auto host = makeNullHost();
  // Hash 8 bytes at io[8] (u64 value 42, little-endian), result at io[20].
  // Then copy the 32-byte digest from io[20..23] into the output buffer so
  // the assertion can compare it against the reference SHA256. A hash
  // implementation that writes zeros (or anything other than SHA256) would
  // pass the old "only check CESVM_OK" version of this test.
  ces::Bytes code;
  code.insert(code.end(), {OP_SET, sv(8), sv(42)});             // io[8] = 42
  code.insert(code.end(), {OP_SET, sv(3), sv(SYS_HASH)});
  code.insert(code.end(), {OP_SET, sv(4), sv(8)});              // data ptr
  code.insert(code.end(), {OP_SET, sv(5), sv(8)});              // len
  code.insert(code.end(), {OP_SET, sv(6), sv(20)});             // out ptr
  code.push_back(OP_HOST);
  code.push_back(OP_MOV);                                       // copy digest
  push2(code, CESVM_IO_OUTPUT);                                 // dst = 764
  code.push_back(sv(20));                                       // src = io[20]
  code.push_back(sv(4));                                        // 4 cells = 32 B
  code.push_back(OP_SET);
  push2(code, CESVM_IO_OUTPUT_LEN);                             // dst = 753
  code.push_back(sv(32));
  code.push_back(OP_TERM);

  auto result = vm.execute(code, host, 1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, CESVM_OK);
  BOOST_REQUIRE_EQUAL(result.output.size(), 32u);

  uint8_t input[8] = {42, 0, 0, 0, 0, 0, 0, 0};
  uint8_t expected[32];
  CryptoPP::SHA256().CalculateDigest(expected, input, sizeof(input));
  BOOST_CHECK_EQUAL_COLLECTIONS(result.output.begin(), result.output.end(),
                                expected, expected + sizeof(expected));
}

BOOST_AUTO_TEST_CASE(MovSegfault) {
  CesVM vm;
  auto host = makeNullHost();
  // MOV with count that goes past end of io
  ces::Bytes code;
  // MOV dst=1020, src=0, count=10 → 1020+10=1030 > 1024 → segfault
  code.push_back(OP_MOV);
  push2(code, 1020);  // dst
  code.push_back(sv(0)); // src
  code.push_back(sv(10)); // count
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_SEGFAULT);
}

// --- RNG ---

BOOST_AUTO_TEST_CASE(RndRegister) {
  CesVM vm;
  auto host = makeNullHost();
  // RND puts random value in R, two calls should differ (with high probability)
  ces::Bytes code = {
    OP_RND,
    OP_PUSH, rp(1),   // push R (first random)
    OP_RND,
    OP_PUSH, rp(1),   // push R (second random)
    static_cast<uint8_t>(OP_EQ | STACK), // compare
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  // Stack top should be 0 (not equal) with overwhelming probability
}

BOOST_AUTO_TEST_CASE(RndStack) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    static_cast<uint8_t>(OP_RND | STACK), // push random to stack
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- TIME ---

BOOST_AUTO_TEST_CASE(TimeRegister) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_TIME,
    OP_PUSH, rp(1),  // push R (millis epoch)
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  // Just verify it ran — can't predict exact value
}

BOOST_AUTO_TEST_CASE(TimeStack) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    static_cast<uint8_t>(OP_TIME | STACK),
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- Atomicity ---

BOOST_AUTO_TEST_CASE(ErrorAfterSyscall) {
  CesVM vm;
  auto host = makeNullHost();
  // Transfer then crash (divide by zero) — server handles rollback
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_TRANSFER),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(42),
    OP_HOST,
    // Now crash
    OP_PUSH, sv(10),
    OP_PUSH, sv(0),
    static_cast<uint8_t>(OP_DIV | STACK),
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_NE(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(MultipleSyscalls) {
  CesVM vm;
  auto host = makeNullHost();
  // Transfer then fund then terminate cleanly
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_TRANSFER),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(42),
    OP_HOST,
    OP_SET, sv(3), sv(SYS_FUND_ASSET),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(10),
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- Self-identity (preloaded in io memory) ---

BOOST_AUTO_TEST_CASE(PreloadedCallerKey) {
  CesVM vm;
  auto host = makeNullHost();
  host.callerKey.fill(0xAA);
  // CESVM_IO_CALLER_KEY > 63 so can't use sv/rp. Use SET to load offset, then deref.
  ces::Bytes code;
  code.push_back(OP_SET);
  code.push_back(sv(9));  // io[9] = CESVM_IO_CALLER_KEY
  push2(code, CESVM_IO_CALLER_KEY);
  code.push_back(OP_PUSH);
  code.push_back(rp(9));  // push io[io[9]] = io[756]
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(PreloadedSelfKey) {
  CesVM vm;
  auto host = makeNullHost();
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code;
  code.push_back(OP_SET);
  code.push_back(sv(9));
  push2(code, CESVM_IO_SELF_KEY);
  code.push_back(OP_PUSH);
  code.push_back(rp(9));
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- Signature verification ---

// Runs SYS_VERIFY_SIG with a mock host returning `hostResult`. Returns the
// value the VM's R register (io[1]) held after the syscall, exposed by
// copying one cell into the output buffer. A plumbing regression where the
// host's return value never reaches R would slip past a test that only
// observed the `verifyCalled` flag.
static uint64_t runVerifySig(bool hostResult, bool& verifyCalled) {
  CesVM vm;
  struct H : NullVmHost {
    bool result;
    bool* called;
    bool verifySig(const uint8_t*, size_t,
                   const uint8_t*, const uint8_t*) override {
      *called = true;
      return result;
    }
  } host;
  host.result = hostResult;
  host.called = &verifyCalled;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code;
  code.insert(code.end(), {OP_SET, sv(3), sv(SYS_VERIFY_SIG)});
  code.insert(code.end(), {OP_SET, sv(4), sv(16)});   // data ptr
  code.insert(code.end(), {OP_SET, sv(5), sv(8)});    // data len
  code.insert(code.end(), {OP_SET, sv(6), sv(24)});   // sig ptr
  code.insert(code.end(), {OP_SET, sv(7), sv(32)});   // pubkey ptr
  code.push_back(OP_HOST);
  code.push_back(OP_MOV);
  push2(code, CESVM_IO_OUTPUT);                      // dst = 764
  code.push_back(sv(CESVM_CELL_R));                  // src = io[1] (R)
  code.push_back(sv(1));                             // 1 cell
  code.push_back(OP_SET);
  push2(code, CESVM_IO_OUTPUT_LEN);
  code.push_back(sv(8));
  code.push_back(OP_TERM);
  auto result = vm.execute(code, host, 1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, CESVM_OK);
  BOOST_REQUIRE_EQUAL(result.output.size(), 8u);
  uint64_t r = 0;
  for (int i = 0; i < 8; ++i)
    r |= static_cast<uint64_t>(result.output[i]) << (8 * i);
  return r;
}

BOOST_AUTO_TEST_CASE(SyscallVerifySig) {
  bool called = false;
  BOOST_CHECK_EQUAL(runVerifySig(true, called), 1u);
  BOOST_CHECK(called);
}

BOOST_AUTO_TEST_CASE(SyscallVerifySigFalse) {
  bool called = false;
  BOOST_CHECK_EQUAL(runVerifySig(false, called), 0u);
  BOOST_CHECK(called);
}

// --- Cross-transfer ---

BOOST_AUTO_TEST_CASE(SyscallCrossTransfer) {
  CesVM vm;
  // Capture whatever the host gets so we can verify the VM actually
  // dispatched the syscall. The previous version of this test installed
  // a no-op lambda and checked only `result.error == CESVM_OK`, which
  // would pass even if SYS_CROSS_TRANSFER silently ran off the end of
  // a cliff — it was a test in name only.
  struct H : NullVmHost {
    bool called = false;
    uint64_t capturedAmount = 0;
    std::string capturedServer;
    minx::Hash capturedDest{};
    uint8_t crossTransfer(const minx::Hash& dest, uint64_t amount,
                          const std::string& server) override {
      called = true;
      capturedDest = dest;
      capturedAmount = amount;
      capturedServer = server;
      return CES_OK;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);

  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_CROSS_TRANSFER),
    OP_SET, sv(4), sv(16),  // dest key ptr (io[16..19], uninitialized → zeros)
    OP_SET, sv(5), sv(50),  // amount = 50
    OP_SET, sv(6), sv(24),  // server addr ptr (io[24..], uninitialized → zeros → "")
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  BOOST_CHECK(host.called);
  BOOST_CHECK_EQUAL(host.capturedAmount, 50u);
  // Dest hash was never written into io[16..19], so the 32 bytes of io memory
  // the VM read are all zero. We only need to prove the syscall reached the
  // host; the end-to-end semantics are covered by the peering test.
  BOOST_CHECK(host.capturedDest == minx::Hash{});
  BOOST_CHECK(host.capturedServer.empty());
}

// --- SYS_LOAD_CODE ---

BOOST_AUTO_TEST_CASE(LoadCodeBasic) {
  CesVM vm;
  // readAsset returns content "SET io[8]=99, TERM" for any key.
  struct H : NullVmHost {
    AssetData libContent{};
    bool readAsset(const minx::Hash&, HashPrefix&, AssetData& content,
                   uint16_t& balance, uint32_t&) override {
      content = libContent;
      balance = 10;
      return true;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  host.libContent[0] = OP_SET;
  host.libContent[1] = sv(8);
  host.libContent[2] = sv(99);
  host.libContent[3] = OP_TERM;
  // Main code: LOAD_CODE → get offset, JMP to it
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_LOAD_CODE),
    OP_SET, sv(4), sv(16),  // asset key ptr (dummy, host ignores it)
    OP_HOST,
    // R now holds the offset of the loaded code block
    // JMP to R (need to store R into a cell for indirect jump)
    // R = io[1], use it as jump target
    OP_JMP,
  };
  // JMP reads a 2-byte address: the offset where SYS_LOAD_CODE will append
  // the loaded block, which is code_.size() after the JMP's own 2 address
  // bytes. So jmpTarget = current size + 2.
  uint16_t jmpTarget = static_cast<uint16_t>(code.size() + 2);
  ces::Buffer::putLE<uint16_t>(code, jmpTarget);

  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(LoadCodeNotFound) {
  CesVM vm;
  auto host = makeNullHost();
  // readAsset returns false (asset not found) — already the default
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_LOAD_CODE),
    OP_SET, sv(4), sv(16),
    OP_HOST,
    // S should be CES_ERROR_ASSET_NOT_FOUND
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(LoadCodeFull) {
  CesVM vm;
  struct H : NullVmHost {
    AssetData libContent{};
    bool readAsset(const minx::Hash&, HashPrefix&, AssetData& content,
                   uint16_t&, uint32_t&) override {
      content = libContent;
      return true;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  host.libContent[0] = OP_NOP;
  // Load enough blocks to fill the code space, then one more → CESVM_CODEFULL
  // Max code = 8192. Each block = 210. Initial code takes some bytes.
  // We'll build a loop that calls LOAD_CODE repeatedly.
  // Simpler: just build a long initial code that's close to 8192 - 210,
  // then load one that fits, then one that doesn't.
  // Easiest: set initial code to ~8000 bytes (padded with NOPs), then load → crash
  ces::Bytes code;
  // Fill to just under the limit where one more block won't fit
  // 8192 - 210 = 7982. If code_.size() > 7982, load will crash.
  code.resize(7983, OP_NOP);
  // Append the LOAD_CODE syscall at the end
  code.push_back(OP_SET); code.push_back(sv(3)); code.push_back(sv(SYS_LOAD_CODE));
  code.push_back(OP_SET); code.push_back(sv(4)); code.push_back(sv(16));
  code.push_back(OP_HOST);
  code.push_back(OP_TERM);

  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_CODEFULL);
}

BOOST_AUTO_TEST_CASE(LoadCodeCallReturn) {
  CesVM vm;
  // Library asset: SET io[8]=42, RET with value 1
  struct H : NullVmHost {
    AssetData libContent{};
    bool readAsset(const minx::Hash&, HashPrefix&, AssetData& content,
                   uint16_t& balance, uint32_t&) override {
      content = libContent;
      balance = 10;
      return true;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  host.libContent[0] = OP_SET;
  host.libContent[1] = sv(8);
  host.libContent[2] = sv(42);
  host.libContent[3] = OP_RET;
  host.libContent[4] = sv(1);
  // Main: load code, CALL into it, check io[8] was set
  ces::Bytes code = {
    // Load the library
    OP_SET, sv(3), sv(SYS_LOAD_CODE),
    OP_SET, sv(4), sv(16),
    OP_HOST,
    // R = offset of loaded block. Store it in io[9] for the CALL target.
    OP_SET, sv(9), rp(1),  // io[9] = R
  };
  // CALL takes a 2-byte literal address. The loaded block lands at
  // code.size() plus the CALL (3 bytes) and the trailing TERM (1 byte).
  size_t callTarget = code.size() + 3 + 1; // +3 for CALL+2bytes, +1 for TERM
  code.push_back(OP_CALL);
  ces::Buffer::putLE<uint16_t>(code, static_cast<uint16_t>(callTarget));
  code.push_back(OP_TERM);

  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- SYS_CREATE_ASSET ---

BOOST_AUTO_TEST_CASE(CreateAssetNew) {
  CesVM vm;
  auto host = makeNullHost();
  // readAsset returns false (not found) — default
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_CREATE_ASSET),
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(24),  // content ptr
    OP_SET, sv(6), sv(10),  // days
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(CreateAssetExists) {
  CesVM vm;
  // createAsset callback returns ASSET_EXISTS for this test
  struct H : NullVmHost {
    uint8_t createAsset(const minx::Hash&, const AssetData&, uint16_t) override {
      return CES_ERROR_ASSET_EXISTS;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_CREATE_ASSET),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(24),
    OP_SET, sv(6), sv(10),
    OP_HOST,
    // S should be CES_ERROR_ASSET_EXISTS
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- S register (error code) ---

BOOST_AUTO_TEST_CASE(SyscallSetsSOk) {
  CesVM vm;
  auto host = makeNullHost();
  // NOP syscall should set S = CES_OK (0)
  ces::Bytes code = {
    OP_SET, sv(2), sv(99),  // S = 99 (dirty it first)
    OP_SET, sv(3), sv(SYS_NOP),
    OP_HOST,
    // S (io[2]) should now be 0
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(ReadAssetNotFoundSetsS) {
  CesVM vm;
  auto host = makeNullHost();
  // readAsset returns false (default) → S = CES_ERROR_ASSET_NOT_FOUND
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_READ_ASSET),
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(24),  // owner out ptr
    OP_SET, sv(6), sv(32),  // content out ptr
    OP_HOST,
    // S should be CES_ERROR_ASSET_NOT_FOUND (0x09)
    // Use HOSTX on a NOP to verify S is nonzero → should abort
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(ReadAssetNotFoundHostxAborts) {
  CesVM vm;
  auto host = makeNullHost();
  // readAsset returns false → S = CES_ERROR_ASSET_NOT_FOUND
  // HOSTX should abort because S != 0
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_READ_ASSET),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(24),
    OP_SET, sv(6), sv(32),
    OP_HOSTX,
    OP_TERM  // should not reach here
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_ABORT);
}

BOOST_AUTO_TEST_CASE(HostxSuccessNoAbort) {
  CesVM vm;
  auto host = makeNullHost();
  // NOP syscall → S = CES_OK → HOSTX should NOT abort
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_NOP),
    OP_HOSTX,
    OP_TERM
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(AbortOpcode) {
  CesVM vm;
  auto host = makeNullHost();
  ces::Bytes code = {
    OP_SET, sv(8), sv(42),
    OP_ABORT,
    OP_TERM  // should not reach here
  };
  auto result = vm.execute(code, host, 1000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_ABORT);
}

BOOST_AUTO_TEST_CASE(CreateAssetExistsHostx) {
  CesVM vm;
  struct H : NullVmHost {
    uint8_t createAsset(const minx::Hash&, const AssetData&, uint16_t) override {
      return CES_ERROR_ASSET_EXISTS;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  // CREATE_ASSET with host returning ASSET_EXISTS → S != 0
  // HOSTX should abort
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_CREATE_ASSET),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(24),
    OP_SET, sv(6), sv(10),
    OP_HOSTX,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_ABORT);
}

// --- Host error propagation ---

BOOST_AUTO_TEST_CASE(TransferFailureSetsS) {
  CesVM vm;
  struct H : NullVmHost {
    uint8_t transfer(const minx::Hash&, uint64_t) override {
      return CES_ERROR_INSUFFICIENT_BALANCE;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_TRANSFER),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(42),
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK); // HOST doesn't crash
}

BOOST_AUTO_TEST_CASE(TransferFailureHostxAborts) {
  CesVM vm;
  struct H : NullVmHost {
    uint8_t transfer(const minx::Hash&, uint64_t) override {
      return CES_ERROR_INSUFFICIENT_BALANCE;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_TRANSFER),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(42),
    OP_HOSTX,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_ABORT); // HOSTX aborts
}

BOOST_AUTO_TEST_CASE(UpdateAssetFailure) {
  CesVM vm;
  struct H : NullVmHost {
    uint8_t updateAsset(const minx::Hash&, const AssetData&) override {
      return CES_ERROR_NOT_OWNER;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_UPDATE_ASSET),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(24),
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK); // HOST continues
}

BOOST_AUTO_TEST_CASE(GiveAssetFailure) {
  CesVM vm;
  struct H : NullVmHost {
    uint8_t giveAsset(const minx::Hash&, const HashPrefix&) override {
      return CES_ERROR_ASSET_NOT_FOUND;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_GIVE_ASSET),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(24),
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

// --- Syscall data tests ---

BOOST_AUTO_TEST_CASE(ReadAccountReturnsData) {
  CesVM vm;
  struct H : NullVmHost {
    int64_t  readAccountBalance(const HashPrefix&) override { return 12345; }
    uint32_t readAccountNonce  (const HashPrefix&) override { return 7; }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_READ_ACCOUNT),
    OP_SET, sv(4), sv(16),  // account prefix ptr
    OP_HOST,
    // R should be 12345, io[5] should be 7
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(ReadAssetSuccess) {
  CesVM vm;
  struct H : NullVmHost {
    bool readAsset(const minx::Hash&, HashPrefix& owner, AssetData& content,
                   uint16_t& balance, uint32_t& price) override {
      owner.fill(0x11);
      content.fill(0x22);
      balance = 365;
      price = 100;
      return true;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_READ_ASSET),
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(24),  // owner out ptr
    OP_SET, sv(6), sv(32),  // content out ptr
    OP_HOST,
    // io[7] should be 365 (balance), io[8] should be 100 (price)
    OP_EQ, rp(7), sv(365 & 0x3F), // can't check 365 with sv, just verify S=OK
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
}

BOOST_AUTO_TEST_CASE(SendUdpDenied) {
  CesVM vm;
  auto host = makeNullHost();
  // SYS_SEND_UDP is disabled — should return S=CES_ERROR_DISABLED
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_SEND_UDP),
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK); // HOST doesn't crash
}

BOOST_AUTO_TEST_CASE(SendUdpDeniedHostxAborts) {
  CesVM vm;
  auto host = makeNullHost();
  // HOSTX on DISABLED should abort
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_SEND_UDP),
    OP_HOSTX,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_ABORT);
}

BOOST_AUTO_TEST_CASE(SendClientCallsHost) {
  CesVM vm;
  struct H : NullVmHost {
    HashPrefix capturedId{};
    ces::Bytes capturedData;
    bool sendClient(const HashPrefix& id, const uint8_t* data,
                    size_t len) override {
      capturedId = id;
      capturedData.assign(data, data + len);
      return true;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  // Populate the cells that the prefix/data pointers will reference so we
  // can verify the syscall actually passed THIS memory through — not just
  // that the lambda was invoked with some undefined bytes.
  ces::Bytes code = {
    OP_SET, sv(16), sv(42),  // cell 16 → u64(42) = 8B prefix
    OP_SET, sv(24), sv(51),  // cell 24 → u64(51) = 8B data payload
    OP_SET, sv(3), sv(SYS_SEND_CLIENT),
    OP_SET, sv(4), sv(16),  // client prefix ptr
    OP_SET, sv(5), sv(24),  // data ptr
    OP_SET, sv(6), sv(8),   // data len
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);

  // Cells are little-endian u64 → u64(42) = {0x2A,0,0,0,0,0,0,0}
  HashPrefix expectedId{0x2A, 0, 0, 0, 0, 0, 0, 0};
  BOOST_CHECK(host.capturedId == expectedId);

  ces::Bytes expectedData{0x33, 0, 0, 0, 0, 0, 0, 0};
  BOOST_CHECK_EQUAL_COLLECTIONS(
    host.capturedData.begin(), host.capturedData.end(),
    expectedData.begin(), expectedData.end());
}

BOOST_AUTO_TEST_CASE(FundAssetSuccess) {
  CesVM vm;
  struct H : NullVmHost {
    bool fundCalled = false;
    uint8_t fundAsset(const minx::Hash&, uint16_t days) override {
      fundCalled = true;
      BOOST_CHECK_EQUAL(days, 10);
      return CES_OK;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_FUND_ASSET),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(10),
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_OK);
  BOOST_CHECK(host.fundCalled);
}

BOOST_AUTO_TEST_CASE(BuyAssetNotForSale) {
  CesVM vm;
  struct H : NullVmHost {
    uint8_t buyAsset(const minx::Hash&, uint64_t) override {
      return CES_ERROR_NOT_FOR_SALE;
    }
  } host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  ces::Bytes code = {
    OP_SET, sv(3), sv(SYS_BUY_ASSET),
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(50),
    OP_HOSTX,
    OP_TERM
  };
  auto result = vm.execute(code, host, 10000000);
  BOOST_CHECK_EQUAL(result.error, CESVM_ABORT);
}

// --- Budget accounting ---

BOOST_AUTO_TEST_CASE(SyscallCostsMoreThanOp) {
  CesVM vm;
  auto host = makeNullHost();
  // Budget = 300: enough for NOP(100) + SET(100) + HOST opcode(100) but not the syscall(+150)
  // The HOST opcode bills COST_PER_OP=100, then hostCall tries to bill COST_PER_SYSCALL=150
  // which exceeds the remaining budget → CESVM_BUDGET
  ces::Bytes code = {
    OP_NOP,
    OP_SET, sv(3), sv(SYS_NOP),
    OP_HOST,
    OP_TERM
  };
  auto result = vm.execute(code, host, 300);
  BOOST_CHECK_EQUAL(result.error, CESVM_BUDGET);
  BOOST_CHECK_EQUAL(result.budgetUsed, 300); // NOP + SET + HOST opcode billed, syscall didn't
}

// --- Server integration (via CesFixture) ---

BOOST_FIXTURE_TEST_CASE(RunAssetNopProgram, CesFixture) {
  // Create an asset containing: SET io[3]=SYS_NOP, HOST, TERM
  minx::Hash assetId;
  assetId.fill(0x42);
  AssetData content{};
  content[0] = OP_SET;
  content[1] = sv(3);
  content[2] = sv(SYS_NOP);
  content[3] = OP_HOST;
  content[4] = OP_TERM;

  uint8_t rc = client->createAsset(assetId, content, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Query balance before RUN_ASSET
  int64_t balBefore = 0;
  uint32_t nonceBefore = 0;
  rc = client->queryAccount(getMyId(), balBefore, nonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(balBefore > 0);

  // Run the asset program
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(assetId, 1'000'000'000, {}, vmError, budgetUsed, output);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);
  BOOST_CHECK(budgetUsed > 0);

  // Caller pays exactly budgetUsed (gas + any syscall fees billed via
  // CesVM::billCredits). Unused budget is refunded.
  int64_t balAfter = 0;
  uint32_t nonceAfter = 0;
  rc = client->queryAccount(getMyId(), balAfter, nonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(balAfter,
                    balBefore - static_cast<int64_t>(budgetUsed));
}

BOOST_FIXTURE_TEST_CASE(RunAssetTransferProgram, CesFixture) {
  // Create a second account to receive a transfer
  KeyPair destKey;
  server->_brr(destKey.getPublicKeyAsHash(), 1000);

  // Create program: TRANSFER 100 credits to destKey
  // The program needs destKey at io[16..19] (32 bytes = 4 cells)
  // We'll pass destKey as input and copy it to io[16] via the preloaded input region
  // Simpler: hard-code a transfer to a zero-filled key (which won't exist, so the VM
  // auto-creates it). But the null host callbacks don't apply here — the server does real work.
  //
  // Easiest: program does TERM (no-op), and we verify the budget was charged.
  // The transfer test requires the program to know the dest key at a known io location.
  // Let's use the input mechanism: pass destKey as input (32 bytes at io[892..895])

  minx::Hash assetId;
  assetId.fill(0x43);
  AssetData pgm{};
  // MOV 4 cells from io[CESVM_IO_INPUT] to io[16] (copy dest key from input to arg position)
  // But CESVM_IO_INPUT=892 > 63, can't use sv(). Use SET with push2.
  // SET io[9] = 892
  size_t pc = 0;
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  // push2 for 892
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  // MOV dst=16, src=io[9]=892, count=4
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  // SYS_TRANSFER: io[3]=SYS_TRANSFER, io[4]=16 (dest key), io[5]=100 (amount)
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_TRANSFER);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(50);
  pgm[pc++] = OP_HOSTX;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(assetId, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Pass destKey as input
  ces::Bytes input(destKey.getPublicKeyAsHash().begin(),
                              destKey.getPublicKeyAsHash().end());

  int64_t balBefore = 0;
  uint32_t nonceBefore = 0;
  rc = client->queryAccount(getMyId(), balBefore, nonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  int64_t destBalBefore = 0;
  uint32_t destNonceBefore = 0;
  HashPrefix destId = Account::getMapKey(destKey.getPublicKeyAsHash());
  rc = client->queryAccount(destId, destBalBefore, destNonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(assetId, 1'000'000'000, input, vmError, budgetUsed, output);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);

  // Caller paid budgetUsed (gas + feeTx, both billed against the
  // pre-paid budget) plus the transferred amount. Unused budget was
  // refunded.
  int64_t balAfter = 0;
  uint32_t nonceAfter = 0;
  rc = client->queryAccount(getMyId(), balAfter, nonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(balAfter,
                    balBefore - static_cast<int64_t>(budgetUsed) - 50);

  // Check: dest received 50
  int64_t destBalAfter = 0;
  uint32_t destNonceAfter = 0;
  rc = client->queryAccount(destId, destBalAfter, destNonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(destBalAfter, destBalBefore + 50);
}

BOOST_FIXTURE_TEST_CASE(RunAssetOwnerTransferProgram, CesFixture) {
  // Program owned by `client` (account A) does SYS_OWNER_TRANSFER 50
  // credits to a third account (destKey). A second client (account B)
  // invokes the program. Outcome: A's balance falls by 50, dest gains
  // 50, B pays only the budget + the syscall feeTx (NOT the transfer
  // amount). Mirrors the dice "house pays caller" pattern.
  KeyPair destKey;
  server->_brr(destKey.getPublicKeyAsHash(), 1000);

  minx::Hash assetId;
  assetId.fill(0x4A);
  AssetData pgm{};
  size_t pc = 0;
  // Copy dest key (32 bytes) from input to io[16..19].
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  // SYS_OWNER_TRANSFER: io[3]=syscall, io[4]=16 (dest key), io[5]=50 (amount).
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_OWNER_TRANSFER);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(50);
  pgm[pc++] = OP_HOSTX;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(assetId, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Account B runs the program created by `client` (account A).
  KeyPair accountB;
  server->_brr(accountB.getPublicKeyAsHash(), 100'000'000);
  wait_net();
  boost::asio::ip::udp::endpoint ep(
    boost::asio::ip::address_v6::loopback(), serverPort);
  CesClient clientB(ep, false);
  clientB.start(0);
  clientB.setKey(accountB);
  BOOST_REQUIRE(clientB.connect());

  ces::Bytes input(destKey.getPublicKeyAsHash().begin(),
                              destKey.getPublicKeyAsHash().end());

  int64_t aBalBefore = 0;
  uint32_t aNonceBefore = 0;
  rc = client->queryAccount(getMyId(), aBalBefore, aNonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  int64_t bBalBefore = 0;
  uint32_t bNonceBefore = 0;
  HashPrefix bId = Account::getMapKey(accountB.getPublicKeyAsHash());
  rc = client->queryAccount(bId, bBalBefore, bNonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  int64_t destBalBefore = 0;
  uint32_t destNonceBefore = 0;
  HashPrefix destId = Account::getMapKey(destKey.getPublicKeyAsHash());
  rc = client->queryAccount(destId, destBalBefore, destNonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = clientB.runAsset(assetId, 10'000'000, input, vmError, budgetUsed,
                        output, true);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);

  // A (the owner) lost the transferred amount. No fee — caller pays
  // the syscall fee.
  int64_t aBalAfter = 0;
  uint32_t aNonceAfter = 0;
  rc = client->queryAccount(getMyId(), aBalAfter, aNonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(aBalAfter, aBalBefore - 50);

  // B (the caller) paid budgetUsed (gas + syscall feeTx, both billed
  // against the pre-paid budget); they did NOT pay the 50 (that came
  // from A via SYS_OWNER_TRANSFER).
  int64_t bBalAfter = 0;
  uint32_t bNonceAfter = 0;
  rc = client->queryAccount(bId, bBalAfter, bNonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(bBalAfter,
                    bBalBefore - static_cast<int64_t>(budgetUsed));

  // Dest received 50, sourced from A's account.
  int64_t destBalAfter = 0;
  uint32_t destNonceAfter = 0;
  rc = client->queryAccount(destId, destBalAfter, destNonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(destBalAfter, destBalBefore + 50);
}

BOOST_FIXTURE_TEST_CASE(RunAssetAbortReverts, CesFixture) {
  // Program: transfer 50, then ABORT. The transfer should be reverted.
  KeyPair destKey;
  server->_brr(destKey.getPublicKeyAsHash(), 1000);

  minx::Hash assetId;
  assetId.fill(0x44);
  AssetData pgm{};
  size_t pc = 0;
  // Copy dest key from input to io[16]
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  // Transfer 50
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_TRANSFER);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(50);
  pgm[pc++] = OP_HOST;
  // ABORT — should revert the transfer
  pgm[pc++] = OP_ABORT;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(assetId, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input(destKey.getPublicKeyAsHash().begin(),
                              destKey.getPublicKeyAsHash().end());

  int64_t callerBalBefore = 0;
  uint32_t callerNonceBefore = 0;
  rc = client->queryAccount(getMyId(), callerBalBefore, callerNonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  int64_t destBalBefore = 0;
  uint32_t destNonceBefore = 0;
  HashPrefix destId = Account::getMapKey(destKey.getPublicKeyAsHash());
  rc = client->queryAccount(destId, destBalBefore, destNonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(assetId, 1'000'000'000, input, vmError, budgetUsed, output);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_VM_FAILED);
  BOOST_CHECK_EQUAL(vmError, CESVM_ABORT);

  // Dest balance should be unchanged — transfer was reverted
  int64_t destBalAfter = 0;
  uint32_t destNonceAfter = 0;
  rc = client->queryAccount(destId, destBalAfter, destNonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(destBalAfter, destBalBefore);

  // ABORT gets the unused budget refund: caller paid only budgetUsed.
  // The threshold here just proves substantial refund — budgetUsed
  // covers gas + the SYS_TRANSFER's feeTx (now billed against
  // budget), so it's well under the 10M reserve but not as small as
  // gas alone.
  int64_t callerBalAfter = 0;
  uint32_t callerNonceAfter = 0;
  rc = client->queryAccount(getMyId(), callerBalAfter, callerNonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(budgetUsed < 1'000'000);
  BOOST_CHECK_EQUAL(callerBalAfter, callerBalBefore - static_cast<int64_t>(budgetUsed));
}

BOOST_FIXTURE_TEST_CASE(RunAssetCrashFee, CesFixture) {
  // Program: divide by zero → CESVM_DIVZERO. Crash fee applied, rest refunded.
  minx::Hash assetId;
  assetId.fill(0x45);
  AssetData pgm{};
  size_t pc = 0;
  pgm[pc++] = OP_PUSH; pgm[pc++] = sv(10);
  pgm[pc++] = OP_PUSH; pgm[pc++] = sv(0);
  pgm[pc++] = static_cast<uint8_t>(OP_DIV | STACK);
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(assetId, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  int64_t balBefore = 0;
  uint32_t nonceBefore = 0;
  rc = client->queryAccount(getMyId(), balBefore, nonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(assetId, 1'000'000'000, {}, vmError, budgetUsed, output);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_VM_FAILED);
  BOOST_CHECK_EQUAL(vmError, CESVM_DIVZERO);

  // Crash: lose budgetUsed + CESVM_CRASH_FEE, rest refunded
  int64_t balAfter = 0;
  uint32_t nonceAfter = 0;
  rc = client->queryAccount(getMyId(), balAfter, nonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  int64_t expectedLoss = static_cast<int64_t>(budgetUsed + CESVM_CRASH_FEE);
  BOOST_CHECK_EQUAL(balAfter, balBefore - expectedLoss);
}

BOOST_FIXTURE_TEST_CASE(SendClientPushToClient, CesFixture) {
  // The client's own prefix — the VM will push to this client
  HashPrefix myId = getMyId();

  // Set up push callback to capture received data
  ces::Bytes received;
  std::atomic<bool> gotPush{false};
  client->onApplicationMessage([&](const uint8_t* data, size_t len) {
    received.assign(data, data + len);
    gotPush = true;
  });

  // Build a program that sends "HELLO" to the caller via SYS_SEND_CLIENT.
  // The caller's prefix is preloaded at io[CESVM_IO_CALLER_KEY] (4 cells = 32 bytes).
  // But SYS_SEND_CLIENT needs a HashPrefix (8 bytes) at io[4].
  // The caller key is the full 32-byte public key. We need the 8-byte prefix.
  // The prefix is the first 8 bytes of the key, which is at CESVM_IO_CALLER_KEY.
  // So we MOV 1 cell from CESVM_IO_CALLER_KEY to io[16] for the prefix arg.
  //
  // Data "HELLO" at io[24]: SET io[24] = 0x48454c4c4f (but that's >63, use STB).
  // Simpler: just send 1 byte (0x42) at io[24].

  minx::Hash assetId;
  assetId.fill(0);
  assetId[0] = 0xF0; assetId[1] = 0x01;
  AssetData pgm{};
  size_t pc = 0;

  // Copy caller prefix from preloaded io[CESVM_IO_CALLER_KEY] to io[16]
  // CESVM_IO_CALLER_KEY = 756, need push2 for SET
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 756); pc += 2;
  // MOV 1 cell from io[756] to io[16]
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(1);

  // Copy "HELLO" from input (preloaded at CESVM_IO_INPUT=892) to io[24]
  // Input is 5 bytes = 1 cell (padded with zeros)
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(24); pgm[pc++] = rp(9); pgm[pc++] = sv(1);

  // SYS_SEND_CLIENT: io[4]=16 (prefix ptr), io[5]=24 (data ptr), io[6]=5 (5 bytes)
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_SEND_CLIENT);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(24);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(6); pgm[pc++] = sv(5);
  pgm[pc++] = OP_HOST;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(assetId, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  ces::Bytes input = {'H', 'E', 'L', 'L', 'O'};
  rc = client->runAsset(assetId, 1'000'000'000, input, vmError, budgetUsed, output);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);

  // Wait briefly for the APPLICATION packet to arrive
  ces::waitFor(2000, [&]() { return gotPush.load(); });

  BOOST_CHECK(gotPush);
  BOOST_REQUIRE_EQUAL(received.size(), 5);
  std::string msg(received.begin(), received.end());
  BOOST_TEST_MESSAGE("VM pushed to client: \"" << msg << "\"");
  BOOST_CHECK_EQUAL(msg, "HELLO");
}

BOOST_FIXTURE_TEST_CASE(NoncelessRunAssetCounter, CesFixture) {
  // Program: read asset content byte 0 as counter, increment, write back.
  // The asset is both the program AND the counter storage.
  //
  // Bytecode:
  //   Read self asset → content at io[32]
  //   LDB byte 256 (io[32] byte 0) → R = counter
  //   INC R (io[1])
  //   STB byte 256, R → write counter back
  //   Update self asset with new content from io[32]
  //   TERM

  minx::Hash assetId;
  assetId.fill(0);
  assetId[0] = 0xF0; assetId[1] = 0x99;
  // Read self, increment byte 209 of content, update self.
  VmProgram p;
  Region key     = p.allocHash();
  Region buf     = p.allocContent();
  p.copySelfKeyTo(key);
  p.readAndUpdateAsset(key, buf, [buf](VmProgram& b){
    b.ldbFromCell(buf, 209);
    b.inc(Imm(CESVM_CELL_R));
    b.stbInCell(buf, 209, Ref(CESVM_CELL_R));
  });
  p.term();
  AssetData pgm = p.buildBootBlock();

  // Create the asset with initial content (counter = 0)
  uint8_t rc = client->createAsset(assetId, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Run 3 times with nonceless — counter should go 0→1→2→3
  for (int i = 0; i < 3; ++i) {
    uint64_t vmError = 0, budgetUsed = 0;
    ces::Bytes output;
    rc = client->runAsset(assetId, 1'000'000'000, {}, vmError, budgetUsed, output, true);
    BOOST_CHECK_EQUAL(rc, CES_OK);
    BOOST_CHECK_EQUAL(vmError, CESVM_OK);
  }

  // Query the asset and check the counter
  HashPrefix owner;
  AssetData content;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(assetId, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_TEST_MESSAGE("Counter after 3 nonceless runs: " << (int)content[209]);
  BOOST_CHECK_EQUAL(content[209], 3);
}

BOOST_FIXTURE_TEST_CASE(ScheduledRunAsset, CesFixture) {
  // Reuse the counter-increment program from NoncelessRunAssetCounter.
  // First run: create asset with counter program, run it once to set counter=1.
  // Then: from within a VM, schedule a second run 200ms in the future.
  // Wait, then verify counter=2.

  // Counter program: read self, increment byte 209, write back.
  minx::Hash counterAsset;
  counterAsset.fill(0);
  counterAsset[0] = 0xF0; counterAsset[1] = 0xB0;
  VmProgram p;
  Region key     = p.allocHash();
  Region buf     = p.allocContent();
  p.copySelfKeyTo(key);
  p.readAndUpdateAsset(key, buf, [buf](VmProgram& b){
    b.ldbFromCell(buf, 209);
    b.inc(Imm(CESVM_CELL_R));
    b.stbInCell(buf, 209, Ref(CESVM_CELL_R));
  });
  p.term();
  AssetData pgm = p.buildBootBlock();

  uint8_t rc = client->createAsset(counterAsset, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Run once to set counter=1
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(counterAsset, 1'000'000'000, {}, vmError, budgetUsed, output, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Now create a "scheduler" program that schedules the counter to run 200ms from now
  minx::Hash schedulerAsset;
  schedulerAsset.fill(0);
  schedulerAsset[0] = 0xF0; schedulerAsset[1] = 0xA1;
  AssetData schedPgm{};
  size_t pc = 0;
  // The counter asset key is passed as input (32 bytes at io[892])
  // Copy it to io[16]
  schedPgm[pc++] = OP_SET; schedPgm[pc++] = sv(9);
  schedPgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(schedPgm.data() + pc, 892); pc += 2;
  schedPgm[pc++] = OP_MOV; schedPgm[pc++] = sv(16); schedPgm[pc++] = rp(9); schedPgm[pc++] = sv(4);
  // SYS_SCHEDULE: io[4]=16 (asset key), io[5]=budget, io[6]=child_allowance (0 — counter doesn't spend),
  //               io[7]=0 (no input), io[8]=0 (input len), io[9]=time
  schedPgm[pc++] = OP_SET; schedPgm[pc++] = sv(3); schedPgm[pc++] = sv(SYS_SCHEDULE);
  schedPgm[pc++] = OP_SET; schedPgm[pc++] = sv(4); schedPgm[pc++] = sv(16);
  // budget = 10000000 — too big for sv, use TIME opcode to get "now" then add 200000 (200ms)
  // Actually, just set budget to 50 (small, sufficient for counter program at unit test gas mult)
  // Budget needs to cover gasMult (50). Use 4-byte encoding for 10000000.
  schedPgm[pc++] = OP_SET; schedPgm[pc++] = sv(5);
  { uint32_t b = 1'000'000'000;  // child counter program needs headroom
                                  // for SYS_UPDATE_ASSET feeAsset rent
                                  // (now billed against budget).
    schedPgm[pc++] = 4;
    ces::Buffer::pokeLE<uint32_t>(schedPgm.data() + pc, b); pc += 4;
  }
  schedPgm[pc++] = OP_SET; schedPgm[pc++] = sv(6); schedPgm[pc++] = sv(0); // child_allowance = 0
  schedPgm[pc++] = OP_SET; schedPgm[pc++] = sv(7); schedPgm[pc++] = sv(0); // no input ptr
  schedPgm[pc++] = OP_SET; schedPgm[pc++] = sv(8); schedPgm[pc++] = sv(0); // input len = 0
  // time = now + 100ms (TIME gives microseconds, add 100000)
  schedPgm[pc++] = OP_TIME; // R = now in microseconds
  schedPgm[pc++] = OP_SET; schedPgm[pc++] = sv(10);
  { uint32_t delay = 100000; // 100ms
    schedPgm[pc++] = 4;
    ces::Buffer::pokeLE<uint32_t>(schedPgm.data() + pc, delay); pc += 4;
  }
  schedPgm[pc++] = OP_ADD; schedPgm[pc++] = rp(1); schedPgm[pc++] = rp(10);
  schedPgm[pc++] = OP_SET; schedPgm[pc++] = sv(9); schedPgm[pc++] = rp(1); // io[9] = time_us
  schedPgm[pc++] = OP_HOSTX;
  schedPgm[pc++] = OP_TERM;

  rc = client->createAsset(schedulerAsset, schedPgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Small delay to ensure different nonceless timestamp
  wait_net();

  // Run the scheduler — it schedules the counter to run on next cron tick
  ces::Bytes schedInput(counterAsset.begin(), counterAsset.end());
  rc = client->runAsset(schedulerAsset, 1'000'000'000, schedInput,
                         vmError, budgetUsed, output, true);
  BOOST_TEST_MESSAGE("Scheduler rc=" << (int)rc << " vmError=" << vmError
                     << " budgetUsed=" << budgetUsed);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);

  // Verify counter is still 1 — scheduled run hasn't fired yet (100ms delay)
  {
    HashPrefix owner;
    AssetData content;
    uint16_t days = 0;
    uint32_t price = 0;
    rc = client->queryAsset(counterAsset, owner, content, days, price);
    BOOST_REQUIRE_EQUAL(rc, CES_OK);
    BOOST_TEST_MESSAGE("Counter before cron: " << (int)content[209]);
    BOOST_CHECK_EQUAL(content[209], 1);
  }

  // Wait for scheduled run to fire (100ms delay + margin)
  ces::sleep(1000);

  // Verify counter is 2 — scheduled run has fired
  {
    HashPrefix owner;
    AssetData content;
    uint16_t days = 0;
    uint32_t price = 0;
    rc = client->queryAsset(counterAsset, owner, content, days, price);
    BOOST_REQUIRE_EQUAL(rc, CES_OK);
    BOOST_TEST_MESSAGE("Counter after cron: " << (int)content[209]);
    BOOST_CHECK_EQUAL(content[209], 2);
  }
}

BOOST_FIXTURE_TEST_CASE(AutoexecAsset, CesFixture) {
  // Create the counter program asset (read self, inc byte 209, update self).
  minx::Hash counterAsset;
  counterAsset.fill(0);
  counterAsset[0] = 0xF0; counterAsset[1] = 0xC0;
  VmProgram p;
  Region key     = p.allocHash();
  Region buf     = p.allocContent();
  p.copySelfKeyTo(key);
  p.readAndUpdateAsset(key, buf, [buf](VmProgram& b){
    b.ldbFromCell(buf, 209);
    b.inc(Imm(CESVM_CELL_R));
    b.stbInCell(buf, 209, Ref(CESVM_CELL_R));
  });
  p.term();
  AssetData pgm = p.buildBootBlock();

  uint8_t rc = client->createAsset(counterAsset, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Build autoexec asset using utility
  auto autoKey = buildAutoexecKey(getMyId());
  auto autoContent = buildAutoexecContent(
    counterAsset, 1'000'000'000, {}, clientKey, client->getServerId());
  BOOST_REQUIRE(autoContent);

  rc = client->createAsset(autoKey, *autoContent, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // Counter should be 0 before autoexec
  {
    HashPrefix owner;
    AssetData content;
    uint16_t days = 0;
    uint32_t price = 0;
    rc = client->queryAsset(counterAsset, owner, content, days, price);
    BOOST_REQUIRE_EQUAL(rc, CES_OK);
    BOOST_TEST_MESSAGE("Counter before autoexec: " << (int)content[209]);
    BOOST_CHECK_EQUAL(content[209], 0);
  }

  // Simulate server boot
  server->_runAutoexecSync();
  wait_net();

  // Counter should be 1 after autoexec
  {
    HashPrefix owner;
    AssetData content;
    uint16_t days = 0;
    uint32_t price = 0;
    rc = client->queryAsset(counterAsset, owner, content, days, price);
    BOOST_REQUIRE_EQUAL(rc, CES_OK);
    BOOST_TEST_MESSAGE("Counter after autoexec: " << (int)content[209]);
    BOOST_CHECK_EQUAL(content[209], 1);
  }
}

BOOST_AUTO_TEST_CASE(AutoexecContentInputCap) {
  // The whole signed run-request lives in one 210-byte asset cell, so input
  // that overflows it must be rejected, not silently truncated.
  KeyPair k;
  minx::Hash programId;
  programId.fill(0xAB);
  HashPrefix serverId;
  serverId.fill(0x11);

  auto fits = buildAutoexecContent(programId, 1000, {}, k, serverId);
  BOOST_REQUIRE(fits.has_value());

  ces::Bytes tooBig(256, 0xCD);
  auto over = buildAutoexecContent(programId, 1000, tooBig, k, serverId);
  BOOST_CHECK(!over.has_value());
}

BOOST_FIXTURE_TEST_CASE(AutoexecDeletesGarbage, CesFixture) {
  // Create an autoexec asset with garbage content
  auto autoKey = buildAutoexecKey(getMyId());
  AssetData garbage{};
  garbage[0] = 0xFF; // bad length prefix
  uint8_t rc = client->createAsset(autoKey, garbage, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // Verify it exists
  HashPrefix owner;
  AssetData content;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(autoKey, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // runAutoexec should delete it
  server->_runAutoexecSync();
  wait_net();

  // Verify the asset is gone. Unsigned queryAsset returns CES_OK with
  // zeroed fields when the asset doesn't exist.
  rc = client->queryAsset(autoKey, owner, content, days, price);
  CES_CHECK_OK(rc);
  BOOST_CHECK_EQUAL(days, 0);
}

BOOST_FIXTURE_TEST_CASE(AutoexecDeletesBroke, CesFixture) {
  // Create a counter program
  minx::Hash counterAsset;
  counterAsset.fill(0);
  counterAsset[0] = 0xF0; counterAsset[1] = 0xD0;
  AssetData pgm{};
  pgm[0] = OP_TERM; // simplest program
  uint8_t rc = client->createAsset(counterAsset, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Create a second account with barely any money
  KeyPair brokeKey;
  server->_brr(brokeKey.getPublicKeyAsHash(), 1000); // very low balance

  // Build autoexec with huge budget the broke account can't afford
  auto autoKey = buildAutoexecKey(Account::getMapKey(brokeKey.getPublicKeyAsHash()));
  auto autoContent = buildAutoexecContent(
    counterAsset, 999999999, {}, brokeKey, client->getServerId());
  BOOST_REQUIRE(autoContent);
  rc = client->createAsset(autoKey, *autoContent, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // runAutoexec: account can't pay → should delete autoexec asset
  server->_runAutoexecSync();
  wait_net();

  // Verify the asset is gone. Unsigned queryAsset returns CES_OK with
  // zeroed fields when the asset doesn't exist.
  HashPrefix owner;
  AssetData content;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(autoKey, owner, content, days, price);
  CES_CHECK_OK(rc);
  BOOST_CHECK_EQUAL(days, 0);
}

BOOST_FIXTURE_TEST_CASE(ProgramAuthWritesCrossOwner, CesFixture) {
  // Account A (clientKey) owns the program and a data asset.
  // Account B runs the program. The program writes to A's data asset.
  // This should succeed because of program auth.

  // Create a data asset owned by A (clientKey)
  minx::Hash dataAsset;
  dataAsset.fill(0);
  dataAsset[0] = 0xF0; dataAsset[1] = 0xE0;
  AssetData dataContent{};
  dataContent[209] = 0; // counter at byte 209
  uint8_t rc = client->createAsset(dataAsset, dataContent, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Create the counter program owned by A — reads dataAsset key from
  // input, reads dataAsset, increments byte 209, writes back. Update
  // succeeds via program auth (program owned by A, target owned by A).
  minx::Hash programAsset;
  programAsset.fill(0);
  programAsset[0] = 0xF0; programAsset[1] = 0xE1;
  VmProgram p;
  Region key     = p.allocHash();
  Region buf     = p.allocContent();
  p.copyFromInput(key, /*inputCellOffset=*/0);
  p.readAndUpdateAsset(key, buf, [buf](VmProgram& b){
    b.ldbFromCell(buf, 209);
    b.inc(Imm(CESVM_CELL_R));
    b.stbInCell(buf, 209, Ref(CESVM_CELL_R));
  });
  p.term();
  AssetData pgm = p.buildBootBlock();

  rc = client->createAsset(programAsset, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Create account B and fund it
  KeyPair accountB;
  server->_brr(accountB.getPublicKeyAsHash(), 10'000'000'000);
  wait_net();

  // Account B runs the program (owned by A) with dataAsset as input
  // B connects as a separate client
  boost::asio::ip::udp::endpoint ep(
    boost::asio::ip::address_v6::loopback(), serverPort);
  CesClient clientB(ep, false);
  clientB.start(0);
  clientB.setKey(accountB);
  BOOST_REQUIRE(clientB.connect());

  ces::Bytes input(dataAsset.begin(), dataAsset.end());
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = clientB.runAsset(programAsset, 1'000'000'000, input, vmError, budgetUsed, output, true);
  BOOST_TEST_MESSAGE("Program auth test: rc=" << (int)rc << " vmError=" << vmError);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);

  // Verify: counter should be 1 — B ran A's program which wrote to A's data
  HashPrefix owner;
  AssetData content;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(dataAsset, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_TEST_MESSAGE("Counter after cross-owner program run: " << (int)content[209]);
  BOOST_CHECK_EQUAL(content[209], 1);

  clientB.stop();
}

BOOST_FIXTURE_TEST_CASE(VMReadsPrivateAsset, CesFixture) {
  // Create a private data asset with known content
  minx::Hash dataAsset;
  dataAsset.fill(0);
  dataAsset[0] = 0xF0; dataAsset[1] = 0xF1;
  AssetData dataContent{};
  dataContent[209] = 42; // value at byte 209
  uint8_t rc = client->createAsset(dataAsset, dataContent, 30, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Verify it's private (unsigned query hides content)
  {
    HashPrefix owner;
    AssetData content;
    uint16_t days = 0;
    uint32_t price = 0;
    rc = client->queryAsset(dataAsset, owner, content, days, price);
    BOOST_REQUIRE_EQUAL(rc, CES_OK);
    BOOST_CHECK_EQUAL(content[209], 0); // hidden
  }

  // Program: read the private asset via SYS_READ_ASSET, copy byte 209
  // to output. The VM should see the real content.
  minx::Hash programAsset;
  programAsset.fill(0);
  programAsset[0] = 0xF0; programAsset[1] = 0xF2;
  VmProgram p;
  Region key      = p.allocHash();
  Region buf      = p.allocContent();
  Region ownerOut = p.allocHashPrefix();
  p.copyFromInput(key, /*inputCellOffset=*/0);
  p.sysReadAsset({.keyPtr = key, .ownerOutCell = ownerOut, .contentOutCell = buf});
  p.ldbFromCell(buf, 209);                 // R = content[209]
  p.setOutput(Ref(CESVM_CELL_R), 1);       // output[0] = low byte of R
  p.term();
  AssetData pgm = p.buildBootBlock();

  rc = client->createAsset(programAsset, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Run the program with the private data asset key as input
  ces::Bytes input(dataAsset.begin(), dataAsset.end());
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(programAsset, 1'000'000'000, input, vmError, budgetUsed, output, true);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);
  BOOST_REQUIRE_EQUAL(output.size(), 1);
  BOOST_TEST_MESSAGE("VM read private asset byte 209 = " << (int)output[0]);
  BOOST_CHECK_EQUAL(output[0], 42); // VM sees the real content
}

BOOST_FIXTURE_TEST_CASE(DualAuthPrivateAssetCrossOwner, CesFixture) {
  // Account A (clientKey) creates a PRIVATE data asset.
  // Account A creates a program that reads the private asset.
  // Account B runs A's program → program auth allows reading A's private data.

  minx::Hash dataAsset;
  dataAsset.fill(0);
  dataAsset[0] = 0xF0; dataAsset[1] = 0xF3;
  AssetData dataContent{};
  dataContent[209] = 99;
  uint8_t rc = client->createAsset(dataAsset, dataContent, 30, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Same reader program as above but also writes back (proving write auth).
  minx::Hash programAsset;
  programAsset.fill(0);
  programAsset[0] = 0xF0; programAsset[1] = 0xF4;
  VmProgram p;
  Region key     = p.allocHash();
  Region buf     = p.allocContent();
  p.copyFromInput(key, /*inputCellOffset=*/0);
  p.readAndUpdateAsset(key, buf, [buf](VmProgram& b){
    b.ldbFromCell(buf, 209);
    b.inc(Imm(CESVM_CELL_R));
    b.stbInCell(buf, 209, Ref(CESVM_CELL_R));
  });
  p.term();
  AssetData pgm = p.buildBootBlock();

  rc = client->createAsset(programAsset, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Account B
  KeyPair accountB;
  server->_brr(accountB.getPublicKeyAsHash(), 10'000'000'000);
  wait_net();

  boost::asio::ip::udp::endpoint ep(
    boost::asio::ip::address_v6::loopback(), serverPort);
  CesClient clientB(ep, false);
  clientB.start(0);
  clientB.setKey(accountB);
  BOOST_REQUIRE(clientB.connect());

  // B runs A's program on A's private data
  ces::Bytes input(dataAsset.begin(), dataAsset.end());
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = clientB.runAsset(programAsset, 1'000'000'000, input, vmError, budgetUsed, output, true);
  BOOST_TEST_MESSAGE("Dual auth private: rc=" << (int)rc << " vmError=" << vmError);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);

  // Verify: byte 209 incremented from 99 to 100 (owner A signed query)
  std::vector<AssetEntry> results;
  rc = client->queryAssetSigned(dataAsset, 0, results);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE(!results.empty());
  BOOST_TEST_MESSAGE("Private asset byte 209 after cross-owner run: " << (int)results[0].content[209]);
  BOOST_CHECK_EQUAL(results[0].content[209], 100);

  clientB.stop();
}

// --- SYS_CREATE_ASSET_MANAGED (asset-owned assets) ---

BOOST_FIXTURE_TEST_CASE(ManagedAssetCreatedByVM, CesFixture) {
  // Program creates a managed asset. The created asset should be
  // owned by the program's asset prefix (not the runner's account).

  // Data asset key (the managed asset to be created)
  minx::Hash managedKey;
  managedKey.fill(0);
  managedKey[0] = 0xE0; managedKey[1] = 0x01;

  // Program: create managed asset with key from input, content all zeros, 10 days
  minx::Hash programAsset;
  programAsset.fill(0);
  programAsset[0] = 0xE0; programAsset[1] = 0x02;
  AssetData pgm{};
  size_t pc = 0;
  // Copy managed key from input (offset 892) to io[16..47]
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  // SYS_CREATE_ASSET_MANAGED: key at io[16], content at io[32], days=10
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_CREATE_ASSET_MANAGED);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);  // key ptr
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(32);  // content ptr (zeros)
  pgm[pc++] = OP_SET; pgm[pc++] = sv(6); pgm[pc++] = sv(10);  // days
  pgm[pc++] = OP_HOSTX;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(programAsset, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Run the program with managedKey as input
  ces::Bytes input(managedKey.begin(), managedKey.end());
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(programAsset, 1'000'000'000, input, vmError, budgetUsed, output, true);
  BOOST_TEST_MESSAGE("ManagedCreate: rc=" << (int)rc << " vmError=" << vmError);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  // Query the managed asset — should exist
  HashPrefix owner;
  AssetData content;
  uint16_t balance = 0;
  uint32_t price = 0;
  rc = client->queryAsset(managedKey, owner, content, balance, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Owner should be the program asset's prefix, not the runner's
  HashPrefix programPrefix = Account::getMapKey(programAsset);
  HashPrefix runnerPrefix = Account::getMapKey(clientKey.getPublicKeyAsHash());
  BOOST_TEST_MESSAGE("Managed asset owner matches program prefix: " << (owner == programPrefix));
  BOOST_TEST_MESSAGE("Managed asset owner matches runner prefix:  " << (owner == runnerPrefix));
  BOOST_CHECK(owner == programPrefix);
  BOOST_CHECK(owner != runnerPrefix);
  // Note: balance from query has flags stripped (assetDays only).
  // The asset-owned bit is internal — verified by the auth checks in other tests.
}

BOOST_FIXTURE_TEST_CASE(ManagedAssetWriteByOwningProgram, CesFixture) {
  // Program creates a managed asset, then writes to it. Should succeed.
  // We write byte 0 of content = 0x37 (simple, avoids >63 encoding issues).
  minx::Hash managedKey;
  managedKey.fill(0);
  managedKey[0] = 0xE1; managedKey[1] = 0x01;

  minx::Hash programAsset;
  programAsset.fill(0);
  programAsset[0] = 0xE1; programAsset[1] = 0x02;
  AssetData pgm{};
  size_t pc = 0;
  // Copy managed key from input to data[16..47]
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);  // io[9] = 892 (input base)
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  // Create managed asset: key at data[16], content at data[32], days=10
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_CREATE_ASSET_MANAGED);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(32);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(6); pgm[pc++] = sv(10);
  pgm[pc++] = OP_HOSTX;
  // Write byte 0 of content area: content starts at io[32] = byte offset 256
  pgm[pc++] = OP_SET; pgm[pc++] = sv(1); pgm[pc++] = sv(0x37);  // io[1] = 55
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);                         // io[9] = 256
  pgm[pc++] = 2; pgm[pc++] = 0; pgm[pc++] = 1;                  // 256 = 0x0100
  pgm[pc++] = OP_STB; pgm[pc++] = rp(9); pgm[pc++] = rp(1);
  // Update asset: key at data[16], content at data[32]
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_UPDATE_ASSET);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(32);
  pgm[pc++] = OP_HOSTX;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(programAsset, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input(managedKey.begin(), managedKey.end());
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(programAsset, 1'000'000'000, input, vmError, budgetUsed, output, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  // Verify byte 0 was written
  HashPrefix owner;
  AssetData content;
  uint16_t balance = 0;
  uint32_t price = 0;
  rc = client->queryAsset(managedKey, owner, content, balance, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(content[0], 0x37);
}

BOOST_FIXTURE_TEST_CASE(ManagedAssetRejectDirectProtocolWrite, CesFixture) {
  // A managed asset created by program A should NOT be writable via
  // the direct CES_UPDATE_ASSET protocol by the runner (account owner).

  // First create via VM
  minx::Hash managedKey;
  managedKey.fill(0);
  managedKey[0] = 0xE2; managedKey[1] = 0x01;

  minx::Hash programAsset;
  programAsset.fill(0);
  programAsset[0] = 0xE2; programAsset[1] = 0x02;
  AssetData pgm{};
  size_t pc = 0;
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_CREATE_ASSET_MANAGED);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(32);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(6); pgm[pc++] = sv(10);
  pgm[pc++] = OP_HOSTX;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(programAsset, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input(managedKey.begin(), managedKey.end());
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(programAsset, 1'000'000'000, input, vmError, budgetUsed, output, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  // Now try direct protocol update — should fail with NOT_OWNER
  AssetData newContent{};
  newContent[0] = 0xFF;
  rc = client->updateAssetFast(managedKey, newContent);
  BOOST_TEST_MESSAGE("Direct protocol update of managed asset: rc=" << (int)rc);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_NOT_OWNER);
}

BOOST_FIXTURE_TEST_CASE(ManagedAssetRejectDifferentProgram, CesFixture) {
  // A managed asset created by program A should NOT be writable by
  // a different program B (even if B is owned by the same account).

  minx::Hash managedKey;
  managedKey.fill(0);
  managedKey[0] = 0xE3; managedKey[1] = 0x01;

  // Program A creates the managed asset
  minx::Hash programA;
  programA.fill(0);
  programA[0] = 0xE3; programA[1] = 0x02;
  AssetData pgmA{};
  size_t pc = 0;
  pgmA[pc++] = OP_SET; pgmA[pc++] = sv(9);
  pgmA[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgmA.data() + pc, 892); pc += 2;
  pgmA[pc++] = OP_MOV; pgmA[pc++] = sv(16); pgmA[pc++] = rp(9); pgmA[pc++] = sv(4);
  pgmA[pc++] = OP_SET; pgmA[pc++] = sv(3); pgmA[pc++] = sv(SYS_CREATE_ASSET_MANAGED);
  pgmA[pc++] = OP_SET; pgmA[pc++] = sv(4); pgmA[pc++] = sv(16);
  pgmA[pc++] = OP_SET; pgmA[pc++] = sv(5); pgmA[pc++] = sv(32);
  pgmA[pc++] = OP_SET; pgmA[pc++] = sv(6); pgmA[pc++] = sv(10);
  pgmA[pc++] = OP_HOSTX;
  pgmA[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(programA, pgmA, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input(managedKey.begin(), managedKey.end());
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(programA, 1'000'000'000, input, vmError, budgetUsed, output, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  // Program B tries to update the managed asset — should fail
  minx::Hash programB;
  programB.fill(0);
  programB[0] = 0xE3; programB[1] = 0x03;
  AssetData pgmB{};
  pc = 0;
  pgmB[pc++] = OP_SET; pgmB[pc++] = sv(9);
  pgmB[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgmB.data() + pc, 892); pc += 2;
  pgmB[pc++] = OP_MOV; pgmB[pc++] = sv(16); pgmB[pc++] = rp(9); pgmB[pc++] = sv(4);
  // Try to update
  pgmB[pc++] = OP_SET; pgmB[pc++] = sv(3); pgmB[pc++] = sv(SYS_UPDATE_ASSET);
  pgmB[pc++] = OP_SET; pgmB[pc++] = sv(4); pgmB[pc++] = sv(16);
  pgmB[pc++] = OP_SET; pgmB[pc++] = sv(5); pgmB[pc++] = sv(32);
  pgmB[pc++] = OP_HOST;  // HOST not HOSTX — don't abort, just set S
  pgmB[pc++] = OP_TERM;

  rc = client->createAsset(programB, pgmB, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  rc = client->runAsset(programB, 1'000'000'000, input, vmError, budgetUsed, output, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);
  // The update should have failed — S should be NOT_OWNER, but we can't
  // easily read S from outside. Instead verify the content is unchanged.
  HashPrefix owner;
  AssetData content;
  uint16_t balance = 0;
  uint32_t price = 0;
  rc = client->queryAsset(managedKey, owner, content, balance, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  // Content should still be all zeros (program B's write was rejected)
  BOOST_CHECK_EQUAL(content[0], 0);
}

// --- Allowance enforcement (per-run cap on caller debits) ---

// A SYS_TRANSFER inside a VM run with an allowance smaller than the
// transfer amount must abort the syscall with
// CES_ERROR_ALLOWANCE_EXCEEDED. Allowance is the cap on caller-side
// *spending* (transfer amounts, not protocol fees — fees go through a
// separate non-allowance debit path). Using OP_HOSTX turns the syscall
// failure into a VM abort, surfaced as CES_ERROR_VM_FAILED with
// vmError == CESVM_ABORT.
BOOST_FIXTURE_TEST_CASE(AllowanceCapBlocksTransfer, CesFixture) {
  KeyPair destKey;
  server->_brr(destKey.getPublicKeyAsHash(), 1000);

  minx::Hash assetId;
  assetId.fill(0);
  assetId[0] = 0xA1; assetId[1] = 0x01;

  AssetData pgm{};
  size_t pc = 0;
  // io[9] = CESVM_IO_INPUT (892), copy 4 cells from input -> io[16] (dest key)
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  // SYS_TRANSFER 50 to io[16] -- HOSTX so the allowance error aborts the VM
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_TRANSFER);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(50);
  pgm[pc++] = OP_HOSTX;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(assetId, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input(destKey.getPublicKeyAsHash().begin(),
                              destKey.getPublicKeyAsHash().end());

  int64_t destBalBefore = 0;
  uint32_t destNonceBefore = 0;
  HashPrefix destId = Account::getMapKey(destKey.getPublicKeyAsHash());
  rc = client->queryAccount(destId, destBalBefore, destNonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Allowance smaller than the transfer amount (50) -- the syscall's
  // amount debit trips the allowance check and HOSTX turns it into an
  // abort. The fee debit is on a separate (non-allowance) path so it
  // doesn't mask the failure mode under test here.
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(assetId, 1'000'000'000, input, vmError, budgetUsed,
                         output, false /*nonceless*/, 49 /*allowance*/);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_VM_FAILED);
  BOOST_CHECK_EQUAL(vmError, CESVM_ABORT);

  // Destination should not have received anything -- the failed SYS_TRANSFER
  // was the only mutation the program tried, and the abort + undo log should
  // have rolled it back.
  int64_t destBalAfter = 0;
  uint32_t destNonceAfter = 0;
  rc = client->queryAccount(destId, destBalAfter, destNonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(destBalAfter, destBalBefore);
}

// Same program, but with an allowance large enough to cover transfer + feeTx,
// runs to completion and the destination receives the funds.
BOOST_FIXTURE_TEST_CASE(AllowanceCapAllowsTransferUnderCap, CesFixture) {
  KeyPair destKey;
  server->_brr(destKey.getPublicKeyAsHash(), 1000);

  minx::Hash assetId;
  assetId.fill(0);
  assetId[0] = 0xA1; assetId[1] = 0x02;

  AssetData pgm{};
  size_t pc = 0;
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_TRANSFER);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(50);
  pgm[pc++] = OP_HOSTX;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(assetId, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input(destKey.getPublicKeyAsHash().begin(),
                              destKey.getPublicKeyAsHash().end());

  int64_t destBalBefore = 0;
  uint32_t destNonceBefore = 0;
  HashPrefix destId = Account::getMapKey(destKey.getPublicKeyAsHash());
  rc = client->queryAccount(destId, destBalBefore, destNonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Allowance: transfer amount (50) + feeTx + a small slack.
  uint64_t allowance = 50 + BASE_FEE_TRANSACTION + 1000;
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(assetId, 1'000'000'000, input, vmError, budgetUsed,
                         output, false, allowance);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);

  int64_t destBalAfter = 0;
  uint32_t destNonceAfter = 0;
  rc = client->queryAccount(destId, destBalAfter, destNonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(destBalAfter, destBalBefore + 50);
}

// Default allowance (UINT64_MAX) means no enforcement: a program with the
// default allowance behaves identically to the pre-allowance world.
BOOST_FIXTURE_TEST_CASE(AllowanceDefaultNoEnforcement, CesFixture) {
  KeyPair destKey;
  server->_brr(destKey.getPublicKeyAsHash(), 1000);

  minx::Hash assetId;
  assetId.fill(0);
  assetId[0] = 0xA1; assetId[1] = 0x03;

  AssetData pgm{};
  size_t pc = 0;
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_TRANSFER);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(50);
  pgm[pc++] = OP_HOSTX;
  pgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(assetId, pgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input(destKey.getPublicKeyAsHash().begin(),
                              destKey.getPublicKeyAsHash().end());

  int64_t destBalBefore = 0;
  uint32_t destNonceBefore = 0;
  HashPrefix destId = Account::getMapKey(destKey.getPublicKeyAsHash());
  rc = client->queryAccount(destId, destBalBefore, destNonceBefore);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Don't pass an allowance argument -- defaults to UINT64_MAX.
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(assetId, 1'000'000'000, input, vmError, budgetUsed,
                         output);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, CESVM_OK);

  int64_t destBalAfter = 0;
  uint32_t destNonceAfter = 0;
  rc = client->queryAccount(destId, destBalAfter, destNonceAfter);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(destBalAfter, destBalBefore + 50);
}

// Phase-2 carry-over: a parent program that calls SYS_SCHEDULE forwards its
// remaining allowance to the scheduled child run. The child sees the same
// cap and aborts on syscalls that would exceed it.
//
// Setup: parent program copies (childKey, destKey) from input and queues a
// child program via SYS_SCHEDULE. The child does a SYS_TRANSFER of 50 to
// destKey via OP_HOSTX. We run the parent twice with different allowances:
// once tight enough that the child's feeTx debit fails, once loose enough
// that the child runs to completion.
BOOST_FIXTURE_TEST_CASE(AllowanceCarriesIntoScheduledChild, CesFixture) {
  // --- Build the child program ---
  minx::Hash childAsset;
  childAsset.fill(0);
  childAsset[0] = 0xA2; childAsset[1] = 0x01;
  AssetData childPgm{};
  size_t pc = 0;
  // io[9] = CESVM_IO_INPUT (892); copy 4 cells -> io[16] (dest key)
  childPgm[pc++] = OP_SET; childPgm[pc++] = sv(9);
  childPgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(childPgm.data() + pc, 892); pc += 2;
  childPgm[pc++] = OP_MOV; childPgm[pc++] = sv(16); childPgm[pc++] = rp(9); childPgm[pc++] = sv(4);
  // SYS_TRANSFER 50 to io[16] -- HOSTX so allowance failure aborts the child
  childPgm[pc++] = OP_SET; childPgm[pc++] = sv(3); childPgm[pc++] = sv(SYS_TRANSFER);
  childPgm[pc++] = OP_SET; childPgm[pc++] = sv(4); childPgm[pc++] = sv(16);
  childPgm[pc++] = OP_SET; childPgm[pc++] = sv(5); childPgm[pc++] = sv(50);
  childPgm[pc++] = OP_HOSTX;
  childPgm[pc++] = OP_TERM;

  uint8_t rc = client->createAsset(childAsset, childPgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // --- Build the parent program ---
  // Parent input layout: [childKey (32)] [destKey (32)]
  // Parent does:
  //   - copy childKey from input[0..32]  -> io[16]
  //   - copy destKey  from input[32..64] -> io[24]
  //   - SYS_SCHEDULE asset=io[16], budget=10M, input_ptr=24, input_len=32, time=0
  //   - TERM
  minx::Hash parentAsset;
  parentAsset.fill(0);
  parentAsset[0] = 0xA2; parentAsset[1] = 0x02;
  AssetData parentPgm{};
  pc = 0;
  // io[9] = 892, copy 4 cells -> io[16] (childKey)
  parentPgm[pc++] = OP_SET; parentPgm[pc++] = sv(9);
  parentPgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(parentPgm.data() + pc, 892); pc += 2;
  parentPgm[pc++] = OP_MOV; parentPgm[pc++] = sv(16); parentPgm[pc++] = rp(9); parentPgm[pc++] = sv(4);
  // io[9] = 896, copy 4 cells -> io[24] (destKey, also the child's input)
  parentPgm[pc++] = OP_SET; parentPgm[pc++] = sv(9);
  parentPgm[pc++] = 2; ces::Buffer::pokeLE<uint16_t>(parentPgm.data() + pc, 896); pc += 2;
  parentPgm[pc++] = OP_MOV; parentPgm[pc++] = sv(24); parentPgm[pc++] = rp(9); parentPgm[pc++] = sv(4);
  // SYS_SCHEDULE: io[4]=child key ptr (16), io[5]=budget (10M as 4-byte literal),
  //               io[6]=child_allowance (= parent's full remaining allowance —
  //                                       hands the whole headroom across so
  //                                       Case A's tight cap propagates),
  //               io[7]=input ptr (24), io[8]=input len (32),
  //               io[9]=time_us (0 = next tick)
  parentPgm[pc++] = OP_SET; parentPgm[pc++] = sv(3); parentPgm[pc++] = sv(SYS_SCHEDULE);
  parentPgm[pc++] = OP_SET; parentPgm[pc++] = sv(4); parentPgm[pc++] = sv(16);
  parentPgm[pc++] = OP_SET; parentPgm[pc++] = sv(5);
  { uint32_t b = 10'000'000;
    parentPgm[pc++] = 4;
    ces::Buffer::pokeLE<uint32_t>(parentPgm.data() + pc, b); pc += 4;
  }
  // io[6] = io[CESVM_IO_ALLOWANCE=1020] (deref via REG_PTR + 2-byte payload)
  parentPgm[pc++] = OP_SET; parentPgm[pc++] = sv(6);
  parentPgm[pc++] = static_cast<uint8_t>(CESVM_REG_PTR | 2);
  ces::Buffer::pokeLE<uint16_t>(parentPgm.data() + pc, CESVM_IO_ALLOWANCE); pc += 2;
  parentPgm[pc++] = OP_SET; parentPgm[pc++] = sv(7); parentPgm[pc++] = sv(24);
  parentPgm[pc++] = OP_SET; parentPgm[pc++] = sv(8); parentPgm[pc++] = sv(32);
  parentPgm[pc++] = OP_SET; parentPgm[pc++] = sv(9); parentPgm[pc++] = sv(0);
  parentPgm[pc++] = OP_HOSTX;
  parentPgm[pc++] = OP_TERM;

  rc = client->createAsset(parentAsset, parentPgm, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // --- Case A: tight allowance, child should fail and dest stays unchanged ---
  KeyPair destA;
  server->_brr(destA.getPublicKeyAsHash(), 1000);
  HashPrefix destAId = Account::getMapKey(destA.getPublicKeyAsHash());
  int64_t destABefore = 0;
  uint32_t nonceTmp = 0;
  rc = client->queryAccount(destAId, destABefore, nonceTmp);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes inputA;
  inputA.insert(inputA.end(), childAsset.begin(), childAsset.end());
  inputA.insert(inputA.end(), destA.getPublicKeyAsHash().begin(),
                destA.getPublicKeyAsHash().end());

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  // Tight allowance: smaller than the child's hard-coded transfer
  // amount (50). The parent passes the allowance verbatim to the
  // child via SYS_SCHEDULE; the child's SYS_TRANSFER amount debit
  // trips the cap. (Fees are on a non-allowance path.)
  rc = client->runAsset(parentAsset, 10'000'000, inputA, vmError, budgetUsed,
                         output, false /*nonceless*/, 49 /*allowance*/);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  // Wait for cron to fire the scheduled child (CRON_TICK_INTERVAL_MS = 100ms).
  ces::sleep(500);

  int64_t destAAfter = 0;
  rc = client->queryAccount(destAId, destAAfter, nonceTmp);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_MESSAGE(destAAfter == destABefore,
    "tight-allowance child should not have transferred (before="
    << destABefore << " after=" << destAAfter << ")");

  // --- Case B: loose allowance, child runs to completion ---
  KeyPair destB;
  server->_brr(destB.getPublicKeyAsHash(), 1000);
  HashPrefix destBId = Account::getMapKey(destB.getPublicKeyAsHash());
  int64_t destBBefore = 0;
  rc = client->queryAccount(destBId, destBBefore, nonceTmp);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes inputB;
  inputB.insert(inputB.end(), childAsset.begin(), childAsset.end());
  inputB.insert(inputB.end(), destB.getPublicKeyAsHash().begin(),
                destB.getPublicKeyAsHash().end());

  // Generous allowance: covers child's feeTx + transfer + slack.
  uint64_t allowance = 50 + BASE_FEE_TRANSACTION + 1'000'000;
  rc = client->runAsset(parentAsset, 10'000'000, inputB, vmError, budgetUsed,
                         output, false, allowance);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  ces::sleep(500);

  int64_t destBAfter = 0;
  rc = client->queryAccount(destBId, destBAfter, nonceTmp);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_MESSAGE(destBAfter == destBBefore + 50,
    "loose-allowance child should have transferred 50 (before="
    << destBBefore << " after=" << destBAfter << ")");
}

// SYS_SCHEDULE enqueues a future run; a VM abort must roll back that enqueue —
// an aborted run must not leave a live scheduled run behind (otherwise it
// fires later and charges the caller for work the rolled-back transaction
// created). The enqueue is recorded in the undo log: commit keeps it, abort
// erases it.
BOOST_FIXTURE_TEST_CASE(ScheduleRollsBackOnAbort, CesFixture) {
  server->_brr(clientKey.getPublicKeyAsHash(), 100'000'000'000LL);

  minx::Hash target; // the asset the program "schedules" (need not exist)
  target.fill(0x99);

  // Fire 60s out (the cron ticks at 100ms, so a past/near deadline would run
  // during the test). Computed here and passed in the input as 8 LE bytes; the
  // hosting cost scales with duration, so 60s is cheap.
  uint64_t nowUs = std::chrono::duration_cast<std::chrono::microseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
  uint64_t fireTime = nowUs + 60'000'000;
  ces::Bytes input(target.begin(), target.end());     // input bytes 0..31
  ces::Buffer::putLE<uint64_t>(input, fireTime);       // input bytes 32..39

  auto buildSchedProgram = [&](bool abort) {
    VmProgram pgm;
    Region keyReg = pgm.allocHash();
    pgm.copyFromInput(keyReg, 0);          // target key (input cells 0..3)
    Region timeReg = pgm.allocCell();
    pgm.copyFromInput(timeReg, 4);         // fireTime value (input cell 4)
    pgm.sysSchedule({keyReg, Imm(1'000'000), Imm(0), Imm(0), Imm(0),
                     Ref(timeReg.cell)});  // io[9] = io[timeReg] = fireTime
    if (abort) pgm.abort();
    pgm.term();
    return pgm.buildBootBlock();
  };

  // Abort variant: the schedule enqueue must be rolled back.
  {
    minx::Hash progId; progId.fill(0x71);
    CES_REQUIRE_OK(client->createAsset(progId, buildSchedProgram(true), 30));
    uint64_t vmError = 0, budgetUsed = 0;
    ces::Bytes output;
    client->runAsset(progId, 1'000'000'000, input, vmError, budgetUsed, output);
    BOOST_CHECK_EQUAL(vmError, static_cast<uint64_t>(CESVM_ABORT));
    wait_net();
    BOOST_CHECK_EQUAL(server->_scheduledRunCount(), 0u);
  }

  // Commit variant: the schedule enqueue must persist.
  {
    minx::Hash progId; progId.fill(0x72);
    CES_REQUIRE_OK(client->createAsset(progId, buildSchedProgram(false), 30));
    uint64_t vmError = 0, budgetUsed = 0;
    ces::Bytes output;
    client->runAsset(progId, 1'000'000'000, input, vmError, budgetUsed, output);
    BOOST_CHECK_EQUAL(vmError, static_cast<uint64_t>(CESVM_OK));
    wait_net();
    BOOST_CHECK_EQUAL(server->_scheduledRunCount(), 1u);
  }
}

BOOST_AUTO_TEST_SUITE_END()
