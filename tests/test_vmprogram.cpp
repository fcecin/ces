/**
 * test_vmprogram.cpp — tests for include/ces/vmprogram.h, the C++
 * builder for CesVM bytecode programs.
 *
 * Coverage:
 *   - Operand encoding: short (< 64), wide (1-8 bytes LE), REG_PTR
 *     (deref) bit, in both short and wide forms.
 *   - Label management: forward reference, placement, build-time
 *     patching, unplaced-label error.
 *   - High-level helpers: copy, writeBytesToIo.
 *   - Typed syscall wrappers: slot layouts match cesvm.cpp dispatch.
 *   - Generic syscall() helper.
 *   - Build outputs: buildBootBlock() (AssetData) and buildBytes() (vector).
 *   - End-to-end execution through CesVM::execute — builds a program,
 *     runs it, and verifies the result via the output path.
 */

#include <boost/test/unit_test.hpp>

#include <ces/cesvm.h>
#include <ces/buffer.h>
#include <ces/util/vmprogram.h>

#include <cstdint>
#include <cstring>
#include <vector>

using namespace ces;

namespace {

// Opcodes and encoding constants come from cesvm.h now.
constexpr uint8_t svCtrl(uint8_t v) {
  return static_cast<uint8_t>(CESVM_SHORT_VAL | (v & CESVM_MAX_SHORT_VAL));
}
constexpr uint8_t rpCtrl(uint8_t c) {
  return static_cast<uint8_t>(CESVM_REG_PTR | CESVM_SHORT_VAL |
                               (c & CESVM_MAX_SHORT_VAL));
}

// Counter-increment template — emits the "in-place counter" idiom used
// by the test_cesvm suite: copy self key, read asset, load+inc+store
// one byte of content, update asset. Caller appends term() or more.
// Does not handle overflow; byteOffsetInContent=255 silently wraps.
VmProgram& emitCounterIncrement(VmProgram& pgm,
                                uint16_t byteOffsetInContent = 209) {
  Region key     = pgm.allocHash();
  Region content = pgm.allocContent();
  pgm.copySelfKeyTo(key);
  pgm.readAndUpdateAsset(key, content, [content, byteOffsetInContent](VmProgram& b){
    b.ldbFromCell(content, byteOffsetInContent);
    b.inc(Imm(CESVM_CELL_R));
    b.stbInCell(content, byteOffsetInContent, Ref(CESVM_CELL_R));
  });
  return pgm;
}

} // namespace

BOOST_AUTO_TEST_SUITE(VmProgramTests)

// ---------------------------------------------------------------------------
// 1. Empty builder yields an empty raw byte vector, and the 210-byte
//    AssetData build is all zeros.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(EmptyProgram) {
  VmProgram pgm;
  auto raw = pgm.buildBytes();
  BOOST_TEST(raw.empty());

  VmProgram pgm2;
  auto code = pgm2.buildBootBlock();
  BOOST_REQUIRE_EQUAL(code.size(), 210u);
  for (auto b : code) BOOST_TEST(b == 0u);
}

// ---------------------------------------------------------------------------
// 2. Short operand encoding: a simple OP_SET with both operands < 64.
//    Verifies the SHORT_VAL encoding (1 byte per operand).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SetShortOperands) {
  VmProgram pgm;
  pgm.set(Imm(9), Imm(17));
  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 3u);
  BOOST_TEST(raw[0] == OP_SET);
  BOOST_TEST(raw[1] == svCtrl(9));
  BOOST_TEST(raw[2] == svCtrl(17));
}

// ---------------------------------------------------------------------------
// 3. Wide operand encoding: OP_SET io[9] = 892. 892 needs 2 bytes LE.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SetWideImmediate) {
  VmProgram pgm;
  pgm.set(Imm(9), Imm(892));
  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 5u);
  BOOST_TEST(raw[0] == OP_SET);
  BOOST_TEST(raw[1] == svCtrl(9));        // dst short
  BOOST_TEST(raw[2] == 2u);                // wide, 2 bytes follow
  BOOST_TEST(raw[3] == (892u & 0xFFu));    // low byte
  BOOST_TEST(raw[4] == ((892u >> 8) & 0xFFu));  // high byte
}

// ---------------------------------------------------------------------------
// 4. Wide cell index: OP_SET to a cell address > 63 uses wide encoding
//    on the dst operand too.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SetWideDst) {
  VmProgram pgm;
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(4));  // 753 → wide 2 bytes
  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 5u);
  BOOST_TEST(raw[0] == OP_SET);
  BOOST_TEST(raw[1] == 2u);
  BOOST_TEST(raw[2] == (CESVM_IO_OUTPUT_LEN & 0xFFu));
  BOOST_TEST(raw[3] == ((CESVM_IO_OUTPUT_LEN >> 8) & 0xFFu));
  BOOST_TEST(raw[4] == svCtrl(4));  // src short
}

// ---------------------------------------------------------------------------
// 5. Deref (REG_PTR) operand encoding.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(RefOperandEncoding) {
  VmProgram pgm;
  pgm.set(Imm(16), Ref(30));  // io[16] = io[30]
  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 3u);
  BOOST_TEST(raw[0] == OP_SET);
  BOOST_TEST(raw[1] == svCtrl(16));
  BOOST_TEST(raw[2] == rpCtrl(30));
}

// ---------------------------------------------------------------------------
// 6. copy() helper emits OP_MOV with all three operands as literals.
//    The source cell index is 892 so it needs wide 2-byte encoding;
//    this is the exact shape the existing TCP gateway program uses, so
//    the builder should produce bytecode that's at least as compact.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(CopyHelperEncoding) {
  VmProgram pgm;
  pgm.copy(16, 892, 4);
  auto raw = pgm.buildBytes();
  // OP_MOV + dst sv(16) + src [wide 2, lo, hi] + count sv(4) = 6 bytes.
  BOOST_REQUIRE_EQUAL(raw.size(), 6u);
  BOOST_TEST(raw[0] == OP_MOV);
  BOOST_TEST(raw[1] == svCtrl(16));
  BOOST_TEST(raw[2] == 2u);
  BOOST_TEST(raw[3] == (892u & 0xFFu));
  BOOST_TEST(raw[4] == ((892u >> 8) & 0xFFu));
  BOOST_TEST(raw[5] == svCtrl(4));
}

// ---------------------------------------------------------------------------
// 7. Label forward reference + placement. Build a program that jumps
//    over a NOP and terminates at the jump target.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(LabelForwardReference) {
  VmProgram pgm;
  auto target = pgm.label();
  pgm.jmp(target);   // 3 bytes: OP_JMP + 2-byte offset
  pgm.nop();         // 1 byte: offset 3
  pgm.place(target); // label offset = 4
  pgm.term();        // 1 byte: offset 4
  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 5u);
  BOOST_TEST(raw[0] == OP_JMP);
  BOOST_TEST(raw[1] == 4u);  // low byte of target offset
  BOOST_TEST(raw[2] == 0u);  // high byte
  BOOST_TEST(raw[3] == OP_NOP);
  BOOST_TEST(raw[4] == OP_TERM);
}

// ---------------------------------------------------------------------------
// 8. Unplaced label at build time is a hard error.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(UnplacedLabelThrows) {
  VmProgram pgm;
  auto dead = pgm.label();
  pgm.jmp(dead);  // references but never places
  pgm.term();
  BOOST_CHECK_THROW(pgm.buildBytes(), VmProgramError);
}

// ---------------------------------------------------------------------------
// 9. writeBytesToIo packs bytes little-endian into cells via OP_SET.
//    "Hello!" (6 bytes) fits in one cell; the packed u64 is:
//      'H'<<0 | 'e'<<8 | 'l'<<16 | 'l'<<24 | 'o'<<32 | '!'<<40 | 0 | 0
//    = 0x0000216F6C6C6548
//    That needs 6 bytes of wide encoding (max byte > 0, bytes 6 and 7
//    are zero, so the encoder picks 6 bytes).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(WriteBytesToIoSingleCell) {
  VmProgram pgm;
  pgm.writeBytesToIo(10, std::string_view("Hello!"));
  auto raw = pgm.buildBytes();
  // OP_SET + dst sv(10) + src [wide 6, 6 bytes]
  BOOST_REQUIRE_EQUAL(raw.size(), 9u);
  BOOST_TEST(raw[0] == OP_SET);
  BOOST_TEST(raw[1] == svCtrl(10));
  BOOST_TEST(raw[2] == 6u);                  // wide, 6 bytes follow
  BOOST_TEST(raw[3] == static_cast<uint8_t>('H'));
  BOOST_TEST(raw[4] == static_cast<uint8_t>('e'));
  BOOST_TEST(raw[5] == static_cast<uint8_t>('l'));
  BOOST_TEST(raw[6] == static_cast<uint8_t>('l'));
  BOOST_TEST(raw[7] == static_cast<uint8_t>('o'));
  BOOST_TEST(raw[8] == static_cast<uint8_t>('!'));
}

// ---------------------------------------------------------------------------
// 10. writeBytesToIo for a 9-byte string ("127.0.0.1") spans 2 cells.
//     First cell: "127.0.0." (8 bytes → packed u64, 8 wide bytes).
//     Second cell: "1" followed by zeros → packed u64 = 0x31 → encoded
//     as short immediate (0x31 < 64... wait, '1' is 0x31 = 49 which IS
//     less than 64, so it fits in the short form). Good.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(WriteBytesToIoMultiCell) {
  VmProgram pgm;
  pgm.writeBytesToIo(32, std::string_view("127.0.0.1"));
  auto raw = pgm.buildBytes();
  // Cell 0: OP_SET sv(32) + wide 8 + 8 bytes = 11 bytes
  // Cell 1: OP_SET sv(33) + short 0x31 ('1' = 49) = 3 bytes
  // Total: 14 bytes
  BOOST_REQUIRE_EQUAL(raw.size(), 14u);

  // First cell
  BOOST_TEST(raw[0] == OP_SET);
  BOOST_TEST(raw[1] == svCtrl(32));
  BOOST_TEST(raw[2] == 8u);  // wide 8 bytes
  BOOST_TEST(raw[3] == static_cast<uint8_t>('1'));
  BOOST_TEST(raw[4] == static_cast<uint8_t>('2'));
  BOOST_TEST(raw[5] == static_cast<uint8_t>('7'));
  BOOST_TEST(raw[6] == static_cast<uint8_t>('.'));
  BOOST_TEST(raw[7] == static_cast<uint8_t>('0'));
  BOOST_TEST(raw[8] == static_cast<uint8_t>('.'));
  BOOST_TEST(raw[9] == static_cast<uint8_t>('0'));
  BOOST_TEST(raw[10] == static_cast<uint8_t>('.'));

  // Second cell. '1' = 0x31 = 49, which is < 64 so it goes short.
  BOOST_TEST(raw[11] == OP_SET);
  BOOST_TEST(raw[12] == svCtrl(33));
  BOOST_TEST(raw[13] == svCtrl(0x31));  // '1' as short immediate
}

// ---------------------------------------------------------------------------
// 11. Generic syscall() helper: io[3] = syscall id, then each (slot,
//     val) pair, then OP_HOSTX. Verify all of that appears in order.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(GenericSyscall) {
  VmProgram pgm;
  pgm.syscall(SYS_READ_ACCOUNT, {{4, Imm(16)}});
  auto raw = pgm.buildBytes();
  // Expected:
  //   OP_SET sv(3) sv(SYS_READ_ACCOUNT=1)          = 3 bytes
  //   OP_SET sv(4) sv(16)                           = 3 bytes
  //   OP_HOSTX                                       = 1 byte
  // Total 7 bytes.
  BOOST_REQUIRE_EQUAL(raw.size(), 7u);
  BOOST_TEST(raw[0] == OP_SET);
  BOOST_TEST(raw[1] == svCtrl(3));
  BOOST_TEST(raw[2] == svCtrl(SYS_READ_ACCOUNT));
  BOOST_TEST(raw[3] == OP_SET);
  BOOST_TEST(raw[4] == svCtrl(4));
  BOOST_TEST(raw[5] == svCtrl(16));
  BOOST_TEST(raw[6] == OP_HOSTX);
}

// ---------------------------------------------------------------------------
// 12. End-to-end: build a program that writes a 32-bit value into the
//     output slot and terminates. Run it through CesVM::execute and
//     verify the output bytes.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(EndToEndSimple) {
  VmProgram pgm;
  // Set output length = 4 bytes.
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(4));
  // Write 0xCAFEF00D into the first output cell.
  pgm.set(Imm(CESVM_IO_OUTPUT), Imm(0xCAFEF00Du));
  pgm.term();

  auto code = pgm.buildBytes();
  BOOST_REQUIRE(!code.empty());

  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto result = vm.execute(code, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 4u);

  // Output bytes are the first 4 bytes of io[CESVM_IO_OUTPUT] LE.
  uint32_t decoded = 0;
  std::memcpy(&decoded, result.output.data(), 4);
  BOOST_TEST(decoded == 0xCAFEF00Du);
}

// ---------------------------------------------------------------------------
// 15. End-to-end with a label and conditional jump: count down a cell
//     from 5 to 0, then write the final value to the output and
//     terminate. Verifies that labels resolve correctly against a
//     running VM (not just against our static expectations).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(EndToEndCountdown) {
  VmProgram pgm;
  // io[30] = 5
  pgm.set(Imm(30), Imm(5));

  auto loopStart = pgm.label();
  pgm.place(loopStart);
  // dec io[30]
  pgm.dec(Imm(30));
  // jt io[30], loopStart — jump if io[30] is still nonzero
  pgm.jt(Ref(30), loopStart);

  // Output: 8 bytes, the value of io[30] (which is now 0).
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(8));
  pgm.set(Imm(CESVM_IO_OUTPUT), Ref(30));
  pgm.term();

  auto code = pgm.buildBytes();
  BOOST_REQUIRE(!code.empty());

  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto result = vm.execute(code, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 8u);

  uint64_t decoded = 0;
  std::memcpy(&decoded, result.output.data(), 8);
  BOOST_TEST(decoded == 0u);
  // Sanity: we should have executed something on the order of
  // 5 × (dec + jt) + a few setup ops. If labels didn't resolve,
  // opsExecuted would be much lower or the VM would crash.
  BOOST_TEST(result.opsExecuted >= 10u);
}

// ---------------------------------------------------------------------------
// 16. End-to-end byte embedding: writeBytesToIo + mov + readback. Builds
//     a program that embeds "abc" at io[20], copies it to io[30], then
//     writes io[30] to the output. Verifies that writeBytesToIo's
//     packed-u64 encoding round-trips correctly through the VM.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(EndToEndWriteBytes) {
  VmProgram pgm;
  pgm.writeBytesToIo(20, std::string_view("abc"));
  pgm.copy(/*dst=*/30, /*src=*/20, /*count=*/1);
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(3));
  pgm.set(Imm(CESVM_IO_OUTPUT), Ref(30));
  pgm.term();

  auto code = pgm.buildBytes();
  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();
  auto result = vm.execute(code, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 3u);
  BOOST_TEST(result.output[0] == static_cast<uint8_t>('a'));
  BOOST_TEST(result.output[1] == static_cast<uint8_t>('b'));
  BOOST_TEST(result.output[2] == static_cast<uint8_t>('c'));
}

// ---------------------------------------------------------------------------
// 17. OP_JMPR encoding + end-to-end: set a cell, jmpr through it, land
//     past a deliberately-skipped OP_NOP and terminate. The runtime
//     value in io[10] dictates where PC goes.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(JmprIndirectRuntimeTarget) {
  VmProgram pgm;
  // Byte 0: OP_SET sv(10) sv(6)  — 3 bytes (io[10] = 6)
  // Byte 3: OP_JMPR rp(10)        — 2 bytes (jumps to io[10] = offset 6)
  // Byte 5: OP_NOP                 — 1 byte  (should be SKIPPED)
  // Byte 6: OP_TERM                — 1 byte  (land here)
  pgm.set(Imm(10), Imm(6));
  pgm.jmpr(Ref(10));
  pgm.nop();
  pgm.term();

  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 7u);
  BOOST_TEST(raw[0] == CesVMOpcode::OP_SET);
  BOOST_TEST(raw[3] == CesVMOpcode::OP_JMPR);
  BOOST_TEST(raw[4] == rpCtrl(10));
  BOOST_TEST(raw[5] == CesVMOpcode::OP_NOP);
  BOOST_TEST(raw[6] == CesVMOpcode::OP_TERM);

  // End-to-end: run in the VM and verify the NOP was skipped. If the
  // jmpr was ignored, the NOP would execute before TERM and
  // opsExecuted would be 4 (set + jmpr + nop + term). With jmpr
  // working correctly, opsExecuted is 3 (set + jmpr + term).
  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_TEST(result.opsExecuted == 3u);
}

// ---------------------------------------------------------------------------
// 18. OP_CALLR saves registers and indirects to a runtime address,
//     RET restores them. Build a program that computes the call target
//     as a cell value, CALLRs into a small subroutine that writes a
//     marker to output, and verifies the marker came through.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(CallrIndirectSubroutine) {
  VmProgram pgm;
  // Layout:
  //   offset 0: set io[10] = <SUB_OFFSET>     (3 bytes)
  //   offset 3: callr Ref(10)                 (2 bytes)
  //   offset 5: <SET output_len=1, output=0xAA, term>
  //              — main body after call returns, ~10 bytes
  //   subroutine:
  //      set io[output_cell] = 0xAA? no, we want different behavior
  //        before and after. Actually, simplest: subroutine sets a
  //        marker cell, rets. Main body writes a composite marker to
  //        output.
  //
  // Simpler design: sub sets io[50] = 0xAA and returns. Main sets
  // output = io[50]. If CALLR failed (sub never ran), io[50] is 0 and
  // the test fails; if CALLR worked, io[50] is 0xAA.
  //
  // Byte budget, computed by hand:
  //   set(Imm(10), Imm(X))            — 3 bytes (io[10] = X)
  //   callr(Ref(10))                  — 2 bytes
  //   set(Imm(OUT_LEN=753), Imm(1))   — 5 bytes (OUT_LEN wide 2 bytes + short src)
  //   set(Imm(OUT=764), Ref(50))      — 5 bytes (OUT wide 2 bytes + short deref src)
  //   term                             — 1 byte
  //                          total: 16 bytes so far (main body)
  //   subroutine at offset 16:
  //     set(Imm(50), Imm(0xAA))       — 4 bytes (dst short + 0xAA wide 1 byte)
  //     ret(Imm(0))                    — 2 bytes
  //   grand total: 22 bytes
  constexpr uint64_t SUB_OFFSET = 16;

  // Main body
  pgm.set(Imm(10), Imm(SUB_OFFSET));
  pgm.callr(Ref(10));
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  pgm.set(Imm(CESVM_IO_OUTPUT), Ref(50));
  pgm.term();

  // Subroutine (should land at byte 14)
  BOOST_REQUIRE_EQUAL(pgm.size(), SUB_OFFSET);
  pgm.set(Imm(50), Imm(0xAA));
  pgm.ret(Imm(0));

  auto raw = pgm.buildBytes();
  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 1u);
  BOOST_TEST(result.output[0] == 0xAA);
}

// ---------------------------------------------------------------------------
// 19. Named register cell indices from cesvm.h work as operands. Write
//     42 to R via set(Imm(CESVM_CELL_R), Imm(42)), then read it back
//     to output via Ref(CESVM_CELL_R).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(NamedRegisterCellIndices) {
  VmProgram pgm;
  pgm.set(Imm(CESVM_CELL_R), Imm(42));  // R = 42
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  pgm.set(Imm(CESVM_IO_OUTPUT), Ref(CESVM_CELL_R));
  pgm.term();

  auto raw = pgm.buildBytes();
  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 1u);
  BOOST_TEST(result.output[0] == 42u);
}

// ---------------------------------------------------------------------------
// 20. hostv() — raw variadic syscall dispatch (non-abort variant).
//     Verify the byte layout: opcode + syscall num + arg count + args.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(HostvEncoding) {
  VmProgram pgm;
  pgm.hostv(SYS_TRANSFER, {Imm(16), Imm(50)});  // dest=io[16], amount=50
  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 5u);
  BOOST_TEST(raw[0] == OP_HOSTV);
  BOOST_TEST(raw[1] == svCtrl(SYS_TRANSFER));
  BOOST_TEST(raw[2] == svCtrl(2));   // arg count
  BOOST_TEST(raw[3] == svCtrl(16));  // dest ptr
  BOOST_TEST(raw[4] == svCtrl(50));  // amount
}

// ---------------------------------------------------------------------------
// 21. hostxv() — abort-on-S variant uses OP_HOSTXV opcode.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(HostxvEncoding) {
  VmProgram pgm;
  pgm.hostxv(SYS_TRANSFER, {Imm(16), Imm(50)});
  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 5u);
  BOOST_TEST(raw[0] == OP_HOSTXV);
  BOOST_TEST(raw[1] == svCtrl(SYS_TRANSFER));
  BOOST_TEST(raw[2] == svCtrl(2));
  BOOST_TEST(raw[3] == svCtrl(16));
  BOOST_TEST(raw[4] == svCtrl(50));
}

// ---------------------------------------------------------------------------
// 22. Builder-time arg count overflow. Asking for more args than
//     CESVM_MAX_HOSTV_ARGS must throw VmProgramError at build call,
//     not silently emit a bytecode the VM would reject.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(HostvArgOverflowThrows) {
  VmProgram pgm;
  // 17 args > CESVM_MAX_HOSTV_ARGS (16).
  BOOST_CHECK_THROW(
    pgm.hostv(SYS_NOP, {
      Imm(0), Imm(1), Imm(2), Imm(3), Imm(4), Imm(5), Imm(6), Imm(7),
      Imm(8), Imm(9), Imm(10), Imm(11), Imm(12), Imm(13), Imm(14),
      Imm(15), Imm(16),
    }),
    VmProgramError);
}

// ---------------------------------------------------------------------------
// 23. End-to-end hostv: the VM actually dispatches a host callback
//     with the right io slot population. We install a host whose
//     transfer lambda captures what it received, run a hostv
//     SYS_TRANSFER, and verify the captured values match.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(HostvDispatchesSyscall) {
  VmProgram pgm;
  // Put a 32-byte destination hash at io[16..19]. We'll write 0xDEAD
  // into the first byte via OP_SET and leave the rest zero.
  pgm.set(Imm(16), Imm(0xDEAD));
  // HOSTV SYS_TRANSFER with io[4] = 16 (dest ptr) and io[5] = 99
  // (amount). Abort-safe path (hostv, not hostxv) so S can be
  // inspected after.
  pgm.hostv(SYS_TRANSFER, {Imm(16), Imm(99)});
  pgm.term();

  CesVM vm;
  struct H : CesVMHost {
    bool transferCalled = false;
    uint64_t capturedAmount = 0;
    uint8_t transfer(const minx::Hash&, uint64_t amount) override {
      transferCalled = true;
      capturedAmount = amount;
      return CES_OK;
    }
    uint8_t debitCaller(uint64_t) override { return CES_OK; }
  } host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_CHECK_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK(host.transferCalled);
  BOOST_CHECK_EQUAL(host.capturedAmount, 99u);
}

// ---------------------------------------------------------------------------
// 24. End-to-end hostxv: abort-on-S semantics. If the syscall sets S
//     to a nonzero error, the VM terminates with CESVM_ABORT instead
//     of continuing past the hostxv instruction.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(HostxvAbortsOnNonzeroS) {
  VmProgram pgm;
  pgm.set(Imm(16), Imm(0));  // dummy dest
  // HOSTXV SYS_TRANSFER: the mock transfer below fails with
  // CES_ERROR_INSUFFICIENT_BALANCE, which sets S nonzero, which
  // OP_HOSTXV promotes to CESVM_ABORT before the TERM below can run.
  pgm.hostxv(SYS_TRANSFER, {Imm(16), Imm(99)});
  // Would set output=1 if we got here (we shouldn't).
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  pgm.set(Imm(CESVM_IO_OUTPUT), Imm(0xAA));
  pgm.term();

  CesVM vm;
  struct H : CesVMHost {
    uint8_t transfer(const minx::Hash&, uint64_t) override {
      return CES_ERROR_INSUFFICIENT_BALANCE;
    }
    uint8_t debitCaller(uint64_t) override { return CES_OK; }
  } host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_CHECK_EQUAL(result.error, static_cast<uint64_t>(CESVM_ABORT));
  // Output was NOT written — we aborted before the setOutput path.
  BOOST_TEST(result.output.empty());
}

// ---------------------------------------------------------------------------
// 25. copyFromInput / copyCallerKeyTo / copySelfKeyTo — the
//     preloaded-context helpers from A2. Run a program that copies
//     the caller key, self key, and a few input cells into the low
//     region, then emits them via setOutput for inspection.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(PreloadedContextCopyHelpers) {
  VmProgram pgm;
  pgm.copyCallerKeyTo(16);     // caller key → io[16..19]
  pgm.copySelfKeyTo(20);       // self key   → io[20..23]
  pgm.copyFromInput(24, 0, 1); // input[0]   → io[24]
  // Output the first 8 bytes of the caller key copy.
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(8));
  pgm.set(Imm(CESVM_IO_OUTPUT), Ref(16));
  pgm.term();

  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();
  host.callerKey.fill(0xCA);
  host.selfAssetKey.fill(0xBB);
  host.input = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 8u);
  // The caller key was filled with 0xCA, so every byte of the
  // copied cell should be 0xCA.
  for (auto b : result.output) BOOST_TEST(b == 0xCAu);
}

// ---------------------------------------------------------------------------
// 26. setOutput — single-cell output helper. Put a value in io[OUTPUT]
//     and set the length, in one call.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SetOutputHelper) {
  VmProgram pgm;
  pgm.setOutput(Imm(0xDEADu), /*byteLen=*/2);
  pgm.term();

  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();
  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 2u);
  BOOST_TEST(result.output[0] == 0xADu);  // low byte
  BOOST_TEST(result.output[1] == 0xDEu);  // high byte
}

// ---------------------------------------------------------------------------
// 27. setOutputBytes — multi-cell output helper. Assemble bytes in
//     scratch space, then return them via a single builder call.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SetOutputBytesHelper) {
  VmProgram pgm;
  // Pack "abcd" into io[30] as a single u64 ('a' | 'b'<<8 | 'c'<<16 | 'd'<<24)
  pgm.set(Imm(30), Imm(0x64636261u));
  pgm.setOutputBytes(/*srcCell=*/30, /*count=*/1, /*byteLen=*/4);
  pgm.term();

  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();
  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 4u);
  BOOST_TEST(result.output[0] == static_cast<uint8_t>('a'));
  BOOST_TEST(result.output[1] == static_cast<uint8_t>('b'));
  BOOST_TEST(result.output[2] == static_cast<uint8_t>('c'));
  BOOST_TEST(result.output[3] == static_cast<uint8_t>('d'));
}

// ---------------------------------------------------------------------------
// 28. byteInCell / ldbFromCell / stbInCell — byte-level addressing
//     helpers from A6. Write a byte into cell 32 offset 5, load it
//     back via R, output.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ByteInCellHelpers) {
  // Compile-time sanity: byte 5 of cell 32 is at byte offset 32*8+5=261.
  static_assert(VmProgram::byteInCell(32, 5) == 261u);

  VmProgram pgm;
  pgm.stbInCell(32, 5, Imm(0x77));      // io[32] byte 5 = 0x77
  pgm.ldbFromCell(32, 5);                // R = that byte
  pgm.setOutput(Ref(CESVM_CELL_R), 1);
  pgm.term();

  CesVM vm;
  CesVMHost host;
  host.allowance = std::numeric_limits<uint64_t>::max();
  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 1u);
  BOOST_TEST(result.output[0] == 0x77u);
}

// ---------------------------------------------------------------------------
// 29. Typed syscall wrappers round-trip. For each wrapper, build a
//     program that calls it and verify the emitted bytecode starts
//     with OP_HOSTXV + the right syscall number + the right arg
//     count. Structural check; the end-to-end sysTransfer test below
//     covers the full slot layout for at least one wrapper.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TypedSyscallWrappersStructuralCheck) {
  auto check = [](VmProgram&& pgm, uint8_t syscall, uint8_t argCount) {
    auto raw = pgm.buildBytes();
    BOOST_REQUIRE(raw.size() >= 3u);
    BOOST_TEST(raw[0] == OP_HOSTXV);
    BOOST_TEST(raw[1] == svCtrl(syscall));
    BOOST_TEST(raw[2] == svCtrl(argCount));
  };

  {
    VmProgram p;
    p.sysReadAccount({.prefixPtr = Imm(16)});
    check(std::move(p), SYS_READ_ACCOUNT, 1);
  }
  {
    VmProgram p;
    p.sysTransfer({.destKeyPtr = Imm(16), .amount = Imm(50)});
    check(std::move(p), SYS_TRANSFER, 2);
  }
  {
    VmProgram p;
    p.sysReadAsset({
      .keyPtr = Imm(16),
      .ownerOutCell = Imm(24),
      .contentOutCell = Imm(32),
    });
    // 3 args: keyPtr + ownerOut + contentOut (balance/price are
    // pure outputs in io[7]/io[8], not staged by the wrapper)
    check(std::move(p), SYS_READ_ASSET, 3);
  }
  {
    VmProgram p;
    p.sysCreateAssetRandom({.contentPtr = Imm(32), .days = Imm(30),
                              .keyOutPtr = Imm(16)});
    check(std::move(p), SYS_CREATE_ASSET_RANDOM, 3);
  }
  {
    VmProgram p;
    p.sysCreateAsset({.keyPtr = Imm(16), .contentPtr = Imm(32),
                       .days = Imm(30)});
    check(std::move(p), SYS_CREATE_ASSET, 3);
  }
  {
    VmProgram p;
    p.sysCreateAssetManaged({.keyPtr = Imm(16), .contentPtr = Imm(32),
                               .days = Imm(30)});
    check(std::move(p), SYS_CREATE_ASSET_MANAGED, 3);
  }
  {
    VmProgram p;
    p.sysUpdateAsset({.keyPtr = Imm(16), .contentPtr = Imm(32)});
    check(std::move(p), SYS_UPDATE_ASSET, 2);
  }
  {
    VmProgram p;
    p.sysFundAsset({.keyPtr = Imm(16), .days = Imm(10)});
    check(std::move(p), SYS_FUND_ASSET, 2);
  }
  {
    VmProgram p;
    p.sysBuyAsset({.keyPtr = Imm(16), .maxPrice = Imm(50)});
    check(std::move(p), SYS_BUY_ASSET, 2);
  }
  {
    VmProgram p;
    p.sysGiveAsset({.keyPtr = Imm(16), .newOwnerPtr = Imm(24)});
    check(std::move(p), SYS_GIVE_ASSET, 2);
  }
  {
    VmProgram p;
    p.sysHash({.dataPtr = Imm(16), .len = Imm(32), .outPtr = Imm(40)});
    check(std::move(p), SYS_HASH, 3);
  }
  {
    VmProgram p;
    p.sysVerifySig({.dataPtr = Imm(16), .dataLen = Imm(32),
                     .sigPtr = Imm(40), .pubkeyPtr = Imm(48)});
    check(std::move(p), SYS_VERIFY_SIG, 4);
  }
  {
    VmProgram p;
    p.sysCrossTransfer({.destKeyPtr = Imm(16), .amount = Imm(50),
                          .serverPtr = Imm(24)});
    check(std::move(p), SYS_CROSS_TRANSFER, 3);
  }
  {
    VmProgram p;
    p.sysLoadCode({.keyPtr = Imm(16)});
    check(std::move(p), SYS_LOAD_CODE, 1);
  }
  {
    VmProgram p;
    p.sysSendClient({.clientIdPtr = Imm(16), .dataPtr = Imm(24),
                       .dataLen = Imm(5)});
    check(std::move(p), SYS_SEND_CLIENT, 3);
  }
  {
    VmProgram p;
    p.sysSchedule({.assetKeyPtr = Imm(16), .budget = Imm(1),
                    .childAllowance = Imm(0),
                    .inputPtr = Imm(24), .inputLen = Imm(32),
                    .timeUs = Imm(0)});
    check(std::move(p), SYS_SCHEDULE, 6);
  }
}

// ---------------------------------------------------------------------------
// 30. End-to-end typed wrapper: sysTransfer actually dispatches through
//     the VM with the right slots populated, so the host's transfer
//     lambda receives the right amount argument.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SysTransferEndToEnd) {
  VmProgram pgm;
  // Place the dest key at io[16..19] (via a set; content irrelevant here).
  pgm.set(Imm(16), Imm(0xBEEF));
  pgm.sysTransfer({.destKeyPtr = Imm(16), .amount = Imm(77)});
  pgm.term();

  CesVM vm;
  struct H : CesVMHost {
    bool called = false;
    uint64_t capturedAmount = 0;
    uint8_t transfer(const minx::Hash&, uint64_t amount) override {
      called = true;
      capturedAmount = amount;
      return CES_OK;
    }
    uint8_t debitCaller(uint64_t) override { return CES_OK; }
  } host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_CHECK_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK(host.called);
  BOOST_CHECK_EQUAL(host.capturedAmount, 77u);
}

// ---------------------------------------------------------------------------
// 31. emitCounterIncrement — the "in-place counter" template from A5.
//     Run a program that increments byte 209 of the self-asset
//     content, using a mock host that reads back a content with
//     initial counter = 5 and captures the updated content the
//     program writes back. Verify the captured byte is 6.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(CounterIncrementTemplate) {
  VmProgram pgm;
  emitCounterIncrement(pgm);  // defaults: keyCell=16, contentCell=32, byte 209
  pgm.term();

  CesVM vm;
  // Mock readAsset returns content whose byte 209 is 5; updateAsset
  // captures the content the program wrote back.
  struct H : CesVMHost {
    AssetData captured{};
    bool updated = false;
    bool readAsset(const minx::Hash&, HashPrefix&, AssetData& content,
                   uint16_t& balance, uint32_t& price) override {
      content.fill(0);
      content[209] = 5;
      balance = 10;
      price = 0;
      return true;
    }
    uint8_t updateAsset(const minx::Hash&, const AssetData& content) override {
      captured = content;
      updated = true;
      return CES_OK;
    }
    uint8_t debitCaller(uint64_t) override { return CES_OK; }
  } host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/10'000'000);
  BOOST_CHECK_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK(host.updated);
  BOOST_CHECK_EQUAL(host.captured[209], 6);  // 5 + 1
}

// ---------------------------------------------------------------------------
// 32. loadCodeAndCall — A7 convenience wrapper. Main program loads a
//     library asset that writes 33 to io[50] and RETs, then reads
//     io[50] back and outputs it. No hand-counted offsets anywhere.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(LoadCodeAndCallWrapper) {
  VmProgram pgm;
  // io[16..19] is zero-initialized; the mock readAsset ignores the
  // key contents and always returns the same library blob.
  pgm.loadCodeAndCall(Imm(16));
  pgm.setOutput(Ref(50), 1);
  pgm.term();

  CesVM vm;
  // Library: OP_SET io[50] = 33; OP_RET 0. Hand-written because the
  // point of the wrapper is that the library's *loaded offset* is
  // unknown until runtime — the library blob itself is just bytes.
  struct H : CesVMHost {
    uint8_t debitCaller(uint64_t) override { return CES_OK; }
    bool readAsset(const minx::Hash&, HashPrefix&, AssetData& content,
                   uint16_t& balance, uint32_t& price) override {
      content.fill(0);
      content[0] = CesVMOpcode::OP_SET;
      content[1] = svCtrl(50);
      content[2] = svCtrl(33);
      content[3] = CesVMOpcode::OP_RET;
      content[4] = svCtrl(0);
      balance = 1;
      price = 0;
      return true;
    }
  } host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/10'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 1u);
  BOOST_TEST(result.output[0] == 33u);
}

// ---------------------------------------------------------------------------
// 33. loadCodeAndJmp — same as loadCodeAndCall but the library ends
//     in TERM instead of RET. Execution does NOT return to the main
//     program; whatever the library's TERM leaves in the output is
//     what the caller sees.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(LoadCodeAndJmpWrapper) {
  VmProgram pgm;
  pgm.loadCodeAndJmp(Imm(16));
  // Anything below here is dead code — jmpr transfers control to the
  // loaded block and never comes back. We add a marker-set that
  // SHOULDN'T run to prove the jmp actually happened.
  pgm.setOutput(Imm(42), 1);  // should NOT execute
  pgm.term();

  CesVM vm;
  // Library program: sets output to {LIB_MARKER, len=1} and TERMs.
  // LIB_MARKER must fit in the 6-bit short-value form (< 64) so
  // svCtrl() doesn't silently truncate it. 0x33 works; 0x55 would
  // not (it's 85, > 63).
  constexpr uint8_t LIB_MARKER = 0x33;
  struct H : CesVMHost {
    uint8_t debitCaller(uint64_t) override { return CES_OK; }
    bool readAsset(const minx::Hash&, HashPrefix&, AssetData& content,
                   uint16_t& balance, uint32_t& price) override {
      content.fill(0);
      size_t i = 0;
      // OP_SET io[CESVM_IO_OUTPUT_LEN=753] = 1
      content[i++] = CesVMOpcode::OP_SET;
      content[i++] = 2;  // wide, 2 bytes follow
      ces::Buffer::pokeLE<uint16_t>(content.data() + i, CESVM_IO_OUTPUT_LEN); i += 2;
      content[i++] = svCtrl(1);
      // OP_SET io[CESVM_IO_OUTPUT=764] = LIB_MARKER (short-encoded)
      content[i++] = CesVMOpcode::OP_SET;
      content[i++] = 2;
      ces::Buffer::pokeLE<uint16_t>(content.data() + i, CESVM_IO_OUTPUT); i += 2;
      content[i++] = svCtrl(LIB_MARKER);
      // OP_TERM
      content[i++] = CesVMOpcode::OP_TERM;
      balance = 1;
      price = 0;
      return true;
    }
  } host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/10'000'000);
  BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(result.output.size(), 1u);
  // LIB_MARKER from the library, NOT 42 from the post-jmp main body.
  BOOST_TEST(result.output[0] == LIB_MARKER);
}

// ---------------------------------------------------------------------------
// 34. build() enforces the 210-byte AssetData limit. A program whose
//     body fills the asset boot block succeeds; exceeding it throws.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(AssetDataSizeLimit) {
  VmProgram pgm;
  // 210 NOPs is exactly one byte per instruction, fills the block.
  for (int i = 0; i < 210; ++i) pgm.nop();
  auto code = pgm.buildBootBlock();
  BOOST_REQUIRE_EQUAL(code.size(), 210u);
  BOOST_TEST(code[0] == OP_NOP);
  BOOST_TEST(code[209] == OP_NOP);

  VmProgram overflow;
  for (int i = 0; i < 211; ++i) overflow.nop();
  BOOST_CHECK_THROW(overflow.buildBootBlock(), VmProgramError);
}

// ---------------------------------------------------------------------------
// 35. ifThen — structural shape: jf(cond, endL); body; place(endL).
//     A non-terminating body lands directly before the end label, so
//     execution continues past the if-block.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(IfThenStructural) {
  VmProgram pgm;
  pgm.ifThen(Imm(1), [](VmProgram& b){
    b.nop();
  });
  pgm.term();
  auto raw = pgm.buildBytes();
  // OP_JF + cond sv(1) + 2-byte label offset + OP_NOP + OP_TERM.
  BOOST_REQUIRE_EQUAL(raw.size(), 6u);
  BOOST_TEST(raw[0] == OP_JF);
  BOOST_TEST(raw[1] == svCtrl(1));
  BOOST_TEST(raw[2] == 5u);   // endL offset = 5 (just before OP_TERM)
  BOOST_TEST(raw[3] == 0u);
  BOOST_TEST(raw[4] == OP_NOP);
  BOOST_TEST(raw[5] == OP_TERM);
}

// ---------------------------------------------------------------------------
// 36. ifThenElse — structural shape with a non-terminating then-body
//     emits the merge jmp:
//       jf(cond, elseL); thenBody; jmp(endL); place(elseL); elseBody; place(endL)
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(IfThenElseStructuralWithMergeJmp) {
  VmProgram pgm;
  pgm.ifThenElse(Imm(1),
    [](VmProgram& b){ b.nop(); },   // non-terminating then
    [](VmProgram& b){ b.nop(); });  // non-terminating else
  pgm.term();
  auto raw = pgm.buildBytes();
  // OP_JF + cond sv(1) + 2-byte elseL offset = 4 bytes (offset 0..3)
  // OP_NOP                                    = 1 byte  (offset 4)
  // OP_JMP + 2-byte endL offset               = 3 bytes (offset 5..7)
  // OP_NOP                                    = 1 byte  (offset 8)
  // OP_TERM                                   = 1 byte  (offset 9)
  BOOST_REQUIRE_EQUAL(raw.size(), 10u);
  BOOST_TEST(raw[0] == OP_JF);
  BOOST_TEST(raw[1] == svCtrl(1));
  BOOST_TEST(raw[2] == 8u);   // elseL offset = 8 (the second OP_NOP)
  BOOST_TEST(raw[3] == 0u);
  BOOST_TEST(raw[4] == OP_NOP);
  BOOST_TEST(raw[5] == OP_JMP);
  BOOST_TEST(raw[6] == 9u);   // endL offset = 9 (the OP_TERM)
  BOOST_TEST(raw[7] == 0u);
  BOOST_TEST(raw[8] == OP_NOP);
  BOOST_TEST(raw[9] == OP_TERM);
}

// ---------------------------------------------------------------------------
// 37. ifThenElse with a term-ending then-body elides the merge jmp:
//       jf(cond, elseL); thenBody...term; place(elseL); elseBody; place(endL)
//     No OP_JMP/offset between the then-body's OP_TERM and the else
//     label — the merge jump would be unreachable, so it's dropped.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(IfThenElseElidesMergeJmpForTermBody) {
  VmProgram pgm;
  pgm.ifThenElse(Imm(1),
    [](VmProgram& b){ b.term(); },    // terminator at end of then-body
    [](VmProgram& b){ b.nop(); });
  auto raw = pgm.buildBytes();
  // OP_JF + cond sv(1) + 2-byte elseL offset + OP_TERM + OP_NOP.
  // No OP_JMP after OP_TERM.
  BOOST_REQUIRE_EQUAL(raw.size(), 6u);
  BOOST_TEST(raw[0] == OP_JF);
  BOOST_TEST(raw[1] == svCtrl(1));
  BOOST_TEST(raw[2] == 5u);   // elseL offset = 5 (the OP_NOP)
  BOOST_TEST(raw[3] == 0u);
  BOOST_TEST(raw[4] == OP_TERM);
  BOOST_TEST(raw[5] == OP_NOP);
}

// ---------------------------------------------------------------------------
// 38. The merge-jmp elision triggers on OP_ABORT too, not just OP_TERM.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(IfThenElseElidesMergeJmpForAbortBody) {
  VmProgram pgm;
  pgm.ifThenElse(Imm(1),
    [](VmProgram& b){ b.abort(); },
    [](VmProgram& b){ b.nop(); });
  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 6u);
  BOOST_TEST(raw[4] == OP_ABORT);
  BOOST_TEST(raw[5] == OP_NOP);
}

// ---------------------------------------------------------------------------
// 39. Peek-back must not false-positive when an operand byte happens
//     to equal OP_TERM (= 1). Build a then-body that ends with
//     `set(io[0], 1)` — the last byte emitted is the immediate value 1
//     which has the same wire byte as OP_TERM. The merge jmp must
//     still be emitted because the body did not end with a terminator
//     opcode.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(IfThenElseDoesNotConfuseOperandWithTerminator) {
  VmProgram pgm;
  pgm.ifThenElse(Imm(1),
    [](VmProgram& b){ b.set(Imm(0), Imm(1)); },  // last byte = svCtrl(1)
    [](VmProgram& b){ b.nop(); });
  pgm.term();
  auto raw = pgm.buildBytes();
  // Confirm the merge jmp is present by walking the layout:
  //   [0] OP_JF [1] cond [2..3] elseL offset
  //   [4] OP_SET [5] svCtrl(0) [6] svCtrl(1)
  //   [7] OP_JMP [8..9] endL offset  ← must be present
  //   [10] OP_NOP
  //   [11] OP_TERM
  BOOST_REQUIRE_EQUAL(raw.size(), 12u);
  BOOST_TEST(raw[7] == OP_JMP);
}

// ---------------------------------------------------------------------------
// 40. End-to-end execution: cond=true takes the then-branch and writes
//     0xAA to output; cond=false takes the else-branch and writes 0xBB.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(IfThenElseEndToEnd) {
  auto run = [](uint64_t condValue) -> uint8_t {
    VmProgram pgm;
    pgm.set(Imm(16), Imm(condValue));
    pgm.ifThenElse(Ref(16),
      [](VmProgram& b){ b.setOutput(Imm(0xAA), 1); b.term(); },
      [](VmProgram& b){ b.setOutput(Imm(0xBB), 1); b.term(); });
    CesVM vm;
    CesVMHost host;
    host.allowance = std::numeric_limits<uint64_t>::max();
    auto raw = pgm.buildBytes();
    auto result = vm.execute(raw, host, /*budget=*/1'000'000);
    BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
    BOOST_REQUIRE_EQUAL(result.output.size(), 1u);
    return result.output[0];
  };
  BOOST_TEST(run(1) == 0xAAu);  // truthy → then
  BOOST_TEST(run(0) == 0xBBu);  // falsy  → else
}

// ---------------------------------------------------------------------------
// 41. Nested ifThenElse executes the right inner branch and produces
//     the expected output for each (outer, inner) cond combination.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 41a. readAndUpdateAsset — structural shape: SYS_READ_ASSET (HOSTXV
//      with 3 args) + body bytes + SYS_UPDATE_ASSET (HOSTXV with 2
//      args). The owner-out scratch is allocated from the bump
//      allocator and lands one cell past `content`.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ReadAndUpdateAssetStructural) {
  VmProgram pgm;
  Region key     = pgm.allocAt(16, 4);     // anchor at cell 16 for predictable bytes
  Region content = pgm.allocAt(32, 27);    // anchor at cell 32
  // Force scratchTop_ past content so the internal allocHashPrefix()
  // for ownerOut lands at a known cell (59 = 32+27).
  pgm.setScratchBase(59);
  pgm.readAndUpdateAsset(key, content, [](VmProgram& b){
    b.nop();
  });
  auto raw = pgm.buildBytes();
  BOOST_REQUIRE_EQUAL(raw.size(), 12u);
  BOOST_TEST(raw[0]  == OP_HOSTXV);
  BOOST_TEST(raw[1]  == svCtrl(SYS_READ_ASSET));
  BOOST_TEST(raw[2]  == svCtrl(3));
  BOOST_TEST(raw[3]  == svCtrl(16));   // keyPtr
  BOOST_TEST(raw[4]  == svCtrl(59));   // ownerOut (alloc'd past content)
  BOOST_TEST(raw[5]  == svCtrl(32));   // contentOut
  BOOST_TEST(raw[6]  == OP_NOP);
  BOOST_TEST(raw[7]  == OP_HOSTXV);
  BOOST_TEST(raw[8]  == svCtrl(SYS_UPDATE_ASSET));
  BOOST_TEST(raw[9]  == svCtrl(2));
  BOOST_TEST(raw[10] == svCtrl(16));
  BOOST_TEST(raw[11] == svCtrl(32));
}

// ---------------------------------------------------------------------------
// 41b. readAndUpdateAsset end-to-end — read asset content (mock host
//      returns content[100] = 5), body increments byte 100, update is
//      called with the mutated content (byte 100 = 6).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ReadAndUpdateAssetEndToEnd) {
  VmProgram pgm;
  Region key     = pgm.allocHash();
  Region content = pgm.allocContent();
  // Stage a 32-byte key (content irrelevant — mock host doesn't inspect).
  for (uint64_t c = key.cell; c < key.cell + key.count; ++c) pgm.set(Imm(c), Imm(0));
  pgm.readAndUpdateAsset(key, content, [content](VmProgram& b){
    b.ldbFromCell(content, 100);
    b.inc(Imm(CESVM_CELL_R));
    b.stbInCell(content, 100, Ref(CESVM_CELL_R));
  });
  pgm.term();

  CesVM vm;
  struct H : CesVMHost {
    AssetData captured{};
    bool updated = false;
    bool readAsset(const minx::Hash&, HashPrefix&, AssetData& content,
                   uint16_t& balance, uint32_t& price) override {
      content.fill(0);
      content[100] = 5;
      balance = 10;
      price = 0;
      return true;
    }
    uint8_t updateAsset(const minx::Hash&, const AssetData& content) override {
      captured = content;
      updated = true;
      return CES_OK;
    }
    uint8_t debitCaller(uint64_t) override { return CES_OK; }
  } host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/10'000'000);
  BOOST_CHECK_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK(host.updated);
  BOOST_CHECK_EQUAL(host.captured[100], 6);
}

// ---------------------------------------------------------------------------
// 41c. Region allocator — bump cursor starts at CESVM_REG_SIZE (16),
//      typed shortcuts return the right counts, allocations are
//      contiguous and non-overlapping.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(RegionAllocatorBumpCursor) {
  VmProgram pgm;
  Region a = pgm.allocHash();         // 4 cells starting at 16
  Region b = pgm.allocHashPrefix();   // 1 cell at 20
  Region c = pgm.allocContent();      // 27 cells at 21
  Region d = pgm.allocCell();         // 1 cell at 48
  Region e = pgm.alloc(8);            // 8 cells at 49

  BOOST_CHECK_EQUAL(a.cell, 16u);  BOOST_CHECK_EQUAL(a.count, 4u);
  BOOST_CHECK_EQUAL(b.cell, 20u);  BOOST_CHECK_EQUAL(b.count, 1u);
  BOOST_CHECK_EQUAL(c.cell, 21u);  BOOST_CHECK_EQUAL(c.count, 27u);
  BOOST_CHECK_EQUAL(d.cell, 48u);  BOOST_CHECK_EQUAL(d.count, 1u);
  BOOST_CHECK_EQUAL(e.cell, 49u);  BOOST_CHECK_EQUAL(e.count, 8u);
}

// ---------------------------------------------------------------------------
// 41d. allocAt — anchors a region at a fixed cell without bumping.
//      Subsequent alloc() returns from the bump cursor (still at 16
//      by default), independent of where allocAt landed.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(RegionAllocatorAllocAtIsExempt) {
  VmProgram pgm;
  Region anchored = pgm.allocAt(500, 4);
  Region bumped   = pgm.alloc(4);

  BOOST_CHECK_EQUAL(anchored.cell, 500u);
  BOOST_CHECK_EQUAL(anchored.count, 4u);
  BOOST_CHECK_EQUAL(bumped.cell, 16u);   // bump cursor untouched
  BOOST_CHECK_EQUAL(bumped.count, 4u);
}

// ---------------------------------------------------------------------------
// 41e. setScratchBase moves the bump cursor; next alloc starts there.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(RegionAllocatorSetScratchBase) {
  VmProgram pgm;
  pgm.setScratchBase(100);
  Region r = pgm.allocCell();
  BOOST_CHECK_EQUAL(r.cell, 100u);
}

// ---------------------------------------------------------------------------
// 41f. Scratch exhaustion — alloc that would push past the protocol-
//      fixed range (cell 752 onwards) throws.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(RegionAllocatorExhaustionThrows) {
  VmProgram pgm;
  // Default range is [16, 752); 736 cells available. Eat almost all,
  // then ask for one that pushes past.
  (void)pgm.alloc(736);  // fills the range exactly: top is now 752
  BOOST_CHECK_THROW(pgm.allocCell(), VmProgramError);
}

// ---------------------------------------------------------------------------
// 41g. Region implicitly converts to VmVal as Imm(cell). Encoding it
//      as an OP_SET source produces the same bytes as Imm(cell).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(RegionImplicitVmValConversion) {
  VmProgram a;
  a.set(Imm(0), a.allocAt(20, 4));   // Region as VmVal source
  auto raw_a = a.buildBytes();

  VmProgram b;
  b.set(Imm(0), Imm(20));            // explicit Imm baseline
  auto raw_b = b.buildBytes();

  BOOST_REQUIRE_EQUAL(raw_a.size(), raw_b.size());
  BOOST_TEST(raw_a == raw_b);
}

BOOST_AUTO_TEST_CASE(IfThenElseNested) {
  auto run = [](uint64_t outer, uint64_t inner) -> uint8_t {
    VmProgram pgm;
    pgm.set(Imm(16), Imm(outer));
    pgm.set(Imm(17), Imm(inner));
    pgm.ifThenElse(Ref(16),
      [](VmProgram& b){
        b.ifThenElse(Ref(17),
          [](VmProgram& bb){ bb.setOutput(Imm(0x11), 1); bb.term(); },
          [](VmProgram& bb){ bb.setOutput(Imm(0x10), 1); bb.term(); });
      },
      [](VmProgram& b){
        b.ifThenElse(Ref(17),
          [](VmProgram& bb){ bb.setOutput(Imm(0x01), 1); bb.term(); },
          [](VmProgram& bb){ bb.setOutput(Imm(0x00), 1); bb.term(); });
      });
    CesVM vm;
    CesVMHost host;
    host.allowance = std::numeric_limits<uint64_t>::max();
    auto raw = pgm.buildBytes();
    auto result = vm.execute(raw, host, /*budget=*/1'000'000);
    BOOST_REQUIRE_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
    BOOST_REQUIRE_EQUAL(result.output.size(), 1u);
    return result.output[0];
  };
  BOOST_TEST(run(1, 1) == 0x11u);
  BOOST_TEST(run(1, 0) == 0x10u);
  BOOST_TEST(run(0, 1) == 0x01u);
  BOOST_TEST(run(0, 0) == 0x00u);
}

// SYS_UPDATE_ASSET_META: program puts its asset up for sale by setting a
// non-zero price + same owner. Mock host captures the args and confirms
// the syscall dispatched with the values the program emitted.
BOOST_AUTO_TEST_CASE(SysUpdateAssetMetaEndToEnd) {
  VmProgram pgm;
  Region key   = pgm.allocHash();        // io[16..19]
  Region owner = pgm.allocHashPrefix();  // io[20]
  // Stuff arbitrary content into the cells; mock ignores key, captures owner.
  pgm.set(Imm(key.cell),   Imm(0xCAFEF00Du));
  pgm.set(Imm(owner.cell), Imm(0xBEEF));
  pgm.sysUpdateAssetMeta({.keyPtr      = key,
                          .newOwnerPtr = owner,
                          .newPrice    = Imm(42)});
  pgm.term();

  CesVM vm;
  struct H : CesVMHost {
    bool called = false;
    HashPrefix capturedOwner{};
    uint32_t capturedPrice = 0;
    uint8_t updateAssetMeta(const minx::Hash&, const HashPrefix& o,
                            uint32_t p) override {
      called = true;
      capturedOwner = o;
      capturedPrice = p;
      return CES_OK;
    }
    uint8_t debitCaller(uint64_t) override { return CES_OK; }
  } host;
  host.allowance = std::numeric_limits<uint64_t>::max();

  auto raw = pgm.buildBytes();
  auto result = vm.execute(raw, host, /*budget=*/1'000'000);
  BOOST_CHECK_EQUAL(result.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK(host.called);
  BOOST_CHECK_EQUAL(host.capturedPrice, 42u);
  // owner cell was set to 0xBEEF; little-endian first byte = 0xEF.
  BOOST_CHECK_EQUAL(host.capturedOwner[0], 0xEFu);
  BOOST_CHECK_EQUAL(host.capturedOwner[1], 0xBEu);
}

BOOST_AUTO_TEST_SUITE_END()
