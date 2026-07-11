// Executable aliases: inline hook/program cells, the VM alias syscalls, and
// the identity model (caller pays gas, self is the boot asset or 0,
// programOwner is the account the run acts as).
//
// Covers: CES_RUN_ALIAS (identity preloads, non-program rejection), the
// mailbox pattern (A's inline WATCH writes B's editor-granted cell on a
// transfer), gate purity (an inline GATE that tries to write fails closed and
// rejects the deposit), SYS_SCHEDULE_ALIAS (async alias-to-alias call, with
// SYS_READ_ACCOUNT's aliasId cell resolving the child's own id),
// SYS_READ_ALIAS windows, SYS_LOAD_CODE_ALIAS linking, the reserved all-zero
// asset key, and the wire account query's aliasId exposure.

#include "test_common.h"

#include <ces/alias.h>
#include <ces/cesvm.h>
#include <ces/util/vmprogram.h>

#include <cstring>

using namespace ces;

BOOST_AUTO_TEST_SUITE(AliasVmTests)

namespace {

// op (host-endian, LE on supported targets) + code/content as one patch at
// ALIAS_OFF_OP.
ces::Bytes opBytes(uint16_t op, const ces::Bytes& rest) {
  ces::Bytes b(sizeof(op) + rest.size());
  std::memcpy(b.data(), &op, sizeof(op));
  std::memcpy(b.data() + sizeof(op), rest.data(), rest.size());
  return b;
}

ces::Bytes str(const std::string& s) {
  ces::Bytes b;
  b.assign(s.begin(), s.end());
  return b;
}

ces::Bytes u64le(uint64_t v) {
  ces::Bytes b(sizeof(v));
  ces::Buffer::pokeLE<uint64_t>(b.data(), v);
  return b;
}

// Install an inline cell in one whole-image patch: op + code area
// (zero-padded to ALIAS_INLINE_CODE_BYTES) + ceiling trailer.
ces::Bytes inlineCell(uint16_t op, ces::Bytes code, uint64_t ceiling) {
  BOOST_REQUIRE_LE(code.size(), ALIAS_INLINE_CODE_BYTES);
  code.resize(ALIAS_INLINE_CODE_BYTES, 0);
  ces::Bytes tail = u64le(ceiling);
  code.insert(code.end(), tail.begin(), tail.end());
  return opBytes(op, code);
}

// Direct-server patch on `who`'s own alias (nonce-skip), mirroring the
// AliasTests helper.
uint32_t patchOwn(CesServer& srv, KeyPair& who, uint16_t offset,
                  const ces::Bytes& bytes) {
  uint32_t id = 0;
  BOOST_REQUIRE_EQUAL(
    srv.setAlias(who.getPublicKeyAsHash(), 0, offset, bytes, 0, id),
    static_cast<int>(CES_OK));
  srv._drainLogic();
  return id;
}

} // namespace

// A public inline program sees its identity triple: caller pays (implicit),
// self = 0 (no boot asset), programOwner = the cell's owner.
BOOST_FIXTURE_TEST_CASE(RunAliasIdentityPreloads, CesFixture) {
  VmProgram p;
  p.mov(Imm(CESVM_IO_OUTPUT), Imm(CESVM_IO_PROGRAM_OWNER), Imm(1));
  p.mov(Imm(CESVM_IO_OUTPUT + 1), Imm(CESVM_IO_SELF_KEY), Imm(1));
  p.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(16));
  p.term();

  uint32_t id = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_INLINE_PROGRAM, p.buildBytes()), id));
  BOOST_REQUIRE(id != 0);

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  CES_REQUIRE_OK(client->runAlias(id, 1'000'000'000, {}, vmError, budgetUsed,
                                  output));
  BOOST_CHECK_EQUAL(vmError, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(output.size(), 16u);
  HashPrefix myId = getMyId();
  BOOST_CHECK(std::memcmp(output.data(), myId.data(), 8) == 0); // speaks as me
  for (int i = 8; i < 16; ++i)
    BOOST_CHECK_EQUAL(output[i], 0);                            // self = 0
}

// A cell that has not opted in as a program is not invocable.
BOOST_FIXTURE_TEST_CASE(RunAliasRejectsNonProgramCell, CesFixture) {
  uint32_t id = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_STRING, str("just a label")), id));
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  uint8_t rc = client->runAlias(id, 1'000'000, {}, vmError, budgetUsed,
                                output);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_BAD_INPUT));
}

// The mailbox: B owns a data cell and grants A editorship; A's inline WATCH
// (fired by A's own outbound transfer) writes into B's cell as A.
BOOST_FIXTURE_TEST_CASE(InlineWatchWritesEditorCell, CesFixture) {
  KeyPair b;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();

  // B's data cell, editor = A.
  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_NONE, str("mail")));
  HashPrefix myId = getMyId();
  ces::Bytes grant(myId.begin(), myId.end());
  patchOwn(*server, b, ALIAS_OFF_EDITOR, grant);

  // A's inline WATCH: refill (the write's feeAlias exceeds the free grant),
  // then write 'X' over B's content[0].
  VmProgram w;
  w.sysRefill({.amount = Imm(100'000'000)});
  w.set(Imm(20), Imm('X'));
  w.sysWriteAlias({.aliasId = Imm(bId),
                   .offset = Imm(ALIAS_OFF_CONTENT),
                   .len = Imm(1),
                   .srcPtr = Imm(20)});
  w.term();
  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP,
    inlineCell(ALIAS_OP_INLINE_HOOK_WATCH, w.buildBytes(), 200'000'000),
    aId));
  BOOST_REQUIRE(aId != 0);

  // A sends a transfer; A's outbound WATCH fires and writes B's cell.
  int64_t nb = 0;
  CES_REQUIRE_OK(client->transfer(b.getPublicKeyAsHash(), 1'000'000, nb));
  server->_drainLogic();

  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_CONTENT, 4, window, found));
  BOOST_REQUIRE(found);
  BOOST_REQUIRE_EQUAL(window.size(), 4u);
  BOOST_CHECK_EQUAL(window[0], static_cast<uint8_t>('X'));   // the message
  BOOST_CHECK_EQUAL(window[1], static_cast<uint8_t>('a'));   // rest intact
  // Header intact: owner still B, editor still A.
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_EDITOR,
                                   sizeof(HashPrefix), window, found));
  BOOST_REQUIRE(found);
  BOOST_CHECK(std::memcmp(window.data(), myId.data(), 8) == 0);
}

// Gate purity: an inline GATE has no principal, so its write attempt aborts
// the run and the deposit is rejected fail-closed; the target cell is
// untouched.
BOOST_FIXTURE_TEST_CASE(InlineGateCannotWrite, CesFixture) {
  KeyPair b;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();

  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_NONE, str("mail")));
  HashPrefix myId = getMyId();
  ces::Bytes grant(myId.begin(), myId.end());
  patchOwn(*server, b, ALIAS_OFF_EDITOR, grant);

  // A's inline GATE tries the same write; principal-less => hostx aborts.
  VmProgram g;
  g.set(Imm(20), Imm('X'));
  g.sysWriteAlias({.aliasId = Imm(bId),
                   .offset = Imm(ALIAS_OFF_CONTENT),
                   .len = Imm(1),
                   .srcPtr = Imm(20)});
  g.term();
  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP,
    inlineCell(ALIAS_OP_INLINE_HOOK_GATE, g.buildBytes(), 0), aId));

  // Inbound transfer to A fires A's IN gate, which rejects.
  int64_t ob = 0;
  uint8_t rc = server->transfer(b.getPublicKeyAsHash(),
                                clientKey.getPublicKeyAsHash(), 5'000'000,
                                CesServer::TransferMode::Safe, 0, 0, ob);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_HOOK_REJECTED));

  // B's cell untouched.
  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_CONTENT, 1, window, found));
  BOOST_REQUIRE(found);
  BOOST_CHECK_EQUAL(window[0], static_cast<uint8_t>('m'));
}

// Async alias-to-alias call: A's program schedules B's program, which
// resolves its own cell id via SYS_READ_ACCOUNT (io[6] = aliasId of its
// programOwner) and writes a marker into its own content.
BOOST_FIXTURE_TEST_CASE(ScheduleAliasAsyncCall, CesFixture) {
  KeyPair b;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();

  // B's inline program: find my own cell (principal -> account -> aliasId),
  // write 'Z' at content[900].
  VmProgram q;
  q.set(Imm(20), Ref(CESVM_IO_PROGRAM_OWNER));
  q.sysReadAccount({.prefixPtr = Imm(20)});   // io[6] = my aliasId
  q.set(Imm(21), Imm('Z'));
  q.sysWriteAlias({.aliasId = Ref(6),
                   .offset = Imm(ALIAS_OFF_CONTENT + 900),
                   .len = Imm(1),
                   .srcPtr = Imm(21)});
  q.term();
  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_INLINE_PROGRAM, q.buildBytes()));

  // A's inline program: schedule B for the next cron tick.
  VmProgram s;
  s.sysScheduleAlias({.aliasId = Imm(bId),
                      .budget = Imm(1'000'000'000),
                      .childAllowance = Imm(0),
                      .inputPtr = Imm(0),
                      .inputLen = Imm(0),
                      .timeUs = Imm(0)});
  s.term();
  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_INLINE_PROGRAM, s.buildBytes()), aId));

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  CES_REQUIRE_OK(client->runAlias(aId, 1'000'000'000, {}, vmError, budgetUsed,
                                  output));
  BOOST_CHECK_EQUAL(vmError, static_cast<uint64_t>(CESVM_OK));

  // Wait for the cron tick to fire the child.
  ces::sleep(1200);

  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_CONTENT + 900, 1, window,
                                   found));
  BOOST_REQUIRE(found);
  BOOST_CHECK_EQUAL(window[0], static_cast<uint8_t>('Z'));
}

// SYS_READ_ALIAS windows a foreign cell; SYS_LOAD_CODE_ALIAS links a library
// cell's code area and jumps into it.
BOOST_FIXTURE_TEST_CASE(ReadAliasAndLoadCodeAlias, CesFixture) {
  KeyPair b, c;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_brr(c.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();

  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_NONE, str("abcd")));

  // C's cell: a library whose code area starts with TERM.
  VmProgram lib;
  lib.term();
  uint32_t cId = patchOwn(*server, c, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_NONE, lib.buildBytes()));

  VmProgram p;
  p.sysReadAlias({.aliasId = Imm(bId),
                  .offset = Imm(ALIAS_OFF_CONTENT),
                  .len = Imm(4),
                  .destPtr = Imm(CESVM_IO_OUTPUT)});
  p.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(4));
  p.sysLoadCodeAlias({.aliasId = Imm(cId)});
  p.jmpr(Ref(CESVM_CELL_R));   // into the loaded block, which TERMs

  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_INLINE_PROGRAM, p.buildBytes()), aId));

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  CES_REQUIRE_OK(client->runAlias(aId, 1'000'000'000, {}, vmError, budgetUsed,
                                  output));
  BOOST_CHECK_EQUAL(vmError, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(output.size(), 4u);
  BOOST_CHECK_EQUAL(output[0], static_cast<uint8_t>('a'));
  BOOST_CHECK_EQUAL(output[3], static_cast<uint8_t>('d'));
}

// The all-zero asset key is the VM's "no boot asset" self sentinel and can
// never be minted.
BOOST_FIXTURE_TEST_CASE(ZeroAssetKeyReserved, CesFixture) {
  AssetData content{};
  uint8_t rc = client->createAsset(minx::Hash{}, content, 5);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_BAD_INPUT));
}

// The unsigned wire account query exposes the account -> alias link, so a
// client can chase pubkey -> account -> cell (the root-alias discovery path).
BOOST_FIXTURE_TEST_CASE(QueryAccountExposesAliasId, CesFixture) {
  uint32_t id = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_STRING, str("findable")), id));

  int64_t bal = 0;
  uint32_t nonce = 0;
  HashPrefix xd{};
  uint64_t xa = 0;
  uint32_t xt = 0;
  CES_REQUIRE_OK(client->queryAccount(getMyId(), bal, nonce, xd, xa, xt));
  BOOST_CHECK_EQUAL(client->getLastQueryAccountAliasId(), id);
}

// An aborted run rolls back its alias writes (the undo-log AliasEntry revert
// branch): the program patches its own cell, then ABORTs; the byte must
// revert to the pre-run value.
BOOST_FIXTURE_TEST_CASE(AbortRevertsAliasWrite, CesFixture) {
  VmProgram p;
  p.set(Imm(20), Ref(CESVM_IO_PROGRAM_OWNER));
  p.sysReadAccount({.prefixPtr = Imm(20)});   // io[6] = my aliasId
  p.set(Imm(21), Imm('W'));
  p.sysWriteAlias({.aliasId = Ref(6),
                   .offset = Imm(ALIAS_OFF_CONTENT + 500),
                   .len = Imm(1),
                   .srcPtr = Imm(21)});
  p.abort();

  uint32_t id = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_INLINE_PROGRAM, p.buildBytes()), id));
  // Pre-existing byte the aborted write must not clobber.
  uint32_t id2 = 0;
  CES_REQUIRE_OK(client->writeAlias(0, ALIAS_OFF_CONTENT + 500, str("O"),
                                    id2));
  BOOST_REQUIRE_EQUAL(id2, id);

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  uint8_t rc = client->runAlias(id, 1'000'000'000, {}, vmError, budgetUsed,
                                output);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_VM_FAILED));
  BOOST_CHECK_EQUAL(vmError, static_cast<uint64_t>(CESVM_ABORT));

  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(id, ALIAS_OFF_CONTENT + 500, 1, window,
                                   found));
  BOOST_REQUIRE(found);
  BOOST_CHECK_EQUAL(window[0], static_cast<uint8_t>('O'));   // reverted
}

// A REAL principal with NO grant on the target: the NOT_OWNER branch (as
// opposed to the gate's empty-principal branch). Non-aborting dispatch so the
// program can report S.
BOOST_FIXTURE_TEST_CASE(VmWriteUngrantedCellRejected, CesFixture) {
  KeyPair b;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();
  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_NONE, str("mail")));
  // No editor grant.

  VmProgram p;
  p.set(Imm(20), Imm('X'));
  p.hostv(SYS_WRITE_ALIAS, {Imm(bId), Imm(ALIAS_OFF_CONTENT), Imm(1),
                            Imm(20)});
  p.mov(Imm(CESVM_IO_OUTPUT), Imm(CESVM_CELL_S), Imm(1));
  p.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  p.term();

  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_INLINE_PROGRAM, p.buildBytes()), aId));
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  CES_REQUIRE_OK(client->runAlias(aId, 1'000'000'000, {}, vmError, budgetUsed,
                                  output));
  BOOST_CHECK_EQUAL(vmError, static_cast<uint64_t>(CESVM_OK));
  BOOST_REQUIRE_EQUAL(output.size(), 1u);
  BOOST_CHECK_EQUAL(output[0], static_cast<uint8_t>(CES_ERROR_NOT_OWNER));

  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_CONTENT, 1, window, found));
  BOOST_CHECK_EQUAL(window[0], static_cast<uint8_t>('m'));   // untouched
}

// An inline GATE that cleanly TERMs accepts: pins inline code extraction on
// the gate path (including the zero-padded tail) and the accept verdict.
BOOST_FIXTURE_TEST_CASE(InlineGateAcceptsTransfer, CesFixture) {
  KeyPair b;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();

  VmProgram g;
  g.term();
  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP,
    inlineCell(ALIAS_OP_INLINE_HOOK_GATE, g.buildBytes(), 0), aId));

  int64_t ob = 0;
  uint8_t rc = server->transfer(b.getPublicKeyAsHash(),
                                clientKey.getPublicKeyAsHash(), 5'000'000,
                                CesServer::TransferMode::Safe, 0, 0, ob);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_OK));
}

// A pointer WATCH whose trigger asset the hooked account itself owns is
// consented code: it runs with the account as principal and can write
// editor-granted cells, exactly like inline.
BOOST_FIXTURE_TEST_CASE(OwnedPointerWatchActsAsAccount, CesFixture) {
  KeyPair b;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();
  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_NONE, str("mail")));
  HashPrefix myId = getMyId();
  patchOwn(*server, b, ALIAS_OFF_EDITOR, ces::Bytes(myId.begin(), myId.end()));

  // Trigger asset owned by A (the client).
  VmProgram w;
  w.sysRefill({.amount = Imm(100'000'000)});
  w.set(Imm(20), Imm('P'));
  w.sysWriteAlias({.aliasId = Imm(bId),
                   .offset = Imm(ALIAS_OFF_CONTENT),
                   .len = Imm(1),
                   .srcPtr = Imm(20)});
  w.term();
  minx::Hash trigger;
  trigger.fill(0x71);
  CES_REQUIRE_OK(client->createAsset(trigger, w.buildBootBlock(), 5));

  // Pointer sidecar: trigger key + ceiling.
  ces::Bytes sidecar(trigger.begin(), trigger.end());
  ces::Bytes ceil = u64le(200'000'000);
  sidecar.insert(sidecar.end(), ceil.begin(), ceil.end());
  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_HOOK_WATCH, sidecar), aId));

  int64_t nb = 0;
  CES_REQUIRE_OK(client->transfer(b.getPublicKeyAsHash(), 1'000'000, nb));
  server->_drainLogic();

  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_CONTENT, 1, window, found));
  BOOST_REQUIRE(found);
  BOOST_CHECK_EQUAL(window[0], static_cast<uint8_t>('P'));
}

// A pointer WATCH on someone else's IMMUTABLE asset passes the set-time
// check but runs with NO principal: its write attempt aborts, the watch
// fails open (the transfer stands), and the target cell is untouched.
BOOST_FIXTURE_TEST_CASE(ForeignImmutableWatchHasNoPrincipal, CesFixture) {
  KeyPair b, c;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_brr(c.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();
  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_NONE, str("mail")));
  HashPrefix myId = getMyId();
  patchOwn(*server, b, ALIAS_OFF_EDITOR, ces::Bytes(myId.begin(), myId.end()));

  // Immutable library watch owned by C.
  VmProgram w;
  w.sysRefill({.amount = Imm(100'000'000)});
  w.set(Imm(20), Imm('C'));
  w.sysWriteAlias({.aliasId = Imm(bId),
                   .offset = Imm(ALIAS_OFF_CONTENT),
                   .len = Imm(1),
                   .srcPtr = Imm(20)});
  w.term();
  minx::Hash trigger;
  trigger.fill(0x72);
  HashPrefix cPfx = Account::getMapKey(c.getPublicKeyAsHash());
  BOOST_REQUIRE_EQUAL(
    server->createAsset(c.getPublicKeyAsHash(), cPfx, trigger,
                        w.buildBootBlock(),
                        assetBalance(2, false, false, /*immut=*/true, false),
                        0),
    static_cast<int>(CES_OK));
  server->_drainLogic();

  ces::Bytes sidecar(trigger.begin(), trigger.end());
  ces::Bytes ceil = u64le(200'000'000);
  sidecar.insert(sidecar.end(), ceil.begin(), ceil.end());
  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_HOOK_WATCH, sidecar), aId));

  int64_t nb = 0;
  CES_REQUIRE_OK(client->transfer(b.getPublicKeyAsHash(), 1'000'000, nb));
  server->_drainLogic();

  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_CONTENT, 1, window, found));
  BOOST_REQUIRE(found);
  BOOST_CHECK_EQUAL(window[0], static_cast<uint8_t>('m'));   // no principal
}

// An editor rewriting a pointer-hook's content re-runs the target check with
// the EDITOR as setter: pointing at a ghost or at someone else's mutable
// asset rejects; an immutable target passes.
BOOST_FIXTURE_TEST_CASE(EditorHookContentPatchRevalidated, CesFixture) {
  KeyPair b, c;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_brr(c.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();

  // B-owned trigger asset; B installs the pointer watch and grants editor A.
  VmProgram w;
  w.term();
  minx::Hash bTrigger;
  bTrigger.fill(0x73);
  HashPrefix bPfx = Account::getMapKey(b.getPublicKeyAsHash());
  BOOST_REQUIRE_EQUAL(
    server->createAsset(b.getPublicKeyAsHash(), bPfx, bTrigger,
                        w.buildBootBlock(), 2, 0),
    static_cast<int>(CES_OK));
  server->_drainLogic();
  ces::Bytes sidecar(bTrigger.begin(), bTrigger.end());
  ces::Bytes ceil = u64le(0);
  sidecar.insert(sidecar.end(), ceil.begin(), ceil.end());
  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_HOOK_WATCH, sidecar));
  HashPrefix myId = getMyId();
  patchOwn(*server, b, ALIAS_OFF_EDITOR, ces::Bytes(myId.begin(), myId.end()));

  // A repoints at a ghost: rejected.
  minx::Hash ghost;
  ghost.fill(0x74);
  uint32_t outId = 0;
  uint8_t rc = client->writeAlias(bId, ALIAS_OFF_CONTENT,
                                  ces::Bytes(ghost.begin(), ghost.end()),
                                  outId);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_HOOK_TARGET));

  // A repoints at B's own (mutable, not A's) asset: also rejected — the
  // setter is A, who neither owns it nor gets immutability.
  rc = client->writeAlias(bId, ALIAS_OFF_CONTENT,
                          ces::Bytes(bTrigger.begin(), bTrigger.end()),
                          outId);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_HOOK_TARGET));

  // A repoints at C's IMMUTABLE asset: accepted.
  minx::Hash immut;
  immut.fill(0x75);
  HashPrefix cPfx = Account::getMapKey(c.getPublicKeyAsHash());
  BOOST_REQUIRE_EQUAL(
    server->createAsset(c.getPublicKeyAsHash(), cPfx, immut,
                        w.buildBootBlock(),
                        assetBalance(2, false, false, /*immut=*/true, false),
                        0),
    static_cast<int>(CES_OK));
  server->_drainLogic();
  CES_REQUIRE_OK(client->writeAlias(bId, ALIAS_OFF_CONTENT,
                                    ces::Bytes(immut.begin(), immut.end()),
                                    outId));
}

// Fire-time re-check: a scheduled alias run whose cell stopped being an
// INLINE_PROGRAM between queue and fire is skipped, not executed.
BOOST_FIXTURE_TEST_CASE(ScheduleAliasFireTimeRecheck, CesFixture) {
  KeyPair b;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();

  // B's marker program (same shape as the async-call test).
  VmProgram q;
  q.set(Imm(20), Ref(CESVM_IO_PROGRAM_OWNER));
  q.sysReadAccount({.prefixPtr = Imm(20)});
  q.set(Imm(21), Imm('Z'));
  q.sysWriteAlias({.aliasId = Ref(6),
                   .offset = Imm(ALIAS_OFF_CONTENT + 900),
                   .len = Imm(1),
                   .srcPtr = Imm(21)});
  q.term();
  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_INLINE_PROGRAM, q.buildBytes()));

  // Queue for +400ms, then repurpose the cell before it fires.
  BOOST_REQUIRE_EQUAL(
    server->scheduleRun(getMyId(), minx::Hash{}, 1'000'000'000,
                        std::numeric_limits<uint64_t>::max(), {},
                        getMicrosSinceEpoch() + 400'000, false, bId),
    static_cast<int>(CES_OK));
  patchOwn(*server, b, ALIAS_OFF_OP, opBytes(ALIAS_OP_NONE, ces::Bytes{}));

  ces::sleep(1200);

  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_CONTENT + 900, 1, window,
                                   found));
  BOOST_REQUIRE(found);
  BOOST_CHECK_EQUAL(window[0], 0);   // never ran
}

// Queue-time rejection: scheduling a dead alias id aborts the scheduling run.
BOOST_FIXTURE_TEST_CASE(ScheduleAliasDeadTargetAborts, CesFixture) {
  VmProgram s;
  s.sysScheduleAlias({.aliasId = Imm(999999),
                      .budget = Imm(1'000'000),
                      .childAllowance = Imm(0),
                      .inputPtr = Imm(0),
                      .inputLen = Imm(0),
                      .timeUs = Imm(0)});
  s.term();
  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_INLINE_PROGRAM, s.buildBytes()), aId));
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  uint8_t rc = client->runAlias(aId, 1'000'000'000, {}, vmError, budgetUsed,
                                output);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_VM_FAILED));
}

// CES_RUN_ALIAS on a dead id refunds the reserved budget (nothing ran); and
// input bytes reach io[INPUT].
BOOST_FIXTURE_TEST_CASE(RunAliasNotFoundAndInputDelivery, CesFixture) {
  int64_t before = 0, after = 0;
  uint32_t nonce = 0;
  CES_REQUIRE_OK(client->queryAccount(getMyId(), before, nonce));
  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  uint8_t rc = client->runAlias(999999, 1'000'000, {}, vmError, budgetUsed,
                                output);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_ALIAS_NOT_FOUND));
  CES_REQUIRE_OK(client->queryAccount(getMyId(), after, nonce));
  BOOST_CHECK_EQUAL(after, before);   // budget refunded, nothing burned

  VmProgram p;
  p.mov(Imm(CESVM_IO_OUTPUT), Imm(CESVM_IO_INPUT), Imm(1));
  p.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(2));
  p.term();
  uint32_t id = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP, opBytes(ALIAS_OP_INLINE_PROGRAM, p.buildBytes()), id));
  CES_REQUIRE_OK(client->runAlias(id, 1'000'000'000, str("hi"), vmError,
                                  budgetUsed, output));
  BOOST_REQUIRE_EQUAL(output.size(), 2u);
  BOOST_CHECK_EQUAL(output[0], static_cast<uint8_t>('h'));
  BOOST_CHECK_EQUAL(output[1], static_cast<uint8_t>('i'));
}

// The inbound direction: a transfer TO the hooked account fires its inline
// watch too (INVOKE_HOOK_XFER_IN).
BOOST_FIXTURE_TEST_CASE(InlineWatchInboundFire, CesFixture) {
  KeyPair b;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();
  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_NONE, str("mail")));
  HashPrefix myId = getMyId();
  patchOwn(*server, b, ALIAS_OFF_EDITOR, ces::Bytes(myId.begin(), myId.end()));

  VmProgram w;
  w.sysRefill({.amount = Imm(100'000'000)});
  w.set(Imm(20), Imm('X'));
  w.sysWriteAlias({.aliasId = Imm(bId),
                   .offset = Imm(ALIAS_OFF_CONTENT),
                   .len = Imm(1),
                   .srcPtr = Imm(20)});
  w.term();
  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP,
    inlineCell(ALIAS_OP_INLINE_HOOK_WATCH, w.buildBytes(), 200'000'000),
    aId));

  int64_t ob = 0;
  BOOST_REQUIRE_EQUAL(
    server->transfer(b.getPublicKeyAsHash(),
                     clientKey.getPublicKeyAsHash(), 5'000'000,
                     CesServer::TransferMode::Safe, 0, 0, ob),
    static_cast<int>(CES_OK));
  server->_drainLogic();

  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_CONTENT, 1, window, found));
  BOOST_REQUIRE(found);
  BOOST_CHECK_EQUAL(window[0], static_cast<uint8_t>('X'));
}

// An INLINE_PROGRAM cell is not a hook: transfers in either direction never
// execute it (the class matcher excludes PROGRAM from gate and watch fires).
BOOST_FIXTURE_TEST_CASE(ProgramCellNeverFiresAsHook, CesFixture) {
  KeyPair b;
  server->_brr(b.getPublicKeyAsHash(), 1'000'000'000);
  server->_drainLogic();
  uint32_t bId = patchOwn(*server, b, ALIAS_OFF_OP,
                          opBytes(ALIAS_OP_NONE, str("mail")));
  HashPrefix myId = getMyId();
  patchOwn(*server, b, ALIAS_OFF_EDITOR, ces::Bytes(myId.begin(), myId.end()));

  // If this ever ran on a transfer, it would stamp B's cell.
  VmProgram p;
  p.sysRefill({.amount = Imm(100'000'000)});
  p.set(Imm(20), Imm('X'));
  p.sysWriteAlias({.aliasId = Imm(bId),
                   .offset = Imm(ALIAS_OFF_CONTENT),
                   .len = Imm(1),
                   .srcPtr = Imm(20)});
  p.term();
  uint32_t aId = 0;
  CES_REQUIRE_OK(client->writeAlias(
    0, ALIAS_OFF_OP,
    inlineCell(ALIAS_OP_INLINE_PROGRAM, p.buildBytes(), 200'000'000), aId));

  int64_t nb = 0;
  CES_REQUIRE_OK(client->transfer(b.getPublicKeyAsHash(), 1'000'000, nb));
  int64_t ob = 0;
  BOOST_REQUIRE_EQUAL(
    server->transfer(b.getPublicKeyAsHash(),
                     clientKey.getPublicKeyAsHash(), 5'000'000,
                     CesServer::TransferMode::Safe, 0, 0, ob),
    static_cast<int>(CES_OK));
  server->_drainLogic();

  ces::Bytes window;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(bId, ALIAS_OFF_CONTENT, 1, window, found));
  BOOST_REQUIRE(found);
  BOOST_CHECK_EQUAL(window[0], static_cast<uint8_t>('m'));   // never fired
}

BOOST_AUTO_TEST_SUITE_END()
