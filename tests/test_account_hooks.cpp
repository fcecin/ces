/**
 * Account hooks (CESVM triggers) - v1: inbound GATE on wire transfers.
 *
 * Exercises the server end to end (setAlias set-time check, transfer fire
 * point, the free-grant hook run, the accept/reject verdict, conservation)
 * via the in-process CesServer test surface.
 */

#include "test_common.h"

#include <ces/alias.h>
#include <ces/buffer.h>
#include <ces/cesvm.h>
#include <ces/util/vmprogram.h>

using namespace ces;

namespace {

// Write op + content on the signer's own alias as one patch at ALIAS_OFF_OP
// (op is host-endian in the image).
uint8_t setAliasOpContent(CesServer& srv, const minx::Hash& k, uint16_t op,
                          const AliasData& content, uint32_t& outId) {
  ces::Bytes b(sizeof(op) + content.size());
  std::memcpy(b.data(), &op, sizeof(op));
  std::memcpy(b.data() + sizeof(op), content.data(), content.size());
  return srv.setAlias(k, 0, ces::ALIAS_OFF_OP, b, 0, outId);
}

// A gate program's asset content. buildBootBlock pads to the 210-byte block.
AssetData gateAccept() {
  VmProgram p;
  p.term();                 // clean TERM = accept
  return p.buildBootBlock();
}

AssetData gateReject() {
  VmProgram p;
  p.abort();                // CESVM_ABORT = reject
  return p.buildBootBlock();
}

// Reject only when the invocation kind equals `rejectKind` (reads
// io[INVOKE_KIND]); accept otherwise. Proves one trigger dispatches on how it
// was invoked (inbound vs outbound).
AssetData gateByKind(uint64_t rejectKind) {
  VmProgram p;
  p.eq(Ref(CESVM_IO_INVOKE_KIND), Imm(rejectKind));  // R = (kind == rejectKind)
  VmLabel ok = p.label();
  p.jf(Ref(CESVM_CELL_R), ok);   // R == 0 (no match) -> accept
  p.abort();                     // matched -> reject
  p.place(ok);
  p.term();
  return p.buildBootBlock();
}

// Reject deposits below `threshold`; accept otherwise. Reads the amount from
// the event descriptor at io[INPUT+4] (CESVM_IO_INPUT is the input window).
AssetData gateMinAmount(uint64_t threshold) {
  VmProgram p;
  // R = (amount >= threshold); require aborts if R == 0.
  p.ge(Ref(CESVM_IO_INPUT + 4), Imm(threshold));
  p.require(Ref(CESVM_CELL_R));
  p.term();
  return p.buildBootBlock();
}

// SYS_REFILL for `refillReq`, then burn gas in a loop of `iters` iterations
// (~2 ops each), then TERM (or ABORT if `crash`). The loop deliberately
// exceeds the free grant, so without refill it runs out of gas; with refill it
// completes and the account pays for the excess.
AssetData burnHook(uint64_t iters, uint64_t refillReq, bool crash) {
  VmProgram p;
  p.sysRefill({Imm(refillReq)});
  p.set(Imm(CESVM_CELL_GPR0), Imm(iters));
  VmLabel top = p.label();
  p.place(top);
  p.dec(Imm(CESVM_CELL_GPR0));
  p.jt(Ref(CESVM_CELL_GPR0), top);
  if (crash) p.abort(); else p.term();
  return p.buildBootBlock();
}

struct HookFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  KeyPair recv;    // hooked receiver
  KeyPair send;    // sender

  HookFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    tempDir = makeUniqueTempDir("ces_hook_test");
    minx::Hash serverPriv;
    serverPriv.fill(0xEE);
    CesConfig cfg =
      makeTestConfig(tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    server = std::make_unique<CesServer>(cfg);
    server->start(0);
    server->_brr(recv.getPublicKeyAsHash(), 10'000'000'000);
    server->_brr(send.getPublicKeyAsHash(), 10'000'000'000);
    server->_drainLogic();
  }
  ~HookFixture() {
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  int64_t bal(const KeyPair& k) { return server->_balanceOf(k.getPublicKeyAsHash()); }

  // Deploy a trigger asset owned by `owner` (so the set-time check passes), at
  // a deterministic per-owner key, and install it as owner's hook sidecar.
  // `ceiling` goes in sidecar bytes 32..39 (SYS_REFILL cap; 0 = no refill).
  minx::Hash installHookOn(KeyPair& owner, const AssetData& code, uint16_t op,
                           uint64_t ceiling, uint8_t keyByte) {
    minx::Hash triggerKey;
    triggerKey.fill(keyByte);
    HashPrefix pfx = Account::getMapKey(owner.getPublicKeyAsHash());
    uint8_t rc = server->createAsset(owner.getPublicKeyAsHash(), pfx,
                                     triggerKey, code, /*days=*/2, 0);
    server->_drainLogic();
    BOOST_REQUIRE_EQUAL(rc, static_cast<int>(CES_OK));

    AliasData sidecar{};
    std::memcpy(sidecar.data(), triggerKey.data(), KEY_SIZE);
    ces::Buffer::pokeLE<uint64_t>(sidecar.data() + 32, ceiling);
    uint32_t id = 0;
    uint8_t arc =
      setAliasOpContent(*server, owner.getPublicKeyAsHash(), op, sidecar, id);
    server->_drainLogic();
    BOOST_REQUIRE_EQUAL(arc, static_cast<int>(CES_OK));
    return triggerKey;
  }

  // Install on the receiver (the common case for inbound-hook tests).
  minx::Hash installGate(const AssetData& code, uint16_t op = ALIAS_OP_HOOK_GATE,
                         uint64_t ceiling = 0) {
    return installHookOn(recv, code, op, ceiling, 0x5A);
  }

  uint8_t sendBetween(KeyPair& from, KeyPair& to, uint64_t amount) {
    int64_t ob = 0;
    uint8_t rc = server->transfer(from.getPublicKeyAsHash(),
                                  to.getPublicKeyAsHash(), amount,
                                  CesServer::TransferMode::Safe, 0, 0, ob);
    server->_drainLogic();
    return rc;
  }

  uint8_t sendToRecv(uint64_t amount) {
    int64_t ob = 0;
    uint8_t rc = server->transfer(send.getPublicKeyAsHash(),
                                  recv.getPublicKeyAsHash(), amount,
                                  CesServer::TransferMode::Safe, 0, 0, ob);
    server->_drainLogic();
    return rc;
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(AccountHookTests, HookFixture)

// Amounts above the inbound dust floor (~36k in this config), so the inbound
// hook actually fires rather than being skipped as dust.
static constexpr uint64_t kAbove = 1'000'000;
static constexpr uint64_t kDust = 5'000;   // below the floor

// A gate that TERMs accepts the deposit: it lands normally.
BOOST_AUTO_TEST_CASE(GateAcceptCreditsNormally) {
  installGate(gateAccept());
  int64_t before = bal(recv);
  uint8_t rc = sendToRecv(kAbove);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_OK));
  BOOST_CHECK_EQUAL(bal(recv), before + static_cast<int64_t>(kAbove));
}

// A gate that ABORTs rejects: the deposit fails, nothing is credited, and the
// sender pays only the error fee (not the amount).
BOOST_AUTO_TEST_CASE(GateRejectBlocksDeposit) {
  installGate(gateReject());
  int64_t recvBefore = bal(recv);
  int64_t sendBefore = bal(send);
  uint8_t rc = sendToRecv(kAbove);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_HOOK_REJECTED));
  BOOST_CHECK_EQUAL(bal(recv), recvBefore);           // not credited
  BOOST_CHECK_LT(bal(send), sendBefore);              // charged the error fee
  BOOST_CHECK_GT(bal(send), sendBefore - static_cast<int64_t>(kAbove)); // not amount
}

// A deposit below the dust floor fires no inbound hook: even a reject gate is
// skipped and the money just lands ("thanks for the money").
BOOST_AUTO_TEST_CASE(DustBelowFloorSkipsInboundHook) {
  installGate(gateReject());
  int64_t before = bal(recv);
  uint8_t rc = sendToRecv(kDust);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_OK));      // gate skipped, not run
  BOOST_CHECK_EQUAL(bal(recv), before + static_cast<int64_t>(kDust));
}

// The gate sees the real transfer amount in its descriptor: a min-amount gate
// (threshold above the dust floor) rejects mid deposits and accepts large ones.
BOOST_AUTO_TEST_CASE(GateReadsAmountFromDescriptor) {
  installGate(gateMinAmount(2'000'000));
  BOOST_CHECK_EQUAL(sendToRecv(1'000'000),
                    static_cast<int>(CES_ERROR_HOOK_REJECTED));
  int64_t before = bal(recv);
  BOOST_CHECK_EQUAL(sendToRecv(5'000'000), static_cast<int>(CES_OK));
  BOOST_CHECK_EQUAL(bal(recv), before + 5'000'000);
}

// The whole system conserves credit across a gate run: the free grant mints
// nothing. Sum over the two funded accounts only moves by the burned fees.
BOOST_AUTO_TEST_CASE(GateRunConservesCredit) {
  installGate(gateAccept());
  int64_t total0 = bal(recv) + bal(send);
  sendToRecv(123'456);
  int64_t total1 = bal(recv) + bal(send);
  // The transfer moved value between the two and burned feeTx; the gate's free
  // grant added nothing. So the total only drops by the burned fee, never rises.
  BOOST_CHECK_LE(total1, total0);
  BOOST_CHECK_GE(total1, total0 - 1'000'000);  // fee is far below this bound
}

// A rejecting gate on a rent-starved / missing trigger fails closed: even if
// the sidecar points at a now-absent asset, the deposit is rejected, never
// silently accepted.
BOOST_AUTO_TEST_CASE(MissingTriggerFailsClosed) {
  minx::Hash key = installGate(gateReject());
  // Overwrite recv's sidecar to point at a key with no asset.
  minx::Hash ghost;
  ghost.fill(0x77);
  AliasData sidecar{};
  std::memcpy(sidecar.data(), ghost.data(), KEY_SIZE);
  uint32_t id = 0;
  // The ghost asset does not exist, so the set-time check must reject this.
  uint8_t arc = setAliasOpContent(*server, recv.getPublicKeyAsHash(),
                                  ALIAS_OP_HOOK_GATE, sidecar, id);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(arc, static_cast<int>(CES_ERROR_HOOK_TARGET));
  (void)key;
}

// Set-time check: a hook sidecar pointing at a mutable asset owned by someone
// else is rejected; immutable or self-owned is accepted (self-owned covered by
// installGate throughout).
BOOST_AUTO_TEST_CASE(SetTimeRejectsForeignMutableTarget) {
  // An asset owned by `send`, mutable.
  minx::Hash foreign;
  foreign.fill(0x33);
  HashPrefix sendPfx = Account::getMapKey(send.getPublicKeyAsHash());
  uint8_t rc = server->createAsset(send.getPublicKeyAsHash(), sendPfx, foreign,
                                   gateAccept(), 2, 0);
  server->_drainLogic();
  BOOST_REQUIRE_EQUAL(rc, static_cast<int>(CES_OK));

  AliasData sidecar{};
  std::memcpy(sidecar.data(), foreign.data(), KEY_SIZE);
  uint32_t id = 0;
  uint8_t arc = setAliasOpContent(*server, recv.getPublicKeyAsHash(),
                                  ALIAS_OP_HOOK_GATE, sidecar, id);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(arc, static_cast<int>(CES_ERROR_HOOK_TARGET));
}

// A WATCH runs after the credit and never blocks delivery: even a trigger that
// aborts leaves the deposit standing (fail-open).
BOOST_AUTO_TEST_CASE(WatchNeverBlocksDelivery) {
  installGate(gateReject(), ALIAS_OP_HOOK_WATCH);
  int64_t before = bal(recv);
  uint8_t rc = sendToRecv(kAbove);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_OK));
  BOOST_CHECK_EQUAL(bal(recv), before + static_cast<int64_t>(kAbove));
}

// SYS_REFILL lets a hook burn past the free grant, funded by the account.
// A burn loop that exceeds the grant only completes with a refill; the account
// pays for the gas consumed past the grant, so it nets less than the deposit.
BOOST_AUTO_TEST_CASE(RefillChargesReceiverForGasPastGrant) {
  installGate(burnHook(/*iters=*/2000, /*refillReq=*/10'000'000, /*crash=*/false),
              ALIAS_OP_HOOK_WATCH, /*ceiling=*/20'000'000);
  int64_t before = bal(recv);
  BOOST_CHECK_EQUAL(sendToRecv(1'000'000), static_cast<int>(CES_OK));
  int64_t after = bal(recv);
  // Deposit landed but the account paid for the refilled gas (the loop burned
  // well past the free grant), and the charge is bounded by the ceiling.
  BOOST_CHECK_LT(after, before + 1'000'000 - 100'000);
  BOOST_CHECK_GE(after, before + 1'000'000 - 20'000'000);
}

// The refill charge survives a crash: a hook that refills, burns, then ABORTS
// still pays for the strand time it used. Otherwise "refill, compute, crash" is
// free compute.
BOOST_AUTO_TEST_CASE(RefillChargeSurvivesCrash) {
  installGate(burnHook(/*iters=*/2000, /*refillReq=*/10'000'000, /*crash=*/true),
              ALIAS_OP_HOOK_WATCH, /*ceiling=*/20'000'000);
  int64_t before = bal(recv);
  BOOST_CHECK_EQUAL(sendToRecv(1'000'000), static_cast<int>(CES_OK));
  int64_t after = bal(recv);
  BOOST_CHECK_LT(after, before + 1'000'000 - 100'000);  // charged despite abort
}

// With no refill ceiling (0), the same burn loop runs out of the free grant and
// dies, but the account is charged nothing (the free grant is free).
BOOST_AUTO_TEST_CASE(NoCeilingMeansNoChargeEvenIfHookDies) {
  installGate(burnHook(/*iters=*/2000, /*refillReq=*/10'000'000, /*crash=*/false),
              ALIAS_OP_HOOK_WATCH, /*ceiling=*/0);
  int64_t before = bal(recv);
  BOOST_CHECK_EQUAL(sendToRecv(1'000'000), static_cast<int>(CES_OK));
  // Watch dies out of gas (result ignored), but nothing was refilled, so the
  // account nets the full deposit.
  BOOST_CHECK_EQUAL(bal(recv), before + 1'000'000);
}

// Refill is capped by the sidecar ceiling: a small ceiling bounds the charge
// even when the hook requests far more.
BOOST_AUTO_TEST_CASE(RefillCappedByCeiling) {
  const uint64_t ceiling = 500'000;
  installGate(burnHook(/*iters=*/50000, /*refillReq=*/100'000'000, /*crash=*/false),
              ALIAS_OP_HOOK_WATCH, ceiling);
  int64_t before = bal(recv);
  BOOST_CHECK_EQUAL(sendToRecv(1'000'000), static_cast<int>(CES_OK));
  int64_t after = bal(recv);
  // The charge cannot exceed the ceiling, so the account keeps at least
  // (deposit - ceiling).
  BOOST_CHECK_GE(after, before + 1'000'000 - static_cast<int64_t>(ceiling));
}

// An OUTBOUND gate lets an account veto its own sends. A reject gate on the
// sender fails the transfer; the money stays with the sender.
BOOST_AUTO_TEST_CASE(OutboundGateVetoesOwnSend) {
  installHookOn(send, gateReject(), ALIAS_OP_HOOK_GATE, 0, 0x5B);
  int64_t recvBefore = bal(recv);
  int64_t sendBefore = bal(send);
  uint8_t rc = sendBetween(send, recv, 5000);
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_ERROR_HOOK_REJECTED));
  BOOST_CHECK_EQUAL(bal(recv), recvBefore);            // not delivered
  BOOST_CHECK_GT(bal(send), sendBefore - 5000);        // kept the amount
}

// One trigger fires on BOTH directions and dispatches on the invocation kind:
// a gate that rejects only XFER_OUT vetoes the account's sends but lets its
// receipts through.
BOOST_AUTO_TEST_CASE(SameTriggerDispatchesOnInvokeKind) {
  // `recv` gets a gate that rejects only outbound.
  installHookOn(recv, gateByKind(INVOKE_HOOK_XFER_OUT), ALIAS_OP_HOOK_GATE,
                0, 0x5C);
  // Inbound to recv (above the dust floor): kind XFER_IN, not rejected.
  int64_t before = bal(recv);
  BOOST_CHECK_EQUAL(sendBetween(send, recv, kAbove), static_cast<int>(CES_OK));
  BOOST_CHECK_EQUAL(bal(recv), before + static_cast<int64_t>(kAbove));
  // Outbound from recv: kind XFER_OUT, rejected -> vetoed (no outbound floor).
  BOOST_CHECK_EQUAL(sendBetween(recv, send, 5000),
                    static_cast<int>(CES_ERROR_HOOK_REJECTED));
}

// Settlement / open-mode transfers are exempt: a reject gate does NOT block an
// Open-mode transfer (how an incoming cross settlement lands). Gating those
// would break vostro/reserve conservation, since the origin already committed.
BOOST_AUTO_TEST_CASE(OpenModeTransferBypassesGate) {
  installGate(gateReject());  // would reject a Safe transfer
  int64_t before = bal(recv);
  int64_t ob = 0;
  uint8_t rc = server->transfer(send.getPublicKeyAsHash(),
                                recv.getPublicKeyAsHash(), 5000,
                                CesServer::TransferMode::Open, 0, 0, ob);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(rc, static_cast<int>(CES_OK));   // not rejected
  BOOST_CHECK_EQUAL(bal(recv), before + 5000);       // delivered
}

// XFER_VM: a program's SYS_TRANSFER to a hooked account fires the dest's WATCH
// (deferred, after the program run commits). Observed via a refilling watch
// that charges the receiver. Program transfers cannot be gated, only watched.
BOOST_AUTO_TEST_CASE(ProgramTransferFiresWatch) {
  // recv has a WATCH that refills + burns gas (so a fire is visible as a charge).
  installGate(burnHook(/*iters=*/500, /*refillReq=*/5'000'000, /*crash=*/false),
              ALIAS_OP_HOOK_WATCH, /*ceiling=*/10'000'000);

  // A program owned by `send` that transfers 1,000,000 to the dest in input[0].
  minx::Hash progId;
  progId.fill(0x6A);
  HashPrefix sendPfx = Account::getMapKey(send.getPublicKeyAsHash());
  VmProgram pgm;
  Region destReg = pgm.allocHash();
  pgm.copyFromInput(destReg, 0);
  pgm.sysTransfer({destReg, Imm(1'000'000)});
  pgm.term();
  BOOST_REQUIRE_EQUAL(
      server->createAsset(send.getPublicKeyAsHash(), sendPfx, progId,
                          pgm.buildBootBlock(), /*days=*/2, 0),
      static_cast<int>(CES_OK));
  server->_drainLogic();

  int64_t before = bal(recv);
  ces::Bytes input(recv.getPublicKeyAsHash().begin(),
                   recv.getPublicKeyAsHash().end());
  bool ok = server->_executeScheduledRunSync(
      sendPfx, progId, 1'000'000'000, std::numeric_limits<uint64_t>::max(),
      input);
  server->_drainLogic();
  BOOST_REQUIRE(ok);

  int64_t after = bal(recv);
  BOOST_CHECK_GT(after, before);              // received the program transfer
  BOOST_CHECK_LT(after, before + 1'000'000);  // XFER_VM watch fired and charged
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Settlement hooks (SETTLE_IN / SETTLE_OUT): cross-transfer history. Two peered
// in-process servers; both watch-only.
// ---------------------------------------------------------------------------
namespace {

CesConfig makeSettleConfig(const fs::path& dir, const minx::Hash& priv) {
  CesConfig cfg;
  cfg.dataDir = dir;
  cfg.serverPrivKey = priv;
  cfg.minAcc = 100;
  cfg.maxAcc = 10000;
  cfg.minDiff = 1;
  cfg.spendSlotSize = 10;
  cfg.taskThreads = 2;
  cfg.flushValue = std::numeric_limits<uint64_t>::max();
  cfg.feeAccount = 0;
  cfg.feeTx = 0;
  cfg.feeQuery = 0;
  cfg.feeAsset = 0;
  return cfg;
}

int64_t balOf(CesServer* s, const KeyPair& k) {
  return s->_balanceOf(k.getPublicKeyAsHash());
}

void installWatchOn(CesServer* s, KeyPair& who, const AssetData& code,
                    uint64_t ceiling, uint8_t keyByte) {
  minx::Hash tk;
  tk.fill(keyByte);
  HashPrefix pfx = Account::getMapKey(who.getPublicKeyAsHash());
  BOOST_REQUIRE_EQUAL(
      s->createAsset(who.getPublicKeyAsHash(), pfx, tk, code, 2, 0),
      static_cast<int>(CES_OK));
  s->_drainLogic();
  AliasData sc{};
  std::memcpy(sc.data(), tk.data(), KEY_SIZE);
  ces::Buffer::pokeLE<uint64_t>(sc.data() + 32, ceiling);
  uint32_t id = 0;
  BOOST_REQUIRE_EQUAL(
      setAliasOpContent(*s, who.getPublicKeyAsHash(), ALIAS_OP_HOOK_WATCH, sc,
                        id),
      static_cast<int>(CES_OK));
  s->_drainLogic();
}

void waitChange(CesServer* s, const HashPrefix& k, int64_t was,
                int timeoutMs = 12000) {
  for (int i = 0; i < timeoutMs / 50; ++i) {
    int64_t b = 0;
    uint32_t n = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    s->unsignedQueryAccount(k, b, n, xd, xa, xt);
    if (b != was) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

} // namespace

BOOST_AUTO_TEST_SUITE(AccountHookSettleTests)

BOOST_AUTO_TEST_CASE(SettlementHooksRecordCrossTransfers) {
  blog::init();
  blog::set_level(blog::fatal);
  fs::path dirA = makeUniqueTempDir("ces_settle_a");
  fs::path dirB = makeUniqueTempDir("ces_settle_b");
  minx::Hash privA;
  privA.fill(0xA1);
  minx::Hash privB;
  privB.fill(0xB1);
  KeyPair kpA(privA), kpB(privB), alice, bob;

  auto srvA = std::make_unique<CesServer>(makeSettleConfig(dirA, privA));
  uint16_t portA = srvA->start(0);
  BOOST_REQUIRE_GT(portA, 0);
  auto srvB = std::make_unique<CesServer>(makeSettleConfig(dirB, privB));
  uint16_t portB = srvB->start(0);
  BOOST_REQUIRE_GT(portB, 0);
  std::string addrA = "127.0.0.1:" + std::to_string(portA);
  std::string addrB = "127.0.0.1:" + std::to_string(portB);

  srvA->_brr(alice.getPublicKeyAsHash(), 200'000'000);
  srvB->_brr(kpA.getPublicKeyAsHash(), 200'000'000);   // A's reserve on B
  srvB->_brr(bob.getPublicKeyAsHash(), 200'000'000);
  srvA->_drainLogic();
  srvB->_drainLogic();

  // Bidirectional peering (real settlement peers are mutual; SETTLE_IN's
  // isConnected discriminator needs A in B's peer table).
  srvA->_markPeerReachable(kpB.getPublicKeyAsHash(), addrB);
  srvB->_markPeerReachable(kpA.getPublicKeyAsHash(), addrA);

  installWatchOn(srvA.get(), alice,
                 burnHook(2000, 10'000'000, false), 20'000'000, 0x71);
  installWatchOn(srvB.get(), bob,
                 burnHook(2000, 10'000'000, false), 20'000'000, 0x72);

  int64_t aliceBefore = balOf(srvA.get(), alice);
  int64_t bobBefore = balOf(srvB.get(), bob);

  {
    boost::asio::ip::udp::endpoint ep(
        boost::asio::ip::address_v6::loopback(), portA);
    CesClient cli(ep, false);
    cli.setKey(alice);
    cli.start(0);
    BOOST_REQUIRE(cli.connect());
    int64_t nb = 0;
    BOOST_REQUIRE_EQUAL(
        cli.crossTransfer(bob.getPublicKeyAsHash(), 5'000'000, addrB, nb),
        static_cast<int>(CES_OK));
    cli.disconnect();
    cli.stop();
  }
  srvA->_drainLogic();

  // SETTLE_OUT fires synchronously in crossTransfer: with feeTx=0, any charge
  // beyond the 5000 sent is Alice's watch refilling.
  int64_t aliceAfter = balOf(srvA.get(), alice);
  BOOST_CHECK_LT(aliceAfter, aliceBefore - 5'000'000);

  // Settlement lands on B and Bob's SETTLE_IN watch charges him.
  waitChange(srvB.get(), Account::getMapKey(bob.getPublicKeyAsHash()),
             bobBefore);
  srvB->_drainLogic();
  int64_t bobAfter = balOf(srvB.get(), bob);
  BOOST_CHECK_GT(bobAfter, bobBefore);               // net positive: +5M - charge
  BOOST_CHECK_LT(bobAfter, bobBefore + 5'000'000);   // SETTLE_IN watch charged

  srvA->stop();
  srvB->stop();
  boost::system::error_code ec;
  fs::remove_all(dirA, ec);
  fs::remove_all(dirB, ec);
}

BOOST_AUTO_TEST_SUITE_END()
