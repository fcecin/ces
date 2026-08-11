// Hardens the L1 account/transfer surface against the int48 balance cap
// (BALANCE_MAX = 2^47-1, ~1.4M credits). Every value-movement op must REVERT
// rather than saturate when the destination would exceed the cap, so credits
// are never destroyed; creation/mint paths may saturate (nothing is destroyed,
// the tally tracks the real delta). Conservation (circulating credits) is
// asserted after each scenario. Fees are pinned to 0 so the arithmetic is
// exact.

#include "test_common.h"

#include <ces/account.h>
#include <ces/types.h>
#include <ces/util/vmprogram.h>

#include <limits>
#include <vector>

BOOST_AUTO_TEST_SUITE(LedgerOverflowTests)

namespace {

struct OverflowFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort;

  OverflowFixture() {
    blog::init();
    tempDir = makeUniqueTempDir("ces_ovf");
    minx::Hash serverPriv;
    serverPriv.fill(0xEE);
    CesConfig cfg =
      makeTestConfig(tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.feeTx = 0;
    cfg.feeAccount = 0;
    cfg.feeQuery = 0;   // getFeeError() returns feeQuery
    cfg.feeAsset = 0;
    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE(serverPort > 0);
  }

  ~OverflowFixture() {
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  void fund(const minx::Hash& k, int64_t amt) {
    server->_brr(k, amt);
    server->_drainLogic();
  }
  int64_t bal(const minx::Hash& k) { return server->_balanceOf(k); }
  int64_t circ() { return server->_getTotalCredits(); }

  uint8_t xfer(const minx::Hash& from, const minx::Hash& to, uint64_t amt,
               CesServer::TransferMode mode = CesServer::TransferMode::Open) {
    int64_t outBal = 0;
    uint8_t rc = server->transfer(from, to, amt, mode, 0, 0, outBal);
    server->_drainLogic();
    return rc;
  }
};

}  // namespace

// ---- The guard predicate itself, at every boundary --------------------------

BOOST_AUTO_TEST_CASE(CreditWouldOverflowBoundaries) {
  using ces::creditWouldOverflow;
  const int64_t M = ces::BALANCE_MAX;
  BOOST_CHECK(!creditWouldOverflow(0, 0));
  BOOST_CHECK(!creditWouldOverflow(0, static_cast<uint64_t>(M)));
  BOOST_CHECK( creditWouldOverflow(0, static_cast<uint64_t>(M) + 1));
  BOOST_CHECK(!creditWouldOverflow(M, 0));
  BOOST_CHECK( creditWouldOverflow(M, 1));
  BOOST_CHECK(!creditWouldOverflow(M - 100, 100));
  BOOST_CHECK( creditWouldOverflow(M - 100, 101));
  BOOST_CHECK( creditWouldOverflow(1, static_cast<uint64_t>(M)));
  BOOST_CHECK(!creditWouldOverflow(1000, 5000));
  // Payment accounts (balance < 0) never take a plain credit.
  BOOST_CHECK(!creditWouldOverflow(-5, 1000));
  BOOST_CHECK(!creditWouldOverflow(-1, 999999999ull));
}

// ---- Transfer into an existing account near the cap -------------------------

BOOST_FIXTURE_TEST_CASE(TransferIntoCappedAccountReverts, OverflowFixture) {
  KeyPair rich, capped;
  fund(rich.getPublicKeyAsHash(), 5'000'000);
  fund(capped.getPublicKeyAsHash(), ces::BALANCE_MAX);
  const int64_t total = 5'000'000 + ces::BALANCE_MAX;
  BOOST_CHECK_EQUAL(circ(), total);

  uint8_t rc = xfer(rich.getPublicKeyAsHash(), capped.getPublicKeyAsHash(), 1);
  CES_CHECK_RC_EQ(rc, CES_ERROR_BALANCE_OVERFLOW);
  BOOST_CHECK_EQUAL(bal(capped.getPublicKeyAsHash()), ces::BALANCE_MAX);
  BOOST_CHECK_EQUAL(bal(rich.getPublicKeyAsHash()), 5'000'000);
  BOOST_CHECK_EQUAL(circ(), total);   // nothing moved, nothing destroyed
}

BOOST_FIXTURE_TEST_CASE(TransferBoundaryExactThenReject, OverflowFixture) {
  KeyPair a, b, c;
  fund(a.getPublicKeyAsHash(), 1000);
  fund(b.getPublicKeyAsHash(), ces::BALANCE_MAX - 1000);
  fund(c.getPublicKeyAsHash(), 1000);
  const int64_t total = 1000 + (ces::BALANCE_MAX - 1000) + 1000;

  // Exactly fill b to the cap.
  CES_CHECK_OK(xfer(a.getPublicKeyAsHash(), b.getPublicKeyAsHash(), 1000));
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), ces::BALANCE_MAX);

  // One more credit into b reverts.
  uint8_t rc = xfer(c.getPublicKeyAsHash(), b.getPublicKeyAsHash(), 1);
  CES_CHECK_RC_EQ(rc, CES_ERROR_BALANCE_OVERFLOW);
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), ces::BALANCE_MAX);
  BOOST_CHECK_EQUAL(circ(), total);
}

BOOST_FIXTURE_TEST_CASE(TransferOnePastCapReverts, OverflowFixture) {
  KeyPair a, b;
  fund(a.getPublicKeyAsHash(), 10'000);
  fund(b.getPublicKeyAsHash(), ces::BALANCE_MAX - 500);

  // 501 would overflow (only 500 headroom); 500 exactly fits.
  CES_CHECK_RC_EQ(xfer(a.getPublicKeyAsHash(), b.getPublicKeyAsHash(), 501),
                  CES_ERROR_BALANCE_OVERFLOW);
  CES_CHECK_OK(xfer(a.getPublicKeyAsHash(), b.getPublicKeyAsHash(), 500));
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), ces::BALANCE_MAX);
}

// ---- Account creation at / past the cap -------------------------------------

BOOST_FIXTURE_TEST_CASE(CreateNewAccountAtExactCapThenReject, OverflowFixture) {
  KeyPair a, fresh, b;
  fund(a.getPublicKeyAsHash(), ces::BALANCE_MAX);
  fund(b.getPublicKeyAsHash(), 1000);

  // a sends its entire cap to a brand-new account -> created at exactly the cap.
  CES_CHECK_OK(xfer(a.getPublicKeyAsHash(), fresh.getPublicKeyAsHash(),
                    static_cast<uint64_t>(ces::BALANCE_MAX)));
  BOOST_CHECK_EQUAL(bal(fresh.getPublicKeyAsHash()), ces::BALANCE_MAX);

  // fresh is now capped -> any further credit reverts.
  CES_CHECK_RC_EQ(xfer(b.getPublicKeyAsHash(), fresh.getPublicKeyAsHash(), 1),
                  CES_ERROR_BALANCE_OVERFLOW);
}

BOOST_FIXTURE_TEST_CASE(AccountHoldsExactCap, OverflowFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), ces::BALANCE_MAX);
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), ces::BALANCE_MAX);
  BOOST_CHECK_EQUAL(circ(), ces::BALANCE_MAX);
}

// ---- Debits are unaffected by the cap ---------------------------------------

BOOST_FIXTURE_TEST_CASE(CappedAccountCanSend, OverflowFixture) {
  KeyPair a, b;
  fund(a.getPublicKeyAsHash(), ces::BALANCE_MAX);
  fund(b.getPublicKeyAsHash(), 1000);
  CES_CHECK_OK(xfer(a.getPublicKeyAsHash(), b.getPublicKeyAsHash(), 1'000'000));
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), ces::BALANCE_MAX - 1'000'000);
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), 1'001'000);
}

// ---- Degenerate transfers ---------------------------------------------------

BOOST_FIXTURE_TEST_CASE(SelfTransferConserves, OverflowFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  const int64_t total = circ();
  CES_CHECK_OK(xfer(a.getPublicKeyAsHash(), a.getPublicKeyAsHash(), 5000));
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), 1'000'000);   // net zero
  BOOST_CHECK_EQUAL(circ(), total);
}

BOOST_FIXTURE_TEST_CASE(TransferZeroAmountConserves, OverflowFixture) {
  KeyPair a, b;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  fund(b.getPublicKeyAsHash(), 1000);
  const int64_t total = circ();
  xfer(a.getPublicKeyAsHash(), b.getPublicKeyAsHash(), 0);
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), 1000);
  BOOST_CHECK_EQUAL(circ(), total);
}

BOOST_FIXTURE_TEST_CASE(SafeVsOpenMode, OverflowFixture) {
  KeyPair a, missing, missing2;
  fund(a.getPublicKeyAsHash(), 1'000'000);

  CES_CHECK_RC_EQ(xfer(a.getPublicKeyAsHash(), missing.getPublicKeyAsHash(), 5000,
                       CesServer::TransferMode::Safe),
                  CES_ERROR_TARGET_NOT_FOUND);
  BOOST_CHECK(!server->_accountExists(missing.getPublicKeyAsHash()));

  CES_CHECK_OK(xfer(a.getPublicKeyAsHash(), missing2.getPublicKeyAsHash(), 5000,
                    CesServer::TransferMode::Open));
  BOOST_CHECK_EQUAL(bal(missing2.getPublicKeyAsHash()), 5000);
}

// ---- Payment accounts (negative-balance marker) -----------------------------

BOOST_FIXTURE_TEST_CASE(PaymentAccountLifecycle, OverflowFixture) {
  KeyPair creator, payAcc, payer;
  fund(creator.getPublicKeyAsHash(), 1'000'000);
  fund(payer.getPublicKeyAsHash(), 1'000'000);

  int64_t outBal = 0;
  uint8_t rc = server->transfer(creator.getPublicKeyAsHash(),
                                payAcc.getPublicKeyAsHash(), 5000,
                                CesServer::TransferMode::Payment, 3, 0, outBal);
  server->_drainLogic();
  CES_CHECK_OK(rc);
  BOOST_CHECK_EQUAL(bal(payAcc.getPublicKeyAsHash()), -5000);   // negative marker

  // Wrong settle amount is rejected; the pending payment is untouched.
  CES_CHECK_RC_EQ(xfer(payer.getPublicKeyAsHash(), payAcc.getPublicKeyAsHash(), 4000),
                  CES_ERROR_WRONG_PAYMENT_AMOUNT);
  BOOST_CHECK_EQUAL(bal(payAcc.getPublicKeyAsHash()), -5000);

  // Exact settle flips it positive.
  CES_CHECK_OK(xfer(payer.getPublicKeyAsHash(), payAcc.getPublicKeyAsHash(), 5000));
  BOOST_CHECK_EQUAL(bal(payAcc.getPublicKeyAsHash()), 5000);
  BOOST_CHECK_EQUAL(bal(payer.getPublicKeyAsHash()), 995'000);
}

// ---- Creation-path (mint / admin credit) saturates without minting phantoms -

BOOST_FIXTURE_TEST_CASE(CreditSaturationNoPhantomCredits, OverflowFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), ces::BALANCE_MAX);
  const int64_t before = circ();
  BOOST_CHECK_EQUAL(before, ces::BALANCE_MAX);

  // Credit onto an already-capped account (the mint/admin path saturates).
  server->_brr(a.getPublicKeyAsHash(), 1'000'000);
  server->_drainLogic();

  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), ces::BALANCE_MAX);  // capped
  BOOST_CHECK_EQUAL(circ(), before);   // nothing minted past the cap
}

// ---- Conservation is the invariant ------------------------------------------

BOOST_FIXTURE_TEST_CASE(ConservationUnderRandomChurn, OverflowFixture) {
  const int N = 8;
  std::vector<KeyPair> acc(N);
  int64_t total = 0;
  uint64_t rng = 0x9e3779b97f4a7c15ull;
  auto nx = [&] { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; };

  for (int i = 0; i < N; ++i) {
    int64_t amt = 100'000 + static_cast<int64_t>(nx() % 900'000);
    fund(acc[i].getPublicKeyAsHash(), amt);
    total += amt;
  }
  BOOST_CHECK_EQUAL(circ(), total);

  for (int k = 0; k < 400; ++k) {
    int s = static_cast<int>(nx() % N);
    int d = static_cast<int>(nx() % N);
    uint64_t amt = 1 + (nx() % 200'000);
    xfer(acc[s].getPublicKeyAsHash(), acc[d].getPublicKeyAsHash(), amt);
  }
  BOOST_CHECK_EQUAL(circ(), total);   // sum of balances is invariant
}

BOOST_FIXTURE_TEST_CASE(ConservationWithRepeatedOverflowReverts, OverflowFixture) {
  KeyPair capped, rich;
  fund(capped.getPublicKeyAsHash(), ces::BALANCE_MAX);
  fund(rich.getPublicKeyAsHash(), 5'000'000);
  const int64_t total = ces::BALANCE_MAX + 5'000'000;

  for (int k = 0; k < 50; ++k) {
    CES_CHECK_RC_EQ(xfer(rich.getPublicKeyAsHash(), capped.getPublicKeyAsHash(),
                         1 + static_cast<uint64_t>(k)),
                    CES_ERROR_BALANCE_OVERFLOW);
  }
  BOOST_CHECK_EQUAL(bal(capped.getPublicKeyAsHash()), ces::BALANCE_MAX);
  BOOST_CHECK_EQUAL(bal(rich.getPublicKeyAsHash()), 5'000'000);
  BOOST_CHECK_EQUAL(circ(), total);
}

// Every value-move path -- wire and VM (transfer/ownerTransfer/deposit/withdraw/
// buyAsset/crossTransfer) -- runs checkCredit (creditWouldOverflow) before any
// debit, so a move never saturate-burns. The VM buyAsset path is exercised by
// VmBuyAssetNearCapSellerNoBurn below; the wire paths by the handler tests.

// Mint/admin credit (_brr) saturates at the cap instead of feeding a
// >2^47 value into the int48 balance (which would wrap NEGATIVE).
BOOST_FIXTURE_TEST_CASE(BrrCredit_SaturatesAtCapNoWrap, OverflowFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), ces::BALANCE_MAX - 100);
  server->_brr(a.getPublicKeyAsHash(), 1'000'000);   // way past the cap
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), ces::BALANCE_MAX);
  BOOST_CHECK(bal(a.getPublicKeyAsHash()) > 0);       // never wrapped negative
}

// A fresh account minted with a >2^47 amount is capped at BALANCE_MAX, not
// truncated by the int48 constructor.
BOOST_FIXTURE_TEST_CASE(BrrCredit_FreshAccountCapsNotTruncates, OverflowFixture) {
  KeyPair a;
  server->_brr(a.getPublicKeyAsHash(),
               static_cast<int64_t>(ces::BALANCE_MAX) + 500'000);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), ces::BALANCE_MAX);
}

// A non-positive admin credit is a no-op (a negative amount must not convert to
// a huge unsigned credit and mint a max balance).
BOOST_FIXTURE_TEST_CASE(BrrCredit_NonPositiveIsNoop, OverflowFixture) {
  KeyPair a;
  server->_brr(a.getPublicKeyAsHash(), -1);
  server->_drainLogic();
  BOOST_CHECK(!server->_accountExists(a.getPublicKeyAsHash()));
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), 0);
}

// A VM program that buys `assetId` for up to `maxPrice` (raw internal units).
static AssetData buildBuyProgram(const minx::Hash& assetId, uint64_t maxPrice) {
  VmProgram pgm;
  Region keyReg = pgm.allocHash();                     // 32-byte asset key
  pgm.writeBytesToIo(keyReg.cell, assetId.data(), 32);
  pgm.sysBuyAsset({keyReg, Imm(maxPrice)});
  pgm.term();
  return pgm.buildBootBlock();
}

// The VM-host buyAsset syscall must checkCredit the seller BEFORE debiting the
// buyer, so buying from a near-cap seller never destroys credit (mirrors the
// wire buyAsset). Pre-fix: the buyer was debited the full price while the
// seller's credit saturated at the cap, vanishing the difference.
BOOST_FIXTURE_TEST_CASE(VmBuyAssetNearCapSellerNoBurn, OverflowFixture) {
  KeyPair seller, buyer;
  const int64_t headroom = 1000;
  fund(seller.getPublicKeyAsHash(), ces::BALANCE_MAX - headroom);
  fund(buyer.getPublicKeyAsHash(),  ces::BALANCE_MAX);
  const HashPrefix sellerPfx = Account::getMapKey(seller.getPublicKeyAsHash());
  const HashPrefix buyerPfx  = Account::getMapKey(buyer.getPublicKeyAsHash());

  // Seller owns a for-sale asset priced far above the seller's headroom.
  minx::Hash assetId; assetId.fill(0xB7);
  AssetData content; content.fill(0);
  CES_REQUIRE_OK(server->createAsset(seller.getPublicKeyAsHash(), sellerPfx,
                                     assetId, content, /*days=*/100, 0));
  const uint32_t priceWhole = 500;
  CES_REQUIRE_OK(server->updateAssetMeta(seller.getPublicKeyAsHash(), assetId,
                                         sellerPfx, priceWhole, 0));

  // A program the buyer runs that buys the asset.
  minx::Hash progId; progId.fill(0xB8);
  const uint64_t maxPrice = static_cast<uint64_t>(priceWhole) * ces::PRICE_UNIT;
  CES_REQUIRE_OK(server->createAsset(buyer.getPublicKeyAsHash(), buyerPfx, progId,
                                     buildBuyProgram(assetId, maxPrice),
                                     /*days=*/100, 0));
  server->_drainLogic();

  server->_executeScheduledRunSync(buyerPfx, progId, 100'000'000,
                                   std::numeric_limits<uint64_t>::max(), {});
  server->_drainLogic();

  // Seller unchanged (no saturating credit); buyer keeps the price (only VM gas
  // spent). Pre-fix: seller == BALANCE_MAX, buyer down by the full price.
  BOOST_CHECK_EQUAL(bal(seller.getPublicKeyAsHash()), ces::BALANCE_MAX - headroom);
  BOOST_CHECK_GT(bal(buyer.getPublicKeyAsHash()),
                 ces::BALANCE_MAX - static_cast<int64_t>(maxPrice));
}

BOOST_AUTO_TEST_SUITE_END()
