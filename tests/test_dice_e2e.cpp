// E2E coverage for the shipped /b/dice bytecode program, run through a
// real in-process CesServer + CesServerVmHost (not the stubbed CesVMHost
// the cesvm unit tests use). This is the path that was previously
// untested: the heads branch performs SYS_WITHDRAW (owner -> caller)
// where the owner is the server's own account.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/cesvm.h>  // CESVM_OK, CESVM_ABORT

BOOST_FIXTURE_TEST_SUITE(DiceE2ETests, CesFixture)

// Run /b/dice many times. Each run is a fair coin: tails (output 0x00,
// bet stays with the house) or heads (output 0x01, house pays 2x back).
// Both outcomes must execute cleanly through the real VM host. A heads
// that aborts (VM error CESVM_ABORT) means SYS_WITHDRAW from the
// server-owned house account is broken.
BOOST_AUTO_TEST_CASE(BDicePlaysBothOutcomesCleanly) {
  const minx::Hash diceKey = makeHash("/b/dice");
  const uint64_t bet = 1000;

  int heads = 0, tails = 0, aborts = 0, other = 0;
  uint64_t firstBadVmErr = 0;
  uint8_t  firstBadRc = CES_OK;

  for (int i = 0; i < 100; ++i) {
    uint64_t vmErr = 0, used = 0;
    ces::Bytes out;
    uint8_t rc = client->runAsset(diceKey, /*budget=*/10'000'000, {},
                                  vmErr, used, out,
                                  /*nonceless=*/false, /*allowance=*/bet);
    if (rc == CES_OK && vmErr == CESVM_OK && out.size() == 1 && out[0] == 0x01)
      ++heads;
    else if (rc == CES_OK && vmErr == CESVM_OK && out.size() == 1 && out[0] == 0x00)
      ++tails;
    else {
      ++aborts;
      if (firstBadVmErr == 0) { firstBadVmErr = vmErr; firstBadRc = rc; }
    }
  }

  BOOST_TEST_MESSAGE("/b/dice over 100 runs: heads=" << heads
                     << " tails=" << tails << " failed=" << aborts
                     << " (first failure rc=" << int(firstBadRc)
                     << " vmErr=" << firstBadVmErr << ")");

  // Both branches must run cleanly.
  BOOST_CHECK_EQUAL(aborts, 0);
  // With 100 fair flips, both outcomes are overwhelmingly likely to appear;
  // the point is that a heads payout actually completes.
  BOOST_CHECK_GT(heads, 0);
  BOOST_CHECK_GT(tails, 0);
}

BOOST_AUTO_TEST_SUITE_END()
