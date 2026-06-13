#include "test_common.h"

BOOST_FIXTURE_TEST_SUITE(PaymentTests, CesFixture)

BOOST_AUTO_TEST_CASE(Test04_PaymentAccountCreate) {
  LOGINFO << "TEST: Starting PaymentAccountCreate";
  KeyPair bill;
  while (Account::getMapKey(bill.getPublicKeyAsHash()) == getMyId()) {
    bill = KeyPair();
  }

  int64_t newBal;
  uint8_t rc = client->createPayment(bill.getPublicKeyAsHash(), 1000, 5, newBal);
  BOOST_REQUIRE_MESSAGE(rc == CES_OK, "Payment Create Failed RC: " << (int)rc);

  CesClient check(testServerEp(serverPort), false);
  check.start(0);
  check.connect();
  int64_t b = 0;
  uint32_t n = 0;
  check.queryAccount(Account::getMapKey(bill.getPublicKeyAsHash()), b, n);

  BOOST_CHECK_EQUAL(b, -1000);
  BOOST_CHECK_EQUAL(n, 6);
}

BOOST_AUTO_TEST_CASE(Test16_PaymentSettlement) {
  LOGINFO << "TEST: Starting PaymentSettlement (Invoice Logic)";
  KeyPair bill;
  // Ensure unique
  while (Account::getMapKey(bill.getPublicKeyAsHash()) == getMyId())
    bill = KeyPair();

  int64_t newBal;
  // 1. Create Bill: Balance -1000 (Invoice for 1000)
  uint8_t rc = client->createPayment(bill.getPublicKeyAsHash(), 1000, 5, newBal);
  CES_REQUIRE_OK(rc);

  // 2. Try to pay wrong amount (e.g. 500)
  rc = client->transfer(bill.getPublicKeyAsHash(), 500, newBal);
  CES_CHECK_RC_EQ(rc, CES_ERROR_WRONG_PAYMENT_AMOUNT);

  // 3. Pay exact amount (1000)
  rc = client->transfer(bill.getPublicKeyAsHash(), 1000, newBal);
  CES_CHECK_OK(rc);

  // Verify Bill is now active with +1000 balance
  CesClient check(testServerEp(serverPort), false);
  check.start(0);
  check.connect();
  int64_t b = 0;
  uint32_t n = 0;
  check.queryAccount(Account::getMapKey(bill.getPublicKeyAsHash()), b, n);

  BOOST_CHECK_EQUAL(b, 1000);
  BOOST_CHECK_EQUAL(n, 0);
}

// A signed op from the payee's own key against their unsettled payment account
// (balance < 0) must not delete it. validateSpend routes balance<0 to
// chargeError, which would compute b = neg - fee <= 0 and erase the account, so
// a signed self-query would silently destroy the pending obligation.
BOOST_AUTO_TEST_CASE(SignedOpOnUnsettledPaymentAccountDoesNotDeleteIt) {
  LOGINFO << "TEST: signed op on payment account must not delete it";
  KeyPair bill;
  while (Account::getMapKey(bill.getPublicKeyAsHash()) == getMyId())
    bill = KeyPair();

  int64_t newBal;
  uint8_t rc = client->createPayment(bill.getPublicKeyAsHash(), 1000, 5, newBal);
  CES_REQUIRE_OK(rc);

  // Payee signs an op from their OWN balance<0 payment account. A signed
  // self-query is the realistic trigger. We don't care about its rc (expected
  // INSUFFICIENT_BALANCE) — only that the account survives.
  {
    CesClient bc(testServerEp(serverPort), false);
    bc.start(0);
    bc.connect();
    bc.setKey(bill);
    std::vector<AccountEntry> entries;
    bc.queryAccountSigned(Account::getMapKey(bill.getPublicKeyAsHash()), 0,
                          entries);
    bc.disconnect();
    bc.stop();
  }

  // The payment account must still exist, still unsettled (-1000, nonce 6).
  CesClient check(testServerEp(serverPort), false);
  check.start(0);
  check.connect();
  int64_t b = 0;
  uint32_t n = 0;
  check.queryAccount(Account::getMapKey(bill.getPublicKeyAsHash()), b, n);
  BOOST_CHECK_EQUAL(b, -1000);  // pre-fix: 0 (account was deleted)
  BOOST_CHECK_EQUAL(n, 6);      // pre-fix: 0
}

BOOST_AUTO_TEST_SUITE_END()
