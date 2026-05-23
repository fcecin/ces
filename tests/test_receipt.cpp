#include "test_common.h"

BOOST_FIXTURE_TEST_SUITE(ReceiptTests, CesFixture)

// Single transfer writes lastXfer fields on the sender account
BOOST_AUTO_TEST_CASE(Receipt_SingleTransfer) {
  KeyPair bob;
  while (Account::getMapKey(bob.getPublicKeyAsHash()) == getMyId())
    bob = KeyPair();

  HashPrefix bobId = Account::getMapKey(bob.getPublicKeyAsHash());

  int64_t newBal;
  uint8_t rc = client->openTransfer(bob.getPublicKeyAsHash(), 5000, newBal);
  CES_REQUIRE_OK(rc);
  wait_net();

  HashPrefix dest;
  uint64_t amount;
  uint32_t time;
  int64_t _bal = 0; uint32_t _nonce = 0;
  server->unsignedQueryAccount(getMyId(), _bal, _nonce, dest, amount, time);

  BOOST_CHECK(dest == bobId);
  BOOST_CHECK_EQUAL(amount, 5000u);
  BOOST_CHECK(time > 0);
}

// New account starts with zero xfer fields
BOOST_AUTO_TEST_CASE(Receipt_NewAccountZero) {
  KeyPair alice;
  while (Account::getMapKey(alice.getPublicKeyAsHash()) == getMyId())
    alice = KeyPair();

  // Create alice by transferring to her
  int64_t newBal;
  uint8_t rc = client->openTransfer(alice.getPublicKeyAsHash(), 1000, newBal);
  CES_REQUIRE_OK(rc);
  wait_net();

  // Alice was just created, she hasn't sent anything
  HashPrefix dest;
  uint64_t amount;
  uint32_t time;
  HashPrefix aliceId = Account::getMapKey(alice.getPublicKeyAsHash());
  int64_t _bal = 0; uint32_t _nonce = 0;
  server->unsignedQueryAccount(aliceId, _bal, _nonce, dest, amount, time);

  HashPrefix zeroPfx{};
  BOOST_CHECK(dest == zeroPfx);
  BOOST_CHECK_EQUAL(amount, 0u);
  BOOST_CHECK_EQUAL(time, 0u);
}

// A second transfer overwrites the previous receipt
BOOST_AUTO_TEST_CASE(Receipt_OverwriteOnSecondTransfer) {
  KeyPair bob, carol;
  while (Account::getMapKey(bob.getPublicKeyAsHash()) == getMyId())
    bob = KeyPair();
  do {
    carol = KeyPair();
  } while (Account::getMapKey(carol.getPublicKeyAsHash()) == getMyId() ||
           Account::getMapKey(carol.getPublicKeyAsHash()) ==
               Account::getMapKey(bob.getPublicKeyAsHash()));

  int64_t newBal;
  uint8_t rc = client->openTransfer(bob.getPublicKeyAsHash(), 1000, newBal);
  CES_REQUIRE_OK(rc);
  wait_net();

  rc = client->openTransfer(carol.getPublicKeyAsHash(), 2000, newBal);
  CES_REQUIRE_OK(rc);
  wait_net();

  HashPrefix dest;
  uint64_t amount;
  uint32_t time;
  int64_t _bal = 0; uint32_t _nonce = 0;
  server->unsignedQueryAccount(getMyId(), _bal, _nonce, dest, amount, time);

  HashPrefix carolId = Account::getMapKey(carol.getPublicKeyAsHash());
  BOOST_CHECK(dest == carolId);
  BOOST_CHECK_EQUAL(amount, 2000u);
}

// PoW/credit does NOT clobber xfer fields
BOOST_AUTO_TEST_CASE(Receipt_CreditDoesNotClobber) {
  KeyPair bob;
  while (Account::getMapKey(bob.getPublicKeyAsHash()) == getMyId())
    bob = KeyPair();

  int64_t newBal;
  uint8_t rc = client->openTransfer(bob.getPublicKeyAsHash(), 3000, newBal);
  CES_REQUIRE_OK(rc);
  wait_net();

  // Credit the sender (simulating PoW or _brr)
  server->_brr(clientKey.getPublicKeyAsHash(), 999);
  wait_net();

  HashPrefix dest;
  uint64_t amount;
  uint32_t time;
  int64_t _bal = 0; uint32_t _nonce = 0;
  server->unsignedQueryAccount(getMyId(), _bal, _nonce, dest, amount, time);

  HashPrefix bobId = Account::getMapKey(bob.getPublicKeyAsHash());
  BOOST_CHECK(dest == bobId);
  BOOST_CHECK_EQUAL(amount, 3000u);
  BOOST_CHECK(time > 0);
}

// Bulk transfer does NOT write xfer fields
BOOST_AUTO_TEST_CASE(Receipt_BulkDoesNotWrite) {
  KeyPair bob, carol;
  while (Account::getMapKey(bob.getPublicKeyAsHash()) == getMyId())
    bob = KeyPair();
  do {
    carol = KeyPair();
  } while (Account::getMapKey(carol.getPublicKeyAsHash()) == getMyId() ||
           Account::getMapKey(carol.getPublicKeyAsHash()) ==
               Account::getMapKey(bob.getPublicKeyAsHash()));

  // Do a single transfer first so we have known xfer fields
  int64_t newBal;
  uint8_t rc = client->openTransfer(bob.getPublicKeyAsHash(), 1000, newBal);
  CES_REQUIRE_OK(rc);
  wait_net();

  // Now do a bulk transfer
  std::vector<BulkTransferItem> items;
  items.push_back({carol.getPublicKeyAsHash(), 500});
  uint8_t successCount = 0;
  rc = client->bulkTransfer(items, newBal, successCount);
  CES_REQUIRE_OK(rc);
  wait_net();

  // xfer fields should still show the single transfer to bob, not the bulk
  HashPrefix dest;
  uint64_t amount;
  uint32_t time;
  int64_t _bal = 0; uint32_t _nonce = 0;
  server->unsignedQueryAccount(getMyId(), _bal, _nonce, dest, amount, time);

  HashPrefix bobId = Account::getMapKey(bob.getPublicKeyAsHash());
  BOOST_CHECK(dest == bobId);
  BOOST_CHECK_EQUAL(amount, 1000u);
}

// Client can read xfer fields via unsigned queryAccount
BOOST_AUTO_TEST_CASE(Receipt_QueryViaClient) {
  KeyPair bob;
  while (Account::getMapKey(bob.getPublicKeyAsHash()) == getMyId())
    bob = KeyPair();
  HashPrefix bobId = Account::getMapKey(bob.getPublicKeyAsHash());

  int64_t newBal;
  uint8_t rc = client->openTransfer(bob.getPublicKeyAsHash(), 8888, newBal);
  CES_REQUIRE_OK(rc);
  wait_net();

  // Query our own account via the client API (unsigned)
  int64_t bal = 0;
  uint32_t nonce = 0;
  HashPrefix qDest{};
  uint64_t qAmount = 0;
  uint32_t qTime = 0;
  rc = client->queryAccount(getMyId(), bal, nonce, qDest, qAmount, qTime);
  CES_REQUIRE_OK(rc);

  BOOST_CHECK(qDest == bobId);
  BOOST_CHECK_EQUAL(qAmount, 8888u);
  BOOST_CHECK(qTime > 0);
}

// Signed queryAccountSigned returns xfer fields in AccountEntry
BOOST_AUTO_TEST_CASE(Receipt_SignedQueryReturnsXferFields) {
  KeyPair bob;
  while (Account::getMapKey(bob.getPublicKeyAsHash()) == getMyId())
    bob = KeyPair();
  HashPrefix bobId = Account::getMapKey(bob.getPublicKeyAsHash());

  int64_t newBal;
  uint8_t rc = client->openTransfer(bob.getPublicKeyAsHash(), 6666, newBal);
  CES_REQUIRE_OK(rc);
  wait_net();

  std::vector<AccountEntry> accounts;
  rc = client->queryAccountSigned(getMyId(), 0, accounts);
  CES_REQUIRE_OK(rc);
  BOOST_REQUIRE_EQUAL(accounts.size(), 1u);

  BOOST_CHECK(accounts[0].lastXferDest == bobId);
  BOOST_CHECK_EQUAL(accounts[0].lastXferAmount, 6666u);
  BOOST_CHECK(accounts[0].lastXferTime > 0);
}

BOOST_AUTO_TEST_SUITE_END()
