#include "test_common.h"

BOOST_FIXTURE_TEST_SUITE(BulkTransferTests, CesFixture)

BOOST_AUTO_TEST_CASE(Test_BulkTransfer_HappyPath) {
  LOGINFO << "TEST: Starting BulkTransfer_HappyPath";

  // 1. Setup Data
  const int NUM_RECIPIENTS = 15;
  std::vector<KeyPair> receivers(NUM_RECIPIENTS);
  std::vector<BulkTransferItem> transfers;
  transfers.reserve(NUM_RECIPIENTS);

  uint64_t amountPerUser = 1000;

  for (int i = 0; i < NUM_RECIPIENTS; ++i) {
    BulkTransferItem item;
    item.destKey = receivers[i].getPublicKeyAsHash();
    item.amount = amountPerUser;

    transfers.push_back(item);
  }

  // Ensure origin is very rich
  int64_t startBal = 0;
  uint32_t nonce = 0;
  client->queryAccount(getMyId(), startBal, nonce);

  // 2. Execute Bulk Transfer
  int64_t newOriginBal = 0;
  uint8_t successCount = 0;
  uint8_t rc = client->bulkTransfer(transfers, newOriginBal, successCount);

  // 3. Verify Result
  CES_REQUIRE_OK(rc);
  BOOST_REQUIRE_EQUAL((int)successCount, NUM_RECIPIENTS);

  // 4. Verify Ledger (Spot check a few receivers)
  CesClient checker(testServerEp(serverPort), false);
  checker.start(0);
  checker.connect();

  for (int i : {0, 7, 14}) {
    int64_t b = 0;
    uint32_t n = 0;
    uint8_t qrc = checker.queryAccount(
      Account::getMapKey(receivers[i].getPublicKeyAsHash()), b, n);
    CES_CHECK_OK(qrc);
    BOOST_CHECK_EQUAL(b, amountPerUser);
  }
}

BOOST_AUTO_TEST_CASE(Test_BulkTransfer_StopAndCommit) {
  LOGINFO << "TEST: Starting BulkTransfer_StopAndCommit";

  // 1. Setup a poor sender who can only afford exactly 2 open transfers
  //    Per open transfer: amount + txFee + 3*accountFee
  //    Fund for 2.5 transfers so 2 succeed and 3rd fails
  KeyPair poorSender;
  int64_t perTransfer = 1000 + BASE_FEE_TRANSACTION + 3 * BASE_FEE_ACCOUNT;
  server->_brr(poorSender.getPublicKeyAsHash(), perTransfer * 2 + perTransfer / 2);
  wait_net();

  CesClient poorClient(testServerEp(serverPort), false);
  poorClient.start(0);
  poorClient.setKey(poorSender);
  poorClient.connect();

  // 2. Setup 5 Transfers
  const int NUM_RECIPIENTS = 5;
  std::vector<KeyPair> receivers(NUM_RECIPIENTS);
  std::vector<BulkTransferItem> transfers;
  transfers.reserve(NUM_RECIPIENTS);

  for (int i = 0; i < NUM_RECIPIENTS; ++i) {
    BulkTransferItem item;
    item.destKey = receivers[i].getPublicKeyAsHash();
    item.amount = 1000;
        transfers.push_back(item);
  }

  // 3. Execute
  int64_t newOriginBal = 0;
  uint8_t successCount = 0;
  uint8_t rc = poorClient.bulkTransfer(transfers, newOriginBal, successCount);

  // 4. Verify the "Fail-Fast" behavior
  CES_CHECK_RC_EQ(rc, CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE);

  // They should have succeeded exactly twice before failing
  BOOST_CHECK_EQUAL((int)successCount, 2);

  // 5. Verify the "Commit" behavior (No Rollbacks)
  CesClient checker(testServerEp(serverPort), false);
  checker.start(0);
  checker.connect();

  int64_t b = 0;
  uint32_t n = 0;

  // Recipient 0: Should be funded
  checker.queryAccount(Account::getMapKey(receivers[0].getPublicKeyAsHash()), b, n);
  BOOST_CHECK_EQUAL(b, 1000);

  // Recipient 1: Should be funded
  checker.queryAccount(Account::getMapKey(receivers[1].getPublicKeyAsHash()), b, n);
  BOOST_CHECK_EQUAL(b, 1000);

  // Recipient 2: The one that caused the failure. Should NOT exist (0 balance)
  checker.queryAccount(Account::getMapKey(receivers[2].getPublicKeyAsHash()), b, n);
  BOOST_CHECK_EQUAL(b, 0);

  // Recipient 3: The loop aborted before this. Should NOT exist (0 balance)
  checker.queryAccount(Account::getMapKey(receivers[3].getPublicKeyAsHash()), b, n);
  BOOST_CHECK_EQUAL(b, 0);
}

BOOST_AUTO_TEST_SUITE_END()
