// L2 file handler edge coverage on the wire path (dispatch* / signerBilling):
//   - positive per-op dedup: a replayed envelope applies once
//   - APPEND over the wire (no cesh subcommand reaches dispatchAppend)
//   - RESIZE grow and shrink over the wire (dispatchResize)
// In-process: one CesServer with /ces/file/1, driven through CesFileClient.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>
#include <ces/cesplex/mux.h>
#include <ces/cesplex/session.h>
#include <ces/server.h>

#include <chrono>
#include <thread>

using namespace ces;

namespace {

struct L2EdgeFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t rpcPort = 0;
  KeyPair ownerKey;
  std::string base;   // "/h/<ownerhex>/"

  L2EdgeFixture() {
    blog::init();
    blog::set_level(blog::fatal);

    tempDir = makeUniqueTempDir("l2_edges");

    minx::Hash serverPriv;
    serverPriv.fill(0xA7);

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = { {"/ces/file/1", "builtin:file"} };
    cfg.cesFileStoreMaxBytes = 64ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    // Full fees so dedup / billing math is exact and not load-scaled.
    cfg.feeDiscountEnabled = false;
    cfg.feeQuery = 1'000'000;

    server = std::make_unique<CesServer>(cfg);
    BOOST_REQUIRE(server->start(0) > 0);
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE(rpcPort > 0);

    server->_brr(ownerKey.getPublicKeyAsHash(), 100'000'000'000ull);
    base = "/h/" + ownerKey.getPublicKeyHexStr() + "/";

    wait_net();
  }

  ~L2EdgeFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  // Open a fresh CesFileClient bound as the owner.
  void connect(CesFileClient& fc) {
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
  }
};

// File-handler per-op verb bytes (TU-local in file_handler.cpp). Mirrored
// here so the raw-channel replay test can drive verbs without the client lib.
constexpr uint8_t kVerbCreate  = 0x01;
constexpr uint8_t kVerbDeposit = 0x05;

} // namespace

BOOST_AUTO_TEST_SUITE(L2EdgeTests)

// A byte-identical retransmit of a NONCELESS verb is deduped: same envelope ->
// same per-op salt -> same sig hash, so the second send returns OK without
// applying the deposit again. buildEnvelope() mints a fresh salt per call, so
// reaching the dedup branch requires reusing one envelope, not two deposit()
// calls.
BOOST_FIXTURE_TEST_CASE(DepositRetransmitDeduped, L2EdgeFixture) {
  const std::string path = base + "dedup.txt";

  CesPlexClient cpc;
  cpc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cpc.connect("localhost", rpcPort, "/ces/file/1", ownerKey));

  const uint64_t createDeposit = 2'000'000'000ull;
  // CREATE the file (ordinary op, fresh salt).
  {
    ces::Bytes pre;
    ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
    ces::Buffer::put<uint64_t>(pre, /*size=*/64);
    ces::Buffer::put<uint64_t>(pre, /*pricePerKb=*/0);
    ces::Buffer::put<uint64_t>(pre, createDeposit);
    ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(path.size()));
    pre.insert(pre.end(), path.begin(), path.end());
    auto env = cpc.buildEnvelope(kVerbCreate, pre);
    ces::Bytes resp;
    CES_REQUIRE_OK(cpc.driveVerb(kVerbCreate, env, /*fixedPre=*/16,
                                 nullptr, resp));
  }

  const uint64_t amount = 1'000'000'000ull;
  // ONE deposit envelope...
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(path.size()));
  pre.insert(pre.end(), path.begin(), path.end());
  auto env = cpc.buildEnvelope(kVerbDeposit, pre);

  // ...driven twice, byte-for-byte.
  ces::Bytes r1, r2;
  CES_REQUIRE_OK(cpc.driveVerb(kVerbDeposit, env, /*fixedPre=*/8, nullptr, r1));
  CES_REQUIRE_OK(cpc.driveVerb(kVerbDeposit, env, /*fixedPre=*/8, nullptr, r2));

  uint64_t fb1 = ces::Buffer::peek<uint64_t>(r1.data());
  uint64_t fb2 = ces::Buffer::peek<uint64_t>(r2.data());

  // Dedup contract: the replay reports the same balance and adds no credit.
  // (Back-to-back, lazy rent on 64 bytes is ~0, so the two reads are equal.)
  BOOST_CHECK_EQUAL(fb1, fb2);
  // Exactly one deposit landed: balance is ~create+amount, never +2*amount.
  BOOST_CHECK_LT(fb2, createDeposit + amount + amount / 2);
  BOOST_CHECK_GT(fb2, createDeposit + amount / 2);

  cpc.disconnect();
}

// APPEND over the wire grows the file by the payload length.
BOOST_FIXTURE_TEST_CASE(WireAppendGrowsFile, L2EdgeFixture) {
  const std::string path = base + "append.bin";

  CesFileClient fc;
  connect(fc);

  uint64_t fb = 0, cost = 0;
  CES_REQUIRE_OK(fc.create(path, /*size=*/10, /*pricePerKb=*/0,
                           /*initialDeposit=*/1'000'000'000ull, fb, cost));

  ces::Bytes tail = {'A', 'B', 'C', 'D', 'E'};
  uint64_t fbAfter = 0, newSize = 0;
  CES_REQUIRE_OK(fc.append(path, tail, fbAfter, newSize));
  BOOST_CHECK_EQUAL(newSize, 15u);

  CesFileClient::StatInfo info;
  CES_REQUIRE_OK(fc.stat(path, info));
  BOOST_CHECK_EQUAL(info.size, 15u);

  fc.disconnect();
}

// RESIZE over the wire shrinks then grows; STAT reflects each new size.
BOOST_FIXTURE_TEST_CASE(WireResizeGrowsAndShrinks, L2EdgeFixture) {
  const std::string path = base + "resize.bin";

  CesFileClient fc;
  connect(fc);

  uint64_t fb = 0, cost = 0;
  CES_REQUIRE_OK(fc.create(path, /*size=*/100, /*pricePerKb=*/0,
                           /*initialDeposit=*/1'000'000'000ull, fb, cost));

  uint64_t newSize = 0;
  CES_REQUIRE_OK(fc.resize(path, 40, newSize));
  BOOST_CHECK_EQUAL(newSize, 40u);
  {
    CesFileClient::StatInfo info;
    CES_REQUIRE_OK(fc.stat(path, info));
    BOOST_CHECK_EQUAL(info.size, 40u);
  }

  CES_REQUIRE_OK(fc.resize(path, 250, newSize));
  BOOST_CHECK_EQUAL(newSize, 250u);
  {
    CesFileClient::StatInfo info;
    CES_REQUIRE_OK(fc.stat(path, info));
    BOOST_CHECK_EQUAL(info.size, 250u);
  }

  fc.disconnect();
}

BOOST_AUTO_TEST_SUITE_END()
