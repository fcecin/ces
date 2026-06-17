// ===========================================================================
// /s/dice.lua — the shipped Lua double-or-nothing program.
// ===========================================================================
//
// Locks down the dice's MONEY MODEL end-to-end against a real cesluajitd,
// over the real /ces/lua/1 channel — the same path the web terminal drives.
// The program is the deposit-and-verify kind: the bet is the player's OWN
// signed transfer to the house (the file's dedicated program account,
// ces.program_pubkey()); the program only READS the player's account to
// confirm the deposit, then pays winnings out of that same program account.
//
// What the dice must do:
//   * `balance` reports CONTRACT state: credits deposited & playable, i.e.
//     a fresh, unconsumed transfer to the house — NOT the CES account.
//   * a single deposit is one bet: balance 0 → deposit N → balance N →
//     play → balance 0 (the deposit is spent, win or lose).
//   * heads pays exactly 2N into the player's CES account, out of the house
//     bankroll; tails pays nothing. The play itself costs the player nothing.
//   * the same deposit can't be replayed (no double-spend of one transfer).
//
// The harness (PlexLuaPeer / LuaConnFixture / line reader) is shared with
// test_lua_conn.cpp via test_lua_conn_common.h.

#define BOOST_TEST_DYN_LINK
#include "test_lua_conn_common.h"

#include <boost/asio/executor_work_guard.hpp>

#include <cctype>
#include <fstream>
#include <future>
#include <sstream>

namespace {

// The bet/deposit used throughout: 100 reads back as "available to play: 100"
// and 0 after a play, and is comfortably above the dice's MIN_BET (1).
constexpr uint64_t kBet = 100;

// Read the actual shipped /s/dice.lua so the test pins the real program, not
// a paraphrase. CES_SOURCE_DIR is the repo root (set by tests/CMakeLists.txt).
std::string readDiceSource() {
  const std::string path =
    std::string(CES_SOURCE_DIR) + "/src/ceslib/builtin_apps/dice.lua";
  std::ifstream f(path, std::ios::binary);
  BOOST_REQUIRE_MESSAGE(f.good(), "cannot open dice.lua at " + path);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

minx::Hash hexToHash(const std::string& hex) {
  BOOST_REQUIRE_EQUAL(hex.size(), 64u);
  minx::Hash h{};
  for (size_t i = 0; i < 32; ++i)
    h[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
  return h;
}

bool sendCmd(PlexLuaPeer& peer, const std::string& s) {
  ces::Bytes b(s.begin(), s.end());
  return peerWrite(peer, b);
}

// Consume every byte currently pending until the program goes quiet — used to
// swallow the multi-line greeting without parsing its exact shape.
void drainQuiet(PlexLuaPeer& peer, PlexLineReader& rd) {
  for (;;) {
    ces::Bytes chunk;
    if (peerReadSome(peer, chunk, 4096, std::chrono::milliseconds(300)) == 0)
      break;
  }
  rd.buf.clear();
}

// `balance` → the integer after "available to play:" (the contract balance).
int64_t readAvailable(PlexLuaPeer& peer, PlexLineReader& rd) {
  BOOST_REQUIRE(sendCmd(peer, "balance\n"));
  const std::string marker = "available to play:";
  std::string line = rd.lineContaining(marker);
  BOOST_REQUIRE_MESSAGE(!line.empty(), "dice did not answer `balance`");
  return std::stoll(line.substr(line.find(marker) + marker.size()));
}

// `play` → the single result line (heads / tails / rejection reason).
std::string playOnce(PlexLuaPeer& peer, PlexLineReader& rd) {
  BOOST_REQUIRE(sendCmd(peer, "play\n"));
  std::string line = rd.nextLine();
  BOOST_REQUIRE_MESSAGE(!line.empty(), "dice did not answer `play`");
  return line;
}

// Synchronous wrappers around the server's async L2 hooks (deposit + account
// balance read), pumped on a private io_context. The "deposit" here stands in
// for the player's `cesh transfer N <house>` — it sets the player's
// last-transfer receipt, which is exactly what the dice verifies.
struct ServerOps {
  boost::asio::io_context ioc;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> wg;
  std::thread th;
  CesServer& srv;

  explicit ServerOps(CesServer& s)
    : wg(boost::asio::make_work_guard(ioc)),
      th([this]() { ioc.run(); }), srv(s) {}
  ~ServerOps() {
    wg.reset();
    ioc.stop();
    if (th.joinable()) th.join();
  }

  uint8_t deposit(const minx::Hash& from, const minx::Hash& to, uint64_t amt) {
    std::promise<uint8_t> p;
    auto fut = p.get_future();
    srv._l2Transfer(from, to, amt,
      [&p](uint8_t rc, int64_t) { p.set_value(rc); }, ioc.get_executor());
    return fut.get();
  }
  int64_t balance(const minx::Hash& acc) {
    std::promise<int64_t> p;
    auto fut = p.get_future();
    srv._l2QueryAccount(acc,
      [&p](int64_t bal, uint32_t, HashPrefix, uint64_t, uint32_t) {
        p.set_value(bal);
      }, ioc.get_executor());
    return fut.get();
  }
};

// Upload + launch the real dice.lua at a /h/ path (owner-deployed; the house
// is the per-source program account either way), attach `peer`, read the
// house pubkey out of the greeting, and bankroll the house so heads payouts
// (2N) can clear. Returns the house key.
minx::Hash diceSetup(LuaConnFixture& fx, PlexLuaPeer& peer,
                     PlexLineReader& rd) {
  const std::string path =
    "/h/" + fx.ownerKey.getPublicKeyHexStr() + "/dice.lua";
  fx.uploadScript(path, readDiceSource());
  uint64_t instId = fx.launchScript(path);
  BOOST_REQUIRE(instId > 0);
  // Wait out (a) set_listener arming the accept gate and (b) the dice's
  // START_S floor: a deposit whose whole-second timestamp == the instance's
  // start second is rejected as "predates this dice instance".
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));

  BOOST_REQUIRE(peer.start() != 0);
  uint64_t st = 0;
  BOOST_REQUIRE(peer.bind(fx.rpcPort, fx.userKey, st));
  CES_REQUIRE_RC_EQ(peer.attach(fx.userKey, st, instId).status, CES_OK);

  // Greeting carries "  house pubkey: <64 hex>".
  const std::string marker = "house pubkey:";
  std::string line = rd.lineContaining(marker);
  BOOST_REQUIRE_MESSAGE(!line.empty(), "no house pubkey in dice greeting");
  std::string hex;
  for (char c : line.substr(line.find(marker) + marker.size())) {
    if (std::isxdigit(static_cast<unsigned char>(c))) {
      hex.push_back(c);
      if (hex.size() == 64) break;
    }
  }
  minx::Hash house = hexToHash(hex);

  drainQuiet(peer, rd);                       // swallow the rest of the greeting
  fx.server->_brr(house, 1'000'000'000);      // bankroll for heads payouts
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  return house;
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(DiceLuaTests, LuaConnFixture)

// The core contract cycle: balance 0 → deposit 100 → balance 100 → play →
// balance 0, plus the payout direction for whichever way the single coin
// lands, plus replay rejection.
BOOST_AUTO_TEST_CASE(DepositBalancePlayCycle) {
  ServerOps ops(*server);
  PlexLuaPeer peer;
  PlexLineReader rd(peer);
  const minx::Hash house = diceSetup(*this, peer, rd);
  const minx::Hash userPub = userKey.getPublicKeyAsHash();

  // Nothing deposited yet → no chips on the table.
  BOOST_CHECK_EQUAL(readAvailable(peer, rd), 0);

  // The bet IS the player's own signed transfer to the house.
  CES_REQUIRE_OK(ops.deposit(userPub, house, kBet));

  // The contract now sees the deposit as playable — this is the line that
  // used to (wrongly) report the player's CES account balance.
  BOOST_CHECK_EQUAL(readAvailable(peer, rd), static_cast<int64_t>(kBet));

  // Play the bet. Snapshot the CES account across just the play; the deposit
  // already happened, so the play itself moves money only on a win.
  const int64_t pre = ops.balance(userPub);
  const std::string result = playOnce(peer, rd);
  const bool heads = result.find("heads") != std::string::npos;
  const bool tails = result.find("tails") != std::string::npos;
  BOOST_REQUIRE_MESSAGE(heads || tails, "unexpected play result: " + result);
  BOOST_CHECK_MESSAGE(result.find("payout failed") == std::string::npos,
                      "house could not pay a win: " + result);
  const int64_t post = ops.balance(userPub);
  if (heads)
    BOOST_CHECK_EQUAL(post - pre, static_cast<int64_t>(2 * kBet));
  else
    BOOST_CHECK_EQUAL(post - pre, 0);

  // The deposit is spent (win or lose) → back to 0 chips on the table.
  BOOST_CHECK_EQUAL(readAvailable(peer, rd), 0);

  // The same deposit can't be replayed.
  const std::string again = playOnce(peer, rd);
  BOOST_CHECK_MESSAGE(again.find("already played") != std::string::npos,
                      "replay of a spent deposit was not rejected: " + again);

  peer.closeStream();
}

// Deterministically exercise the WIN path (house → player payout), the one
// that actually moves the house bankroll. Bet until the first heads (fair
// coin: ~2 rounds expected, 16 is a p<2e-5 ceiling) and assert the exact
// delta every round: heads → +2N into the account, tails → 0.
BOOST_AUTO_TEST_CASE(HeadsPaysTwoNFromHouse) {
  ServerOps ops(*server);
  PlexLuaPeer peer;
  PlexLineReader rd(peer);
  const minx::Hash house = diceSetup(*this, peer, rd);
  const minx::Hash userPub = userKey.getPublicKeyAsHash();

  bool sawHeads = false;
  const int kMaxRounds = 16;
  for (int i = 0; i < kMaxRounds && !sawHeads; ++i) {
    // Each bet must land in a NEW whole second: the ledger stamps
    // last_xfer_time in seconds, and the dice's replay guard keys on it, so
    // two same-second deposits would collide.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    CES_REQUIRE_OK(ops.deposit(userPub, house, kBet));
    BOOST_REQUIRE_EQUAL(readAvailable(peer, rd), static_cast<int64_t>(kBet));

    const int64_t pre = ops.balance(userPub);
    const std::string result = playOnce(peer, rd);
    const int64_t post = ops.balance(userPub);

    if (result.find("heads") != std::string::npos) {
      sawHeads = true;
      BOOST_CHECK_MESSAGE(result.find("payout failed") == std::string::npos,
                          "house could not pay a win: " + result);
      BOOST_CHECK_EQUAL(post - pre, static_cast<int64_t>(2 * kBet));
    } else {
      BOOST_REQUIRE_MESSAGE(result.find("tails") != std::string::npos,
                            "unexpected play result: " + result);
      BOOST_CHECK_EQUAL(post - pre, 0);
    }
    BOOST_REQUIRE_EQUAL(readAvailable(peer, rd), 0);
  }
  BOOST_CHECK_MESSAGE(
    sawHeads, "no heads in 16 fair flips — payout path likely broken");

  peer.closeStream();
}

BOOST_AUTO_TEST_SUITE_END()
