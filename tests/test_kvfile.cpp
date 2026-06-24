// ===========================================================================
// kv file type tests — builtin:file managing a logkv key-value store whose
// keys are self-renting cells.
// ===========================================================================
//
// Each kv value is stored as [balance u64][last_charged_us u64][user bytes]:
// a file-service-owned billing header the program never sees (GET strips it).
// A key is funded with a deposit (KV_PUT seed / KV_DEPOSIT top-up), pays its
// own rent (feeFileRent x (key+value bytes) x time) on the daily sweep, and is
// evicted when its balance hits 0. The store's program-account balance ==
// sum of live cell balances. These tests drive fileHandlerExec directly (the
// in-process path builtin:compute uses) and call the sweep directly.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/l2/file_handler.h>
#include <ces/l2/file_client.h>
#include <ces/server.h>
#include <ces/keys.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h>   // ces::sha256

#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include <chrono>
#include <cstring>
#include <optional>
#include <string>
#include <thread>

using namespace ces;

namespace {

// kv verb codes (mirror file_handler.cpp's anon-namespace constants). Exec-only.
constexpr uint8_t KV_CREATE  = 0x0b;
constexpr uint8_t KV_PUT     = 0x0c;
constexpr uint8_t KV_GET     = 0x0d;
constexpr uint8_t KV_ERASE   = 0x0e;
constexpr uint8_t KV_ITER    = 0x0f;
constexpr uint8_t KV_DEPOSIT = 0x10;
constexpr uint8_t KV_RANGE   = 0x11;
constexpr uint8_t FLAT_STAT  = 0x04;

// Per-cell billing header overhead (matches kKvHeaderLen in file_handler.cpp).
constexpr uint64_t HDR = 16;

std::string toHex(const minx::Hash& h) {
  static const char* d = "0123456789abcdef";
  std::string s; s.reserve(64);
  for (auto b : h) { s += d[(b >> 4) & 0xF]; s += d[b & 0xF]; }
  return s;
}
std::array<uint8_t, 32> toArr(const minx::Hash& h) {
  std::array<uint8_t, 32> a{}; std::memcpy(a.data(), h.data(), 32); return a;
}
ces::Bytes b_(const std::string& s) { return ces::Bytes(s.begin(), s.end()); }
std::string s_(const ces::Bytes& b) { return std::string(b.begin(), b.end()); }

struct KvFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t rpcPort = 0;
  minx::Hash serverPriv;
  KeyPair serverKey;
  KeyPair ownerKey;

  KvFixture()
      : serverPriv([](){ minx::Hash h; h.fill(0xEE); return h; }()),
        serverKey(serverPriv) {
    blog::init();
    blog::set_level(blog::fatal);
    tempDir = makeUniqueTempDir("kvfile");
    startServer();
    server->_brr(serverKey.getPublicKeyAsHash(), 100'000'000'000ull);
    server->_brr(ownerKey.getPublicKeyAsHash(), 100'000'000'000ull);
    wait_net();

    // Billing source: a /s/ file (unmetered → deposits mint, write cost waived).
    auto fc = std::make_unique<CesFileClient>();
    fc->setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    BOOST_REQUIRE_EQUAL((int)fc->connect("localhost", rpcPort, serverKey), (int)CES_OK);
    uint64_t bal = 0, cost = 0;
    BOOST_REQUIRE_EQUAL((int)fc->create("/s/kvsrc.lua", 1, 0, 0, bal, cost), (int)CES_OK);
  }

  CesConfig buildConfig() {
    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = { {"/ces/file/1", "builtin:file"} };
    cfg.cesFileStoreMaxBytes = 100 * 1024 * 1024;
    // High rent so the per-cell sweep charges a meaningful amount over the few
    // milliseconds between a PUT and a directly-invoked sweep.
    cfg.feeFileRent = 1'000'000'000ull;
    cfg.feeQuery = 20000;
    return cfg;
  }

  void startServer() {
    server = std::make_unique<CesServer>(buildConfig());
    uint16_t port = server->start(0);
    BOOST_REQUIRE_MESSAGE(port > 0, "server port bind failed");
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort > 0, "rpc port bind failed");
    wait_net();
  }

  // Stop and rebuild the server on the SAME store dir. fileHandlerBind(nullptr)
  // on stop closes the kv-store cache, so a reopened store must reload from the
  // on-disk logkv event log — the real persistence guarantee.
  void restartServer() {
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    startServer();
  }

  ~KvFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  FileExecResp exec(const FileExecReq& req) {
    boost::asio::io_context io;
    auto work = boost::asio::make_work_guard(io);
    std::optional<FileExecResp> out;
    fileHandlerExec(req,
      [&](FileExecResp r) { out = std::move(r); work.reset(); },
      io.get_executor());
    io.run();
    return std::move(*out);
  }

  // Build a kv request under the owner's home dir, billed to /s/kvsrc.lua.
  FileExecReq req(uint8_t verb, const std::string& name) {
    FileExecReq r;
    r.verb = verb;
    r.name = name;
    r.ownerPubkey = toArr(ownerKey.getPublicKeyAsHash());
    r.sourceName = "/s/kvsrc.lua";
    return r;
  }
  std::string home() { return "/h/" + toHex(ownerKey.getPublicKeyAsHash()) + "/"; }

  // Create an empty kv-store (no deposit — cells are funded per-key).
  void createStore(const std::string& name) {
    auto cr = req(KV_CREATE, name);
    cr.initialDeposit = 0;
    CES_REQUIRE_OK(exec(cr).status);
  }
  // Put a record into a cell, seeding the cell's rent balance with `deposit`.
  uint8_t put(const std::string& name, const std::string& k,
              const std::string& v, uint64_t deposit) {
    auto r = req(KV_PUT, name); r.key = b_(k); r.value = b_(v); r.amount = deposit;
    return exec(r).status;
  }
  uint64_t statSize(const std::string& name) {
    return exec(req(FLAT_STAT, name)).size;
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(KvFileTests, KvFixture)

BOOST_AUTO_TEST_CASE(PutGetEraseIterAndSize) {
  const std::string name = home() + "store.kv";
  createStore(name);
  BOOST_CHECK_EQUAL(statSize(name), 0u);

  // Put k1 -> v1 (size counts key + 16B header + value).
  CES_REQUIRE_OK(put(name, "k1", "v1", 1'000'000'000ull));
  BOOST_CHECK_EQUAL(statSize(name), 2 + HDR + 2);

  // Get k1 — the header is stripped, only "v1" comes back.
  {
    auto r = req(KV_GET, name); r.key = b_("k1");
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_CHECK(resp.found);
    BOOST_CHECK_EQUAL(s_(resp.value), "v1");
  }
  // Missing key.
  {
    auto r = req(KV_GET, name); r.key = b_("nope");
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_CHECK(!resp.found);
  }

  // Second key, then overwrite k1 (deposit 0: funding + content both preserved
  // for the balance, value replaced).
  CES_REQUIRE_OK(put(name, "k2", "vv2", 1'000'000'000ull));   // +(2+16+3)
  BOOST_CHECK_EQUAL(statSize(name), (2 + HDR + 2) + (2 + HDR + 3));
  CES_REQUIRE_OK(put(name, "k1", "V1longer", 0));             // k1 value 2->8
  BOOST_CHECK_EQUAL(statSize(name), (2 + HDR + 8) + (2 + HDR + 3));
  { auto r = req(KV_GET, name); r.key = b_("k1");
    BOOST_CHECK_EQUAL(s_(exec(r).value), "V1longer"); }

  // Iterate keys.
  {
    auto resp = exec(req(KV_ITER, name));
    CES_REQUIRE_OK(resp.status);
    BOOST_REQUIRE_EQUAL(resp.keys.size(), 2u);
    bool sawK1 = false, sawK2 = false;
    for (auto& k : resp.keys) { if (s_(k) == "k1") sawK1 = true; if (s_(k) == "k2") sawK2 = true; }
    BOOST_CHECK(sawK1 && sawK2);
  }

  // Erase k1.
  { auto r = req(KV_ERASE, name); r.key = b_("k1");
    CES_REQUIRE_OK(exec(r).status); }
  BOOST_CHECK_EQUAL(statSize(name), 2 + HDR + 3);             // only k2
  { auto r = req(KV_GET, name); r.key = b_("k1");
    BOOST_CHECK(!exec(r).found); }
}

// GET returns exactly the stored bytes — the 16-byte billing header never leaks.
BOOST_AUTO_TEST_CASE(GetStripsHeader) {
  const std::string name = home() + "strip.kv";
  createStore(name);
  const std::string val = "exactly-these-bytes";
  CES_REQUIRE_OK(put(name, "k", val, 1'000'000'000ull));
  auto r = req(KV_GET, name); r.key = b_("k");
  auto resp = exec(r);
  CES_REQUIRE_OK(resp.status);
  BOOST_REQUIRE(resp.found);
  BOOST_CHECK_EQUAL(resp.value.size(), val.size());   // not val.size()+HDR
  BOOST_CHECK_EQUAL(s_(resp.value), val);
}

// The daily sweep charges each cell its own rent and evicts the one that runs
// dry, leaving the well-funded one alive.
BOOST_AUTO_TEST_CASE(SweepEvictsUnfundedKeepsFunded) {
  const std::string name = home() + "sweep.kv";
  createStore(name);
  CES_REQUIRE_OK(put(name, "poor", "x", 100));                  // tiny balance
  CES_REQUIRE_OK(put(name, "rich", "y", 1'000'000'000'000ull)); // huge balance

  std::this_thread::sleep_for(std::chrono::milliseconds(15));   // accrue rent
  fileHandlerSweepKvRent(server.get());

  { auto r = req(KV_GET, name); r.key = b_("poor");
    BOOST_CHECK(!exec(r).found); }                              // evicted
  { auto r = req(KV_GET, name); r.key = b_("rich");
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_CHECK(resp.found);
    BOOST_CHECK_EQUAL(s_(resp.value), "y"); }                   // survived
  // Only the rich cell's bytes remain.
  BOOST_CHECK_EQUAL(statSize(name), 4 + HDR + 1);               // "rich"(4)+hdr+"y"(1)
}

// A deposit tops up a cell's balance so it survives a sweep it would otherwise
// lose — funding from any source keeps an entry alive (reinforcement).
BOOST_AUTO_TEST_CASE(DepositKeepsCellAlive) {
  const std::string name = home() + "fund.kv";
  createStore(name);
  CES_REQUIRE_OK(put(name, "k", "v", 100));                     // would evict
  { auto r = req(KV_DEPOSIT, name); r.key = b_("k");
    r.amount = 1'000'000'000'000ull;
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_CHECK_GT(resp.fileBalance, 1'000'000'000'000ull); }   // 100 + deposit

  std::this_thread::sleep_for(std::chrono::milliseconds(15));
  fileHandlerSweepKvRent(server.get());

  auto r = req(KV_GET, name); r.key = b_("k");
  auto resp = exec(r);
  CES_REQUIRE_OK(resp.status);
  BOOST_CHECK(resp.found);
  BOOST_CHECK_EQUAL(s_(resp.value), "v");
}

// Depositing to a missing key fails (you fund a stored record, not a phantom).
BOOST_AUTO_TEST_CASE(DepositMissingKeyFails) {
  const std::string name = home() + "nokey.kv";
  createStore(name);
  auto r = req(KV_DEPOSIT, name); r.key = b_("ghost"); r.amount = 1000;
  CES_CHECK_RC_EQ(exec(r).status, CES_ERROR_FILE_NOT_FOUND);
}

// Only the owner may PUT/ERASE; GET is open to any signer.
BOOST_AUTO_TEST_CASE(NonOwnerCannotMutate) {
  const std::string name = home() + "owned.kv";
  createStore(name);
  CES_REQUIRE_OK(put(name, "k", "v", 1'000'000'000ull));

  KeyPair other;
  auto otherPk = toArr(other.getPublicKeyAsHash());
  { auto r = req(KV_PUT, name); r.ownerPubkey = otherPk;
    r.key = b_("k"); r.value = b_("hijack"); r.amount = 1'000'000'000ull;
    CES_CHECK_RC_EQ(exec(r).status, CES_ERROR_NOT_OWNER); }
  { auto r = req(KV_ERASE, name); r.ownerPubkey = otherPk; r.key = b_("k");
    CES_CHECK_RC_EQ(exec(r).status, CES_ERROR_NOT_OWNER); }
  { auto r = req(KV_GET, name); r.ownerPubkey = otherPk; r.key = b_("k");
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_CHECK(resp.found);
    BOOST_CHECK_EQUAL(s_(resp.value), "v"); }
}

BOOST_AUTO_TEST_CASE(KvVerbOnFlatFileRejected) {
  // /s/kvsrc.lua is a flat file; a kv PUT on it must be rejected.
  auto r = req(KV_PUT, "/s/kvsrc.lua"); r.key = b_("k"); r.value = b_("v");
  r.amount = 1000;
  CES_CHECK_RC_EQ(exec(r).status, CES_ERROR_BAD_INPUT);
}

// Keys/values are opaque bytes (DHT keys are raw sha256). A binary key + value
// round-trips through put/get/iter/erase, header invisible.
BOOST_AUTO_TEST_CASE(BinaryKeyAndValueRoundTrip) {
  const std::string name = home() + "bin.kv";
  createStore(name);
  ces::Bytes key;
  for (int i = 0; i < 32; ++i) key.push_back(uint8_t((i * 7) ^ (i == 3 ? 0 : 0xA5)));
  key[5] = 0x00; key[6] = 0x00; key[7] = 0xFF;
  ces::Bytes val{0x00, 0x01, 0xFF, 0x00, 0x7F, 0x80};

  { auto r = req(KV_PUT, name); r.key = key; r.value = val;
    r.amount = 1'000'000'000ull;
    CES_REQUIRE_OK(exec(r).status); }
  { auto r = req(KV_GET, name); r.key = key;
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_REQUIRE(resp.found);
    BOOST_CHECK(resp.value == val); }
  { auto resp = exec(req(KV_ITER, name));
    CES_REQUIRE_OK(resp.status);
    BOOST_REQUIRE_EQUAL(resp.keys.size(), 1u);
    BOOST_CHECK(resp.keys[0] == key); }
  { auto r = req(KV_ERASE, name); r.key = key;
    CES_REQUIRE_OK(exec(r).status); }
  { auto r = req(KV_GET, name); r.key = key;
    BOOST_CHECK(!exec(r).found); }
}

BOOST_AUTO_TEST_CASE(EmptyValueRejected) {
  const std::string name = home() + "empty.kv";
  createStore(name);
  auto r = req(KV_PUT, name); r.key = b_("k"); r.value = ces::Bytes{};
  r.amount = 1'000'000'000ull;
  CES_CHECK_RC_EQ(exec(r).status, CES_ERROR_BAD_INPUT);
}

// A funded record survives a full server stop/start, reloaded from the on-disk
// logkv event log (the in-RAM store cache is dropped on unbind).
BOOST_AUTO_TEST_CASE(DataReloadsFromDiskAfterServerRestart) {
  const std::string name = home() + "persist.kv";
  createStore(name);
  CES_REQUIRE_OK(put(name, "durable", "on-disk", 1'000'000'000'000ull));

  restartServer();

  auto r = req(KV_GET, name); r.key = b_("durable");
  auto resp = exec(r);
  CES_REQUIRE_OK(resp.status);
  BOOST_REQUIRE(resp.found);
  BOOST_CHECK_EQUAL(s_(resp.value), "on-disk");
}

// The trustless "anyone funds any entry there" path: an external funder binds
// /ces/file/1 and tops up a key's rent balance directly (real account, no owner
// check, no dht2 mediation).
// Range scan: ordered, half-open [lo,hi), and (with a tight byte budget)
// truncated with a resume point that a continuation query stitches back
// together into the full ordered set.
BOOST_AUTO_TEST_CASE(RangeOrderedSubRangeAndContinuation) {
  const std::string name = home() + "range.kv";
  createStore(name);
  // Insert out of order; the store keeps them sorted.
  CES_REQUIRE_OK(put(name, "c", "vc", 1'000'000'000ull));
  CES_REQUIRE_OK(put(name, "a", "va", 1'000'000'000ull));
  CES_REQUIRE_OK(put(name, "e", "ve", 1'000'000'000ull));
  CES_REQUIRE_OK(put(name, "b", "vb", 1'000'000'000ull));
  CES_REQUIRE_OK(put(name, "d", "vd", 1'000'000'000ull));

  // Full scan, generous budget: all five, sorted, with stripped values.
  {
    auto r = req(KV_RANGE, name); r.amount = 1'000'000;  // big budget
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_REQUIRE_EQUAL(resp.keys.size(), 5u);
    BOOST_REQUIRE_EQUAL(resp.values.size(), 5u);
    const char* ek[] = {"a","b","c","d","e"};
    const char* ev[] = {"va","vb","vc","vd","ve"};
    for (int i = 0; i < 5; ++i) {
      BOOST_CHECK_EQUAL(s_(resp.keys[i]), ek[i]);
      BOOST_CHECK_EQUAL(s_(resp.values[i]), ev[i]);
    }
    BOOST_CHECK(resp.rangeEnd.empty());   // complete (asked hi was empty)
  }

  // Half-open sub-range [b, d): b and c only.
  {
    auto r = req(KV_RANGE, name); r.rangeLo = b_("b"); r.rangeHi = b_("d");
    r.amount = 1'000'000;
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_REQUIRE_EQUAL(resp.keys.size(), 2u);
    BOOST_CHECK_EQUAL(s_(resp.keys[0]), "b");
    BOOST_CHECK_EQUAL(s_(resp.keys[1]), "c");
    BOOST_CHECK_EQUAL(s_(resp.rangeEnd), "d");  // complete to hi
  }

  // Tight budget (each entry is key(1)+value(2)=3 bytes; budget 7 fits two):
  // paginate the full set and confirm continuation reassembles a..e in order.
  {
    std::vector<std::string> got;
    ces::Bytes lo;                  // start empty
    for (int guard = 0; guard < 10; ++guard) {
      auto r = req(KV_RANGE, name); r.rangeLo = lo; r.amount = 7;
      auto resp = exec(r);
      CES_REQUIRE_OK(resp.status);
      for (auto& k : resp.keys) got.push_back(s_(k));
      if (resp.rangeEnd.empty()) break;          // hi was empty -> done
      BOOST_REQUIRE(resp.keys.size() >= 1u);     // always progresses
      lo = resp.rangeEnd;                        // resume at next undelivered key
    }
    BOOST_REQUIRE_EQUAL(got.size(), 5u);
    BOOST_CHECK_EQUAL(got[0], "a"); BOOST_CHECK_EQUAL(got[4], "e");
  }
}

// Keys order by UNSIGNED bytes (memcmp), not signed char: a 0x80-prefixed key
// sorts after 0x00/0x7F and before 0xFF. DHT hash keys depend on this.
BOOST_AUTO_TEST_CASE(RangeBinaryKeysUnsignedOrder) {
  const std::string name = home() + "bin_range.kv";
  createStore(name);
  ces::Bytes k00{0x00, 0x01}, k7F{0x7F, 0x01}, k80{0x80, 0x01}, kFF{0xFF, 0x01};
  auto putk = [&](const ces::Bytes& k, const ces::Bytes& v) {
    auto r = req(KV_PUT, name); r.key = k; r.value = v; r.amount = 1'000'000'000ull;
    CES_REQUIRE_OK(exec(r).status);
  };
  putk(kFF, b_("f")); putk(k00, b_("a")); putk(k80, b_("c")); putk(k7F, b_("b"));
  {
    auto r = req(KV_RANGE, name); r.amount = 1'000'000;
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_REQUIRE_EQUAL(resp.keys.size(), 4u);
    BOOST_CHECK(resp.keys[0] == k00);
    BOOST_CHECK(resp.keys[1] == k7F);
    BOOST_CHECK(resp.keys[2] == k80);   // unsigned: after 0x7F, NOT before 0x00
    BOOST_CHECK(resp.keys[3] == kFF);
    BOOST_CHECK_EQUAL(s_(resp.values[0]), "a");
  }
  // Half-open [k7F, kFF): k7F, k80 (kFF excluded).
  {
    auto r = req(KV_RANGE, name); r.rangeLo = k7F; r.rangeHi = kFF; r.amount = 1'000'000;
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_REQUIRE_EQUAL(resp.keys.size(), 2u);
    BOOST_CHECK(resp.keys[0] == k7F);
    BOOST_CHECK(resp.keys[1] == k80);
    BOOST_CHECK(resp.rangeEnd == kFF);  // complete to hi
  }
}

// Empty store, lo between keys, lo past end, and an inverted (hi < lo) range.
BOOST_AUTO_TEST_CASE(RangeEdgeCases) {
  const std::string name = home() + "edge_range.kv";
  createStore(name);
  { auto resp = exec(req(KV_RANGE, name));        // empty store
    CES_REQUIRE_OK(resp.status);
    BOOST_CHECK_EQUAL(resp.keys.size(), 0u);
    BOOST_CHECK(resp.rangeEnd.empty()); }          // complete (hi was empty)

  CES_REQUIRE_OK(put(name, "a", "1", 1'000'000'000ull));
  CES_REQUIRE_OK(put(name, "c", "3", 1'000'000'000ull));
  CES_REQUIRE_OK(put(name, "e", "5", 1'000'000'000ull));

  // lo between keys -> lower_bound to the next key (b -> c).
  { auto r = req(KV_RANGE, name); r.rangeLo = b_("b"); r.amount = 1'000'000;
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_REQUIRE_EQUAL(resp.keys.size(), 2u);
    BOOST_CHECK_EQUAL(s_(resp.keys[0]), "c");
    BOOST_CHECK_EQUAL(s_(resp.keys[1]), "e"); }

  // lo past the last key -> empty, complete.
  { auto r = req(KV_RANGE, name); r.rangeLo = b_("z"); r.amount = 1'000'000;
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_CHECK_EQUAL(resp.keys.size(), 0u);
    BOOST_CHECK(resp.rangeEnd.empty()); }

  // Inverted range (hi < lo) -> empty; effective_hi == hi (nothing to resume).
  { auto r = req(KV_RANGE, name); r.rangeLo = b_("e"); r.rangeHi = b_("b");
    r.amount = 1'000'000;
    auto resp = exec(r);
    CES_REQUIRE_OK(resp.status);
    BOOST_CHECK_EQUAL(resp.keys.size(), 0u);
    BOOST_CHECK_EQUAL(s_(resp.rangeEnd), "b"); }
}

// A value larger than the byte budget still yields one pair, so a paginated
// scan always advances (no stall, no empty-page loop).
BOOST_AUTO_TEST_CASE(RangeAlwaysProgressesOnOversizedValue) {
  const std::string name = home() + "big_range.kv";
  createStore(name);
  CES_REQUIRE_OK(put(name, "big", std::string(500, 'x'), 1'000'000'000ull));
  CES_REQUIRE_OK(put(name, "z", "s", 1'000'000'000ull));
  auto r = req(KV_RANGE, name); r.amount = 10;   // budget << "big"'s value
  auto resp = exec(r);
  CES_REQUIRE_OK(resp.status);
  BOOST_REQUIRE_EQUAL(resp.keys.size(), 1u);      // included despite oversize
  BOOST_CHECK_EQUAL(s_(resp.keys[0]), "big");
  BOOST_CHECK_EQUAL(s_(resp.rangeEnd), "z");      // resume at the next key
}

// The DHT name index, the actual pattern: one row per claimant keyed by
// H(name)‖claimant_pubkey, surveyed by a prefix range [H(name), H(name)+1).
// This is how "many people register the same name" is expressed — each claim
// is its own independently-funded row, and the survey returns them all (sorted,
// no bleed into other names) so the client can pick earliest-first-seen.
BOOST_AUTO_TEST_CASE(NameIndexPrefixSurvey) {
  const std::string name = home() + "names.kv";
  createStore(name);

  auto H = [](const std::string& s) -> ces::Bytes {
    minx::Hash h = ces::sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    return ces::Bytes(h.begin(), h.end());
  };
  // Prefix successor: H(name) as a 256-bit number + 1 (carry); empty if it
  // wrapped (all 0xFF), meaning "to end of store".
  auto succ = [](ces::Bytes p) -> ces::Bytes {
    for (int i = static_cast<int>(p.size()) - 1; i >= 0; --i)
      if (++p[i] != 0) return p;
    return ces::Bytes{};
  };
  // Register claimant `who` for name-hash `hn`: row H(name)‖who -> value.
  auto claim = [&](const ces::Bytes& hn, uint8_t who) {
    ces::Bytes key = hn; key.push_back(who);
    auto r = req(KV_PUT, name); r.key = key; r.value = ces::Bytes{who};
    r.amount = 1'000'000'000ull;
    CES_REQUIRE_OK(exec(r).status);
  };

  const ces::Bytes hA = H("pubcom.org");
  const ces::Bytes hB = H("example.com");
  claim(hA, 0x03); claim(hA, 0x01); claim(hA, 0x02);  // 3 claim "pubcom.org"
  claim(hB, 0x09);                                    // a different name

  // Survey "pubcom.org": prefix range -> exactly its 3 claimants, sorted by
  // pubkey, no bleed from the other name.
  auto r = req(KV_RANGE, name); r.rangeLo = hA; r.rangeHi = succ(hA);
  r.amount = 1'000'000;
  auto resp = exec(r);
  CES_REQUIRE_OK(resp.status);
  BOOST_REQUIRE_EQUAL(resp.keys.size(), 3u);
  BOOST_CHECK_EQUAL(resp.keys[0].back(), 0x01);
  BOOST_CHECK_EQUAL(resp.keys[1].back(), 0x02);
  BOOST_CHECK_EQUAL(resp.keys[2].back(), 0x03);
  for (auto& k : resp.keys) {
    BOOST_REQUIRE_EQUAL(k.size(), hA.size() + 1);
    BOOST_CHECK(ces::Bytes(k.begin(), k.end() - 1) == hA);   // all under H(name A)
  }
  // The whole range was delivered (effective_hi == requested hi).
  BOOST_CHECK(resp.rangeEnd == succ(hA));
}

BOOST_AUTO_TEST_CASE(RangeRejectsFlatAndMissing) {
  { auto r = req(KV_RANGE, "/s/kvsrc.lua"); r.amount = 1000;   // flat file
    CES_CHECK_RC_EQ(exec(r).status, CES_ERROR_BAD_INPUT); }
  { auto r = req(KV_RANGE, home() + "nope.kv"); r.amount = 1000;  // no such store
    CES_CHECK_RC_EQ(exec(r).status, CES_ERROR_FILE_NOT_FOUND); }
}

BOOST_AUTO_TEST_CASE(WireKvDepositFundsCell) {
  const std::string name = home() + "wire.kv";
  createStore(name);
  CES_REQUIRE_OK(put(name, "k", "v", 1000));   // cell balance 1000

  CesFileClient fc;
  fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  BOOST_REQUIRE_EQUAL((int)fc.connect("localhost", rpcPort, ownerKey), (int)CES_OK);

  uint64_t cellBal = 0;
  BOOST_REQUIRE_EQUAL((int)fc.kvDeposit(name, b_("k"), 5'000'000ull, cellBal),
                      (int)CES_OK);
  BOOST_CHECK_EQUAL(cellBal, 1000ull + 5'000'000ull);

  // Funding a key that doesn't exist fails cleanly.
  uint64_t tmp = 0;
  CES_CHECK_RC_EQ(fc.kvDeposit(name, b_("ghost"), 100, tmp),
                  CES_ERROR_FILE_NOT_FOUND);
  fc.disconnect();
}

BOOST_AUTO_TEST_SUITE_END()
