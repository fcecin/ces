/**
 * test_webadmin.cpp — WebAdmin dashboard HTTP endpoints.
 *
 * In-process CesServer + WebAdmin bound to 127.0.0.1:0; a tiny raw-TCP HTTP
 * client drives the endpoints. No simulator — this proves the admin surface
 * (status, mint/burn, peering, hello banner, lookups, logs, config) is live
 * and behaves correctly. Filter with: --test WebAdminTests
 */

#include "test_common.h"

#include <ces/webadmin.h>

#include <boost/asio.hpp>

#include <cctype>
#include <climits>
#include <cstdlib>
#include <utility>

namespace {

struct HttpResp {
  int status = 0;
  std::string body;
  std::string raw;
};

std::string urlEncode(const std::string& s) {
  static const char* hex = "0123456789ABCDEF";
  std::string o;
  for (unsigned char c : s) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
      o += static_cast<char>(c);
    else { o += '%'; o += hex[c >> 4]; o += hex[c & 0xF]; }
  }
  return o;
}

std::string form(
    std::initializer_list<std::pair<std::string, std::string>> kv) {
  std::string o;
  bool first = true;
  for (auto& [k, v] : kv) {
    if (!first) o += '&';
    first = false;
    o += urlEncode(k) + "=" + urlEncode(v);
  }
  return o;
}

HttpResp httpReq(uint16_t port, const std::string& method,
                 const std::string& target, const std::string& body = "") {
  boost::asio::io_context io;
  boost::asio::ip::tcp::socket sock(io);
  sock.connect({boost::asio::ip::make_address("127.0.0.1"), port});
  std::string req = method + " " + target +
    " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n";
  if (method == "POST") {
    req += "Content-Type: application/x-www-form-urlencoded\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  }
  req += "\r\n" + body;
  boost::asio::write(sock, boost::asio::buffer(req));
  std::string resp;
  char buf[4096];
  boost::system::error_code ec;
  for (;;) {
    size_t n = sock.read_some(boost::asio::buffer(buf), ec);
    if (n) resp.append(buf, n);
    if (ec) break;
  }
  HttpResp r;
  r.raw = resp;
  if (resp.size() >= 12) r.status = std::atoi(resp.substr(9, 3).c_str());
  auto h = resp.find("\r\n\r\n");
  r.body = (h == std::string::npos) ? "" : resp.substr(h + 4);
  return r;
}

bool has(const std::string& body, const std::string& needle) {
  return body.find(needle) != std::string::npos;
}

// Extract the integer following "key": in a flat JSON object.
long long jnum(const std::string& body, const std::string& key) {
  auto p = body.find("\"" + key + "\":");
  if (p == std::string::npos) return LLONG_MIN;
  return std::atoll(body.c_str() + p + key.size() + 3);
}

struct WebAdminFix {
  std::unique_ptr<CesServer> server;
  std::unique_ptr<ces::WebAdmin> web;
  boost::asio::io_context webIO;
  std::thread webThread;
  fs::path tempDir;
  uint16_t port = 0;
  uint16_t mainPort = 0;
  KeyPair clientKey;

  WebAdminFix() {
    blog::init();
    tempDir = makeUniqueTempDir("ces_web_test");
    minx::Hash sp;
    sp.fill(0xEE);
    CesConfig cfg =
      makeTestConfig(tempDir, sp, std::numeric_limits<uint64_t>::max());
    server = std::make_unique<CesServer>(cfg);
    mainPort = server->start(0);
    BOOST_REQUIRE(mainPort > 0);
    web = std::make_unique<ces::WebAdmin>(webIO, *server);
    BOOST_REQUIRE(web->listen("127.0.0.1", 0));
    port = web->boundPort();
    BOOST_REQUIRE(port > 0);
    webThread = std::thread([this]() { webIO.run(); });
    server->_brr(clientKey.getPublicKeyAsHash(), 5'000'000'000);
  }

  ~WebAdminFix() {
    if (web) web->stop();
    webIO.stop();
    if (webThread.joinable()) webThread.join();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  std::string clientHex() { return clientKey.getPublicKeyHexStr(); }
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(WebAdminTests, WebAdminFix)

BOOST_AUTO_TEST_CASE(ServesDashboardHtml) {
  auto r = httpReq(port, "GET", "/");
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(has(r.body, "CES Server Dashboard"));
  BOOST_CHECK(has(r.body, "/api/status"));
}

BOOST_AUTO_TEST_CASE(StatusEndpoint) {
  auto r = httpReq(port, "GET", "/api/status");
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(has(r.body, "\"pubkey\""));
  BOOST_CHECK(has(r.body, "\"circulating\""));
  BOOST_CHECK(has(r.body, "\"gauges\""));
  BOOST_CHECK(has(r.body, "\"features\""));
  BOOST_CHECK(has(r.body, "\"hello\""));
}

BOOST_AUTO_TEST_CASE(NotFound) {
  auto r = httpReq(port, "GET", "/api/nope");
  BOOST_CHECK_EQUAL(r.status, 404);
  BOOST_CHECK(has(r.body, "not found"));
}

BOOST_AUTO_TEST_CASE(CreditAndDebit) {
  std::string key = clientHex();
  auto r1 = httpReq(port, "POST", "/api/credit",
                    form({{"pubkey", key}, {"amount", "1000000"}}));
  BOOST_CHECK_EQUAL(r1.status, 200);
  BOOST_CHECK(has(r1.body, "\"ok\":true"));

  auto a = httpReq(port, "GET", "/api/account?key=" + key);
  BOOST_CHECK(has(a.body, "\"exists\":true"));
  BOOST_CHECK_GT(jnum(a.body, "balance"), 5'000'000'000LL);

  auto r2 = httpReq(port, "POST", "/api/debit",
                    form({{"pubkey", key}, {"amount", "500000"}}));
  BOOST_CHECK(has(r2.body, "\"ok\":true"));
}

BOOST_AUTO_TEST_CASE(CreditRejectsBadInput) {
  auto r = httpReq(port, "POST", "/api/credit",
                   form({{"pubkey", "short"}, {"amount", "100"}}));
  BOOST_CHECK(has(r.body, "error"));
  auto r2 = httpReq(port, "POST", "/api/credit",
                    form({{"pubkey", clientHex()}, {"amount", "0"}}));
  BOOST_CHECK(has(r2.body, "error"));
}

BOOST_AUTO_TEST_CASE(AccountLookupMissing) {
  std::string k(64, 'a');
  auto r = httpReq(port, "GET", "/api/account?key=" + k);
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(has(r.body, "\"exists\":false"));
}

BOOST_AUTO_TEST_CASE(AssetLookupMissing) {
  std::string k(64, 'c');
  auto r = httpReq(port, "GET", "/api/asset?key=" + k);
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(has(r.body, "\"exists\":false"));
}

BOOST_AUTO_TEST_CASE(PeerAddListRemove) {
  // Point at the fixture's OWN server so the miner's first probe connects
  // instantly — a dead address would make connect() time out and stall
  // teardown (stop() joins the probe-blocked miner thread). peer_add now
  // verifies the key against the remote's handshake, so use the real one.
  std::string pk = server->_serverKeyPair().getPublicKeyHexStr();
  std::string addr = "127.0.0.1:" + std::to_string(mainPort);
  auto add = httpReq(port, "POST", "/api/peer_add",
                     form({{"key", pk}, {"address", addr}}));
  BOOST_CHECK(has(add.body, "\"ok\":true"));

  auto list = httpReq(port, "GET", "/api/peers");
  BOOST_CHECK(has(list.body, addr));
  BOOST_CHECK(has(list.body, "\"outbound\":true"));

  auto rm = httpReq(port, "POST", "/api/peer_remove", form({{"key", pk}}));
  BOOST_CHECK(has(rm.body, "\"ok\":true"));

  auto list2 = httpReq(port, "GET", "/api/peers");
  BOOST_CHECK(!has(list2.body, addr));
}

BOOST_AUTO_TEST_CASE(PeerAddRejectsWrongKey) {
  // A wrong key for a reachable server must be rejected (the handshake reports
  // the real key) — otherwise the miner would burn PoW toward a key the server
  // doesn't hold. Point at the fixture's own server with a bogus key.
  std::string wrong(64, 'a');
  std::string addr = "127.0.0.1:" + std::to_string(mainPort);
  auto add = httpReq(port, "POST", "/api/peer_add",
                     form({{"key", wrong}, {"address", addr}}));
  BOOST_CHECK(!has(add.body, "\"ok\":true"));
  BOOST_CHECK(has(add.body, "mismatch"));
  // And it was not added.
  auto list = httpReq(port, "GET", "/api/peers");
  BOOST_CHECK(!has(list.body, addr));
}

BOOST_AUTO_TEST_CASE(PeerTargetStartsMiner) {
  auto r = httpReq(port, "POST", "/api/peer_target", form({{"target", "5000"}}));
  BOOST_CHECK(has(r.body, "\"ok\":true"));
  auto s = httpReq(port, "GET", "/api/status");
  BOOST_CHECK_EQUAL(jnum(s.body, "peerTarget"), 5000);
  BOOST_CHECK(has(s.body, "\"minerRunning\":true"));
}

BOOST_AUTO_TEST_CASE(HelloSaveGetCapAndFile) {
  auto sv = httpReq(port, "POST", "/api/hello_save",
                    form({{"text", "Hello CES network"}}));
  BOOST_CHECK(has(sv.body, "\"ok\":true"));
  BOOST_CHECK(has(sv.body, "Hello CES network"));

  auto g = httpReq(port, "GET", "/api/hello");
  BOOST_CHECK(has(g.body, "Hello CES network"));
  BOOST_CHECK(has(g.body, "\"fileExists\":true"));
  BOOST_CHECK(fs::exists(tempDir / "hello.txt"));

  // The hello shows up in /api/status (the dashboard banner).
  auto st = httpReq(port, "GET", "/api/status");
  BOOST_CHECK(has(st.body, "Hello CES network"));

  // 160-byte cap (ASCII).
  std::string big(200, 'x');
  auto cap = httpReq(port, "POST", "/api/hello_save", form({{"text", big}}));
  BOOST_CHECK_EQUAL(jnum(cap.body, "bytes"), 160);
}

BOOST_AUTO_TEST_CASE(HelloUtf8CodepointSafe) {
  // 159 'a' + 'é' (0xC3 0xA9) = 161 bytes. Trimming must drop the whole
  // 2-byte codepoint, landing on exactly 159 — never split mid-sequence.
  std::string s(159, 'a');
  s += "\xC3\xA9";
  auto r = httpReq(port, "POST", "/api/hello_save", form({{"text", s}}));
  BOOST_CHECK_EQUAL(jnum(r.body, "bytes"), 159);
}

BOOST_AUTO_TEST_CASE(LogTailCapturesActivity) {
  // An action that logs at INFO ("hello banner set via admin" in server.cpp).
  httpReq(port, "POST", "/api/hello_save", form({{"text", "logtest banner"}}));
  std::this_thread::sleep_for(std::chrono::milliseconds(60));
  auto r = httpReq(port, "GET", "/api/logs?since=0");
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(has(r.body, "\"hi\":"));
  BOOST_CHECK(has(r.body, "\"lines\":"));
  BOOST_CHECK(has(r.body, "hello banner set"));
}

BOOST_AUTO_TEST_CASE(InspectRequiresAddress) {
  // Empty address → the worker-thread path returns an error JSON (no network).
  auto r = httpReq(port, "POST", "/api/inspect", form({{"address", ""}}));
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(has(r.body, "error"));
}

BOOST_AUTO_TEST_CASE(ConfigEndpoint) {
  auto r = httpReq(port, "GET", "/api/config");
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(has(r.body, "\"knobs\""));
  BOOST_CHECK(has(r.body, "\"multipliers\""));
  BOOST_CHECK(has(r.body, "feeAccount"));
}

BOOST_AUTO_TEST_CASE(ConfigSetKnobLive) {
  // A fee knob set live is reflected by /api/config on the next read.
  auto set = httpReq(port, "POST", "/api/config_set",
                     form({{"key", "fee_account"}, {"value", "12345"}}));
  BOOST_CHECK(has(set.body, "\"ok\":true"));
  BOOST_CHECK_EQUAL(jnum(httpReq(port, "GET", "/api/config").body, "feeAccount"),
                    12345);

  // min_difficulty within [1,54] takes effect.
  auto md = httpReq(port, "POST", "/api/config_set",
                    form({{"key", "min_difficulty"}, {"value", "7"}}));
  BOOST_CHECK(has(md.body, "\"ok\":true"));
  BOOST_CHECK_EQUAL(jnum(httpReq(port, "GET", "/api/config").body, "minDifficulty"),
                    7);

  // Out-of-range difficulty is rejected and leaves the value untouched.
  auto bad = httpReq(port, "POST", "/api/config_set",
                     form({{"key", "min_difficulty"}, {"value", "99"}}));
  BOOST_CHECK(has(bad.body, "\"ok\":false"));
  BOOST_CHECK_EQUAL(jnum(httpReq(port, "GET", "/api/config").body, "minDifficulty"),
                    7);

  // An unknown knob is rejected.
  auto unk = httpReq(port, "POST", "/api/config_set",
                     form({{"key", "no_such_knob"}, {"value", "1"}}));
  BOOST_CHECK(has(unk.body, "\"ok\":false"));
}

BOOST_AUTO_TEST_CASE(L2FeeKnobsAndStatsEndpoints) {
  // L2 fee knobs (file / compute / net) are live-editable like the base fees.
  auto setKnob = [&](const char* k, const char* v) {
    return httpReq(port, "POST", "/api/config_set",
                   form({{"key", k}, {"value", v}}));
  };
  BOOST_CHECK(has(setKnob("fee_file_rent", "321").body, "\"ok\":true"));
  BOOST_CHECK(has(setKnob("fee_compute_slot_sec", "654").body, "\"ok\":true"));
  BOOST_CHECK(has(setKnob("fee_net_byte_sent", "9").body, "\"ok\":true"));
  auto cfg = httpReq(port, "GET", "/api/config").body;
  BOOST_CHECK_EQUAL(jnum(cfg, "feeFileRent"), 321);
  BOOST_CHECK_EQUAL(jnum(cfg, "feeComputeSlotSec"), 654);
  BOOST_CHECK_EQUAL(jnum(cfg, "feeNetByteSent"), 9);

  // The File/Compute monitoring endpoints respond with the right shape; the
  // features are off in this fixture (no rpc port, caps 0) → enabled:false.
  auto fs = httpReq(port, "GET", "/api/filestore");
  BOOST_CHECK_EQUAL(fs.status, 200);
  BOOST_CHECK(has(fs.body, "\"enabled\":false"));
  BOOST_CHECK(has(fs.body, "totalFiles"));

  auto cp = httpReq(port, "GET", "/api/compute");
  BOOST_CHECK_EQUAL(cp.status, 200);
  BOOST_CHECK(has(cp.body, "\"enabled\":false"));
  BOOST_CHECK(has(cp.body, "\"instances\":[]"));

  // File STAT lookup responds; the file feature is off in this fixture.
  auto fst = httpReq(port, "GET", "/api/filestat?path=/s/x.lua");
  BOOST_CHECK_EQUAL(fst.status, 200);
  BOOST_CHECK(has(fst.body, "\"enabled\":false"));

  // Feature caps can't cross the 0 boundary live (the handler binds at boot).
  // Both features are off (cap 0) in this fixture → enabling live is rejected.
  BOOST_CHECK(has(setKnob("file_store_max_bytes", "1000000").body, "\"ok\":false"));
  BOOST_CHECK(has(setKnob("compute_max_instances", "4").body, "\"ok\":false"));
}

BOOST_AUTO_TEST_CASE(FileStatActivePathWhenEnabled) {
  // WebAdminFix has the file feature off; stand one up with it on so /api/filestat
  // takes the active path (posts onto rpcTaskIO, runs execStat) not the gate.
  fs::path d = makeUniqueTempDir("ces_web_filestat");
  minx::Hash sp; sp.fill(0xAB);
  CesConfig cfg = makeTestConfig(d, sp, std::numeric_limits<uint64_t>::max());
  cfg.rpcPort = 0;
  cfg.rpcAutoPort = true;
  cfg.cesplexMounts = {{"/ces/file/1", "builtin:file"}};
  cfg.cesFileStoreMaxBytes = 64ull * 1024 * 1024;
  cfg.feeFileRent = 1;
  auto srv = std::make_unique<CesServer>(cfg);
  srv->start(0);
  BOOST_REQUIRE(srv->_rpcBoundPort() != 0);
  boost::asio::io_context io;
  ces::WebAdmin w(io, *srv);
  BOOST_REQUIRE(w.listen("127.0.0.1", 0));
  uint16_t p = w.boundPort();
  std::thread t([&] { io.run(); });
  auto r = httpReq(p, "GET", "/api/filestat?path=/p/nope.txt");
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(has(r.body, "\"enabled\":true"));
  BOOST_CHECK(has(r.body, "\"found\":false"));
  w.stop();
  io.stop();
  if (t.joinable()) t.join();
  srv->stop();
  boost::system::error_code ec;
  fs::remove_all(d, ec);
}

BOOST_AUTO_TEST_CASE(NetbillInactiveWithoutRpc) {
  // No rpc port in this fixture → ChannelMeter absent → active:false.
  auto r = httpReq(port, "GET", "/api/netbill");
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(has(r.body, "\"active\":false"));
}

BOOST_AUTO_TEST_CASE(CreditCreatesNewAccount) {
  std::string k(64, 'd');  // 0xdd..dd — valid hex, not the funded client
  auto before = httpReq(port, "GET", "/api/account?key=" + k);
  BOOST_CHECK(has(before.body, "\"exists\":false"));
  auto cr = httpReq(port, "POST", "/api/credit",
                    form({{"pubkey", k}, {"amount", "777"}}));
  BOOST_CHECK(has(cr.body, "\"ok\":true"));
  auto after = httpReq(port, "GET", "/api/account?key=" + k);
  BOOST_CHECK(has(after.body, "\"exists\":true"));
  BOOST_CHECK_EQUAL(jnum(after.body, "balance"), 777);
}

BOOST_AUTO_TEST_CASE(WalletTransferFromServer) {
  // Transfer from the server's own (bottomless) account creates + credits dest.
  std::string dest(64, 'e');  // 0xee..ee — fresh account
  BOOST_CHECK(has(httpReq(port, "GET", "/api/account?key=" + dest).body,
                  "\"exists\":false"));
  auto r = httpReq(port, "POST", "/api/transfer",
                   form({{"pubkey", dest}, {"amount", "500"}}));
  BOOST_CHECK(has(r.body, "\"ok\":true"));
  auto after = httpReq(port, "GET", "/api/account?key=" + dest);
  BOOST_CHECK(has(after.body, "\"exists\":true"));
  BOOST_CHECK_EQUAL(jnum(after.body, "balance"), 500);
}

BOOST_AUTO_TEST_CASE(AccountPrefixCollisionNotExists) {
  // Two keys sharing the 8-byte map prefix (first 16 hex) but with different
  // 24-byte tails are DIFFERENT accounts. Querying the second must not report
  // the first as existing — it's a prefix collision, not a match.
  std::string keyX = std::string(16, 'a') + std::string(48, 'b');  // prefix aa.., tail bb..
  std::string keyY = std::string(16, 'a') + std::string(48, 'c');  // SAME prefix, tail cc..
  BOOST_CHECK(has(httpReq(port, "POST", "/api/credit",
                          form({{"pubkey", keyX}, {"amount", "100"}})).body,
                  "\"ok\":true"));
  BOOST_CHECK(has(httpReq(port, "GET", "/api/account?key=" + keyX).body,
                  "\"exists\":true"));
  auto ry = httpReq(port, "GET", "/api/account?key=" + keyY);
  BOOST_CHECK(has(ry.body, "\"exists\":false"));
  BOOST_CHECK(has(ry.body, "\"prefixTaken\":true"));
}

BOOST_AUTO_TEST_CASE(HelloLoadRoundTrip) {
  httpReq(port, "POST", "/api/hello_save", form({{"text", "loaded greeting"}}));
  auto r = httpReq(port, "POST", "/api/hello_load", "");
  BOOST_CHECK(has(r.body, "loaded greeting"));
  BOOST_CHECK(has(r.body, "\"fileExists\":true"));
}

BOOST_AUTO_TEST_CASE(ConfigHasFeeMultipliers) {
  auto r = httpReq(port, "GET", "/api/config");
  BOOST_CHECK(has(r.body, "\"Tx\":"));
  BOOST_CHECK(has(r.body, "\"Net\":"));
  BOOST_CHECK(has(r.body, "feeDiscountEnabled"));
}

BOOST_AUTO_TEST_CASE(DefaultStateNoMiner) {
  // Fresh fixture: peerTarget defaults to 0 and the miner isn't started.
  auto s = httpReq(port, "GET", "/api/status");
  BOOST_CHECK_EQUAL(jnum(s.body, "peerTarget"), 0);
  BOOST_CHECK(has(s.body, "\"minerRunning\":false"));
}

BOOST_AUTO_TEST_CASE(ConfigExportWritesFile) {
  auto r = httpReq(port, "POST", "/api/config_export", "");
  BOOST_CHECK(has(r.body, "\"ok\":true"));
  BOOST_CHECK(fs::exists(tempDir / "ces.toml"));
  std::ifstream f((tempDir / "ces.toml").string());
  std::stringstream ss;
  ss << f.rdbuf();
  std::string toml = ss.str();
  // Exports the live peer target + identity; excludes peers/hello (own files).
  BOOST_CHECK(toml.find("peer_target") != std::string::npos);
  BOOST_CHECK(toml.find("server_key") != std::string::npos);
  BOOST_CHECK(toml.find("web_port") != std::string::npos);
  // The export must dump the WHOLE effective config (no silent rot): one
  // representative key from every section, all using canonical TOML names.
  BOOST_CHECK(toml.find("fee_tx") != std::string::npos);              // base fees
  BOOST_CHECK(toml.find("fee_discount_enabled") != std::string::npos);
  BOOST_CHECK(toml.find("fee_file_rent") != std::string::npos);       // file fees
  BOOST_CHECK(toml.find("fee_compute_slot_sec") != std::string::npos);// compute fees
  BOOST_CHECK(toml.find("fee_compute_net_byte") != std::string::npos);
  BOOST_CHECK(toml.find("fee_net_byte_sent") != std::string::npos);   // net metering
  BOOST_CHECK(toml.find("rpc_max_pending") != std::string::npos);     // rpc backpressure
  BOOST_CHECK(toml.find("compute_client_pool_size") != std::string::npos);
  BOOST_CHECK(toml.find("ext_funding_per_day") != std::string::npos);
  BOOST_CHECK(toml.find("[rpc_rudp]") != std::string::npos);          // tables
}

BOOST_AUTO_TEST_CASE(AddPeerStartsMinerAndProbes) {
  // Adding a peer now starts the probe/mine thread even at target 0, so the
  // peer's reachability is checked without committing to mining. We point it
  // at the fixture's OWN server so the probe connects instantly — a dead
  // address would make the miner's first connect time out and stall teardown.
  // peer_add verifies the key via handshake, so use the server's real key.
  std::string pk = server->_serverKeyPair().getPublicKeyHexStr();
  std::string addr = "127.0.0.1:" + std::to_string(mainPort);
  auto add = httpReq(port, "POST", "/api/peer_add",
                     form({{"key", pk}, {"address", addr}}));
  BOOST_CHECK(has(add.body, "\"ok\":true"));
  auto p = httpReq(port, "GET", "/api/peers");
  BOOST_CHECK(has(p.body, "\"minerRunning\":true"));
  BOOST_CHECK(has(p.body, "\"lastCycle\":"));
  BOOST_CHECK(has(p.body, "\"cycles\":"));
}

BOOST_AUTO_TEST_CASE(LogLevelSetAndReport) {
  // /api/logs reports the live server level; /api/loglevel sets it.
  auto set = httpReq(port, "POST", "/api/loglevel", form({{"level", "debug"}}));
  BOOST_CHECK(has(set.body, "\"ok\":true"));
  BOOST_CHECK_EQUAL(jnum(set.body, "level"), 1);  // debug == 1
  auto logs = httpReq(port, "GET", "/api/logs?since=0");
  BOOST_CHECK_EQUAL(jnum(logs.body, "level"), 1);
  auto bad = httpReq(port, "POST", "/api/loglevel", form({{"level", "bogus"}}));
  BOOST_CHECK(has(bad.body, "\"ok\":false"));
  blog::set_level(blog::info);  // restore (blog state is process-global)
}

BOOST_AUTO_TEST_SUITE_END()
