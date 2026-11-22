// ===========================================================================
// builtin:lua — /ces/lua/1 user RUDP connection routing.
// ===========================================================================
//
// The in-process bind/attach/byte-pipe harness lives in
// test_lua_conn_common.h (shared with test_dice_lua.cpp). This file is just
// the routing test suite that rides it.

#define BOOST_TEST_DYN_LINK
#include "test_lua_conn_common.h"
#include <ces/account.h>
#include <ces/cesplex/meter.h>

#include <cstring>

BOOST_FIXTURE_TEST_SUITE(LuaConnTests, LuaConnFixture)

// ATTACH must fail with CES_ERROR_NOT_LISTENING when the program never
// called ces.conn.set_listener — the per-instance accept gate defaults
// OFF.
BOOST_AUTO_TEST_CASE(AttachRequiresListener) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/silent.lua";
  // No set_listener: just block on ces.client_recv so the process stays
  // alive while we attempt an ATTACH against it.
  const std::string src =
    "while true do\n"
    "  local pfx, msg = ces.client_recv()\n"
    "  if not pfx then break end\n"
    "end\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceConnected(*server, instId));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));

  auto r = peer.attach(userKey, bindDigest, instId);
  CES_CHECK_RC_EQ(r.status, CES_ERROR_NOT_LISTENING);
}

// Round-trip: program calls set_listener({on_data = echo}) + run().
// User attaches, sends "ping", reads "ping" back from on_data → conn:write.
BOOST_AUTO_TEST_CASE(EchoRoundTrip) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/echo_conn.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data) conn:write(data) end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));

  auto r = peer.attach(userKey, bindDigest, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  BOOST_CHECK(r.connId > 0);
  BOOST_CHECK(r.hello.empty());   // request-driven program: no greeting

  // Channel is now in DATA mode. Send "ping", expect "ping" back.
  const std::string msg = "ping";
  ces::Bytes wire(msg.begin(), msg.end());
  BOOST_REQUIRE(peerWrite(peer, wire));
  ces::Bytes echoed;
  BOOST_REQUIRE(peerReadExact(peer, echoed, msg.size(),
                              std::chrono::seconds(5)));
  std::string got(echoed.begin(), echoed.end());
  BOOST_CHECK_EQUAL(got, msg);
}

// A terminal-style program declares a greeting via set_listener{hello}. It
// rides the ATTACH reply atomically (helloLen > 0), so the client knows the
// program speaks first without waiting on a timeout.
BOOST_AUTO_TEST_CASE(HelloRidesAttachReply) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/greeter.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  hello = 'CES TERMINAL v1\\n',\n"
    "  on_data = function(conn, data) conn:write(data) end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));

  auto r = peer.attach(userKey, bindDigest, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  BOOST_CHECK_EQUAL(r.hello, "CES TERMINAL v1\n");
}

// on_open fires with the bound user pubkey on conn.pubkey. Program
// writes "open:" + 32 raw bytes back as soon as on_open lands.
BOOST_AUTO_TEST_CASE(OnOpenFiresWithBoundPubkey) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/open_pk.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_open = function(conn) conn:write('open:' .. conn.pubkey) end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));
  auto r = peer.attach(userKey, bindDigest, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 5 + 32,
                              std::chrono::seconds(5)));
  BOOST_CHECK(std::memcmp(got.data(), "open:", 5) == 0);
  const auto& expectedPk = userKey.getPublicKeyAsHash();
  BOOST_CHECK(std::memcmp(got.data() + 5, expectedPk.data(), 32) == 0);
}

// Bursty bidirectional echo — on_data fires 10 conn:writes per call.
// Without the per-conn write queue, two of those async_writes would
// race on the same RudpStream and the user side would either error or
// see corrupted ordering.
BOOST_AUTO_TEST_CASE(BurstyBidirectionalEcho) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/burst.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, _)\n"
    "    for i = 0, 9 do\n"
    "      conn:write(string.format('c%02d', i))\n"
    "    end\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));
  auto r = peer.attach(userKey, bindDigest, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  // One inbound byte triggers ten outbound writes.
  BOOST_REQUIRE(peerWrite(peer, ces::Bytes{'x'}));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 30, kTestWaitLimit));
  std::string s(got.begin(), got.end());
  // Strict ordering: c00..c09 in sequence.
  BOOST_CHECK_EQUAL(s, "c00c01c02c03c04c05c06c07c08c09");
}

// Lua program calls conn:close() inside on_data. The user-side stream
// must die cleanly (any subsequent peerReadExact errors).
BOOST_AUTO_TEST_CASE(ProgramCloseTearsDownUserChannel) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/prog_close.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, _)\n"
    "    conn:write('bye')\n"
    "    conn:close()\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));
  auto r = peer.attach(userKey, bindDigest, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  BOOST_REQUIRE(peerWrite(peer, ces::Bytes{'x'}));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 3, kTestWaitLimit));
  BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "bye");

  // Subsequent reads must fail — the channel is gone.
  ces::Bytes after;
  BOOST_CHECK(!peerReadExact(peer, after, 1, std::chrono::seconds(2)));
}

struct SmallWindowLuaConnFixture : LuaConnFixture {
  SmallWindowLuaConnFixture()
      : LuaConnFixture([](CesConfig& c) {
          c.rpcRudpMaxReorderMsgsPerChannel = 32;
          c.rpcRudpMaxReorderBytesPerChannel = 32 * minx::Rudp::MAX_MESSAGE_SIZE;
        }) {}
};

BOOST_FIXTURE_TEST_CASE(ProgramCloseDeliversEveryQueuedWrite, SmallWindowLuaConnFixture) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/prog_close_many.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, _)\n"
    "    conn:write(string.rep('a', 30000))\n"
    "    conn:write(string.rep('b', 60000))\n"
    "    conn:write('END')\n"
    "    conn:close()\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));
  auto r = peer.attach(userKey, bindDigest, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  BOOST_REQUIRE(peerWrite(peer, ces::Bytes{'x'}));
  const std::size_t total = 30000 + 60000 + 3;
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, total, std::chrono::seconds(10)));
  BOOST_CHECK(got[0] == 'a' && got[29999] == 'a' && got[30000] == 'b' && got[89999] == 'b');
  BOOST_CHECK_EQUAL(std::string(got.end() - 3, got.end()), "END");
}

// Helper: poll a file's content via the file-handler client until it
// reaches `expectedBytes` (up to `timeout`). Returns the final content.
inline ces::Bytes pollFileContent(
    LuaConnFixture& fx, const std::string& path,
    std::size_t expectedBytes,
    std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
  using clk = std::chrono::steady_clock;
  const auto deadline = clk::now() + timeout;
  CesFileClient fc;
  fc.setServerPubkey(fx.server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(fc.connect("localhost", fx.rpcPort, fx.ownerKey));
  ces::Bytes data;
  while (clk::now() < deadline) {
    CesFileClient::StatInfo info;
    if (fc.stat(path, info) == CES_OK && info.size >= expectedBytes) {
      minx::Hash _h{};
      uint8_t rc = fc.read(path, /*offset=*/0,
                           static_cast<uint32_t>(info.size), data, _h);
      if (rc == CES_OK) {
        fc.disconnect();
        return data;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  fc.disconnect();
  return data;
}

// User-side stream close fires on_close in the program. Program logs
// the event into a side file via ces.file_append; test reads it.
BOOST_AUTO_TEST_CASE(OnCloseFiresOnUserClose) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/uclose.lua";
  const std::string logPath    = "/h/" + ownerHex + "/uclose.log";
  const std::string src =
    "local logp = '" + logPath + "'\n"
    "ces.file_create(logp, 1024, 0, 5000000, 'text/plain')\n"
    "ces.conn.set_listener({\n"
    "  on_close = function(_) ces.file_append(logp, 'closed') end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  {
    PlexLuaPeer peer;
    BOOST_REQUIRE(peer.start() != 0);
    ces::BindDigest bindDigest{};
    BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));
    auto r = peer.attach(userKey, bindDigest, instId);
    CES_REQUIRE_RC_EQ(r.status, CES_OK);
    // Explicit close emits HS_CLOSE so the server's dataReadLoop
    // errors out immediately (instead of waiting for RUDP idle GC),
    // which fires computeSendConnClosed → on_close in the program.
    peer.closeStream();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  auto data = pollFileContent(*this, logPath,
                              /*expectedBytes=*/1024 + 6);
  // The file is sparse-prefilled with 1024 zero bytes; "closed" is
  // appended past that (offset = original size).
  BOOST_REQUIRE_GE(data.size(), 1024u + 6u);
  std::string tail(data.end() - 6, data.end());
  BOOST_CHECK_EQUAL(tail, "closed");
}

// SIGKILLing the cesluajitd child cascades through the supervisor's
// luaHandlerOnInstanceDying: every routed connection is dropped. The
// user side observes its stream die.
BOOST_AUTO_TEST_CASE(InstanceDyingCascadesToUser) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/dying.lua";
  const std::string src =
    "ces.conn.set_listener({})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));
  auto r = peer.attach(userKey, bindDigest, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  // Kill the instance via the compute client (separate channel).
  {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    CES_REQUIRE_OK(cc.kill(instId));
    cc.disconnect();
  }

  // The user's stream must error within a reasonable window.
  ces::Bytes after;
  BOOST_CHECK(!peerReadExact(peer, after, 1, std::chrono::seconds(3)));
}

// Two independent ATTACHes from the same user → distinct conn_ids,
// each with its own (instId, connId) routing entry. Both echo
// independently.
BOOST_AUTO_TEST_CASE(MultipleConnsSameUser) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/many.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data)\n"
    // Fixed-width id so the peer can read an exact length. conn.id is a
    // host-assigned uid (unique across transports), not the wire conn_id.
    "    conn:write(string.format('%020d:%s', conn.id, data))\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  PlexLuaPeer p1, p2;
  BOOST_REQUIRE(p1.start() != 0);
  BOOST_REQUIRE(p2.start() != 0);
  ces::BindDigest st1{}, st2{};
  BOOST_REQUIRE(p1.bind(rpcPort, userKey, st1));
  BOOST_REQUIRE(p2.bind(rpcPort, userKey, st2));
  auto r1 = p1.attach(userKey, st1, instId);
  auto r2 = p2.attach(userKey, st2, instId);
  CES_REQUIRE_RC_EQ(r1.status, CES_OK);
  CES_REQUIRE_RC_EQ(r2.status, CES_OK);
  BOOST_REQUIRE_NE(r1.connId, r2.connId);

  BOOST_REQUIRE(peerWrite(p1, ces::Bytes{'A'}));
  BOOST_REQUIRE(peerWrite(p2, ces::Bytes{'B'}));
  // Reply = 20-digit conn.id + ':' + 1 data byte = 22 bytes.
  ces::Bytes g1, g2;
  BOOST_REQUIRE(peerReadExact(p1, g1, 22));
  BOOST_REQUIRE(peerReadExact(p2, g2, 22));
  const std::string s1(g1.begin(), g1.end());
  const std::string s2(g2.begin(), g2.end());
  BOOST_CHECK_EQUAL(s1[20], ':');
  BOOST_CHECK_EQUAL(s2[20], ':');
  BOOST_CHECK_EQUAL(s1[21], 'A');   // p1's data echoed back on p1's conn
  BOOST_CHECK_EQUAL(s2[21], 'B');   // p2's data echoed back on p2's conn
  // Distinct host uids → the two conns are independent routes.
  BOOST_CHECK_NE(s1.substr(0, 20), s2.substr(0, 20));
}

// Two ATTACHes from two different users → conn.pubkey distinct on
// the program side, both echo independently.
BOOST_AUTO_TEST_CASE(MultipleConnsMultipleUsers) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/mu.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data)\n"
    "    conn:write(conn.pubkey:sub(1, 4) .. ':' .. data)\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  KeyPair u2;
  server->_brr(u2.getPublicKeyAsHash(), 10'000'000'000);

  PlexLuaPeer p1, p2;
  BOOST_REQUIRE(p1.start() != 0);
  BOOST_REQUIRE(p2.start() != 0);
  ces::BindDigest st1{}, st2{};
  BOOST_REQUIRE(p1.bind(rpcPort, userKey, st1));
  BOOST_REQUIRE(p2.bind(rpcPort, u2,      st2));
  CES_REQUIRE_RC_EQ(p1.attach(userKey, st1, instId).status, CES_OK);
  CES_REQUIRE_RC_EQ(p2.attach(u2,      st2, instId).status, CES_OK);

  BOOST_REQUIRE(peerWrite(p1, ces::Bytes{'A'}));
  BOOST_REQUIRE(peerWrite(p2, ces::Bytes{'B'}));
  ces::Bytes g1, g2;
  BOOST_REQUIRE(peerReadExact(p1, g1, 4 + 1 + 1));
  BOOST_REQUIRE(peerReadExact(p2, g2, 4 + 1 + 1));
  // First 4 bytes of p1's reply == first 4 bytes of userKey's pubkey.
  // First 4 bytes of p2's reply == first 4 bytes of u2's pubkey.
  const auto& pk1 = userKey.getPublicKeyAsHash();
  const auto& pk2 = u2.getPublicKeyAsHash();
  BOOST_CHECK(std::memcmp(g1.data(), pk1.data(), 4) == 0);
  BOOST_CHECK_EQUAL(g1[4], ':');
  BOOST_CHECK_EQUAL(g1[5], 'A');
  BOOST_CHECK(std::memcmp(g2.data(), pk2.data(), 4) == 0);
  BOOST_CHECK_EQUAL(g2[4], ':');
  BOOST_CHECK_EQUAL(g2[5], 'B');
}

// ATTACH for a pid that isn't registered →
// CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND. Covers both "pid was never
// minted" and pid=0 (gNextPid starts at 1).
BOOST_AUTO_TEST_CASE(AttachUnknownInstance) {
  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));
  auto r = peer.attach(userKey, bindDigest, /*bogus*/ 99999ULL);
  CES_CHECK_RC_EQ(r.status, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND);
}

// Bad sig on ATTACH → handler silently tears down the channel without
// replying. The user side observes timeout (no reply byte), confirming
// the verifyPerOp path on the server actually rejects forged sigs and
// drops the channel instead of admitting it.
BOOST_AUTO_TEST_CASE(AttachBadSigDropsChannel) {
  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, bindDigest));

  // Build an ATTACH wire by hand with a deliberately wrong sig (signed
  // with a DIFFERENT key — passes shape checks but won't verify
  // against the channel's bound pubkey).
  KeyPair stranger;
  ces::Bytes preamble;
  ces::Buffer::put<uint64_t>(preamble, /*any id*/ 1ULL);

  constexpr uint8_t kVerbAttach = 0x01;
  ces::Signature badSig = ces::signPerOp(
    stranger, kVerbAttach,
    std::span<const uint8_t>(preamble.data(), preamble.size()),
    bindDigest);

  ces::Bytes wire;
  wire.push_back(kVerbAttach);
  ces::Buffer::put<uint32_t>(wire, static_cast<uint32_t>(preamble.size()));
  wire.insert(wire.end(), preamble.begin(), preamble.end());
  wire.insert(wire.end(), badSig.begin(), badSig.end());

  BOOST_REQUIRE(peerWrite(peer, wire));
  // No reply: the handler tears down silently. Reading any byte
  // within 1 s must fail.
  ces::Bytes out;
  BOOST_CHECK(!peerReadExact(peer, out, 1, std::chrono::seconds(1)));
}

// set_listener(nil) flips the per-instance accept gate OFF. New
// ATTACHes get CES_ERROR_NOT_LISTENING. The existing channel is NOT
// torn down — the user can still write to it and the channel stays
// open — but on_data won't fire (no listener installed), so bytes
// silently disappear at the Lua layer until set_listener is called
// again with a non-nil handler.
BOOST_AUTO_TEST_CASE(SetListenerNilFlipsGateOff) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/toggle.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data)\n"
    "    if data == 'OFF' then\n"
    "      ces.conn.set_listener(nil)\n"
    "      conn:write('off')\n"
    "    else\n"
    "      conn:write(data)\n"
    "    end\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  // First peer attaches successfully.
  PlexLuaPeer p1;
  BOOST_REQUIRE(p1.start() != 0);
  ces::BindDigest st1{};
  BOOST_REQUIRE(p1.bind(rpcPort, userKey, st1));
  CES_REQUIRE_RC_EQ(p1.attach(userKey, st1, instId).status, CES_OK);

  // Echo works (gate ON).
  BOOST_REQUIRE(peerWrite(p1, ces::Bytes{'h', 'i'}));
  ces::Bytes g1;
  BOOST_REQUIRE(peerReadExact(p1, g1, 2));
  BOOST_CHECK_EQUAL(std::string(g1.begin(), g1.end()), "hi");

  // Tell the program to flip the gate off + ack.
  BOOST_REQUIRE(peerWrite(p1, {'O', 'F', 'F'}));
  ces::Bytes ack;
  BOOST_REQUIRE(peerReadExact(p1, ack, 3));
  BOOST_CHECK_EQUAL(std::string(ack.begin(), ack.end()), "off");

  // New ATTACH must be rejected.
  PlexLuaPeer p2;
  BOOST_REQUIRE(p2.start() != 0);
  ces::BindDigest st2{};
  BOOST_REQUIRE(p2.bind(rpcPort, userKey, st2));
  auto r2 = p2.attach(userKey, st2, instId);
  CES_CHECK_RC_EQ(r2.status, CES_ERROR_NOT_LISTENING);

  // Existing conn is alive but silent — write succeeds, but no
  // callback fires (listener registry slot is nil), so no echo.
  BOOST_REQUIRE(peerWrite(p1, {'!', '!'}));
  ces::Bytes g3;
  BOOST_CHECK(!peerReadExact(p1, g3, 2, std::chrono::seconds(1)));
}

// The compute payout at a factor of 2, and no supervisor tick in the test, so
// no compute fee moves the program account while the test reads it. Each
// instance gets an rpc port, for direct /ces/luarpc/1 dials.
struct PayoutLuaConnFixture : LuaConnFixture {
  PayoutLuaConnFixture() : LuaConnFixture([](CesConfig& c) {
    c.computePayoutFactorBp = 20000;
    c.computeTickIntervalMs = 3'600'000;
    c.computePortBase = findFreeUdpPortRange(8);
    c.computePortCount = 8;
  }) {}
};

static const char* const kEcho =
  "ces.conn.set_listener({ on_data = function(conn, d) conn:write(d) end })\n"
  "ces.conn.run()\n";

// A visit is one short channel: bind, ATTACH, a request and its reply, then
// a close, with no meter tick between. The meter bills it at the close. The
// ATTACH names the program as the channel's payee, so the visitor pays twice
// the price and the program gets the price once.
BOOST_FIXTURE_TEST_CASE(AVisitPaysAtTheCloseAndPaysTheProgram, PayoutLuaConnFixture) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/visit.lua";
  uploadScript(path, kEcho);
  const uint64_t instId = launchScript(path);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));
  std::array<uint8_t, 32> pk{};
  BOOST_REQUIRE(server->fileHandler()->readProgramPubkey(path, pk));
  minx::Hash programKey;
  std::copy(pk.begin(), pk.end(), programKey.begin());

  KeyPair visitor;
  const auto visitorKey = visitor.getPublicKeyAsHash();
  const HashPrefix visitorPfx = Account::getMapKey(visitorKey);
  server->_brr(visitorKey, 10'000'000);
  server->_drainLogic();

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, visitor, bindDigest));
  auto r = peer.attach(visitor, bindDigest, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  BOOST_REQUIRE(peerWrite(peer, ces::Bytes(4096, 'x')));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 4096, std::chrono::seconds(10)));

  // The visitor's channel names the program as its payee.
  auto visitorRows = [&] {
    std::vector<ChannelMeter::ChannelSnapshot> out;
    for (auto& row : server->_channelMeter()->snapshot())
      if (row.payerPfx == visitorPfx) out.push_back(row);
    return out;
  };
  auto rows = visitorRows();
  BOOST_REQUIRE_EQUAL(rows.size(), 1u);
  BOOST_CHECK(rows[0].payeePfx == Account::getMapKey(programKey));

  server->_drainLogic();
  const int64_t visitorBefore = server->_balanceOf(visitorKey);
  const int64_t programBefore = server->_balanceOf(programKey);
  peer.closeStream();
  // Between ticks only the close makes the meter forget the channel, and it
  // posts the debit to the logic strand before that.
  BOOST_REQUIRE(waitUntil([&] { return visitorRows().empty(); }));
  server->_drainLogic();
  const int64_t paid = visitorBefore - server->_balanceOf(visitorKey);
  const int64_t payout = server->_balanceOf(programKey) - programBefore;
  BOOST_CHECK_GT(paid, 0);
  BOOST_CHECK_EQUAL(payout * 2, paid);
}

// A direct /ces/luarpc/1 dial into a program bills its caller when it closes,
// from the program's own endpoint meter (whose tick is 60 s away, past the
// wait), and pays the program as an ATTACH does: the caller's bind signed this
// program's key and the challenge of this channel.
BOOST_FIXTURE_TEST_CASE(ADirectDialPaysAtTheCloseAndPaysTheProgram, PayoutLuaConnFixture) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/direct.lua";
  uploadScript(path, kEcho);
  const uint64_t instId = launchScript(path);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));
  const uint16_t childPort = server->computeHandler()->testInstanceRpcPort(instId);
  BOOST_REQUIRE(childPort != 0);
  std::array<uint8_t, 32> pk{};
  BOOST_REQUIRE(server->fileHandler()->readProgramPubkey(path, pk));
  minx::Hash programKey;
  std::copy(pk.begin(), pk.end(), programKey.begin());

  KeyPair caller;
  const auto callerKey = caller.getPublicKeyAsHash();
  server->_brr(callerKey, 10'000'000);
  server->_drainLogic();
  const int64_t callerBefore = server->_balanceOf(callerKey);
  const int64_t programBefore = server->_balanceOf(programKey);

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(childPort, caller, bindDigest, std::chrono::seconds(3), "/ces/luarpc/1"));
  BOOST_REQUIRE(peerWrite(peer, ces::Bytes(4096, 'x')));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 4096, std::chrono::seconds(10)));
  peer.closeStream();
  // The bill and the payout land in one logic task, so once the caller paid,
  // the program's balance is final.
  BOOST_REQUIRE(waitUntil([&] {
    server->_drainLogic();
    return server->_balanceOf(callerKey) < callerBefore;
  }, std::chrono::seconds(30)));
  server->_drainLogic();
  const int64_t paid = callerBefore - server->_balanceOf(callerKey);
  const int64_t payout = server->_balanceOf(programKey) - programBefore;
  BOOST_CHECK_GT(paid, 0);
  BOOST_CHECK_EQUAL(payout * 2, paid);
}

// The endpoint of a program takes only a bind signed for that program's key:
// a bind for the key of another program, with the true challenge, gets a NACK.
BOOST_FIXTURE_TEST_CASE(LuaRpcBindForAnotherProgramIsRejected, PayoutLuaConnFixture) {
  auto launchEcho = [&](const std::string& file, minx::Hash& key) {
    const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/" + file;
    uploadScript(path, kEcho);
    const uint64_t id = launchScript(path);
    BOOST_REQUIRE(waitInstanceListening(*server, id));
    std::array<uint8_t, 32> pk{};
    BOOST_REQUIRE(server->fileHandler()->readProgramPubkey(path, pk));
    std::copy(pk.begin(), pk.end(), key.begin());
    return id;
  };
  minx::Hash keyA{}, keyB{};
  launchEcho("progA.lua", keyA);
  const uint64_t idB = launchEcho("progB.lua", keyB);
  const uint16_t portB = server->computeHandler()->testInstanceRpcPort(idB);
  BOOST_REQUIRE(portB != 0);

  KeyPair caller;
  {
    PlexLuaPeer peer;
    BOOST_REQUIRE(peer.start() != 0);
    BOOST_CHECK(peer.bindFor(portB, caller, "/ces/luarpc/1", keyA) ==
                ces::BindError::Rejected);
  }
  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  BOOST_CHECK(peer.bindFor(portB, caller, "/ces/luarpc/1", keyB) ==
              ces::BindError::None);
}

// A visitor with no credit on the server cannot ATTACH: it could not pay for
// the channel.
BOOST_FIXTURE_TEST_CASE(AVisitorWithNoCreditCannotAttach, LuaConnFixture) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/free.lua";
  uploadScript(path, kEcho);
  const uint64_t instId = launchScript(path);
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  KeyPair nobody;
  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, nobody, bindDigest));
  auto r = peer.attach(nobody, bindDigest, instId);
  CES_CHECK_RC_EQ(r.status, CES_ERROR_INSUFFICIENT_BALANCE);
}

// A program in the server zone (/s/) gets no payout: a visitor's channel into
// it names no payee.
BOOST_FIXTURE_TEST_CASE(AServerZoneProgramGetsNoPayee, PayoutLuaConnFixture) {
  const KeyPair& serverKey = server->_serverKeyPair();
  const std::string path = "/s/visit.lua";
  {
    CesFileClient fc;
    fc.setServerPubkey(serverKey.getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, serverKey));
    uint64_t bal = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, std::strlen(kEcho), 0, 0, bal, cost));
    ces::Bytes content(kEcho, kEcho + std::strlen(kEcho));
    CES_REQUIRE_OK(fc.write(path, 0, content, bal));
    fc.disconnect();
  }
  uint64_t instId = 0;
  {
    CesComputeClient cc;
    cc.setServerPubkey(serverKey.getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, serverKey));
    uint64_t started = 0;
    CES_REQUIRE_OK(cc.launch(path, instId, started));
    cc.disconnect();
  }
  BOOST_REQUIRE(waitInstanceListening(*server, instId));

  KeyPair visitor;
  const HashPrefix visitorPfx = Account::getMapKey(visitor.getPublicKeyAsHash());
  server->_brr(visitor.getPublicKeyAsHash(), 10'000'000);
  server->_drainLogic();
  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::BindDigest bindDigest{};
  BOOST_REQUIRE(peer.bind(rpcPort, visitor, bindDigest));
  auto r = peer.attach(visitor, bindDigest, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  BOOST_REQUIRE(peerWrite(peer, ces::Bytes{'x'}));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 1, std::chrono::seconds(10)));

  bool seen = false;
  for (auto& row : server->_channelMeter()->snapshot()) {
    if (row.payerPfx != visitorPfx) continue;
    seen = true;
    BOOST_CHECK(row.payeePfx == HashPrefix{});
  }
  BOOST_CHECK(seen);
  peer.closeStream();
}

BOOST_AUTO_TEST_SUITE_END()
