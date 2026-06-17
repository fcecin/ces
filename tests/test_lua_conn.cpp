// ===========================================================================
// builtin:lua — /ces/lua/1 user RUDP connection routing.
// ===========================================================================
//
// The in-process bind/attach/byte-pipe harness lives in
// test_lua_conn_common.h (shared with test_dice_lua.cpp). This file is just
// the routing test suite that rides it.

#define BOOST_TEST_DYN_LINK
#include "test_lua_conn_common.h"

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
  // Let the child reach ces.client_recv (ensures it's running, not
  // that the gate would change — gate stays OFF either way).
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));

  auto r = peer.attach(userKey, sessionToken, instId);
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
  // Give the child time to install set_listener (which sends the
  // TAG_LISTEN_ON IPC frame the supervisor needs to flip
  // acceptsConnections=true).
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));

  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  BOOST_CHECK(r.connId > 0);

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
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
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
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  // One inbound byte triggers ten outbound writes.
  BOOST_REQUIRE(peerWrite(peer, ces::Bytes{'x'}));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 30, std::chrono::seconds(5)));
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
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  BOOST_REQUIRE(peerWrite(peer, ces::Bytes{'x'}));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 3, std::chrono::seconds(5)));
  BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "bye");

  // Subsequent reads must fail — the channel is gone.
  ces::Bytes after;
  BOOST_CHECK(!peerReadExact(peer, after, 1, std::chrono::seconds(2)));
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
  std::this_thread::sleep_for(std::chrono::milliseconds(400));

  {
    PlexLuaPeer peer;
    BOOST_REQUIRE(peer.start() != 0);
    uint64_t sessionToken = 0;
    BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
    auto r = peer.attach(userKey, sessionToken, instId);
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
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
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
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer p1, p2;
  BOOST_REQUIRE(p1.start() != 0);
  BOOST_REQUIRE(p2.start() != 0);
  uint64_t st1 = 0, st2 = 0;
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
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  KeyPair u2;
  server->_brr(u2.getPublicKeyAsHash(), 10'000'000'000);

  PlexLuaPeer p1, p2;
  BOOST_REQUIRE(p1.start() != 0);
  BOOST_REQUIRE(p2.start() != 0);
  uint64_t st1 = 0, st2 = 0;
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

// ATTACH for an instance_id that isn't registered →
// CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND. Covers both "id was never
// minted" and id=0 (gNextInstanceId starts at 1).
BOOST_AUTO_TEST_CASE(AttachUnknownInstance) {
  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, /*bogus*/ 99999ULL);
  CES_CHECK_RC_EQ(r.status, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND);
}

// Bad sig on ATTACH → handler silently tears down the channel without
// replying. The user side observes timeout (no reply byte), confirming
// the verifyPerOp path on the server actually rejects forged sigs and
// drops the channel instead of admitting it.
BOOST_AUTO_TEST_CASE(AttachBadSigDropsChannel) {
  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));

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
    sessionToken);

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
  std::this_thread::sleep_for(std::chrono::milliseconds(400));

  // First peer attaches successfully.
  PlexLuaPeer p1;
  BOOST_REQUIRE(p1.start() != 0);
  uint64_t st1 = 0;
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
  uint64_t st2 = 0;
  BOOST_REQUIRE(p2.bind(rpcPort, userKey, st2));
  auto r2 = p2.attach(userKey, st2, instId);
  CES_CHECK_RC_EQ(r2.status, CES_ERROR_NOT_LISTENING);

  // Existing conn is alive but silent — write succeeds, but no
  // callback fires (listener registry slot is nil), so no echo.
  BOOST_REQUIRE(peerWrite(p1, {'!', '!'}));
  ces::Bytes g3;
  BOOST_CHECK(!peerReadExact(p1, g3, 2, std::chrono::seconds(1)));
}

BOOST_AUTO_TEST_SUITE_END()
