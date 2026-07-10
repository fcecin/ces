// test_ext_panel.cpp -- the mene admin-panel lane of the extension contract:
// a /s/ extension registers `panel = mene.app{...}` via ces.extension_admin,
// the host pulls render frames (EXT_REQ_PANEL_RENDER) and dispatches browser
// events (EXT_REQ_PANEL_EVENT) through extensionPanel/extensionPanelEvent.
// Real cesluajitd child; the mene Lua library is host-installed (global
// `mene`), so the inline source below requires nothing.

#include "test_ext_common.h"

#include <ces/extension_manager.h>
#include <ces/l2/compute_handler.h>
#include <ces/webadmin.h>

#include <boost/asio.hpp>
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <string>
#include <thread>

using namespace ces;
using namespace ces::exttest;

namespace {

// A panel-registering extension: counter + form + a deliberately throwing
// handler for the toast path. Also registers a flat status so the legacy lane
// coexists with the panel lane.
const char* kPanelExt = R"LUA(
CES_MANIFEST = { name = "paneltest", version = "1.0",
                 description = "panel wire test" }

local app = mene.app{
  model = { count = 0, ticks = 0, note = "" },
  view = function(m)
    return mene.card({ title = "paneltest" },
      mene.stat({ label = "count", value = m.count }),
      mene.stat({ label = "ticks", value = m.ticks }),
      mene.text(m.note),
      mene.row({},
        mene.button({ on = "inc" }, "+1"),
        mene.button({ on = "boom" }, "Boom")),
      mene.form({ on = "setnote" },
        mene.field({ name = "note" }),
        mene.submit({}, "Set")))
  end,
  update = function(ev, m)
    if ev.on == "inc" then m.count = m.count + 1 end
    if ev.on == "boom" then error("kaboom") end
    if ev.on == "setnote" then m.note = ev.value.note end
    if ev.on == "savecfg" then
      ces.extension_admin.save_config("pace = " .. tostring(ev.value.pace) .. "\n")
      m.note = "cfg-saved"
    end
    return m
  end,
}

ces.extension_admin{
  status = function() return { count = tostring(app.model.count) } end,
  panel = app,
}

-- Spontaneous state: nothing pushes explicitly; the host's change-detect tick
-- must notice the frame changing and push to watchers on its own.
ces.every(300, function()
  app.model.ticks = app.model.ticks + 1
end)

ces.run()
)LUA";

// A no-panel extension: the panel request must fail cleanly (capability
// distinguishable from a panel-side error).
const char* kNoPanelExt = R"LUA(
CES_MANIFEST = { name = "nopanel", version = "1.0", description = "no panel" }
ces.extension_admin{
  status = function() return { ok = "1" } end,
}
ces.run()
)LUA";

// startExtNode deploys from the extensions/ catalog; panel tests deploy inline
// sources instead, so this mirrors it with the source passed directly.
void startPanelNode(ExtNode& n, int idx, const std::string& name,
                    const std::string& source) {
  n.dir = makeUniqueTempDir("extpanel_" + std::to_string(idx));
  minx::Hash priv;
  priv.fill(static_cast<uint8_t>(0x61 + idx));

  CesConfig cfg =
    makeTestConfig(n.dir, priv, std::numeric_limits<uint64_t>::max());
  cfg.rpcPort = 0;
  cfg.rpcAutoPort = true;
  cfg.cesplexMounts = {
    {"/ces/file/1",    "builtin:file"},
    {"/ces/compute/1", "builtin:compute"},
    {"/ces/lua/1",     "builtin:lua"},
  };
  cfg.cesFileStoreDir = (n.dir / "cesfilestore").string();
  cfg.cesFileStoreMaxBytes = 64ull * 1024 * 1024;
  cfg.feeFileRent = 0;
  cfg.feeFileWrite = 0;
  cfg.feeFileRead = 0;
  cfg.feeQuery = 0;
  cfg.feeDiscountEnabled = false;
  cfg.computeMaxInstances = 4;
  cfg.feeComputeSlotSec = 0;
  cfg.computePortBase = 0;
  cfg.computePortCount = 0;
  cfg.cesComputeChildBinary = ces::e2e::findBinary("cesluajitd");
  cfg.cesComputeWorkDir = (n.dir / "cescompute").string();
  cfg.extensions = { name };
  writeFile(fs::path(cfg.cesFileStoreDir) / "s" / (name + ".lua"), source);

  n.server = std::make_unique<CesServer>(cfg);
  n.mainPort = n.server->start(0);
  BOOST_REQUIRE_MESSAGE(n.mainPort > 0, "panel node main bind failed");
  n.rpcPort = n.server->_rpcBoundPort();
  BOOST_REQUIRE_MESSAGE(n.rpcPort > 0, "panel node rpc bind failed");
}

// Poll the panel render until the extension has registered (the request itself
// is the registration barrier: it fails until TAG_EXT_REGISTER lands).
bool waitPanel(CesServer* s, const std::string& name, std::string& frame,
               int tries = 200) {
  for (int i = 0; i < tries; i++) {
    frame.clear();
    if (extensionPanel(s, name, frame)) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  return false;
}

// ---- minimal WebSocket client (RFC 6455) over a blocking boost socket ------

using BoostTcp = boost::asio::ip::tcp;

// Read bytes until `needle` appears; returns everything read.
std::string readUntil(BoostTcp::socket& sock, const std::string& needle) {
  std::string buf;
  char c;
  boost::system::error_code ec;
  while (buf.find(needle) == std::string::npos) {
    size_t n = sock.read_some(boost::asio::buffer(&c, 1), ec);
    if (ec || n == 0) break;
    buf.push_back(c);
  }
  return buf;
}

bool wsClientHandshake(BoostTcp::socket& sock, uint16_t port) {
  std::string req =
    "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(port) + "\r\n"
    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n";
  boost::asio::write(sock, boost::asio::buffer(req));
  std::string resp = readUntil(sock, "\r\n\r\n");
  return resp.find(" 101 ") != std::string::npos &&
         // RFC 6455 sample key -> fixed accept value.
         resp.find("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != std::string::npos;
}

// Client->server frames must be masked.
void wsClientSend(BoostTcp::socket& sock, const std::string& payload) {
  std::string f;
  f.push_back(static_cast<char>(0x81));   // FIN + text
  const uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
  size_t len = payload.size();
  if (len < 126) {
    f.push_back(static_cast<char>(0x80 | len));
  } else {
    f.push_back(static_cast<char>(0x80 | 126));
    f.push_back(static_cast<char>((len >> 8) & 0xFF));
    f.push_back(static_cast<char>(len & 0xFF));
  }
  f.append(reinterpret_cast<const char*>(mask), 4);
  for (size_t i = 0; i < len; i++)
    f.push_back(static_cast<char>(payload[i] ^ mask[i & 3]));
  boost::asio::write(sock, boost::asio::buffer(f));
}

// Read exactly n bytes (blocking).
bool readN(BoostTcp::socket& sock, std::string& out, size_t n) {
  out.resize(n);
  boost::system::error_code ec;
  size_t got = boost::asio::read(sock, boost::asio::buffer(out.data(), n), ec);
  if (ec) {
    BOOST_TEST_MESSAGE("ws read error: " << ec.message() << " got=" << got
                                         << " want=" << n);
  }
  return !ec && got == n;
}

// Read one server frame; returns false on error. TEXT payloads land in `text`
// (empty for control frames, which are skipped by the caller loop).
bool wsClientRead(BoostTcp::socket& sock, std::string& text) {
  text.clear();
  std::string hdr;
  if (!readN(sock, hdr, 2)) return false;
  uint8_t op = hdr[0] & 0x0F;
  uint64_t len = static_cast<uint8_t>(hdr[1]) & 0x7F;
  if (len == 126) {
    std::string ext;
    if (!readN(sock, ext, 2)) return false;
    len = (uint64_t(uint8_t(ext[0])) << 8) | uint8_t(ext[1]);
  } else if (len == 127) {
    std::string ext;
    if (!readN(sock, ext, 8)) return false;
    len = 0;
    for (int i = 0; i < 8; i++) len = (len << 8) | uint8_t(ext[i]);
  }
  std::string payload;
  if (len && !readN(sock, payload, len)) return false;
  if (op == 0x1) text = std::move(payload);
  return true;
}

// Read messages until one contains `needle` (or the deadline passes).
bool wsWaitFor(BoostTcp::socket& sock, const std::string& needle,
               std::string& out, int seconds = 8) {
  // Bound each read via a socket-level receive timeout.
  timeval tv{seconds, 0};
  ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::seconds(seconds);
  while (std::chrono::steady_clock::now() < deadline) {
    std::string text;
    if (!wsClientRead(sock, text)) return false;
    if (!text.empty() && text.find(needle) != std::string::npos) {
      out = std::move(text);
      return true;
    }
  }
  return false;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(ExtPanelTests)

BOOST_AUTO_TEST_CASE(PanelRenderEventAndErrors) {
  ExtNode n;
  startPanelNode(n, 0, "paneltest", kPanelExt);

  // Registration barrier + initial render.
  std::string frame;
  BOOST_REQUIRE_MESSAGE(waitPanel(n.server.get(), "paneltest", frame),
                        "panel never became available");
  BOOST_TEST(frame.find("\"type\":\"render\"") != std::string::npos);
  // Canonical tree JSON: attrs keys sorted, so label precedes value.
  BOOST_TEST(frame.find("\"label\":\"count\",\"value\":0") != std::string::npos);

  // The registration advertises the panel capability.
  bool sawCap = false;
  for (const auto& it : extensionList(n.server.get())) {
    if (it.name == "paneltest") {
      BOOST_TEST(it.isExtension);
      sawCap = (it.caps & kComputeExtCapPanel) != 0;
    }
  }
  BOOST_TEST(sawCap);

  // Button event -> update -> fresh render.
  BOOST_REQUIRE(extensionPanelEvent(n.server.get(), "paneltest",
                                    "{\"on\":\"inc\",\"value\":null}", frame));
  BOOST_TEST(frame.find("\"label\":\"count\",\"value\":1") != std::string::npos);

  // Form event: value map reaches update as a table.
  BOOST_REQUIRE(extensionPanelEvent(
    n.server.get(), "paneltest",
    "{\"on\":\"setnote\",\"value\":{\"note\":\"hello-note\"}}", frame));
  BOOST_TEST(frame.find("hello-note") != std::string::npos);

  // A throwing update becomes a toast FRAME (transport still succeeds)...
  BOOST_REQUIRE(extensionPanelEvent(n.server.get(), "paneltest",
                                    "{\"on\":\"boom\",\"value\":null}", frame));
  BOOST_TEST(frame.find("\"type\":\"toast\"") != std::string::npos);
  BOOST_TEST(frame.find("kaboom") != std::string::npos);

  // ...and the panel survives it: model intact, renders again.
  BOOST_REQUIRE(extensionPanel(n.server.get(), "paneltest", frame));
  BOOST_TEST(frame.find("\"type\":\"render\"") != std::string::npos);
  BOOST_TEST(frame.find("\"label\":\"count\",\"value\":1") != std::string::npos);

  // Malformed event JSON -> toast, not a crash.
  BOOST_REQUIRE(extensionPanelEvent(n.server.get(), "paneltest",
                                    "{ this is not json", frame));
  BOOST_TEST(frame.find("\"type\":\"toast\"") != std::string::npos);

  // ces.extension_admin.save_config persists the extension's own
  // /s/<name>.conf on the host (the panel config-form path).
  BOOST_REQUIRE(extensionPanelEvent(
    n.server.get(), "paneltest",
    "{\"on\":\"savecfg\",\"value\":{\"pace\":\"777\"}}", frame));
  BOOST_TEST(frame.find("cfg-saved") != std::string::npos);
  std::string conf;
  for (int i = 0; i < 50 && conf.find("pace = 777") == std::string::npos; i++) {
    conf = extensionConfigGet(n.server.get(), "paneltest");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_TEST(conf.find("pace = 777") != std::string::npos);

  stopExt(n);
}

BOOST_AUTO_TEST_CASE(WebSocketPanelPush) {
  ExtNode n;
  startPanelNode(n, 2, "paneltest", kPanelExt);

  // Dashboard on its own io thread (the production shape).
  boost::asio::io_context webIO;
  auto guard = boost::asio::make_work_guard(webIO);
  ces::WebAdmin web(webIO, *n.server);
  BOOST_REQUIRE(web.listen("127.0.0.1", 0));
  std::thread webThread([&] { webIO.run(); });
  uint16_t port = web.boundPort();

  // Registration barrier.
  std::string frame;
  BOOST_REQUIRE_MESSAGE(waitPanel(n.server.get(), "paneltest", frame),
                        "panel never became available");

  // Upgrade.
  boost::asio::io_context io;
  BoostTcp::socket sock(io);
  sock.connect({boost::asio::ip::make_address("127.0.0.1"), port});
  BOOST_REQUIRE_MESSAGE(wsClientHandshake(sock, port),
                        "websocket handshake failed");

  // hello -> an immediate panel frame for the subscribed extension.
  wsClientSend(sock, "{\"type\":\"hello\",\"ext\":\"paneltest\"}");
  std::string msg;
  BOOST_REQUIRE(wsWaitFor(sock, "\"type\":\"panel\"", msg));
  BOOST_TEST(msg.find("\"ext\":\"paneltest\"") != std::string::npos);
  BOOST_TEST(msg.find("\"label\":\"count\",\"value\":0") != std::string::npos);

  // Spontaneous push: the extension's ces.every mutates `ticks`; the child's
  // change-detect tick must push a fresh frame with NO request from us. The
  // very first push may be byte-identical to the hello pull (watch-on resets
  // the change hash to guarantee freshness), so wait for one that differs.
  std::string spontaneous;
  bool changed = false;
  for (int i = 0; i < 6 && !changed; i++) {
    spontaneous.clear();
    if (!wsWaitFor(sock, "\"label\":\"ticks\",\"value\":", spontaneous)) break;
    changed = (spontaneous != msg);
  }
  BOOST_REQUIRE_MESSAGE(changed, "no spontaneous change-detect push arrived");

  // Event over the socket -> pushed render with the new model.
  wsClientSend(sock,
    "{\"type\":\"event\",\"ext\":\"paneltest\","
    "\"event\":{\"on\":\"inc\",\"value\":null}}");
  std::string after;
  BOOST_REQUIRE(wsWaitFor(sock, "\"label\":\"count\",\"value\":1", after));

  // The 2s status heartbeat rides the same socket.
  std::string status;
  BOOST_REQUIRE(wsWaitFor(sock, "\"type\":\"status\"", status));

  boost::system::error_code ic;
  sock.close(ic);
  web.stop();
  guard.reset();
  webIO.stop();
  webThread.join();
  stopExt(n);
}

BOOST_AUTO_TEST_CASE(NoPanelIsCleanlyUnavailable) {
  ExtNode n;
  startPanelNode(n, 1, "nopanel", kNoPanelExt);

  // Wait for registration via the status lane...
  std::vector<std::pair<std::string, std::string>> kv;
  bool up = false;
  for (int i = 0; i < 200 && !up; i++) {
    kv.clear();
    up = extensionStatus(n.server.get(), "nopanel", kv);
    if (!up) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_REQUIRE_MESSAGE(up, "extension never registered");

  // ...then the panel lane reports unavailable (no toast, no frame).
  std::string frame;
  BOOST_TEST(!extensionPanel(n.server.get(), "nopanel", frame));
  BOOST_TEST(!extensionPanelEvent(n.server.get(), "nopanel",
                                  "{\"on\":\"x\",\"value\":null}", frame));

  stopExt(n);
}

// Every SHIPPED extension registers a working panel: deploy each bundle from
// extensions/<name>.lua exactly as an operator would and require a render
// frame. Catches integration breakage the synthetic-source tests cannot (real
// bundles, real registration path, real view code).
BOOST_AUTO_TEST_CASE(ShippedExtensionPanelsRender) {
  const char* names[] = {"dice", "discovery", "hylesolo",
                         "peerfunder", "peerclusterer", "coalition"};
  int idx = 10;
  for (const char* name : names) {
    ExtNode n;
    startPanelNode(n, idx++, name, readExtSource(name));
    std::string frame;
    BOOST_REQUIRE_MESSAGE(waitPanel(n.server.get(), name, frame),
                          std::string(name) + ": panel never became available");
    BOOST_TEST_MESSAGE(std::string(name) + " frame: " + frame.substr(0, 120));
    BOOST_TEST(frame.find("\"type\":\"render\"") != std::string::npos);
  }
}

BOOST_AUTO_TEST_SUITE_END()
