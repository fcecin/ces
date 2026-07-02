// ---------------------------------------------------------------------------
// ces.* bindings
// ---------------------------------------------------------------------------

// Per-instance source program prefix, supplied by bootstrap env.
// Sent as part of outbound CES_APP_COMPUTE_MSG so the remote CES
// client can demux by prog_pfx.
uint8_t g_prog_prefix[8] = {0,0,0,0,0,0,0,0};
// Per-instance owner pubkey, supplied by bootstrap. Surfaced via
// ces.owner_pubkey() — programs use it (e.g. to know the house
// pubkey for /s/ programs running under the server's identity).
uint8_t g_owner_pubkey[32] = {0};
// Per-instance program-account pubkey, supplied by bootstrap. Surfaced
// via ces.program_pubkey() — the account ces.transfer spends from, which
// programs advertise as their receive address so deposits and payouts
// share one pool.
uint8_t g_program_pubkey[32] = {0};
uint8_t g_program_privkey[32] = {0};
// Per-instance birth wall-clock microseconds, supplied by bootstrap.
// Surfaced via ces.start_time(). Programs use it as a replay-
// protection anchor: any payment with lastXferTime ≤ start_time/1e6
// cannot have been a fresh deposit aimed at THIS instance.
uint64_t g_start_time_us = 0;
// UDP port the server statically assigned this instance for its
// outbound CES client, supplied by bootstrap. The client binds it so
// every outbound op leaves from a known, firewall-configured source
// port. 0 = no compute port range configured → this instance has no
// network: the outbound remote_* verbs fail with "networking disabled"
// rather than binding an unreachable ephemeral port.
uint16_t g_program_port = 0;
// The static UDP port reserved for this instance's inbound CesPlex host
// (/ces/luarpc/1). 0 = none → the instance hosts nothing.
uint16_t g_rpc_port = 0;
// Whether this instance runs privileged, decided once by the server (source in
// the /s/ zone) and delivered in the bootstrap. The host trusts this verdict;
// it never re-derives privilege. Gates operator-only API such as ces.log.
bool g_privileged = false;

// ---------------------------------------------------------------------------
// /ces/luarpc/1 — the protocol this lua host SERVES (and, later, dials) on
// its rpc port. A raw, opaque byte pipe: whatever bytes arrive are handed to
// the program; whatever bytes the program writes are sent. No host framing,
// batching, or buffering — any grammar lives in Lua.
//
// The endpoint runs on its own single strand; the Lua VM runs on main. The
// bridge below crosses that boundary: inbound (endpoint → Lua) via a
// mutex+condvar event queue drained by ces.conn.run(); outbound (Lua →
// endpoint) via asio::post onto the endpoint strand, where the per-conn
// RudpStreams live. Blocking here is fine — the compute child is sandboxed
// and metered, so a stalled strand has no global consequence.
//
// All per-conn stream state (g_luarpc_conns, g_luarpc_next_id) is touched
// ONLY on the endpoint strand: the handler runs there, and the Lua-side
// write/close hop there via post. So no lock guards them. Only the inbound
// event queue is cross-thread (mutex+condvar); the accept gate is atomic.
// ---------------------------------------------------------------------------
namespace {

struct LuaRpcEvent {
  enum class Type { Opened, Data, Closed } type;
  uint64_t connId = 0;
  std::array<uint8_t, 32> peer{};   // Opened
  std::string bytes;                // Data
};

std::mutex               g_luarpc_mx;
std::deque<LuaRpcEvent>  g_luarpc_inq;     // endpoint pushes, run() drains
int                      g_luarpc_wakefd = -1;  // eventfd; nudges run()'s poll

// Per-conn serialized handler dispatch for direct (/ces/luarpc/1) conns -- the
// direct-transport twin of g_conn_exec/g_conn_advance (see their comment). Kept
// separate because the direct id space (g_luarpc_next_id) is independent of the
// relay's.
struct LuaRpcExec { std::deque<LuaRpcEvent> pending; bool busy = false; };
std::map<uint64_t, LuaRpcExec> g_luarpc_exec;     // direct conn id -> serialized state
std::deque<uint64_t>           g_luarpc_advance;  // direct conns with an event ready

// Accept gate: set by ces.conn.set_listener (Lua), read by serve()
// (endpoint). No listener → close-on-connect.
std::atomic<bool> g_luarpc_listening{false};

// The endpoint's task strand, armed in main once the endpoint is up. Null
// until then (and forever if this instance got no rpc port).
boost::asio::io_context* g_luarpc_io = nullptr;

struct LuaRpcConn {
  std::shared_ptr<minx::RudpStream> stream;
  std::deque<std::string> writeQ;   // RudpStream forbids overlapping writes,
  bool writing = false;             //   so we serialize: one in flight.
  bool closing = false;
  std::array<uint8_t, 4096> readBuf{};
};
std::map<uint64_t, std::shared_ptr<LuaRpcConn>> g_luarpc_conns;  // strand-only
uint64_t g_luarpc_next_id = 1;                                   // strand-only

// Per-channel resource usage the endpoint's ChannelMeter reports (endpoint
// strand); the run() loop drains it into a one-way TAG_NET_USAGE frame to the
// parent (IPC thread; only it may touch g_sock_fd). Each report carries the
// channel's bound payer prefix. Inbound channels carry the remote caller's
// prefix; outbound channels are tracked under this instance's OWN program prefix
// (see luarpc_do_connect). The parent prices the usage and routes the bill by
// payer: own prefix -> source file_balance, anyone else -> that caller.
struct NetUsageRecord {
  ces::HashPrefix   payer{};
  ces::CesPlexUsage usage{};
};
std::mutex                  g_net_usage_mx;
std::deque<NetUsageRecord>  g_net_usage_q;

void luarpc_push(LuaRpcEvent e) {
  {
    std::lock_guard<std::mutex> lk(g_luarpc_mx);
    g_luarpc_inq.push_back(std::move(e));
  }
  // Nudge the unified run() poll on the Lua thread. The endpoint threads
  // can't call into the single-threaded Lua VM, so they queue + wake; run()
  // re-enters Lua to dispatch.
  if (g_luarpc_wakefd >= 0) {
    uint64_t one = 1;
    ssize_t w = ::write(g_luarpc_wakefd, &one, sizeof(one));
    (void)w;
  }
}

// Endpoint strand: drain a conn's writeQ, one async_write at a time.
void luarpc_drain_writes(uint64_t id, std::shared_ptr<LuaRpcConn> c) {
  if (c->writing || c->closing || c->writeQ.empty()) return;
  c->writing = true;
  auto buf = std::make_shared<std::string>(std::move(c->writeQ.front()));
  c->writeQ.pop_front();
  boost::asio::async_write(*c->stream, boost::asio::buffer(*buf),
    [id, c, buf](const boost::system::error_code& ec, std::size_t) {
      c->writing = false;
      if (ec) {
        if (!c->closing) luarpc_push({LuaRpcEvent::Type::Closed, id, {}, {}});
        g_luarpc_conns.erase(id);
        return;
      }
      luarpc_drain_writes(id, c);
    });
}

// Endpoint strand: read whatever arrives → push Data → repeat. A read error
// (peer close / reset) → push Closed + drop the conn.
void luarpc_start_read(uint64_t id, std::shared_ptr<LuaRpcConn> c) {
  c->stream->async_read_some(
    boost::asio::buffer(c->readBuf.data(), c->readBuf.size()),
    [id, c](const boost::system::error_code& ec, std::size_t n) {
      if (ec) {
        if (!c->closing) luarpc_push({LuaRpcEvent::Type::Closed, id, {}, {}});
        g_luarpc_conns.erase(id);
        return;
      }
      LuaRpcEvent e{LuaRpcEvent::Type::Data, id, {}, {}};
      e.bytes.assign(reinterpret_cast<const char*>(c->readBuf.data()), n);
      luarpc_push(std::move(e));
      luarpc_start_read(id, c);
    });
}

// Called from Lua → hop to the endpoint strand to enqueue + send.
void luarpc_conn_write(uint64_t id, std::string bytes) {
  if (!g_luarpc_io) return;
  boost::asio::post(*g_luarpc_io,
    [id, bytes = std::move(bytes)]() mutable {
      auto it = g_luarpc_conns.find(id);
      if (it == g_luarpc_conns.end() || it->second->closing) return;
      it->second->writeQ.push_back(std::move(bytes));
      luarpc_drain_writes(id, it->second);
    });
}

// Called from Lua → hop to the strand to gracefully close.
void luarpc_conn_close(uint64_t id) {
  if (!g_luarpc_io) return;
  boost::asio::post(*g_luarpc_io, [id]() {
    auto it = g_luarpc_conns.find(id);
    if (it == g_luarpc_conns.end()) return;
    it->second->closing = true;
    it->second->stream->shutdown(ces::kRudpStreamCloseTimeout);
    // The read completion (error after shutdown) erases the conn.
  });
}

// Outbound dialing rides the SAME endpoint Rudp/socket as serving (the user's
// "religiously the same socket"). Armed in main alongside g_luarpc_io.
minx::Rudp*                   g_luarpc_rudp = nullptr;
ces::ChannelMeter*            g_luarpc_meter = nullptr;  // = endpoint->meter()
std::shared_ptr<ces::KeyPair> g_luarpc_signer;   // the program's keypair

struct LuaRpcConnectResult {
  uint8_t status = ces::CES_ERROR_INTERNAL;
  uint64_t connId = 0;
  std::array<uint8_t, 32> peer{};
};

// A finished ces.conn.connect awaiting its coroutine's resume. The endpoint
// thread pushes (under g_luarpc_mx) + nudges g_luarpc_wakefd; the run loop
// drains, builds the conn on the coroutine, and resumes it. The blocking
// (main-chunk) connect path keeps its own promise instead.
struct ConnectDelivery { lua_State* co; LuaRpcConnectResult res; };
std::deque<ConnectDelivery> g_connect_done;

// Endpoint strand: open an OUTBOUND /ces/luarpc/1 channel to `peer`, drive the
// client bind (signed by the program key), verify the reply AND that the
// server pubkey matches `expectPk` (the program knows who it dialed), and on
// success register the bound stream as a raw conn + start pumping. Reports via
// `pr`. Mirrors CesPlexClient::doSelect, but on the endpoint's own Rudp.
void luarpc_do_connect(minx::SockAddr peer, std::array<uint8_t, 32> expectPk,
                       std::function<void(LuaRpcConnectResult)> done,
                       int timeoutMs) {
  if (!g_luarpc_rudp || !g_luarpc_signer || !g_luarpc_io) {
    done({ces::CES_ERROR_INTERNAL, 0, {}});
    return;
  }
  // Seed Rudp's clock so the fresh channel isn't idle-GC'd on the next tick.
  g_luarpc_rudp->tick(ces::getMicrosSinceEpoch());
  std::random_device rd;
  uint32_t channel = static_cast<uint32_t>(rd());
  auto stream = std::make_shared<minx::RudpStream>(g_luarpc_io->get_executor());
  if (!g_luarpc_rudp->registerChannel(peer, channel, stream)) {
    done({ces::CES_ERROR_INTERNAL, 0, {}});
    return;
  }

  // Bind-handshake timeout, bounded AT THE SOURCE: if no reply within
  // timeoutMs, close the half-open stream so the pending read fails with ec ->
  // done(error), the clean "connect failed" path. Cancelled the instant the
  // bind resolves (so it never closes a now-live conn). Beats waiting on RUDP
  // idle-GC (~60s), and there is no racing coroutine-side timer to leave an
  // orphaned conn behind: a timeout fails before the conn is ever registered.
  auto timer = std::make_shared<boost::asio::steady_timer>(*g_luarpc_io);
  if (timeoutMs > 0) {
    timer->expires_after(std::chrono::milliseconds(timeoutMs));
    timer->async_wait([stream](const boost::system::error_code& tec) {
      if (tec) return;   // cancelled: the bind already resolved
      try { stream->close(); } catch (...) {}
    });
  }

  static const std::string kProto = "/ces/luarpc/1";
  const uint64_t bindNowUs = ces::getMicrosSinceEpoch();
  auto bindReq = std::make_shared<minx::Bytes>(
    ces::buildBindRequest(kProto, bindNowUs, *g_luarpc_signer));
  const auto& pkArr = g_luarpc_signer->getPublicKeyAsHash();
  auto clientDigest =
    std::make_shared<std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>>(
      ces::computeBindRequestDigest(
        std::span<const uint8_t>(
          reinterpret_cast<const uint8_t*>(kProto.data()), kProto.size()),
        bindNowUs,
        std::span<const uint8_t>(pkArr.data(), pkArr.size())));

  boost::asio::async_write(*stream, boost::asio::buffer(*bindReq),
    [stream, bindReq, clientDigest, done, expectPk, peer, channel, timer]
    (const boost::system::error_code& ec, std::size_t) {
      if (ec) { timer->cancel(); done({ces::CES_ERROR_INTERNAL, 0, {}}); return; }
      auto reply = std::make_shared<
        std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
      boost::asio::async_read(*stream, boost::asio::buffer(*reply),
        [stream, reply, clientDigest, done, expectPk, peer, channel, timer]
        (const boost::system::error_code& ec2, std::size_t) {
          timer->cancel();   // bind resolved (ok or fail): disarm the timeout
          if (ec2) { done({ces::CES_ERROR_INTERNAL, 0, {}}); return; }
          ces::ParsedBindReply r = ces::parseBindReply(
            std::span<const uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
              reply->data(), reply->size()));
          const bool ok =
            r.status == ces::CES_PLEX_OK &&
            ces::verifyBindReply(r, std::span<const uint8_t>(
              clientDigest->data(), clientDigest->size())) &&
            std::memcmp(r.serverPubkey.data(), expectPk.data(), 32) == 0;
          if (!ok) {
            done({ces::CES_ERROR_PROTO_REJECTED, 0, {}});
            return;
          }
          uint64_t id = g_luarpc_next_id++;
          auto c = std::make_shared<LuaRpcConn>();
          c->stream = stream;
          g_luarpc_conns[id] = c;
          // Meter this OUTBOUND channel so the instance pays its own server
          // (file_balance) for dialing out. Track it under this instance's own
          // program prefix: the parent recognizes that as "the instance itself"
          // and routes the bill to file_balance (vs an inbound caller's prefix).
          if (g_luarpc_meter) {
            ces::HashPrefix self{};
            std::memcpy(self.data(), g_program_pubkey, self.size());
            g_luarpc_meter->track(peer, channel, "luarpc:out", self);
          }
          LuaRpcConnectResult res{ces::CES_OK, id, {}};
          std::memcpy(res.peer.data(), r.serverPubkey.data(), 32);
          luarpc_start_read(id, c);
          done(res);
        });
    });
}

// One serve() per inbound /ces/luarpc/1 channel, on the endpoint strand. No
// Lua listener → close-on-connect (drop the stream). Else register the conn,
// announce it (on_open), and start pumping bytes.
class LuaRpcHandler : public ces::CesPlexHandler {
public:
  void serve(std::shared_ptr<minx::RudpStream> stream,
             ces::BoundChannelContext bound) override {
    if (!g_luarpc_listening.load(std::memory_order_relaxed)) {
      (void)stream;   // dropped on return → channel closes
      return;
    }
    uint64_t id = g_luarpc_next_id++;
    auto c = std::make_shared<LuaRpcConn>();
    c->stream = std::move(stream);
    LuaRpcEvent opened{LuaRpcEvent::Type::Opened, id, {}, {}};
    const ces::Hash& pk = bound.boundPubkey.getHash();
    std::memcpy(opened.peer.data(), pk.data(), opened.peer.size());
    g_luarpc_conns[id] = c;
    luarpc_push(std::move(opened));
    luarpc_start_read(id, c);
  }
};
LuaRpcHandler g_luaRpcHandler;

// CesPlexHost for this lua host's rpc endpoint: signs bind replies + per-op
// responses with the program's own keypair. Usage is reported up to the parent
// server, which prices it and bills the caller (inbound) or this instance's
// file_balance (outbound).
class LuaHostPlexHost : public ces::CesPlexHost {
public:
  explicit LuaHostPlexHost(const ces::KeyPair& key) : key_(key) {}
  const ces::KeyPair& cesplexSigningKey() const override { return key_; }
  void cesplexReportUsage(const ces::HashPrefix& payer,
                          const minx::SockAddr& /*peer*/,
                          uint32_t /*channelId*/,
                          const ces::CesPlexUsage& usage) override {
    // Endpoint strand: must NOT touch g_sock_fd. Queue the (payer, usage) and
    // nudge; run() emits the TAG_NET_USAGE frame on the IPC thread. The parent
    // decides who pays from the payer prefix.
    {
      std::lock_guard<std::mutex> lk(g_net_usage_mx);
      g_net_usage_q.push_back(NetUsageRecord{payer, usage});
    }
    if (g_luarpc_wakefd >= 0) {
      uint64_t one = 1;
      ssize_t w = ::write(g_luarpc_wakefd, &one, sizeof(one));
      (void)w;
    }
  }
private:
  ces::KeyPair key_;
};

// The endpoint is opened LAZILY — the first time the program touches luarpc
// (set_listener or connect). A program that never speaks luarpc opens no
// socket and spawns no endpoint threads. Once up, it stays for the instance's
// life. No-op if already up or if this instance got no rpc port.
std::unique_ptr<LuaHostPlexHost>      g_luarpc_host;
std::unique_ptr<ces::CesPlexEndpoint> g_luarpc_endpoint;

void luarpc_ensure_endpoint() {
  if (g_luarpc_endpoint || g_rpc_port == 0) return;
  try {
    ces::Hash priv{};
    std::memcpy(priv.data(), g_program_privkey, 32);
    g_luarpc_signer =
        std::make_shared<ces::KeyPair>(priv, ces::KeyAlgo::ED25519);
    g_luarpc_host = std::make_unique<LuaHostPlexHost>(*g_luarpc_signer);

    // The eventfd the endpoint threads nudge so the unified run() poll wakes.
    // Created before the endpoint so it exists before any thread can push.
    if (g_luarpc_wakefd < 0)
      g_luarpc_wakefd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

    minx::MinxConfig minxCfg{};
    minxCfg.instanceName = "luarpc";
    minxCfg.randomXVMsToKeep = 0;
    minxCfg.randomXInitThreads = 0;
    // No PoW engine + spam disabled → dialable without tickets, mirroring the
    // server's own rpc port. (Anti-spam posture for a public luarpc port is a
    // deliberate decision still owed — see the compute closure design doc.)
    minxCfg.spamThreshold = std::numeric_limits<uint16_t>::max();
    minxCfg.spamSampleRate = 512;
    minxCfg.trustLoopback = true;

    minx::RudpConfig rudpCfg{};
    rudpCfg.baseTickInterval = std::chrono::milliseconds(1);
    // The endpoint is a full server+client: it serves /ces/luarpc/1 AND dials
    // out (luarpc + file + compute), so one program may hold several channels
    // to the SAME peer at once (e.g. a file client then a compute client to
    // one server). The Rudp default of 1 channel/peer is far too low; match
    // CesPlexClient's headroom.
    rudpCfg.maxChannelsPerPeer = 8;

    g_luarpc_endpoint = std::make_unique<ces::CesPlexEndpoint>(
        g_rpc_port, g_luarpc_host.get(),
        std::map<std::string, ces::CesPlexHandler*>{
            {"/ces/luarpc/1", &g_luaRpcHandler}},
        std::move(minxCfg), std::move(rudpCfg));
    g_luarpc_io = &g_luarpc_endpoint->io();
    g_luarpc_rudp = g_luarpc_endpoint->rudp();
    g_luarpc_meter = g_luarpc_endpoint->meter();
  } catch (const std::exception& e) {
    host_log(3, std::string("rpc endpoint setup failed: ") + e.what());
    g_luarpc_endpoint.reset();
    g_luarpc_host.reset();
    g_luarpc_signer.reset();
  }
}
}  // namespace
uint16_t g_next_corr_id = 1;

int lua_ces_now(lua_State* L) {
  auto us = std::chrono::duration_cast<std::chrono::microseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
  lua_pushnumber(L, static_cast<lua_Number>(us));
  return 1;
}

int lua_ces_sha256(lua_State* L) {
  size_t n = 0;
  const char* s = luaL_checklstring(L, 1, &n);
  Sha256Ctx c{};
  sha256_init(c);
  sha256_update(c, reinterpret_cast<const uint8_t*>(s), n);
  uint8_t digest[32];
  sha256_final(c, digest);
  lua_pushlstring(L, reinterpret_cast<const char*>(digest), 32);
  return 1;
}

// ces.log([level,] msg) - operator instrumentation, registered ONLY for
// privileged (/s/) programs (see install_ces_api). The application picks the
// level ("trace"|"debug"|"info"|"warn"|"error", default "info"); the operator
// picks what's visible via blog's "compute" module level. Fire-and-forget over
// a one-way IPC frame; the host (builtin:compute) logs it through blog under
// "compute", tagged with the instance + program prefix (added host-side, not
// trusted from here). Never reaches user programs. Capped so a program can't
// emit huge log lines.
// Level byte: 0=trace 1=debug 2=info 3=warn 4=error (mirrors the compute side).
static uint8_t log_level_from_name(lua_State* L, const char* name) {
  if (std::strcmp(name, "trace") == 0) return 0;
  if (std::strcmp(name, "debug") == 0) return 1;
  if (std::strcmp(name, "info")  == 0) return 2;
  if (std::strcmp(name, "warn")  == 0 || std::strcmp(name, "warning") == 0) return 3;
  if (std::strcmp(name, "error") == 0) return 4;
  return static_cast<uint8_t>(luaL_error(L, "ces.log: invalid level '%s'", name));
}

int lua_ces_log(lua_State* L) {
  if (!g_privileged) return 0;  // no-op for non-/s/ instances (also gated server-side)
  uint8_t level = 2;  // info
  size_t n = 0;
  const char* s;
  if (lua_gettop(L) >= 2) {
    level = log_level_from_name(L, luaL_checkstring(L, 1));
    s = luaL_checklstring(L, 2, &n);
  } else {
    s = luaL_checklstring(L, 1, &n);
  }
  if (n > 4096) n = 4096;
  std::vector<uint8_t> body;
  body.reserve(1 + n);
  body.push_back(level);
  body.insert(body.end(), s, s + n);
  write_frame(TAG_LOG, 0, body.data(), body.size());
  return 0;
}

// ces.sign(bytes) -> sig(65 bytes). Signs with this instance's program key.
// The private key never enters the sandbox: signing happens here in the host
// and only the signature comes back. Decorator byte + 64-byte signature.
int lua_ces_sign(lua_State* L) {
  size_t n = 0;
  const char* s = luaL_checklstring(L, 1, &n);
  ces::Hash priv{};
  std::memcpy(priv.data(), g_program_privkey, 32);
  ces::KeyPair kp(priv, ces::KeyAlgo::ED25519);
  ces::Signature sig = kp.signData(s, n);
  lua_pushlstring(L, reinterpret_cast<const char*>(sig.data()), sig.size());
  return 1;
}

// ces.verify(pubkey(32), bytes, sig(65)) -> bool. Verifies any party's
// signature over bytes; the signature's decorator byte selects the algorithm.
int lua_ces_verify(lua_State* L) {
  size_t pkn = 0, dn = 0, sn = 0;
  const char* pk = luaL_checklstring(L, 1, &pkn);
  const char* data = luaL_checklstring(L, 2, &dn);
  const char* sigs = luaL_checklstring(L, 3, &sn);
  if (pkn != 32 || sn != ces::SIG_SIZE) {
    lua_pushboolean(L, 0);
    return 1;
  }
  ces::Hash pkh{};
  std::memcpy(pkh.data(), pk, 32);
  ces::PublicKey pub(pkh);
  ces::Signature sig{};
  std::memcpy(sig.data(), sigs, ces::SIG_SIZE);
  bool ok = false;
  try {
    ok = pub.verifySignature(data, dn, sig);
  } catch (...) {
    // A malformed pubkey or signature must verify as false, never throw
    // through LuaJIT.
    ok = false;
  }
  lua_pushboolean(L, ok ? 1 : 0);
  return 1;
}

// The reserved domain tag for ces.serverSign / ces.serverVerify. MUST match
// CesServer::serverSign in src/ceslib/server.cpp byte-for-byte: the signer (CES core)
// and the verifier (here) live in different processes, so the tag is duplicated and
// the two must agree. Signing hashes SHA256(tag || bytes); verify mirrors it.
constexpr char kExtAttestTag[] = "CES_EXT_ATTEST_V1";

// ces.serverVerify(server_pubkey(32), bytes, sig(65)) -> bool. Verifies a server-key
// attestation produced by ces.serverSign on some server. Pure local crypto (no host
// round-trip): apply the same domain tag, hash, and verify against the claimed server
// pubkey. The 32-byte digest is passed to verifySignature directly (it treats a
// 32-byte input as the message digest), matching the host's tagged-digest signing.
int lua_ces_server_verify(lua_State* L) {
  size_t pkn = 0, dn = 0, sn = 0;
  const char* pk = luaL_checklstring(L, 1, &pkn);
  const char* data = luaL_checklstring(L, 2, &dn);
  const char* sigs = luaL_checklstring(L, 3, &sn);
  if (pkn != 32 || sn != ces::SIG_SIZE) {
    lua_pushboolean(L, 0);
    return 1;
  }
  Sha256Ctx c;
  sha256_init(c);
  sha256_update(c, reinterpret_cast<const uint8_t*>(kExtAttestTag),
                sizeof(kExtAttestTag) - 1);
  sha256_update(c, reinterpret_cast<const uint8_t*>(data), dn);
  uint8_t digest[32];
  sha256_final(c, digest);
  ces::Hash pkh{};
  std::memcpy(pkh.data(), pk, 32);
  ces::PublicKey pub(pkh);
  ces::Signature sig{};
  std::memcpy(sig.data(), sigs, ces::SIG_SIZE);
  bool ok = false;
  try {
    ok = pub.verifySignature(reinterpret_cast<const char*>(digest), 32, sig);
  } catch (...) {
    ok = false;
  }
  lua_pushboolean(L, ok ? 1 : 0);
  return 1;
}

// ces.client_recv([nowait]) → (sender_pfx:string(8), payload:string) | nil
//
// Default: BLOCKING. Drains the socket first (so any currently-
// queued deliver frames come out), then if the inbox is still
// empty blocks on read() until either a deliver frame arrives
// or the host closes the pipe (which means the supervisor is
// about to SIGKILL us; we return nil and the top-level loop
// exits).
//
// Pass any truthy arg (e.g. `true`) to request non-blocking mode:
// returns nil immediately if no message is queued.
int lua_ces_client_recv(lua_State* L) {
  bool nowait = lua_toboolean(L, 1);
  auto pop_if_available = [L]() -> int {
    if (g_inbox.empty()) return 0;
    Frame f = std::move(g_inbox.front());
    g_inbox.pop_front();
    if (f.body.size() < 8) return 0;
    lua_pushlstring(L, reinterpret_cast<const char*>(f.body.data()), 8);
    lua_pushlstring(L, reinterpret_cast<const char*>(f.body.data() + 8),
                       f.body.size() - 8);
    return 2;
  };
  if (!drain_socket_nonblocking()) return 0;
  if (int r = pop_if_available()) return r;
  if (nowait) return 0;

  // Blocking path: read frames until a deliver arrives (or socket
  // dies). Replies we don't expect get buffered; non-deliver frames
  // (which shouldn't happen) get dropped.
  for (;;) {
    Frame f;
    if (!read_frame(f)) return 0; // socket dead
    if (f.tag == TAG_DELIVER) {
      g_inbox.push_back(std::move(f));
      return pop_if_available();
    }
    if (f.tag == TAG_API_REPLY) {
      route_to_queue(std::move(f));   // diverts a parked coroutine's reply to g_io_ready
      continue;
    }
    // Anything else: ignore and keep waiting.
  }
}

// ces.client_send(target_pfx:string(8), bytes:string) → true | nil, err
int lua_ces_client_send(lua_State* L) {
  size_t pfx_len = 0, bytes_len = 0;
  const char* pfx = luaL_checklstring(L, 1, &pfx_len);
  const char* bytes = luaL_checklstring(L, 2, &bytes_len);
  if (pfx_len != 8) {
    lua_pushnil(L);
    lua_pushstring(L, "prefix must be 8 bytes");
    return 2;
  }
  if (bytes_len > 1024) {
    lua_pushnil(L);
    lua_pushstring(L, "payload too large (max 1024)");
    return 2;
  }
  // send_api_call prepends the u16 method; args = [8B target_pfx][u16 BE len][bytes].
  std::vector<uint8_t> args;
  args.reserve(WIRE_PREFIX_LEN + sizeof(uint16_t) + bytes_len);
  args.insert(args.end(), reinterpret_cast<const uint8_t*>(pfx),
              reinterpret_cast<const uint8_t*>(pfx) + 8);
  put_u16(args, static_cast<uint16_t>(bytes_len));
  args.insert(args.end(), reinterpret_cast<const uint8_t*>(bytes),
              reinterpret_cast<const uint8_t*>(bytes) + bytes_len);

  // Through io_call so it yields from a coroutine instead of freezing the VM on
  // the host round-trip (the only request/response verb that still blocked).
  return io_call(L, METHOD_CLIENT_SEND, args,
                 [](lua_State* L, const Frame& reply) -> int {
    uint8_t status = reply.body[0];
    if (status == STATUS_OK) { lua_pushboolean(L, 1); return 1; }
    lua_pushnil(L);
    switch (status) {
      case STATUS_NOT_CONNECTED:    lua_pushstring(L, "not_connected"); break;
      case STATUS_INSUFFICIENT_BAL: lua_pushstring(L, "insufficient_balance"); break;
      default:                      lua_pushstring(L, "internal"); break;
    }
    return 2;
  });
}

// ces.prog_prefix() → string(8) — convenience so scripts can log
// or key state by their own identity.
int lua_ces_prog_prefix(lua_State* L) {
  lua_pushlstring(L, reinterpret_cast<const char*>(g_prog_prefix), 8);
  return 1;
}

// ces.owner_pubkey() → string(32) — the source file's owner pubkey.
// /s/ programs see the server's pubkey here (their "house key").
int lua_ces_owner_pubkey(lua_State* L) {
  lua_pushlstring(L, reinterpret_cast<const char*>(g_owner_pubkey), 32);
  return 1;
}

// ces.program_pubkey() → string(32) — the file's dedicated program
// account: the pool ces.transfer spends from, and the address a program
// should advertise to receive funds (a game's "house", a service's
// wallet) so deposits and payouts share one pool.
int lua_ces_program_pubkey(lua_State* L) {
  lua_pushlstring(L, reinterpret_cast<const char*>(g_program_pubkey), 32);
  return 1;
}

// ces.start_time() → number — this instance's birth time in
// microseconds since epoch. Stable for the instance's life. Programs
// use it as a freshness anchor: a payment whose lastXferTime is
// ≤ start_time / 1e6 (seconds) cannot have been a fresh deposit
// aimed at THIS instance, so it should not count as a bet.
int lua_ces_start_time(lua_State* L) {
  lua_pushnumber(L, static_cast<lua_Number>(g_start_time_us));
  return 1;
}

