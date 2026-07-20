// ---------------------------------------------------------------------------
// ces.hyle - a hyle blockchain hosted IN this cesluajitd process.
// Extension-only: registered solely for privileged (/s/) programs.
//
// `ces.hyle.*` is the CHAIN INTERFACE: submit, sudo, govern, read, and the op builders. It
// says nothing about how many nodes are behind it. `ces.hyle.solo.*` is the LIFECYCLE of one
// implementation: a single-validator, transportless chain a program drives by hand, one block
// per tick. A transport-enabled multi-node implementation adds its own lifecycle (ces.hyle.net)
// and leaves the interface alone, so a program written against ces.hyle.* moves from the devnet
// to a real chain unchanged.
//
// Sudo is here in full. A sudo act runs with its guards waived, so it needs a supermajority's
// approval, collected ON CHAIN: propose() opens the proposal with the program's own vote,
// approve() adds more, and the vote reaching quorum executes it. On a one-validator chain that
// single vote is the supermajority, so propose() executes at once; raise the validator count
// and the same path waits for the other members to approve() first.
//
// Only present when the node was built with --hyle (CES_HYLE): hyle_services is statically
// linked, so these calls drive a hyle::services::Runtime DIRECTLY, no host IPC. In-RAM only:
// stop() (or the process dying) drops the chain.
//
// IDENTITY. A node's validator identity is its OWN CES ed25519 identity, chosen by topology: on
// solo it is the program key, so ces.hyle.self() == ces.program_pubkey(); on net it is the SERVER
// key (the peer-mesh identity). Both are one key across two ledgers -- the CES account and the
// chain account are the same 32 bytes -- which lets a payment on one side authorize a mint on the
// other with no mapping table. self()/self_secret()/op.* all report and sign as hyle_active_key().
//
// Surface (drives extensions/hylesolo.lua; see apps/hylesolo in cesdk for the source):
//   solo lifecycle
//     ces.hyle.solo.start{ chain_id=, block_pace_ms=, alloc=, fee_transfer=, fee_entry=,
//                          fee_sudo=, rent_rate=, rip_bounty=, sudo_ttl_secs=,
//                          credit_autofill_ceiling=, refill_rate= } -> true | nil,err
//     ces.hyle.solo.tick()   -- advance exactly one height; -> new height
//     ces.hyle.solo.stop()   -- destroy the node
//   chain
//     ces.hyle.running() / height() / chain_id() / self()
//     ces.hyle.info()    -- one table: everything live
//     ces.hyle.config()  -- the genesis economy
//     ces.hyle.account(pubkey) / entry(name) / tx_result(txid) / validators()
//     ces.hyle.submit(bytes)          -- admit signed ops; -> {txid,..} | nil,reason
//     ces.hyle.op.*                   -- build ops signed AS THIS PROGRAM
//     ces.hyle.sudo.op.*              -- build a sudo act's inner bytes
//     ces.hyle.sudo.propose(inner) / approve(proposer,inner) / pending(proposer) / quorum()
//     ces.hyle.vote_add(pk) / vote_remove(pk)
// ---------------------------------------------------------------------------
#ifdef CES_HYLE

// hyle headers are included at global scope in main.cpp (guarded by CES_HYLE):
// this .inc is textually inside `namespace cesluajitd`, and library/std headers
// must not be included inside a namespace.

static std::unique_ptr<hyle::services::Runtime> g_hyle_node;
static std::unique_ptr<hyle::KeyPair> g_hyle_key;  // the sole validator (== the program key)
static std::string g_hyle_chain;

// Lifetime meters (RAM, reset on start): txs summed from the commit event, queries bumped by the readers.
static uint64_t g_hyle_txs = 0;
static uint64_t g_hyle_queries = 0;

static hyle::wire::View hyle_chain_view() {
  return hyle::wire::View(reinterpret_cast<const uint8_t*>(g_hyle_chain.data()),
                          g_hyle_chain.size());
}

static hyle::wire::View hyle_view(const hyle::wire::Bytes& b) {
  return hyle::wire::View(b.data(), b.size());
}

// Read a uint64 field from the config table at stack index 1 (default if absent/non-numeric).
static uint64_t hyle_cfg_u64(lua_State* L, const char* key, uint64_t def) {
  lua_getfield(L, 1, key);
  uint64_t v = lua_isnumber(L, -1) ? static_cast<uint64_t>(lua_tonumber(L, -1)) : def;
  lua_pop(L, 1);
  return v;
}

// Field readers for the op builders: every builder takes one table argument.
static uint64_t hyle_fld_u64(lua_State* L, const char* key, uint64_t def) {
  return hyle_cfg_u64(L, key, def);
}

static hyle::wire::Bytes hyle_fld_bytes(lua_State* L, const char* key) {
  lua_getfield(L, 1, key);
  size_t n = 0;
  const char* s = lua_isstring(L, -1) ? lua_tolstring(L, -1, &n) : nullptr;
  hyle::wire::Bytes out;
  if (s != nullptr) out.assign(s, s + n);
  lua_pop(L, 1);
  return out;
}

// A 32-byte key field. Absent or wrong-sized yields the zero key, which every op path
// treats as "not given" (and which sudo refuses to leave owning anything).
static hyle::PubKey hyle_fld_key(lua_State* L, const char* key) {
  hyle::PubKey k{};
  lua_getfield(L, 1, key);
  size_t n = 0;
  const char* s = lua_isstring(L, -1) ? lua_tolstring(L, -1, &n) : nullptr;
  if (s != nullptr && n == 32) std::memcpy(k.data(), s, 32);
  lua_pop(L, 1);
  return k;
}

// A key field that must be there. Absent or wrong-sized is an error, not a zero key:
// the zero key is the mint sentinel, and quietly resolving `to` to it would turn a
// mistyped transfer into a burn.
static hyle::PubKey hyle_fld_key_req(lua_State* L, const char* key) {
  lua_getfield(L, 1, key);
  size_t n = 0;
  const char* s = lua_isstring(L, -1) ? lua_tolstring(L, -1, &n) : nullptr;
  if (s == nullptr || n != 32)
    luaL_error(L, "field '%s' must be a 32-byte pubkey", key);
  hyle::PubKey k{};
  std::memcpy(k.data(), s, 32);
  lua_pop(L, 1);
  return k;
}

static hyle::PubKey hyle_arg_key(lua_State* L, int idx) {
  size_t n = 0;
  const char* s = luaL_checklstring(L, idx, &n);
  if (n != 32) luaL_error(L, "expected a 32-byte pubkey, got %d bytes", static_cast<int>(n));
  hyle::PubKey k{};
  std::memcpy(k.data(), s, 32);
  return k;
}

static void hyle_push_bytes(lua_State* L, const hyle::wire::Bytes& b) {
  lua_pushlstring(L, reinterpret_cast<const char*>(b.data()), b.size());
}

static void hyle_set_u64(lua_State* L, const char* key, uint64_t v) {
  lua_pushnumber(L, static_cast<lua_Number>(v));
  lua_setfield(L, -2, key);
}

static void hyle_set_bytes(lua_State* L, const char* key, const uint8_t* p, size_t n) {
  lua_pushlstring(L, reinterpret_cast<const char*>(p), n);
  lua_setfield(L, -2, key);
}

// The program's own hyle identity. Same 32 bytes as ces.program_pubkey(); see IDENTITY above.
static hyle::KeyPair hyle_program_key() {
  hyle::PrivKey secret{};
  std::memcpy(secret.data(), g_program_privkey, 32);
  return hyle::KeyPair::from_secret(secret);
}

// The active node identity: the running chain's validator key -- the program key on solo, the
// server key on net (both a node's own CES identity, per topology) -- or the program key before
// any chain starts. self()/self_secret()/op.* sign and report as this, so the same code moves
// from solo to net unchanged.
static hyle::KeyPair hyle_active_key() {
  if (g_hyle_key) return *g_hyle_key;
  return hyle_program_key();
}

// Every interface call needs a chain. Returns false having pushed (nil, reason).
static bool hyle_need_node(lua_State* L) {
  if (g_hyle_node) return true;
  lua_pushnil(L);
  lua_pushstring(L, "no chain running");
  return false;
}

// 'a' + pubkey, or 'e' + name: hyle's two transfer destinations.
static hyle::wire::Bytes hyle_account_dest(const hyle::PubKey& pk) {
  hyle::wire::Bytes b;
  b.push_back(hyle::services::ACCOUNT_PREFIX);
  b.insert(b.end(), pk.begin(), pk.end());
  return b;
}

static hyle::wire::Bytes hyle_entry_dest(const hyle::wire::Bytes& name) {
  hyle::wire::Bytes b;
  b.push_back(hyle::services::ENTRY_PREFIX);
  b.insert(b.end(), name.begin(), name.end());
  return b;
}

// The genesis economy + consensus-rule fields, read from the start{} table. Shared by the solo
// and net lifecycles: the economy is part of the chain definition and must match across nodes.
// Validators and allocations differ per lifecycle and are set by the caller.
static void hyle_fill_config(lua_State* L, hyle::services::Config& c) {
  // With rent on, hyle checks rip_bounty <= min(fee_transfer, fee_entry) -- a bounty worth more
  // than the fee to create a rippable entry is a pump that mints money out of the cull.
  c.fee_transfer = hyle_cfg_u64(L, "fee_transfer", 10);
  c.fee_entry    = hyle_cfg_u64(L, "fee_entry", 10);
  c.fee_sudo     = hyle_cfg_u64(L, "fee_sudo", 1);
  // At rate 0 an entry is immortal: its balance buys nothing and nothing can cull it.
  c.rent_rate    = hyle_cfg_u64(L, "rent_rate", 1);
  c.rip_bounty   = hyle_cfg_u64(L, "rip_bounty", 10);
  // A pending sudo proposal past this age cannot execute and is cleared. 0 = never expires.
  c.sudo_ttl_secs = hyle_cfg_u64(L, "sudo_ttl_secs", 0);
  // Consensus rules (validator-set bounds, max block payload): part of the chain definition.
  c.member_cap      = static_cast<unsigned>(hyle_cfg_u64(L, "member_cap", 21));
  c.member_floor    = static_cast<unsigned>(hyle_cfg_u64(L, "member_floor", 1));
  c.max_value_bytes = hyle_cfg_u64(L, "max_value_bytes", 4u << 20);
  // Hard cap on total state RAM in bytes (0 = unbounded).
  c.max_state_bytes = hyle_cfg_u64(L, "max_state_bytes", 0);
  // Per-block credit autofill: tops each validator toward the ceiling (0 = off).
  c.credit_autofill_ceiling = hyle_cfg_u64(L, "credit_autofill_ceiling", 0);
  c.refill_rate             = hyle_cfg_u64(L, "refill_rate", 0);
}

// ---------------------------------------------------------------------------
// Lifecycle (solo)
// ---------------------------------------------------------------------------

int lua_ces_hyle_start(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  if (g_hyle_node) { lua_pushboolean(L, 1); return 1; }  // idempotent: already running

  lua_getfield(L, 1, "chain_id");
  g_hyle_chain = lua_isstring(L, -1) ? lua_tostring(L, -1) : "hylesolo";
  lua_pop(L, 1);

  // The sole validator is derived deterministically from this program's own secret, so the
  // chain's identity is stable across restarts and tied to the program.
  g_hyle_key = std::make_unique<hyle::KeyPair>(hyle_program_key());

  hyle::services::Genesis g;
  g.chain_id = g_hyle_chain;
  g.validators = { g_hyle_key->pub };
  g.allocations = { { g_hyle_key->pub, hyle_cfg_u64(L, "alloc", 1000000000ull) } };
  hyle_fill_config(L, g.config);

  std::string err;
  if (!g.validate(err)) {
    g_hyle_key.reset();
    lua_pushnil(L);
    lua_pushstring(L, ("hyle genesis invalid: " + err).c_str());
    return 2;
  }

  // Node operational config (pacing, RAM history policy): distinct from the genesis above, which
  // is the chain's consensus definition. snapshot_interval > 0 snapshots every N blocks and
  // drops older ones; else a rolling block_retention window bounds RAM.
  hyle::services::NodeOptions opts;
  opts.block_pace_ms     = hyle_cfg_u64(L, "block_pace_ms", 1000);  // Lua drives ticks; advisory
  opts.block_retention   = hyle_cfg_u64(L, "block_retention", 1024);
  opts.snapshot_interval = hyle_cfg_u64(L, "snapshot_interval", 0);
  opts.mempool_capacity  = static_cast<std::size_t>(hyle_cfg_u64(L, "mempool_capacity", 8192));
  // data_dir/evidence_dir left empty: solo is in-RAM, no WAL, and dies on stop.
  g_hyle_node = std::make_unique<hyle::services::Runtime>(g, *g_hyle_key, opts, nullptr);

  g_hyle_txs = 0;
  g_hyle_queries = 0;
  g_hyle_node->app().add_on_commit(
      [](const hyle::services::CommitEvent& ev) { g_hyle_txs += ev.txs.size(); });

  lua_pushboolean(L, 1);
  return 1;
}

int lua_ces_hyle_tick(lua_State* L) {
  if (!g_hyle_node) { lua_pushnil(L); return 1; }
  g_hyle_node->run_to(g_hyle_node->height() + 1);  // solo self-quorum: synchronous, non-blocking
  lua_pushnumber(L, static_cast<lua_Number>(g_hyle_node->height()));
  return 1;
}

int lua_ces_hyle_stop(lua_State* L) {
  g_hyle_node.reset();
  g_hyle_key.reset();
  g_hyle_chain.clear();
  g_hyle_txs = 0;
  g_hyle_queries = 0;
  lua_pushboolean(L, 1);
  return 1;
}

int lua_ces_hyle_running(lua_State* L) {
  lua_pushboolean(L, g_hyle_node ? 1 : 0);
  return 1;
}

// ---------------------------------------------------------------------------
// Lifecycle (net): a real multi-node chain. The validator identity is the SERVER key
// (read in-process from g_server_secret), and consensus rides the CES server peer mesh (ces.peer.*), addressed by
// server pubkey. The driver mirrors morphe's Driver::tick (pump/advance/idle-debounced timeout);
// the extension calls net.tick() on a fine ces.every. No dialing: the peer mesh is already there.
// ---------------------------------------------------------------------------

// Bridges hyle's Transport to the CES peer mesh. send/broadcast frame [u8 type][u8 ch][payload]
// into a ces.peer.send; inbound frames (via the drain_peer hook) feed on_recv and, for consensus,
// re-flood one hop to defeat equivocation. Addresses peers by CES server pubkey.
struct CesPeerTransport : hyle::services::Transport {
  std::string service;                    // "hyle/" + chain_id
  std::vector<hyle::PubKey> peers;        // the OTHER validators (server pubkeys)
  std::deque<uint64_t> seenOrder;
  std::unordered_set<uint64_t> seen;
  static constexpr size_t kSeenCap = 8192;

  void frameTo(const hyle::PubKey& dest, uint8_t type, uint8_t ch,
               const uint8_t* payload, size_t plen) {
    std::vector<uint8_t> body;
    body.reserve(32 + 2 + service.size() + 2 + plen);
    body.insert(body.end(), dest.begin(), dest.end());
    put_u16(body, static_cast<uint16_t>(service.size()));
    body.insert(body.end(), service.begin(), service.end());
    body.push_back(type);
    body.push_back(ch);
    if (plen) body.insert(body.end(), payload, payload + plen);
    write_frame(TAG_PEER_MSG_OUT, 0, body.data(), body.size());
  }
  void send(const hyle::PubKey& dest, hyle::services::MsgType type,
            hyle::services::Channel ch, hyle::wire::View payload) override {
    frameTo(dest, static_cast<uint8_t>(type), static_cast<uint8_t>(ch),
            payload.data(), payload.size());
  }
  void broadcast(hyle::services::MsgType type, hyle::services::Channel ch,
                 hyle::wire::View payload) override {
    for (const auto& p : peers)
      frameTo(p, static_cast<uint8_t>(type), static_cast<uint8_t>(ch),
              payload.data(), payload.size());
  }
  size_t peer_count() const override { return peers.size(); }
  // Bulk pieces are sized to this. Kept small (64 KiB): a small piece drains fast and backs up
  // little in the send buffer, yet dwarfs the per-frame framing and 1241-byte RUDP packet overhead.
  // The peer mesh size-routes anything this large onto its bulk channel, off the consensus one.
  size_t max_message() const override { return 64 * 1024; }

  bool markSeen(const uint8_t* inner, size_t len) {
    const hyle::Hash h = hyle::sha256(hyle::wire::View(inner, len));
    uint64_t k = 0;
    for (int i = 0; i < 8; ++i) k = (k << 8) | h[i];
    if (!seen.insert(k).second) return false;
    seenOrder.push_back(k);
    if (seenOrder.size() > kSeenCap) { seen.erase(seenOrder.front()); seenOrder.pop_front(); }
    return true;
  }

  // Inbound from drain_peer; `data` = inner frame [u8 type][u8 ch][payload]. Returns true iff a
  // FRESH consensus/prop message was delivered (drives the timeout clock; Tx and dups return false
  // so a mempool stream or a re-flood storm cannot starve a needed timeout).
  //
  // Dedup gates the re-flood and the timeout clock, never local delivery of consensus or sync
  // frames. The engine's liveness rebroadcasts are byte-identical, and a node whose engine lost
  // its first copy (rebuilt by catch-up) can only recover the round's votes from a re-delivery;
  // sync control and the streamed bulk pieces are point-to-point, never re-flooded, and retried.
  bool onInbound(const hyle::PubKey& from, const uint8_t* data, size_t len) {
    if (len < 2) return false;
    const auto type = static_cast<hyle::services::MsgType>(data[0]);
    using MT = hyle::services::MsgType;
    const bool sync = (type == MT::ValueReq || type == MT::SnapReq || type == MT::SnapResp ||
                       type == MT::BulkChunk);
    const bool consensus = (type == MT::Consensus || type == MT::Prop);
    const bool fresh = sync || markSeen(data, len);
    if (!fresh && !consensus) return false;
    hyle::wire::View pl(data + 2, len - 2);
    if (on_recv) on_recv(from, type, pl);
    if (consensus && fresh)
      for (const auto& p : peers)
        if (!(p == from)) frameTo(p, data[0], data[1], data + 2, len - 2);
    return consensus && fresh;
  }
};

static std::unique_ptr<CesPeerTransport> g_hyle_net_tp;
static std::chrono::steady_clock::time_point g_hyle_net_last_commit{};
static std::chrono::steady_clock::time_point g_hyle_net_last_progress{};
static std::chrono::steady_clock::time_point g_hyle_net_last_regossip{};
static std::chrono::steady_clock::time_point g_hyle_net_last_syncreq{};
static uint64_t g_hyle_net_last_h = 0;
static uint64_t g_hyle_net_pace_ms = 1000;
// Deliver one pending consensus timeout after this many ms with NO consensus activity. Paced on
// wall time, not tick count: net.tick rides a cooperative ces.every whose cadence sags under load,
// so a tick-count debounce (morphe's) stretches to seconds and stalls rounds. The clock resets on
// any fresh inbound consensus/prop message (see the peer hook), so an active round -- even below
// quorum, votes still trickling -- never times out early; only a genuine stall (silent proposer)
// fires it. Default is WAN-safe (sub-second RTT keeps the clock reset); tune via conf.
static uint64_t g_hyle_net_timeout_ms = 1000;

static bool hyleNetDeliverPeer(const uint8_t* from32, const std::string& service,
                               const uint8_t* payload, size_t plen) {
  if (!g_hyle_net_tp || service != g_hyle_net_tp->service) return false;
  hyle::PubKey from{};
  std::memcpy(from.data(), from32, 32);
  const bool consensusProgress = g_hyle_net_tp->onInbound(from, payload, plen);
  if (g_hyle_node) {
    // Flush any consensus response this message produced right now, event-driven, rather than
    // waiting for the next timer-due net.tick. drain_peer runs after net.tick in the main loop, so
    // without this a vote/proposal reply sits in the outbox for up to a full (stretched) timer
    // period. A fresh consensus message also resets the no-activity timeout clock.
    g_hyle_node->pump();
    if (consensusProgress) g_hyle_net_last_progress = std::chrono::steady_clock::now();
  }
  return true;
}

int lua_ces_hyle_net_start(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  if (g_hyle_node) { lua_pushnil(L); lua_pushstring(L, "a hyle chain is already running"); return 2; }
  if (!g_has_server_secret) {
    lua_pushnil(L);
    lua_pushstring(L, "server_secret unavailable (need a /s/ extension on an ed25519 server)");
    return 2;
  }
  hyle::PrivKey secret{};
  std::memcpy(secret.data(), g_server_secret, 32);
  auto key = std::make_unique<hyle::KeyPair>(hyle::KeyPair::from_secret(secret));
  // The derived ed25519 pubkey must equal the server's advertised pubkey (owner for /s/): this
  // both authenticates the secret and rejects a non-ed25519 server key (which has no hyle identity).
  if (std::memcmp(key->pub.data(), g_owner_pubkey, 32) != 0) {
    lua_pushnil(L); lua_pushstring(L, "server key is not ed25519 (no hyle identity)"); return 2;
  }

  lua_getfield(L, 1, "chain_id");
  g_hyle_chain = lua_isstring(L, -1) ? lua_tostring(L, -1) : "hylenet";
  lua_pop(L, 1);

  std::vector<hyle::PubKey> vals;
  lua_getfield(L, 1, "validators");
  if (lua_istable(L, -1)) {
    const int n = static_cast<int>(lua_objlen(L, -1));
    for (int i = 1; i <= n; ++i) {
      lua_rawgeti(L, -1, i);
      size_t klen = 0;
      const char* k = lua_tolstring(L, -1, &klen);
      if (k && klen == 32) { hyle::PubKey pk{}; std::memcpy(pk.data(), k, 32); vals.push_back(pk); }
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);
  if (vals.empty()) {
    lua_pushnil(L); lua_pushstring(L, "validators: need a list of 32-byte server pubkeys"); return 2;
  }
  // A node not in the genesis validator set starts as a FOLLOWER: it syncs and awaits promotion
  // by a governance vote_add. This is how a new validator joins a running chain.
  hyle::services::Genesis g;
  g.chain_id = g_hyle_chain;
  g.validators = vals;
  hyle_fill_config(L, g.config);
  std::string err;
  if (!g.validate(err)) {
    lua_pushnil(L); lua_pushstring(L, ("hyle genesis invalid: " + err).c_str()); return 2;
  }

  auto tp = std::make_unique<CesPeerTransport>();
  tp->service = "hyle/" + g_hyle_chain;
  for (const auto& v : vals)
    if (std::memcmp(v.data(), key->pub.data(), 32) != 0) tp->peers.push_back(v);
  // Register the service so the server routes inbound mesh messages to us (mirrors ces.peer.listen).
  {
    std::vector<uint8_t> lb;
    put_u16(lb, static_cast<uint16_t>(tp->service.size()));
    lb.insert(lb.end(), tp->service.begin(), tp->service.end());
    write_frame(TAG_PEER_LISTEN, 0, lb.data(), lb.size());
  }
  g_hyle_net_tp = std::move(tp);
  g_peer_msg_hook = &hyleNetDeliverPeer;

  hyle::services::NodeOptions opts;
  opts.block_pace_ms     = hyle_cfg_u64(L, "block_pace_ms", 1000);
  opts.block_retention   = hyle_cfg_u64(L, "block_retention", 1024);
  opts.snapshot_interval = hyle_cfg_u64(L, "snapshot_interval", 0);
  opts.mempool_capacity  = static_cast<std::size_t>(hyle_cfg_u64(L, "mempool_capacity", 8192));
  g_hyle_net_pace_ms = opts.block_pace_ms;
  g_hyle_net_timeout_ms = hyle_cfg_u64(L, "consensus_timeout_ms", 1000);  // no-activity round timeout

  g_hyle_key = std::move(key);
  g_hyle_node = std::make_unique<hyle::services::Runtime>(g, *g_hyle_key, opts, g_hyle_net_tp.get());
  g_hyle_txs = 0;
  g_hyle_queries = 0;
  g_hyle_node->app().add_on_commit(
      [](const hyle::services::CommitEvent& ev) { g_hyle_txs += ev.txs.size(); });
  g_hyle_node->begin();
  g_hyle_net_last_h = 0;
  g_hyle_net_last_commit = std::chrono::steady_clock::now();
  g_hyle_net_last_progress = g_hyle_net_last_commit;
  g_hyle_net_last_regossip = g_hyle_net_last_commit;
  lua_pushboolean(L, 1);
  return 1;
}

int lua_ces_hyle_net_tick(lua_State* L) {
  if (!g_hyle_node) { lua_pushnil(L); return 1; }
  bool prog = g_hyle_node->pump();
  const bool pending = g_hyle_node->app().mempool().size() > 0;
  const auto now = std::chrono::steady_clock::now();
  const bool paced =
      std::chrono::duration_cast<std::chrono::milliseconds>(now - g_hyle_net_last_commit).count() >=
      static_cast<long long>(g_hyle_net_pace_ms);
  if ((pending || paced) && g_hyle_node->advance()) {
    prog = true;
    g_hyle_node->pump();  // flush the freshly-started height's proposal this tick, not the next
  }
  // Re-gossip pending mempool txs on a modest cadence. submit() broadcasts once and on_message
  // re-floods a tx only on FRESH receipt, so a tx that missed a peer whose mesh channel was
  // flapping under load never reaches it -- and unlike consensus (which the engine re-sends on
  // timeout) tx delivery has no other self-heal. This is that self-heal.
  if (pending &&
      std::chrono::duration_cast<std::chrono::milliseconds>(now - g_hyle_net_last_regossip).count() >=
          1000) {
    g_hyle_node->regossip();
    g_hyle_net_last_regossip = now;
  }
  // Blocksync: if we have fallen behind the head observed from peers, ask for the missing blocks.
  // request_sync no-ops at head, so this is cheap; pace it so a long catch-up pulls batch after
  // batch without flooding.
  if (std::chrono::duration_cast<std::chrono::milliseconds>(now - g_hyle_net_last_syncreq).count() >=
      250) {
    g_hyle_node->request_sync();
    g_hyle_net_last_syncreq = now;
  }
  if (g_hyle_node->height() != g_hyle_net_last_h) {
    g_hyle_net_last_h = g_hyle_node->height();
    g_hyle_net_last_commit = now;
    // Refresh the transport peers from the LIVE validator set so membership changes (add/remove)
    // route consensus correctly -- a newly added validator starts receiving, a removed one stops.
    if (g_hyle_net_tp && g_hyle_key) {
      const auto set = g_hyle_node->node().validators_for(g_hyle_node->height() + 1);
      g_hyle_net_tp->peers.clear();
      for (const auto& v : set) {
        hyle::PubKey pk{};
        std::memcpy(pk.data(), v.public_key.data(), 32);
        if (std::memcmp(pk.data(), g_hyle_key->pub.data(), 32) != 0)
          g_hyle_net_tp->peers.push_back(pk);
      }
    }
  }
  if (prog) {
    g_hyle_net_last_progress = now;
  } else if (std::chrono::duration_cast<std::chrono::milliseconds>(now - g_hyle_net_last_progress)
                 .count() >= static_cast<long long>(g_hyle_net_timeout_ms)) {
    g_hyle_node->fire_one_timeout();
    g_hyle_net_last_progress = now;
  }
  lua_pushnumber(L, static_cast<lua_Number>(g_hyle_node->height()));
  return 1;
}

int lua_ces_hyle_net_stop(lua_State* L) {
  g_peer_msg_hook = nullptr;
  g_hyle_node.reset();
  g_hyle_key.reset();
  g_hyle_net_tp.reset();
  g_hyle_chain.clear();
  g_hyle_txs = 0;
  g_hyle_queries = 0;
  lua_pushboolean(L, 1);
  return 1;
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

int lua_ces_hyle_height(lua_State* L) {
  ++g_hyle_queries;
  lua_pushnumber(L, g_hyle_node ? static_cast<lua_Number>(g_hyle_node->height()) : 0);
  return 1;
}

int lua_ces_hyle_chain_id(lua_State* L) {
  lua_pushlstring(L, g_hyle_chain.data(), g_hyle_chain.size());
  return 1;
}

int lua_ces_hyle_self(lua_State* L) {
  const hyle::KeyPair kp = hyle_active_key();
  lua_pushlstring(L, reinterpret_cast<const char*>(kp.pub.data()), kp.pub.size());
  return 1;
}

// The validator's 32-byte private key. This IS absolute chain authority (mint, sudo), so a
// program must only ever hand it to a caller it has authenticated as the owner. A caller
// holding it can act as the node from cesh.
int lua_ces_hyle_self_secret(lua_State* L) {
  const hyle::KeyPair kp = hyle_active_key();
  lua_pushlstring(L, reinterpret_cast<const char*>(kp.priv.data()), kp.priv.size());
  return 1;
}

// State exposes size()/canonical() but no iteration, so count a/e cells over the canonical KV dump.
// The walk lives in ceslib (countCanonicalKvKeyPrefix), unit-tested there.
static uint64_t hyle_canon_count(uint8_t prefix) {
  if (!g_hyle_node) return 0;
  auto canon = g_hyle_node->app().store().canonical();
  return ces::countCanonicalKvKeyPrefix(std::span<const uint8_t>(canon.data(), canon.size()), prefix);
}

int lua_ces_hyle_info(lua_State* L) {
  ++g_hyle_queries;
  if (!g_hyle_node) { lua_pushnil(L); return 1; }
  const hyle::services::App& app = g_hyle_node->app();

  lua_newtable(L);
  lua_pushlstring(L, g_hyle_chain.data(), g_hyle_chain.size());
  lua_setfield(L, -2, "chain_id");
  hyle_set_u64(L, "height", g_hyle_node->height());
  hyle_set_u64(L, "last_block_time", app.last_timestamp());
  hyle_set_u64(L, "accounts", hyle_canon_count(hyle::services::ACCOUNT_PREFIX));
  hyle_set_u64(L, "entries", hyle_canon_count(hyle::services::ENTRY_PREFIX));
  hyle_set_u64(L, "txs", g_hyle_txs);
  hyle_set_u64(L, "queries", g_hyle_queries);
  hyle_set_u64(L, "mempool", app.mempool().size());
  hyle_set_u64(L, "sudo_minted", app.sudo_minted());
  hyle_set_u64(L, "sudo_pending", hyle_canon_count(hyle::services::PENDING_PREFIX));
  const uint64_t nmembers = g_hyle_node->node().member_count();
  hyle_set_u64(L, "validators", nmembers);
  hyle_set_u64(L, "quorum", (2 * nmembers) / 3 + 1);
  hyle_set_u64(L, "balance", app.balance(g_hyle_key->pub));

  const hyle::Hash h = g_hyle_node->node().composite_hash();
  hyle_set_bytes(L, "app_hash", h.data(), h.size());
  hyle_set_bytes(L, "self", g_hyle_key->pub.data(), g_hyle_key->pub.size());
  return 1;
}

int lua_ces_hyle_config(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  ++g_hyle_queries;
  const hyle::services::Config& c = g_hyle_node->app().config();
  lua_newtable(L);
  hyle_set_u64(L, "fee_transfer", c.fee_transfer);
  hyle_set_u64(L, "fee_entry", c.fee_entry);
  hyle_set_u64(L, "fee_sudo", c.fee_sudo);
  hyle_set_u64(L, "rent_rate", c.rent_rate);
  hyle_set_u64(L, "rip_bounty", c.rip_bounty);
  hyle_set_u64(L, "sudo_ttl_secs", c.sudo_ttl_secs);
  hyle_set_u64(L, "pbts_window_secs", c.pbts_window_secs);
  hyle_set_u64(L, "member_cap", c.member_cap);
  hyle_set_u64(L, "member_floor", c.member_floor);
  hyle_set_u64(L, "max_value_bytes", c.max_value_bytes);
  return 1;
}

int lua_ces_hyle_account(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  ++g_hyle_queries;
  const hyle::PubKey pk = hyle_arg_key(L, 1);
  const hyle::services::App& app = g_hyle_node->app();
  lua_newtable(L);
  hyle_set_u64(L, "balance", app.balance(pk));
  hyle_set_u64(L, "sequence", app.sequence(pk));
  lua_pushboolean(L, app.account_exists(pk) ? 1 : 0);
  lua_setfield(L, -2, "exists");
  return 1;
}

int lua_ces_hyle_entry(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  ++g_hyle_queries;
  size_t n = 0;
  const char* s = luaL_checklstring(L, 1, &n);
  const hyle::wire::View name(reinterpret_cast<const uint8_t*>(s), n);

  hyle::services::Entry e;
  if (!g_hyle_node->app().entry_info(name, e)) { lua_pushnil(L); return 1; }

  lua_newtable(L);
  hyle_set_bytes(L, "owner", e.owner.data(), e.owner.size());
  hyle_set_u64(L, "balance", e.balance);
  hyle_set_u64(L, "created", e.created);
  hyle_set_u64(L, "last_modified", e.last_modified);
  hyle_set_u64(L, "last_rent", e.last_rent);
  hyle_set_bytes(L, "payload", e.payload.data(), e.payload.size());
  return 1;
}

int lua_ces_hyle_tx_result(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  ++g_hyle_queries;
  size_t n = 0;
  const char* s = luaL_checklstring(L, 1, &n);
  if (n != 32) luaL_error(L, "expected a 32-byte tx id, got %d bytes", static_cast<int>(n));
  hyle::Hash id{};
  std::memcpy(id.data(), s, 32);

  hyle::services::TxResult r;
  if (!g_hyle_node->app().tx_result(id, r)) { lua_pushnil(L); return 1; }
  lua_newtable(L);
  hyle_set_u64(L, "height", r.height);
  lua_pushboolean(L, r.applied ? 1 : 0);
  lua_setfield(L, -2, "applied");
  return 1;
}

int lua_ces_hyle_validators(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  ++g_hyle_queries;
  const auto set = g_hyle_node->node().validators_for(g_hyle_node->height() + 1);
  lua_newtable(L);
  int i = 1;
  for (const auto& v : set) {
    lua_pushlstring(L, reinterpret_cast<const char*>(v.public_key.data()), v.public_key.size());
    lua_rawseti(L, -2, i++);
  }
  return 1;
}

// ---------------------------------------------------------------------------
// submit: admit already-signed ops. CES does not interpret them; each carries its own signature.
// ---------------------------------------------------------------------------

int lua_ces_hyle_submit(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  size_t n = 0;
  const char* s = luaL_checklstring(L, 1, &n);

  hyle::services::Decoded d;
  try {
    d = hyle::services::decode_ops(hyle::wire::View(reinterpret_cast<const uint8_t*>(s), n));
  } catch (const hyle::wire::Error&) {
    lua_pushnil(L);
    lua_pushstring(L, "malformed op batch");
    return 2;
  }

  // Admit each op and hand back its tx id, so the caller can poll tx_result. An op that
  // fails admission stops the batch; the ones already admitted stay admitted.
  const hyle::wire::View cv = hyle_chain_view();
  std::vector<hyle::Hash> ids;
  const char* fail = nullptr;

  for (const auto& o : d.transfers) {
      const hyle::services::Admit a = g_hyle_node->submit(o);
      if (a != hyle::services::Admit::Ok) { fail = hyle::services::admit_reason(a); break; }
      ids.push_back(hyle::services::tx_id(cv, o));
    }
  if (fail == nullptr)
    for (const auto& o : d.entries) {
      const hyle::services::Admit a = g_hyle_node->submit(o);
      if (a != hyle::services::Admit::Ok) { fail = hyle::services::admit_reason(a); break; }
      ids.push_back(hyle::services::tx_id(cv, o));
    }
  if (fail == nullptr)
    for (const auto& o : d.sudos) {
      const hyle::services::Admit a = g_hyle_node->submit(o);
      if (a != hyle::services::Admit::Ok) { fail = hyle::services::admit_reason(a); break; }
      ids.push_back(hyle::services::tx_id(cv, o));
    }

  if (fail != nullptr) {
    lua_pushnil(L);
    lua_pushstring(L, fail);
    return 2;
  }
  if (ids.empty()) {
    lua_pushnil(L);
    lua_pushstring(L, "no ops");
    return 2;
  }

  lua_newtable(L);
  int i = 1;
  for (const auto& id : ids) {
    lua_pushlstring(L, reinterpret_cast<const char*>(id.data()), id.size());
    lua_rawseti(L, -2, i++);
  }
  return 1;
}

// ---------------------------------------------------------------------------
// op builders: the program signing AS ITSELF. Its CES program key IS its chain account,
// so these need no key argument. A user's op is signed by the user's own client and
// arrives here as opaque bytes for submit(); the program never holds a user's key.
// ---------------------------------------------------------------------------

// Default seq is the committed sequence. Pipelining several ops before the first commits
// needs explicit, consecutive seq values.
static uint64_t hyle_self_seq(lua_State* L, const hyle::PubKey& self) {
  lua_getfield(L, 1, "seq");
  const bool given = lua_isnumber(L, -1) != 0;
  const uint64_t v = given ? static_cast<uint64_t>(lua_tonumber(L, -1)) : 0;
  lua_pop(L, 1);
  return given ? v : g_hyle_node->app().sequence(self);
}

static int hyle_push_transfer(lua_State* L, const hyle::wire::Bytes& to, uint64_t amount,
                              bool max) {
  const hyle::KeyPair kp = hyle_active_key();
  const uint64_t seq = hyle_self_seq(L, kp.pub);
  hyle::services::Decoded d;
  d.transfers.push_back(
      hyle::services::make_transfer(kp, hyle_view(to), amount, seq, hyle_chain_view(), max));
  hyle_push_bytes(L, hyle::services::encode_ops(d));
  return 1;
}

int lua_ces_hyle_op_transfer(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  if (!hyle_need_node(L)) return 2;
  lua_getfield(L, 1, "max");
  const bool max = lua_toboolean(L, -1) != 0;
  lua_pop(L, 1);
  return hyle_push_transfer(L, hyle_account_dest(hyle_fld_key_req(L, "to")),
                            hyle_fld_u64(L, "amount", 0), max);
}

// Fund a K,V mapping: a transfer whose destination is the entry itself. Anyone may do it.
int lua_ces_hyle_op_fund(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  if (!hyle_need_node(L)) return 2;
  return hyle_push_transfer(L, hyle_entry_dest(hyle_fld_bytes(L, "name")),
                            hyle_fld_u64(L, "amount", 0), /*max=*/false);
}

static int hyle_push_entry(lua_State* L, const hyle::services::EntryOp& op) {
  hyle::services::Decoded d;
  d.entries.push_back(op);
  hyle_push_bytes(L, hyle::services::encode_ops(d));
  return 1;
}

// Publish or update: first Put owns the name, and only the owner may Put again.
int lua_ces_hyle_op_entry_put(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  if (!hyle_need_node(L)) return 2;
  const hyle::KeyPair kp = hyle_active_key();
  const hyle::wire::Bytes name = hyle_fld_bytes(L, "name");
  const hyle::wire::Bytes payload = hyle_fld_bytes(L, "payload");
  return hyle_push_entry(
      L, hyle::services::make_entry_put(kp, hyle_view(name), hyle_self_seq(L, kp.pub),
                                      hyle_fld_u64(L, "fund", 0), hyle_view(payload),
                                      hyle_chain_view()));
}

int lua_ces_hyle_op_entry_del(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  if (!hyle_need_node(L)) return 2;
  const hyle::KeyPair kp = hyle_active_key();
  const hyle::wire::Bytes name = hyle_fld_bytes(L, "name");
  return hyle_push_entry(L, hyle::services::make_entry_del(kp, hyle_view(name),
                                                         hyle_self_seq(L, kp.pub),
                                                         hyle_chain_view()));
}

int lua_ces_hyle_op_entry_give(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  if (!hyle_need_node(L)) return 2;
  const hyle::KeyPair kp = hyle_active_key();
  const hyle::wire::Bytes name = hyle_fld_bytes(L, "name");
  return hyle_push_entry(
      L, hyle::services::make_entry_give(kp, hyle_view(name), hyle_self_seq(L, kp.pub),
                                       hyle_fld_key_req(L, "to"), hyle_chain_view()));
}

// The cull. Unsigned by construction: anyone may reap an entry whose rent ran out, and
// collects rip_bounty for doing it.
int lua_ces_hyle_op_entry_rip(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  if (!hyle_need_node(L)) return 2;
  const hyle::wire::Bytes name = hyle_fld_bytes(L, "name");
  hyle::PubKey culler = hyle_fld_key(L, "culler");
  if (hyle::services::is_mint_sentinel(culler)) culler = hyle_active_key().pub;
  return hyle_push_entry(L, hyle::services::make_entry_rip(hyle_view(name), culler));
}

// ---------------------------------------------------------------------------
// sudo: run one act with its own guards waived, on a supermajority's authority.
//
// The act is opaque `inner` bytes (an op batch of transfers/entries; only the mint sentinel
// creates credit, every other act must find the money it moves). Approval is collected ON
// CHAIN: propose() opens the proposal carrying the program's own vote, approve() adds more,
// and the vote that reaches quorum executes the act. A one-validator chain is its own
// supermajority, so its propose() reaches quorum at once. propose/approve are ordinary signed
// ops from the program, so they ride submit() into a block; on solo, tick to commit.
// ---------------------------------------------------------------------------

static int hyle_push_inner(lua_State* L, const hyle::services::Decoded& d) {
  hyle_push_bytes(L, hyle::services::encode_ops(d));
  return 1;
}

// A sudo transfer with no source: mints from the mint sentinel.
int lua_ces_hyle_sudo_op_mint(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  hyle::services::Decoded d;
  hyle::services::TransferOp t;
  t.from = hyle::services::MINT_SENTINEL;
  t.to = hyle_account_dest(hyle_fld_key_req(L, "to"));
  t.amount = hyle_fld_u64(L, "amount", 0);
  d.transfers.push_back(t);
  return hyle_push_inner(L, d);
}

int lua_ces_hyle_sudo_op_seize(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  hyle::services::Decoded d;
  hyle::services::TransferOp t;
  t.from = hyle_fld_key_req(L, "from");
  t.to = hyle_account_dest(hyle_fld_key_req(L, "to"));
  t.amount = hyle_fld_u64(L, "amount", 0);
  d.transfers.push_back(t);
  return hyle_push_inner(L, d);
}

static int hyle_sudo_entry(lua_State* L, hyle::services::EntryKind kind) {
  luaL_checktype(L, 1, LUA_TTABLE);
  hyle::services::Decoded d;
  hyle::services::EntryOp e;
  e.kind = kind;
  e.signer = hyle_fld_key(L, "owner");  // who the act makes the owner
  const hyle::wire::Bytes name = hyle_fld_bytes(L, "name");
  e.name = name;
  e.amount = hyle_fld_u64(L, "fund", 0);
  e.aux = hyle_fld_key(L, "to");
  e.payload = hyle_fld_bytes(L, "payload");
  d.entries.push_back(e);
  return hyle_push_inner(L, d);
}

int lua_ces_hyle_sudo_op_entry_put(lua_State* L) {
  return hyle_sudo_entry(L, hyle::services::EntryKind::Put);
}
int lua_ces_hyle_sudo_op_entry_give(lua_State* L) {
  return hyle_sudo_entry(L, hyle::services::EntryKind::Give);
}
int lua_ces_hyle_sudo_op_entry_del(lua_State* L) {
  return hyle_sudo_entry(L, hyle::services::EntryKind::Del);
}
int lua_ces_hyle_sudo_op_entry_rip(lua_State* L) {
  return hyle_sudo_entry(L, hyle::services::EntryKind::Rip);
}

// The current validator set and 2/3+1 of it, as the app weighs a proposal's votes.
static std::vector<hyle::PubKey> hyle_members() {
  std::vector<hyle::PubKey> out;
  if (!g_hyle_node) return out;
  for (const auto& v : g_hyle_node->node().validators_for(g_hyle_node->height() + 1)) {
    hyle::PubKey k{};
    std::memcpy(k.data(), v.public_key.data(), v.public_key.size());
    out.push_back(k);
  }
  return out;
}
static unsigned hyle_quorum() {
  return static_cast<unsigned>((2 * hyle_members().size()) / 3 + 1);
}

int lua_ces_hyle_sudo_quorum(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  lua_pushnumber(L, static_cast<lua_Number>(hyle_quorum()));
  return 1;
}

// Open a proposal for an act, carrying the program's own vote. On a one-validator chain that
// is quorum, so the next committed block executes it. -> true | nil,reason
int lua_ces_hyle_sudo_propose(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  size_t n = 0;
  const char* s = luaL_checklstring(L, 1, &n);
  const hyle::wire::View inner(reinterpret_cast<const uint8_t*>(s), n);
  const hyle::KeyPair kp = hyle_active_key();
  const uint64_t seq = g_hyle_node->app().sequence(kp.pub);
  const hyle::services::Admit a =
      g_hyle_node->submit(hyle::services::make_sudo_propose(kp, seq, inner, hyle_chain_view()));
  if (a != hyle::services::Admit::Ok) {
    lua_pushnil(L);
    lua_pushstring(L, hyle::services::admit_reason(a));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

// Add the program's approval to a member's open proposal. `inner` is the act being approved,
// exactly as proposed (its hash is what the vote commits to). -> true | nil,reason
int lua_ces_hyle_sudo_approve(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  const hyle::PubKey proposer = hyle_arg_key(L, 1);
  size_t n = 0;
  const char* s = luaL_checklstring(L, 2, &n);
  const hyle::Hash inner_hash =
      hyle::sha256(hyle::wire::View(reinterpret_cast<const uint8_t*>(s), n));
  const hyle::KeyPair kp = hyle_active_key();
  const uint64_t seq = g_hyle_node->app().sequence(kp.pub);
  const hyle::services::Admit a = g_hyle_node->submit(
      hyle::services::make_sudo_approve(kp, seq, proposer, inner_hash, hyle_chain_view()));
  if (a != hyle::services::Admit::Ok) {
    lua_pushnil(L);
    lua_pushstring(L, hyle::services::admit_reason(a));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

// Inspect a member's open proposal: the act, how many current members have approved, and how
// many are needed. -> {created, approvals, quorum, inner, inner_hash} | nil
int lua_ces_hyle_sudo_pending(lua_State* L) {
  if (!hyle_need_node(L)) return 2;
  const hyle::PubKey proposer = hyle_arg_key(L, 1);
  hyle::services::Pending p;
  if (!g_hyle_node->app().pending_info(proposer, p)) { lua_pushnil(L); return 1; }
  const std::vector<hyle::PubKey> members = hyle_members();
  lua_newtable(L);
  hyle_set_u64(L, "created", p.created);
  hyle_set_u64(L, "approvals", g_hyle_node->app().pending_approvals(p, members));
  hyle_set_u64(L, "quorum", static_cast<uint64_t>((2 * members.size()) / 3 + 1));
  hyle_set_bytes(L, "inner", p.inner.data(), p.inner.size());
  const hyle::Hash ih = hyle::sha256(hyle::wire::View(p.inner.data(), p.inner.size()));
  hyle_set_bytes(L, "inner_hash", ih.data(), ih.size());
  return 1;
}

// submit(inner) is propose(inner): the one-call path a solo chain uses -- any caller that just
// wants to run an act on a chain it is the sole quorum of.
int lua_ces_hyle_sudo_submit(lua_State* L) {
  return lua_ces_hyle_sudo_propose(L);
}

// ---------------------------------------------------------------------------
// Membership governance. Votes accumulate on-chain until a supermajority agrees; the
// change then takes effect two heights later. A one-validator chain settles at once.
// ---------------------------------------------------------------------------

static int hyle_vote(lua_State* L, hyle::consensus::Governance::Kind kind) {
  if (!hyle_need_node(L)) return 2;
  const hyle::PubKey target = hyle_arg_key(L, 1);
  g_hyle_node->node().submit_gov_vote(kind, target);
  lua_pushboolean(L, 1);
  return 1;
}

int lua_ces_hyle_vote_add(lua_State* L) {
  return hyle_vote(L, hyle::consensus::Governance::Kind::Add);
}
int lua_ces_hyle_vote_remove(lua_State* L) {
  return hyle_vote(L, hyle::consensus::Governance::Kind::Remove);
}

// ---------------------------------------------------------------------------

static void hyle_fn(lua_State* L, const char* name, lua_CFunction fn) {
  lua_pushcfunction(L, fn);
  lua_setfield(L, -2, name);
}

// Install the ces.hyle table. Call with the ces table on top of the stack.
void install_ces_hyle_api(lua_State* L) {
  lua_newtable(L);  // ces.hyle

  hyle_fn(L, "running",    guarded<lua_ces_hyle_running>);
  hyle_fn(L, "height",     guarded<lua_ces_hyle_height>);
  hyle_fn(L, "chain_id",   guarded<lua_ces_hyle_chain_id>);
  hyle_fn(L, "self",        guarded<lua_ces_hyle_self>);
  hyle_fn(L, "self_secret", guarded<lua_ces_hyle_self_secret>);
  hyle_fn(L, "info",       guarded<lua_ces_hyle_info>);
  hyle_fn(L, "config",     guarded<lua_ces_hyle_config>);
  hyle_fn(L, "account",    guarded<lua_ces_hyle_account>);
  hyle_fn(L, "entry",      guarded<lua_ces_hyle_entry>);
  hyle_fn(L, "tx_result",  guarded<lua_ces_hyle_tx_result>);
  hyle_fn(L, "validators", guarded<lua_ces_hyle_validators>);
  hyle_fn(L, "submit",     guarded<lua_ces_hyle_submit>);
  hyle_fn(L, "vote_add",    guarded<lua_ces_hyle_vote_add>);
  hyle_fn(L, "vote_remove", guarded<lua_ces_hyle_vote_remove>);

  lua_newtable(L);  // ces.hyle.op
  hyle_fn(L, "transfer",   guarded<lua_ces_hyle_op_transfer>);
  hyle_fn(L, "fund",       guarded<lua_ces_hyle_op_fund>);
  hyle_fn(L, "entry_put",  guarded<lua_ces_hyle_op_entry_put>);
  hyle_fn(L, "entry_del",  guarded<lua_ces_hyle_op_entry_del>);
  hyle_fn(L, "entry_give", guarded<lua_ces_hyle_op_entry_give>);
  hyle_fn(L, "entry_rip",  guarded<lua_ces_hyle_op_entry_rip>);
  lua_setfield(L, -2, "op");

  lua_newtable(L);  // ces.hyle.sudo
  hyle_fn(L, "propose", guarded<lua_ces_hyle_sudo_propose>);
  hyle_fn(L, "approve", guarded<lua_ces_hyle_sudo_approve>);
  hyle_fn(L, "pending", guarded<lua_ces_hyle_sudo_pending>);
  hyle_fn(L, "submit",  guarded<lua_ces_hyle_sudo_submit>);
  hyle_fn(L, "quorum",  guarded<lua_ces_hyle_sudo_quorum>);
  lua_newtable(L);  // ces.hyle.sudo.op
  hyle_fn(L, "mint",       guarded<lua_ces_hyle_sudo_op_mint>);
  hyle_fn(L, "seize",      guarded<lua_ces_hyle_sudo_op_seize>);
  hyle_fn(L, "entry_put",  guarded<lua_ces_hyle_sudo_op_entry_put>);
  hyle_fn(L, "entry_give", guarded<lua_ces_hyle_sudo_op_entry_give>);
  hyle_fn(L, "entry_del",  guarded<lua_ces_hyle_sudo_op_entry_del>);
  hyle_fn(L, "entry_rip",  guarded<lua_ces_hyle_sudo_op_entry_rip>);
  lua_setfield(L, -2, "op");
  lua_setfield(L, -2, "sudo");

  lua_newtable(L);  // ces.hyle.solo
  hyle_fn(L, "start", guarded<lua_ces_hyle_start>);
  hyle_fn(L, "tick",  guarded<lua_ces_hyle_tick>);
  hyle_fn(L, "stop",  guarded<lua_ces_hyle_stop>);
  lua_setfield(L, -2, "solo");

  lua_newtable(L);  // ces.hyle.net
  hyle_fn(L, "start", guarded<lua_ces_hyle_net_start>);
  hyle_fn(L, "tick",  guarded<lua_ces_hyle_net_tick>);
  hyle_fn(L, "stop",  guarded<lua_ces_hyle_net_stop>);
  lua_setfield(L, -2, "net");

  lua_setfield(L, -2, "hyle");  // ces.hyle = <table>
}

#endif // CES_HYLE
