// ---------------------------------------------------------------------------
// ces.hyle.solo - a SINGLE-NODE (transportless) hyle-services blockchain hosted
// IN this cesluajitd process. Extension-only: registered solely for privileged
// (/s/) programs.
//
// "solo" is a deliberate sub-namespace: these primitives are hardcoded to the
// one-validator, no-transport case (Runtime with transport == nullptr, genesis
// validator set == {self}), which is why they are hand-driven -- tick() means
// "synchronously produce exactly one block." A future transport-enabled multi-node
// API (validators across servers, meshed over dedicated CesPlex channels) would
// live under a different ces.hyle.* name and be event-driven, not ticked; the root
// ces.hyle namespace is reserved for it.
//
// Only present when the node was built with --hyle (CES_HYLE): hyle_services is
// statically linked, so these calls drive a hyle::morphe::Runtime DIRECTLY -- no
// host IPC. Solo means the program's own key is the sole validator and proposer,
// so a tick reaches its own 1-of-1 quorum and proposes+precommits+commits
// synchronously, then returns -- it never blocks the cooperative Lua VM. In-RAM
// only: stop() (or the process dying on disable) drops the chain; a later start()
// boots a fresh one from the current config.
//
// Surface (see apps/hylesolo in cesdk for the extension that drives it):
//   ces.hyle.solo.start{ chain_id=, block_pace_ms=, alloc=, fee_transfer=,
//                        fee_entry=, fee_mint=, reward_base= }  -> true, or nil,err
//   ces.hyle.solo.tick()     -- advance exactly one height (one block); -> new height
//   ces.hyle.solo.height()   -- committed height (number)
//   ces.hyle.solo.chain_id() -- string
//   ces.hyle.solo.balance()  -- the sole validator's own minted balance (number)
//   ces.hyle.solo.accounts() -- current account (a) cell count in the RAM state
//   ces.hyle.solo.entries()  -- current entry (e) cell count in the RAM state
//   ces.hyle.solo.last_block_time() -- PBTS wall-time (unix seconds) of the last block
//   ces.hyle.solo.txs()      -- lifetime ops committed into blocks (RAM, reset on start)
//   ces.hyle.solo.queries()  -- lifetime chain-read binding calls (RAM, reset on start)
//   ces.hyle.solo.running()  -- bool
//   ces.hyle.solo.stop()     -- destroy the node
// ---------------------------------------------------------------------------
#ifdef CES_HYLE

// hyle headers are included at global scope in main.cpp (guarded by CES_HYLE):
// this .inc is textually inside `namespace cesluajitd`, and library/std headers
// must not be included inside a namespace.

static std::unique_ptr<hyle::morphe::Runtime> g_hyle_node;
static std::unique_ptr<hyle::KeyPair> g_hyle_key;  // the sole validator (== the program key)
static std::string g_hyle_chain;

// Lifetime meters (RAM, reset on start): txs summed from the commit event, queries bumped by the getters.
static uint64_t g_hyle_txs = 0;
static uint64_t g_hyle_queries = 0;

// Read a uint64 field from the config table at stack index 1 (default if absent/non-numeric).
static uint64_t hyle_cfg_u64(lua_State* L, const char* key, uint64_t def) {
  lua_getfield(L, 1, key);
  uint64_t v = lua_isnumber(L, -1) ? static_cast<uint64_t>(lua_tonumber(L, -1)) : def;
  lua_pop(L, 1);
  return v;
}

int lua_ces_hyle_start(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  if (g_hyle_node) { lua_pushboolean(L, 1); return 1; }  // idempotent: already running

  lua_getfield(L, 1, "chain_id");
  g_hyle_chain = lua_isstring(L, -1) ? lua_tostring(L, -1) : "hyle-hello";
  lua_pop(L, 1);

  // The sole validator is derived deterministically from this program's own secret, so the 1-node
  // chain's identity is stable across restarts and tied to the program.
  hyle::PrivKey secret{};
  std::memcpy(secret.data(), g_program_privkey, 32);
  g_hyle_key = std::make_unique<hyle::KeyPair>(hyle::KeyPair::from_secret(secret));

  hyle::morphe::Genesis g;
  g.chain_id = g_hyle_chain;
  g.validators = { g_hyle_key->pub };
  g.allocations = { { g_hyle_key->pub, hyle_cfg_u64(L, "alloc", 1000000000ull) } };
  g.config.fee_transfer = hyle_cfg_u64(L, "fee_transfer", 1);
  g.config.fee_entry    = hyle_cfg_u64(L, "fee_entry", 1);
  g.config.fee_mint     = hyle_cfg_u64(L, "fee_mint", 1);
  g.config.reward_base  = hyle_cfg_u64(L, "reward_base", 2);

  std::string err;
  if (!g.validate(err)) {
    g_hyle_key.reset();
    lua_pushnil(L);
    lua_pushstring(L, ("hyle genesis invalid: " + err).c_str());
    return 2;
  }

  const uint64_t pace = hyle_cfg_u64(L, "block_pace_ms", 1000);  // Lua drives the ticks; pace is advisory
  g_hyle_node = std::make_unique<hyle::morphe::Runtime>(g, *g_hyle_key, pace, nullptr);

  // reset meters and count committed ops per block
  g_hyle_txs = 0;
  g_hyle_queries = 0;
  g_hyle_node->app().add_on_commit(
    [](const hyle::morphe::CommitEvent& ev) { g_hyle_txs += ev.txs.size(); });

  lua_pushboolean(L, 1);
  return 1;
}

int lua_ces_hyle_tick(lua_State* L) {
  if (!g_hyle_node) { lua_pushnil(L); return 1; }
  g_hyle_node->run_to(g_hyle_node->height() + 1);  // solo self-quorum: synchronous, non-blocking
  lua_pushnumber(L, static_cast<lua_Number>(g_hyle_node->height()));
  return 1;
}

int lua_ces_hyle_height(lua_State* L) {
  ++g_hyle_queries;
  lua_pushnumber(L, g_hyle_node ? static_cast<lua_Number>(g_hyle_node->height()) : 0);
  return 1;
}

int lua_ces_hyle_chain_id(lua_State* L) {
  lua_pushlstring(L, g_hyle_chain.data(), g_hyle_chain.size());
  return 1;
}

// balance of the sole validator's own account (minted reward_base per committed block)
int lua_ces_hyle_balance(lua_State* L) {
  ++g_hyle_queries;
  if (!g_hyle_node || !g_hyle_key) { lua_pushnil(L); return 1; }
  lua_pushnumber(L, static_cast<lua_Number>(g_hyle_node->app().balance(g_hyle_key->pub)));
  return 1;
}

int lua_ces_hyle_running(lua_State* L) {
  lua_pushboolean(L, g_hyle_node ? 1 : 0);
  return 1;
}

// State exposes size()/canonical() but no iteration, so count a/e cells over the canonical KV dump.
// The walk lives in ceslib (countCanonicalKvKeyPrefix), unit-tested there.
static uint64_t hyle_canon_count(uint8_t prefix) {
  if (!g_hyle_node) return 0;
  auto canon = g_hyle_node->app().store().canonical();
  return ces::countCanonicalKvKeyPrefix(std::span<const uint8_t>(canon.data(), canon.size()), prefix);
}

int lua_ces_hyle_accounts(lua_State* L) {
  ++g_hyle_queries;
  lua_pushnumber(L, static_cast<lua_Number>(hyle_canon_count(hyle::morphe::ACCOUNT_PREFIX)));
  return 1;
}

int lua_ces_hyle_entries(lua_State* L) {
  ++g_hyle_queries;
  lua_pushnumber(L, static_cast<lua_Number>(hyle_canon_count(hyle::morphe::ENTRY_PREFIX)));
  return 1;
}

// PBTS wall-time (unix seconds) of the last committed block; 0 before the first
int lua_ces_hyle_last_block_time(lua_State* L) {
  ++g_hyle_queries;
  lua_pushnumber(L, g_hyle_node ? static_cast<lua_Number>(g_hyle_node->app().last_timestamp()) : 0);
  return 1;
}

// lifetime ops committed into blocks (from the commit event); reset on start
int lua_ces_hyle_txs(lua_State* L) {
  lua_pushnumber(L, static_cast<lua_Number>(g_hyle_txs));
  return 1;
}

// lifetime chain-read binding calls (height/balance/accounts/entries/last_block_time); reset on start
int lua_ces_hyle_queries(lua_State* L) {
  lua_pushnumber(L, static_cast<lua_Number>(g_hyle_queries));
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

// Install the ces.hyle.solo subtable. Call with the ces table on top of the stack.
void install_ces_hyle_api(lua_State* L) {
  lua_newtable(L);                                      // ces.hyle
  lua_newtable(L);                                      // ces.hyle.solo
  lua_pushcfunction(L, guarded<lua_ces_hyle_start>);    lua_setfield(L, -2, "start");
  lua_pushcfunction(L, guarded<lua_ces_hyle_tick>);     lua_setfield(L, -2, "tick");
  lua_pushcfunction(L, guarded<lua_ces_hyle_height>);   lua_setfield(L, -2, "height");
  lua_pushcfunction(L, guarded<lua_ces_hyle_chain_id>); lua_setfield(L, -2, "chain_id");
  lua_pushcfunction(L, guarded<lua_ces_hyle_balance>);  lua_setfield(L, -2, "balance");
  lua_pushcfunction(L, guarded<lua_ces_hyle_accounts>); lua_setfield(L, -2, "accounts");
  lua_pushcfunction(L, guarded<lua_ces_hyle_entries>);  lua_setfield(L, -2, "entries");
  lua_pushcfunction(L, guarded<lua_ces_hyle_last_block_time>); lua_setfield(L, -2, "last_block_time");
  lua_pushcfunction(L, guarded<lua_ces_hyle_txs>);      lua_setfield(L, -2, "txs");
  lua_pushcfunction(L, guarded<lua_ces_hyle_queries>);  lua_setfield(L, -2, "queries");
  lua_pushcfunction(L, guarded<lua_ces_hyle_running>);  lua_setfield(L, -2, "running");
  lua_pushcfunction(L, guarded<lua_ces_hyle_stop>);     lua_setfield(L, -2, "stop");
  lua_setfield(L, -2, "solo");                          // ces.hyle.solo = <table>
  lua_setfield(L, -2, "hyle");                          // ces.hyle = <table>
}

#endif // CES_HYLE
