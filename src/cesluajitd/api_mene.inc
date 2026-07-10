// ---------------------------------------------------------------------------
// mene — the declarative admin-UI library (global `mene`), plus the panel
// frame helpers the extension-admin contract uses.
//
// The library comes embedded in mene::assets (linked; see <mene/assets.h>)
// and is installed into every program VM as the global `mene`. It is pure Lua
// over the sandbox's computation surface (base/string/table/math); its modules
// require() each other, and the sandbox has no require, so installation
// resolves modules from the embedded sources through a loader that exists only
// during this call — program code never sees a require global.
//
// The browser half comes from the same linked mene::assets (served by
// webadmin), so the wire contract between the Lua encoder here and the JS
// renderer there cannot skew across a server binary.
// ---------------------------------------------------------------------------
// <mene/assets.h> is included by main.cpp at file scope: this .inc is included
// inside namespace cesluajitd, where a header include would re-home ::mene.

const char* mene_module_src(const char* name) {
  std::size_t count = 0;
  const ::mene::LuaModule* mods = ::mene::luaModules(count);
  for (std::size_t i = 0; i < count; i++) {
    if (std::strcmp(mods[i].name, name) == 0) return mods[i].src;
  }
  return nullptr;
}

// require(name) over the embedded sources; upvalue 1 is the module cache.
int lua_mene_require(lua_State* L) {
  const char* name = luaL_checkstring(L, 1);
  lua_getfield(L, lua_upvalueindex(1), name);
  if (!lua_isnil(L, -1)) return 1;
  lua_pop(L, 1);
  const char* src = mene_module_src(name);
  if (!src) return luaL_error(L, "module '%s' not found", name);
  std::string chunkname = std::string("=") + name;
  if (luaL_loadbufferx(L, src, std::strlen(src), chunkname.c_str(), "t") != 0)
    return lua_error(L);
  lua_call(L, 0, 1);                       // module chunk returns its table
  lua_pushvalue(L, -1);
  lua_setfield(L, lua_upvalueindex(1), name);
  return 1;
}

// Install the global `mene`. Called once at VM setup, before any program code.
void install_mene_lib(lua_State* L) {
  lua_newtable(L);                          // module cache (loader upvalue)
  lua_pushcclosure(L, lua_mene_require, 1);
  lua_pushvalue(L, -1);
  lua_setglobal(L, "require");              // inter-module requires resolve here
  lua_pushstring(L, "mene");
  if (lua_pcall(L, 1, 1, 0) != 0) {
    host_log(4, std::string("mene install failed: ") + lua_err_str(L));
    lua_pop(L, 1);
  } else {
    lua_setglobal(L, "mene");
  }
  lua_pushnil(L);
  lua_setglobal(L, "require");              // loader gone again
}

// ---- panel frame helpers (used by the extension-admin contract) -----------

// Minimal JSON string escape for toast frames built on the C++ side.
std::string mene_json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('"');
  return out;
}

// {"type":"toast","level":"error","text":...} — the panel error shape. Errors
// travel as frames (the browser shows them), never as transport failures.
std::string mene_toast_frame(const std::string& msg) {
  return std::string("{\"type\":\"toast\",\"level\":\"error\",\"text\":") +
         mene_json_escape(msg) + "}";
}

// Only wire frames may leave the VM: the host splices these strings verbatim
// into its own envelope JSON, so an arbitrary program string could otherwise
// spoof other message types (JSON duplicate-key semantics). mene only ever
// produces these two shapes.
bool mene_is_wire_frame(const char* p, size_t n) {
  static const char kRender[] = "{\"type\":\"render\"";
  static const char kToast[]  = "{\"type\":\"toast\"";
  return (n >= sizeof(kRender) - 1 &&
          std::memcmp(p, kRender, sizeof(kRender) - 1) == 0) ||
         (n >= sizeof(kToast) - 1 &&
          std::memcmp(p, kToast, sizeof(kToast) - 1) == 0);
}

// Call app:render_frame() on the registry-pinned panel app; returns a render
// frame, or a toast frame on any Lua error. Balanced stack.
std::string mene_panel_render(lua_State* L, int panelRef) {
  int base = lua_gettop(L);
  lua_rawgeti(L, LUA_REGISTRYINDEX, panelRef);
  lua_getfield(L, -1, "render_frame");
  if (!lua_isfunction(L, -1)) {
    lua_settop(L, base);
    return mene_toast_frame("panel has no render_frame (not a mene.app?)");
  }
  lua_pushvalue(L, -2);                     // self
  if (lua_pcall(L, 1, 1, 0) != 0) {
    std::string err = lua_err_str(L);
    lua_settop(L, base);
    return mene_toast_frame(err);
  }
  size_t n = 0;
  const char* p = lua_tolstring(L, -1, &n);
  // Same wire-frame gate as the push path: the reply is spliced into host
  // JSON, and a program may have replaced render_frame with its own.
  std::string frame = (p && mene_is_wire_frame(p, n))
    ? std::string(p, n)
    : mene_toast_frame("panel render did not produce a wire frame");
  lua_settop(L, base);
  return frame;
}

// ---- live push (webadmin WebSocket lane) ----------------------------------
// Two producers, one wire tag (TAG_EXT_UI_PUSH):
//   * the mene push bridge: __mene_host_push, installed when a panel registers.
//     mene's App:dispatch auto-pushes through it, and an extension may call
//     app:push() for immediacy. Fires the instant state changes.
//   * the change-detect tick: while the host says someone is watching
//     (TAG_EXT_UI_WATCH), render every ~500ms and push ONLY when the frame's
//     hash changed — spontaneous updates (ces.every mutations) reach the
//     browser with no polling anywhere and no extension code.
// Both producers update the same last-pushed hash, so neither re-sends what
// the other already delivered.

bool     g_ext_ui_watch = false;
uint64_t g_ext_ui_last_hash = 0;
uint64_t g_ext_ui_next_check_us = 0;
constexpr uint64_t kExtUiCheckIntervalUs = 500 * 1000;
constexpr size_t   kExtUiMaxFrame = 1 << 20;   // sanity cap on a pushed frame

uint64_t mene_frame_hash(const char* p, size_t n) {
  Sha256Ctx c;
  sha256_init(c);
  sha256_update(c, reinterpret_cast<const uint8_t*>(p), n);
  uint8_t d[32];
  sha256_final(c, d);
  uint64_t h = 0;
  for (int i = 0; i < 8; i++) h = (h << 8) | d[i];
  return h;
}

void mene_ui_push_frame(const char* p, size_t n) {
  if (n == 0 || n > kExtUiMaxFrame) return;
  if (!mene_is_wire_frame(p, n)) return;
  g_ext_ui_last_hash = mene_frame_hash(p, n);
  write_frame(TAG_EXT_UI_PUSH, 0, reinterpret_cast<const uint8_t*>(p), n);
}

// __mene_host_push(frame): the mene push bridge target. The mene app always
// hands a complete frame string (render or toast).
int lua_mene_host_push(lua_State* L) {
  size_t n = 0;
  const char* p = lua_tolstring(L, 1, &n);
  if (p) mene_ui_push_frame(p, n);
  return 0;
}

// The change-detect tick, called from the run loop. Cheap when idle: gated on
// watch + a 500ms deadline before any Lua runs.
void mene_ui_tick(lua_State* L, int panelRef) {
  if (!g_ext_ui_watch || panelRef == LUA_NOREF) return;
  uint64_t now = timer_now_us();
  if (now < g_ext_ui_next_check_us) return;
  g_ext_ui_next_check_us = now + kExtUiCheckIntervalUs;
  std::string frame = mene_panel_render(L, panelRef);
  if (frame.empty() || frame.size() > kExtUiMaxFrame) return;
  uint64_t h = mene_frame_hash(frame.data(), frame.size());
  if (h == g_ext_ui_last_hash) return;
  g_ext_ui_last_hash = h;
  write_frame(TAG_EXT_UI_PUSH, 0,
              reinterpret_cast<const uint8_t*>(frame.data()), frame.size());
}

// Decode an event JSON and run app:dispatch(event), then render. Any Lua error
// (malformed event, update/view throw) becomes a toast frame. Balanced stack.
std::string mene_panel_event(lua_State* L, int panelRef,
                             const uint8_t* ev, size_t evLen) {
  int base = lua_gettop(L);
  // mene.decode_event(evJson) -> {on, value}
  lua_getglobal(L, "mene");
  if (!lua_istable(L, -1)) {
    lua_settop(L, base);
    return mene_toast_frame("mene library not installed");
  }
  lua_getfield(L, -1, "decode_event");
  lua_pushlstring(L, reinterpret_cast<const char*>(ev), evLen);
  if (lua_pcall(L, 1, 1, 0) != 0) {
    std::string err = lua_err_str(L);
    lua_settop(L, base);
    return mene_toast_frame(err);
  }
  // app:dispatch(event)
  lua_rawgeti(L, LUA_REGISTRYINDEX, panelRef);
  lua_getfield(L, -1, "dispatch");
  if (!lua_isfunction(L, -1)) {
    lua_settop(L, base);
    return mene_toast_frame("panel has no dispatch (not a mene.app?)");
  }
  lua_pushvalue(L, -2);                     // self
  lua_pushvalue(L, -4);                     // event table
  if (lua_pcall(L, 2, 1, 0) != 0) {
    std::string err = lua_err_str(L);
    lua_settop(L, base);
    return mene_toast_frame(err);
  }
  lua_settop(L, base);
  return mene_panel_render(L, panelRef);
}
