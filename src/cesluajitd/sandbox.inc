// ---------------------------------------------------------------------------
// Sandbox: load ONLY the safe standard libraries (default-deny).
// ---------------------------------------------------------------------------
//
// Rather than open everything (luaL_openlibs) and remove the dangerous
// libraries afterward, open only the safe subset — base, string, table,
// math, bit — so os / io / debug / package / ffi / jit are never present
// at all, regardless of any removal list. None of the loaded libraries
// expose a filesystem, process, or memory-unsafe surface. A text program
// can only reach what's here plus the ces.* bindings; it cannot fabricate
// access to unbound C (no ffi, no pointers), and bytecode never reaches
// the VM (main()'s program loader is text-only).

void load_safe_libs(lua_State* L) {
  // Open ONLY the safe computation libraries. luaL_openlibs is never
  // called, so os, io, debug, package, ffi, and jit are never present in
  // the VM at all — there is no removal list to get wrong for those. What
  // remains is a pure computation surface: numbers, strings, tables, bit
  // ops, plus the ces.* host bindings installed separately.
  static const luaL_Reg kSafeLibs[] = {
    { "",       luaopen_base },   // also brings coroutine.* (in-VM, benign)
    { "table",  luaopen_table },
    { "string", luaopen_string },
    { "math",   luaopen_math },
    { "bit",    luaopen_bit },
    { nullptr,  nullptr }
  };
  for (const luaL_Reg* lib = kSafeLibs; lib->func; ++lib) {
    lua_pushcfunction(L, lib->func);
    lua_pushstring(L, lib->name);
    lua_call(L, 1, 0);
  }

  // The base library brings code loaders, environment reflection, GC
  // control, and print; remove all of them. After this there is no way
  // for program text to load code/bytecode, reach another stack frame's
  // environment, drive the collector, or write to stdout (which goes
  // nowhere for the daemon child anyway).
  static const char* const kRemoveGlobals[] = {
    "load", "loadstring", "dofile", "loadfile", // code / bytecode loaders
    "getfenv", "setfenv",                       // environment reflection
    "collectgarbage", "gcinfo",                 // GC control / mem info leak
    "newproxy",                                 // userdata fabrication
    "print",                                    // stdout goes nowhere here
    nullptr
  };
  for (int i = 0; kRemoveGlobals[i] != nullptr; ++i) {
    lua_pushnil(L);
    lua_setglobal(L, kRemoveGlobals[i]);
  }

  // string.dump serializes a function to BYTECODE. Nothing here can load
  // it back (the loaders are gone, and main()'s program loader is
  // text-only), but remove it anyway: the program surface deals in text,
  // never bytecode, in either direction.
  lua_getglobal(L, "string");
  if (lua_istable(L, -1)) {
    lua_pushnil(L);
    lua_setfield(L, -2, "dump");
  }
  lua_pop(L, 1);
}

