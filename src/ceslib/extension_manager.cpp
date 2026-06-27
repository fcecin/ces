// extension_manager.cpp - see ces/extension_manager.h.

#include <ces/extension_manager.h>

#include <ces/buffer.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/server.h>
#include <ces/types.h>

#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <utility>

namespace fs = std::filesystem;

namespace ces {
namespace {

// A name must be a bare basename: letters/digits/._- only, no "..". Keeps every
// derived path inside the catalog or /s/.
bool validName(const std::string& n) {
  if (n.empty() || n.size() > 64) return false;
  for (char c : n)
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' ||
          c == '_' || c == '-'))
      return false;
  if (n.find("..") != std::string::npos) return false;
  return true;
}

// builtin:file is a per-server object now; the /s/ file ops route through it.
// Thin guarded wrappers keep the old "" / false-on-disabled contract.
std::string fhReadServerFile(CesServer* s, const std::string& name) {
  FileHandler* fh = s ? s->fileHandler() : nullptr;
  return fh ? fh->readServerFile(name) : std::string();
}
bool fhWriteServerFile(CesServer* s, const std::string& name,
                       const std::string& content) {
  FileHandler* fh = s ? s->fileHandler() : nullptr;
  return fh && fh->writeServerFile(name, content);
}
bool fhRemoveServerFile(CesServer* s, const std::string& name) {
  FileHandler* fh = s ? s->fileHandler() : nullptr;
  return fh && fh->removeServerFile(name);
}

std::string catalogDir(CesServer* s) { return s->_config().cesExtensionsDir; }
fs::path storeSDir(CesServer* s) {
  return fs::path(s->_config().cesFileStoreDir) / "s";
}
fs::path catalogLua(CesServer* s, const std::string& n) {
  return fs::path(catalogDir(s)) / (n + ".lua");
}
fs::path sLua(CesServer* s, const std::string& n) {
  return storeSDir(s) / (n + ".lua");
}
std::string srcName(const std::string& n) { return "/s/" + n + ".lua"; }

// Pid of the running instance of /s/<name>.lua, or 0.
uint64_t runningPid(CesServer* server, const std::string& name) {
  ComputeHandler* h = server ? server->computeHandler() : nullptr;
  if (!h) return 0;
  std::string src = srcName(name);
  for (auto& st : h->snapshot())
    if (st.source == src) return st.pid;
  return 0;
}

// /s/ file I/O is in the file handler (FileHandler::read/write/removeServerFile),
// reached via the guarded fhReadServerFile / fhWriteServerFile / fhRemoveServerFile.

struct ProbedManifest { std::string name, version, description; };

std::string shellQuote(const std::string& s) {
  std::string r = "'";
  for (char c : s) { if (c == '\'') r += "'\\''"; else r += c; }
  r += "'";
  return r;
}

// Identity for a NOT-running extension: run its file through
// `cesluajitd --manifest`, which loadfile-evaluates the static CES_MANIFEST table
// in a no-op sandbox (no source-text parsing). Cached by (path, mtime) so the
// subprocess runs once per file version, not per dashboard poll. Empty on any
// failure (binary missing, no manifest) -> the row shows its filename.
ProbedManifest probeManifest(CesServer* s, const fs::path& path) {
  static std::mutex mx;
  static std::map<std::string, std::pair<int64_t, ProbedManifest>> cache;
  std::error_code ec;
  auto mt = fs::last_write_time(path, ec);
  if (ec) return {};
  int64_t key = static_cast<int64_t>(mt.time_since_epoch().count());
  std::string ps = path.string();
  {
    std::lock_guard<std::mutex> lk(mx);
    auto it = cache.find(ps);
    if (it != cache.end() && it->second.first == key) return it->second.second;
  }
  ProbedManifest out;
  std::string cmd = shellQuote(s->_config().cesComputeChildBinary) +
                    " --manifest " + shellQuote(ps) + " 2>/dev/null";
  if (FILE* p = ::popen(cmd.c_str(), "r")) {
    std::string* fields[3] = { &out.name, &out.version, &out.description };
    char line[1024];
    for (int i = 0; i < 3 && std::fgets(line, sizeof(line), p); i++) {
      std::string v(line);
      while (!v.empty() && (v.back() == '\n' || v.back() == '\r')) v.pop_back();
      *fields[i] = v;
    }
    ::pclose(p);
  }
  std::lock_guard<std::mutex> lk(mx);
  cache[ps] = { key, out };
  return out;
}

// Pull a /s/<name>.lua source path back to its bare name, "" if it isn't one.
std::string nameFromSource(const std::string& src) {
  const std::string pre = "/s/", suf = ".lua";
  if (src.size() <= pre.size() + suf.size()) return "";
  if (src.compare(0, pre.size(), pre) != 0) return "";
  if (src.compare(src.size() - suf.size(), suf.size(), suf) != 0) return "";
  std::string n = src.substr(pre.size(), src.size() - pre.size() - suf.size());
  return validName(n) ? n : std::string();
}

}  // namespace

std::vector<ExtensionItem> extensionList(CesServer* server) {
  std::map<std::string, ExtensionItem> byName;
  std::error_code ec;

  if (!catalogDir(server).empty())
    for (auto& e : fs::directory_iterator(catalogDir(server), ec)) {
      if (e.path().extension() != ".lua") continue;
      std::string n = e.path().stem().string();
      if (!validName(n)) continue;
      byName[n].name = n;
      byName[n].available = true;
    }
  ec.clear();
  for (auto& e : fs::directory_iterator(storeSDir(server), ec)) {
    if (e.path().extension() != ".lua") continue;
    std::string n = e.path().stem().string();
    if (!validName(n)) continue;
    byName[n].name = n;
    byName[n].installed = true;
  }
  ComputeHandler* ch = server->computeHandler();
  for (auto& st : ch ? ch->snapshot() : std::vector<ComputeInstanceStat>{}) {
    std::string n = nameFromSource(st.source);
    if (n.empty()) continue;
    auto& it = byName[n];
    it.name = n;
    it.enabled = true;
    it.pid = st.pid;
    ComputeExtInfo info;
    if (ch->extInfo(st.pid, info)) {
      // Identity from the live CES_MANIFEST report (present even with no contract).
      if (!info.name.empty()) it.displayName = info.name;
      it.version = info.version;
      it.description = info.description;
      // Admin contract from ces.extension_admin{} (may be absent — dice).
      if (info.isExtension) {
        it.isExtension = true;
        it.caps = info.caps;
        it.commands = info.commands;
      }
    }
  }
  // Not-running rows: harvest CES_MANIFEST from the file via the cesluajitd probe
  // (cached). Enabled rows already have identity from the live report above.
  for (auto& kv : byName) {
    auto& it = kv.second;
    if (it.enabled) continue;
    fs::path f = it.available ? catalogLua(server, it.name) : sLua(server, it.name);
    ProbedManifest pm = probeManifest(server, f);
    if (!pm.name.empty()) it.displayName = pm.name;
    it.version = pm.version;
    it.description = pm.description;
  }
  std::vector<ExtensionItem> out;
  out.reserve(byName.size());
  for (auto& kv : byName) out.push_back(std::move(kv.second));
  return out;
}

bool extensionInstall(CesServer* server, const std::string& name) {
  if (!validName(name) || catalogDir(server).empty()) return false;
  std::error_code ec;
  if (!fs::exists(catalogLua(server, name), ec)) return false;
  // The catalog is an external operator directory, not the file store: read it
  // directly, then hand the bytes to the file store to land in /s/.
  std::ifstream in(catalogLua(server, name), std::ios::binary);
  if (!in) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  return fhWriteServerFile(server, "/s/" + name + ".lua", ss.str());
}

bool extensionUninstall(CesServer* server, const std::string& name) {
  if (!validName(name)) return false;
  if (ComputeHandler* h = server->computeHandler()) h->killBySource(srcName(name));
  fhRemoveServerFile(server, "/s/" + name + ".lua");
  return true;
}

bool extensionEnable(CesServer* server, const std::string& name) {
  if (!validName(name)) return false;
  std::error_code ec;
  if (!fs::exists(sLua(server, name), ec)) return false;
  ComputeHandler* h = server->computeHandler();
  return h && h->launchInternal(srcName(name)) == CES_OK;
}

bool extensionDisable(CesServer* server, const std::string& name) {
  if (!validName(name)) return false;
  if (ComputeHandler* h = server->computeHandler()) h->killBySource(srcName(name));
  return true;
}

bool extensionStatus(CesServer* server, const std::string& name,
                     std::vector<std::pair<std::string, std::string>>& kv) {
  ComputeHandler* h = server->computeHandler();
  if (!h) return false;
  uint64_t pid = runningPid(server, name);
  if (!pid) return false;
  ces::Bytes out;
  if (!h->extRequest(pid, kComputeExtReqStatus, ces::Bytes{}, out, 2000))
    return false;
  if (out.size() < 2) return true;
  size_t o = 0;
  uint16_t count = ces::Buffer::peek<uint16_t>(out.data());
  o = 2;
  for (uint16_t i = 0; i < count; i++) {
    if (out.size() < o + 2) break;
    uint16_t kn = ces::Buffer::peek<uint16_t>(out.data() + o); o += 2;
    if (out.size() < o + kn) break;
    std::string k(reinterpret_cast<const char*>(out.data()) + o, kn); o += kn;
    if (out.size() < o + 2) break;
    uint16_t vn = ces::Buffer::peek<uint16_t>(out.data() + o); o += 2;
    if (out.size() < o + vn) break;
    std::string v(reinterpret_cast<const char*>(out.data()) + o, vn); o += vn;
    kv.emplace_back(std::move(k), std::move(v));
  }
  return true;
}

bool extensionCommand(CesServer* server, const std::string& name,
                      const std::string& id, const std::string& arg,
                      std::string& out) {
  ComputeHandler* h = server->computeHandler();
  if (!h) return false;
  uint64_t pid = runningPid(server, name);
  if (!pid) return false;
  ces::Bytes in;
  in.push_back(static_cast<uint8_t>((id.size() >> 8) & 0xFF));
  in.push_back(static_cast<uint8_t>(id.size() & 0xFF));
  in.insert(in.end(), id.begin(), id.end());
  in.insert(in.end(), arg.begin(), arg.end());
  ces::Bytes outb;
  if (!h->extRequest(pid, kComputeExtReqCommand, in, outb, 5000))
    return false;
  out.assign(reinterpret_cast<const char*>(outb.data()), outb.size());
  return true;
}

std::string extensionConfigGet(CesServer* server, const std::string& name) {
  if (!validName(name)) return "";
  return fhReadServerFile(server, "/s/" + name + ".conf");
}

// Make the on-disk /s/<name>.conf take effect on the running instance. Config is
// read at launch, so a program that registered on_config hot-reloads live; one
// that did not can only pick up the change by relaunching. Either way an edit
// actually takes effect -- writing the file and changing nothing (a silent
// no-op) is worse than having no editor. No-op if the extension is not running.
void applyExtConfig(CesServer* server, const std::string& name) {
  ComputeHandler* h = server->computeHandler();
  if (!h) return;
  uint64_t pid = runningPid(server, name);
  if (!pid) return;
  ComputeExtInfo info;
  if (h->extInfo(pid, info) && (info.caps & kComputeExtCapOnConfig)) {
    h->extConfig(pid, fhReadServerFile(server, "/s/" + name + ".conf"));  // hot-reload
  } else {
    h->killBySource(srcName(name));                     // relaunch:
    h->launchInternal(srcName(name));                   // re-read at launch
  }
}

bool extensionConfigSet(CesServer* server, const std::string& name,
                        const std::string& text) {
  if (!validName(name)) return false;
  if (!fhWriteServerFile(server, "/s/" + name + ".conf", text)) return false;
  applyExtConfig(server, name);
  return true;
}

bool extensionConfigReset(CesServer* server, const std::string& name) {
  if (!validName(name)) return false;
  ComputeHandler* h = server->computeHandler();
  if (!h) return false;
  uint64_t pid = runningPid(server, name);
  if (!pid) return false;
  ComputeExtInfo info;
  if (!h->extInfo(pid, info)) return false;
  if (!fhWriteServerFile(server, "/s/" + name + ".conf", info.configDefaults)) return false;
  applyExtConfig(server, name);
  return true;
}

}  // namespace ces
