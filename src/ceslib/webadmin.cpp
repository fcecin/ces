/**
 * webadmin.cpp — CES server localhost web dashboard.
 *
 * See ces/webadmin.h for the security model (loopback + SSH tunnel, no auth)
 * and architecture (one acceptor + per-connection session, like Cesco).
 */

#include <ces/webadmin.h>

#include <ces/cesplex/meter.h>
#include <ces/extension_manager.h>
#include <ces/feemult.h>
#include <ces/keys.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/protocol.h>
#include <ces/server.h>
#include <ces/util/hex.h>

#include <minx/blog.h>
#include <minx/minx.h>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/log/attributes/value_extraction.hpp>
#include <boost/log/core.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/trivial.hpp>
#include <boost/make_shared.hpp>

#include <array>
#include <cstdint>
#include <future>
#include <ostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <algorithm>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

LOG_MODULE("web");

namespace ces {

// =============================================================================
// LogRing — bounded in-memory tail of recent log lines
// =============================================================================

LogRing& LogRing::instance() {
  static LogRing ring;
  return ring;
}

void LogRing::push(std::string text) {
  std::lock_guard lock(mu_);
  Line ln;
  ln.seq = nextSeq_++;
  ln.ts = minx::getSecsSinceEpoch();
  ln.text = std::move(text);
  lines_.push_back(std::move(ln));
  while (lines_.size() > kCap)
    lines_.pop_front();
}

std::vector<LogRing::Line> LogRing::since(uint64_t sinceSeq,
                                          uint64_t& outHi) const {
  std::lock_guard lock(mu_);
  std::vector<Line> out;
  for (const auto& l : lines_)
    if (l.seq > sinceSeq)
      out.push_back(l);
  outHi = nextSeq_ - 1;
  return out;
}

// =============================================================================
// Boost.Log sink → LogRing
//
// blog is a Boost.Log facade with no sink hook, but the core takes custom
// sinks. We add a text_ostream sink whose stream is backed by a streambuf
// that splits on '\n' and pushes each finished line into the ring. The
// formatter mirrors the console one's attribute extraction (minus color and
// timestamp — the ring stamps unix time at push) so VAR(x) fields show up.
// =============================================================================

namespace {

class RingStreambuf : public std::streambuf {
protected:
  int overflow(int c) override {
    if (c == EOF) return c;
    char ch = static_cast<char>(c);
    if (ch == '\n') flushLine();
    else cur_.push_back(ch);
    return c;
  }
  std::streamsize xsputn(const char* s, std::streamsize n) override {
    for (std::streamsize i = 0; i < n; ++i) {
      if (s[i] == '\n') flushLine();
      else cur_.push_back(s[i]);
    }
    return n;
  }

private:
  void flushLine() {
    if (!cur_.empty()) {
      LogRing::instance().push(std::move(cur_));
      cur_.clear();
    }
  }
  std::string cur_;
};

void webLogFormatter(boost::log::record_view const& rec,
                     boost::log::formatting_ostream& strm) {
  auto sev = rec[boost::log::trivial::severity];
  if (sev) {
    switch (sev.get()) {
      case blog::trace:   strm << "TRC"; break;
      case blog::debug:   strm << "DBG"; break;
      case blog::info:    strm << "INF"; break;
      case blog::warning: strm << "WRN"; break;
      case blog::error:   strm << "ERR"; break;
      case blog::fatal:   strm << "FTL"; break;
      default:            strm << "LOG"; break;
    }
    strm << ' ';
  }
  if (auto ch = boost::log::extract<std::string>("Channel", rec)) {
    const std::string& c = ch.get();
    if (!c.empty()) strm << c << ' ';
  }
  if (auto msg = boost::log::extract<std::string>("Message", rec))
    strm << msg.get();

  for (auto const& a : rec.attribute_values()) {
    const std::string& name = a.first.string();
    if (name == "Severity" || name == "Message" || name == "Channel" ||
        name == "TimeStamp" || name == "File" || name == "Line" ||
        name == "Inst")
      continue;
    strm << ' ' << name << '=';
    if (auto v = boost::log::extract<std::string>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<const char*>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<std::array<uint8_t, 32>>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<std::array<uint8_t, 8>>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<std::vector<uint8_t>>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<std::vector<char>>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<uint64_t>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<uint32_t>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<uint16_t>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<uint8_t>(name, rec)) strm << static_cast<unsigned>(v.get());
    else if (auto v = boost::log::extract<int64_t>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<int32_t>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<int16_t>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<int8_t>(name, rec)) strm << static_cast<int>(v.get());
    else if (auto v = boost::log::extract<bool>(name, rec)) strm << (v.get() ? "true" : "false");
    else if (auto v = boost::log::extract<boost::asio::ip::udp::endpoint>(name, rec)) strm << v.get();
    else if (auto v = boost::log::extract<boost::asio::ip::address>(name, rec)) strm << v.get();
    else strm << "[?]";
  }

  if (auto file = boost::log::extract<std::string>("File", rec)) {
    if (auto line = boost::log::extract<int>("Line", rec))
      strm << ' ' << boost::filesystem::path(file.get()).filename().string()
           << ':' << line.get();
  }
}

using text_sink =
  boost::log::sinks::synchronous_sink<boost::log::sinks::text_ostream_backend>;
boost::shared_ptr<text_sink> g_logSink;

void installLogSink() {
  if (g_logSink) return;
  static RingStreambuf ringbuf;  // process-lifetime; sink may detach/reattach
  auto backend = boost::make_shared<boost::log::sinks::text_ostream_backend>();
  backend->add_stream(boost::shared_ptr<std::ostream>(new std::ostream(&ringbuf)));
  backend->auto_flush(true);
  auto sink = boost::make_shared<text_sink>(backend);
  sink->set_formatter(&webLogFormatter);
  boost::log::core::get()->add_sink(sink);
  g_logSink = sink;
}

void removeLogSink() {
  if (!g_logSink) return;
  boost::log::core::get()->remove_sink(g_logSink);
  g_logSink.reset();
}

uint64_t g_webStartUnix = 0;

// Worker threads for the blocking remote ops (inspect/mine). They hold a
// CesServer& and a session shared_ptr, so they must finish before the server
// is torn down — joined in WebAdmin::stop() rather than detached. A mine
// respects ces::notInterrupted(), so a Ctrl-C unwinds these promptly.
std::mutex g_workerMu;
std::vector<std::thread> g_workers;

void addWorker(std::thread t) {
  std::lock_guard lock(g_workerMu);
  g_workers.push_back(std::move(t));
}
void joinWorkers() {
  std::vector<std::thread> ws;
  {
    std::lock_guard lock(g_workerMu);
    ws.swap(g_workers);
  }
  for (auto& t : ws)
    if (t.joinable()) t.join();
}

// ---------------------------------------------------------------------------
// Small text helpers (JSON out, form/query parse, hex)
// ---------------------------------------------------------------------------

std::string jesc(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          static const char* hex = "0123456789abcdef";
          o += "\\u00";
          o += hex[(c >> 4) & 0xF];
          o += hex[c & 0xF];
        } else {
          o += c;
        }
    }
  }
  return o;
}

// JSON string literal (quoted + escaped).
std::string jstr(const std::string& s) { return "\"" + jesc(s) + "\""; }

std::string hexOf(std::span<const uint8_t> b) { return bytesToHex(b); }
std::string hexOfHash(const minx::Hash& h) {
  return bytesToHex(std::span<const uint8_t>(h.data(), h.size()));
}
std::string hexOfPrefix(const HashPrefix& p) {
  return bytesToHex(std::span<const uint8_t>(p.data(), p.size()));
}

int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Parse exactly 64 hex chars into a 32-byte hash. Returns false otherwise.
bool parseHash64(const std::string& s, minx::Hash& out) {
  if (s.size() != 64) return false;
  for (size_t i = 0; i < 32; ++i) {
    int hi = hexNibble(s[i * 2]), lo = hexNibble(s[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

bool parseU64(const std::string& s, uint64_t& out) {
  if (s.empty()) return false;
  uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    if (v > (UINT64_MAX - static_cast<uint64_t>(c - '0')) / 10) return false;
    v = v * 10 + static_cast<uint64_t>(c - '0');
  }
  out = v;
  return true;
}

std::string urlDecode(const std::string& s) {
  std::string o;
  o.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    if (c == '+') {
      o += ' ';
    } else if (c == '%' && i + 2 < s.size()) {
      int hi = hexNibble(s[i + 1]), lo = hexNibble(s[i + 2]);
      if (hi >= 0 && lo >= 0) { o += static_cast<char>((hi << 4) | lo); i += 2; }
      else o += c;
    } else {
      o += c;
    }
  }
  return o;
}

std::map<std::string, std::string> parseKV(const std::string& s) {
  std::map<std::string, std::string> m;
  size_t i = 0;
  while (i < s.size()) {
    size_t amp = s.find('&', i);
    std::string pair = s.substr(i, amp == std::string::npos ? std::string::npos : amp - i);
    size_t eq = pair.find('=');
    if (eq != std::string::npos)
      m[urlDecode(pair.substr(0, eq))] = urlDecode(pair.substr(eq + 1));
    else if (!pair.empty())
      m[urlDecode(pair)] = "";
    if (amp == std::string::npos) break;
    i = amp + 1;
  }
  return m;
}

std::string getParam(const std::map<std::string, std::string>& m,
                     const std::string& k) {
  auto it = m.find(k);
  return it == m.end() ? std::string() : it->second;
}

// ---------------------------------------------------------------------------
// JSON endpoint builders
// ---------------------------------------------------------------------------

// Host unicast IP addresses, non-loopback first, so a node with no serverName
// still shows where it is reachable (the bind is all-interfaces; getifaddrs is
// the only way to know the concrete addresses). Linux/POSIX; runs once per
// /api/status on the loopback-only dashboard, so cost is irrelevant.
std::vector<std::string> hostIpList() {
  std::vector<std::string> normal, loopback;
  struct ifaddrs* ifa = nullptr;
  if (getifaddrs(&ifa) != 0) return normal;
  for (struct ifaddrs* p = ifa; p; p = p->ifa_next) {
    if (!p->ifa_addr) continue;
    char buf[INET6_ADDRSTRLEN] = {0};
    bool isLoopback = false;
    if (p->ifa_addr->sa_family == AF_INET) {
      auto* a = reinterpret_cast<struct sockaddr_in*>(p->ifa_addr);
      if (!inet_ntop(AF_INET, &a->sin_addr, buf, sizeof buf)) continue;
      isLoopback = (ntohl(a->sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u;
    } else if (p->ifa_addr->sa_family == AF_INET6) {
      auto* a = reinterpret_cast<struct sockaddr_in6*>(p->ifa_addr);
      if (IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr)) continue;  // not reachable alone
      if (!inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof buf)) continue;
      isLoopback = IN6_IS_ADDR_LOOPBACK(&a->sin6_addr);
    } else {
      continue;
    }
    std::string ip(buf);
    auto& bucket = isLoopback ? loopback : normal;
    if (std::find(bucket.begin(), bucket.end(), ip) == bucket.end())
      bucket.push_back(ip);
  }
  freeifaddrs(ifa);
  normal.insert(normal.end(), loopback.begin(), loopback.end());
  return normal;
}

std::string buildStatus(CesServer& s) {
  const CesConfig& c = s._config();
  auto stats = s._adminStats();
  std::ostringstream o;
  uint64_t now = minx::getSecsSinceEpoch();
  uint64_t uptime = (g_webStartUnix && now >= g_webStartUnix)
                      ? now - g_webStartUnix : 0;
  o << "{";
  o << "\"pubkey\":" << jstr(hexOfHash(s._serverKeyPair().getPublicKeyAsHash()));
  o << ",\"serverName\":" << jstr(c.serverName);
  o << ",\"boundAddrs\":[";
  {
    auto ips = hostIpList();
    for (size_t i = 0; i < ips.size(); ++i) {
      if (i) o << ",";
      o << jstr(ips[i]);
    }
  }
  o << "]";
  o << ",\"version\":" << jstr(c.version);
  o << ",\"port\":" << s._boundPort();
  o << ",\"rpcPort\":" << s._rpcBoundPort();
  o << ",\"now\":" << now;
  o << ",\"uptime\":" << uptime;
  o << ",\"circulating\":" << stats.circulating;
  o << ",\"accounts\":" << stats.accounts;
  o << ",\"assets\":" << stats.assets;
  o << ",\"txCount\":" << stats.txCount;
  o << ",\"tps\":" << s.getTps();
  o << ",\"minDifficulty\":" << static_cast<unsigned>(c.minDiff);
  o << ",\"gauges\":{"
    << "\"l1cpu\":" << s.getL1cpuBp()
    << ",\"l2cpu\":" << s.getL2cpuBp()
    << ",\"l1memac\":" << s.getL1memacBp()
    << ",\"l1memas\":" << s.getL1memasBp()
    << ",\"l2mem\":" << s.getL2memBp()
    << ",\"net\":" << s.getNetBp() << "}";
  o << ",\"features\":{"
    << "\"rpc\":" << (s._rpcBoundPort() != 0 ? "true" : "false")
    << ",\"file\":" << (c.cesFileStoreMaxBytes > 0 ? "true" : "false")
    << ",\"compute\":" << (c.computeMaxInstances > 0 ? "true" : "false")
    << ",\"peering\":" << (s._peerTarget() > 0 ? "true" : "false")
    << ",\"powReady\":" << (s.isPoWEngineReady() ? "true" : "false") << "}";
  o << ",\"peerCount\":" << s._peerSnapshot().size();
  o << ",\"peerTarget\":" << s._peerTarget();
  o << ",\"minerRunning\":" << (s._peerMinerRunning() ? "true" : "false");
  o << ",\"hello\":" << jstr(s._getHello());
  o << "}";
  return o.str();
}

std::string buildPeers(CesServer& s) {
  auto peers = s._peerSnapshot();
  auto act = s._peerMinerActivity();
  // The vostro half of each pair: the peer's account on THIS server (what we owe
  // them). Looked up from the ledger, not the peer table.
  std::vector<minx::Hash> peerKeys;
  peerKeys.reserve(peers.size());
  for (const auto& p : peers) peerKeys.push_back(p.ckey);
  auto vostro = s._peerVostroBalances(peerKeys);
  std::ostringstream o;
  o << "{\"target\":" << s._peerTarget()
    << ",\"minerRunning\":" << (s._peerMinerRunning() ? "true" : "false")
    << ",\"lastCycle\":" << s._peerMinerLastCycle()
    << ",\"cycles\":" << s._peerMinerCycles()
    << ",\"miningActive\":" << (act.mining ? "true" : "false")
    << ",\"miningPeer\":" << jstr(act.peer)
    << ",\"miningDifficulty\":" << static_cast<int>(act.difficulty)
    << ",\"miningElapsedSecs\":"
    << ((act.mining && act.startSecs &&
         minx::getSecsSinceEpoch() >= act.startSecs)
            ? (minx::getSecsSinceEpoch() - act.startSecs) : 0)
    << ",\"hashRate\":" << static_cast<uint64_t>(act.hashRate)
    << ",\"peers\":[";
  for (size_t i = 0; i < peers.size(); ++i) {
    const auto& p = peers[i];
    if (i) o << ",";
    o << "{\"key\":" << jstr(hexOfHash(p.ckey))
      << ",\"address\":" << jstr(p.declaredAddress)
      << ",\"resolvedIP\":" << jstr(p.resolvedIP)
      << ",\"outbound\":" << (p.outbound ? "true" : "false")
      << ",\"inbound\":" << (p.inbound ? "true" : "false")
      << ",\"reachable\":" << (p.reachable ? "true" : "false")
      << ",\"verified\":" << (p.verified ? "true" : "false")
      << ",\"ourBalanceThere\":" << p.ourBalanceThere
      << ",\"theirBalanceHere\":" << (i < vostro.size() ? vostro[i] : 0)
      << ",\"totalInboundPoW\":" << p.totalInboundPoW
      << ",\"totalOutboundPoW\":" << p.totalOutboundPoW
      << ",\"lastInboundTime\":" << p.lastInboundTime
      << ",\"lastCheckTime\":" << p.lastCheckTime
      << ",\"pingFailures\":" << p.pingFailures << "}";
  }
  o << "]}";
  return o.str();
}

std::string buildNetbill(CesServer& s) {
  std::ostringstream o;
  auto* nb = s._channelMeter();
  o << "{\"active\":" << (nb ? "true" : "false") << ",\"rows\":[";
  if (nb) {
    auto rows = nb->snapshot();
    for (size_t i = 0; i < rows.size(); ++i) {
      const auto& r = rows[i];
      if (i) o << ",";
      std::ostringstream peer;
      peer << r.peer;
      o << "{\"peer\":" << jstr(peer.str())
        << ",\"channelId\":" << r.channelId
        << ",\"tag\":" << jstr(r.tag)
        << ",\"payer\":" << jstr(hexOfPrefix(r.payerPfx))
        << ",\"bytesSent\":" << r.metrics.bytesSent
        << ",\"bytesReceived\":" << r.metrics.bytesReceived
        << ",\"memByteSec\":" << r.metrics.memoryByteSeconds
        << ",\"dSent\":" << r.deltaBytesSent
        << ",\"dRecv\":" << r.deltaBytesReceived
        << ",\"dMemByteSec\":" << r.deltaMemByteSeconds
        << ",\"dAge\":" << r.deltaAgeSec << "}";
    }
  }
  o << "]}";
  return o.str();
}

std::string buildConfig(CesServer& s) {
  const CesConfig& c = s._config();
  auto kv = [](std::ostringstream& o, const char* k, uint64_t v, bool first) {
    if (!first) o << ",";
    o << jstr(k) << ":" << v;
  };
  std::ostringstream o;
  o << "{\"knobs\":{";
  kv(o, "feeAccount", c.feeAccount, true);
  kv(o, "feeAsset", c.feeAsset, false);
  kv(o, "feeTx", c.feeTx, false);
  kv(o, "feeQuery", c.feeQuery, false);
  kv(o, "feeVmMult", c.feeVmMult, false);
  kv(o, "minDifficulty", c.minDiff, false);
  kv(o, "spendSlotSize", c.spendSlotSize, false);
  kv(o, "taskThreads", static_cast<uint64_t>(c.taskThreads), false);
  kv(o, "maxLogBytes", c.maxLogBytes, false);
  kv(o, "minAccounts", c.minAcc, false);
  kv(o, "maxAccounts", c.maxAcc, false);
  kv(o, "minAssets", c.minAsset, false);
  kv(o, "maxAssets", c.maxAsset, false);
  kv(o, "cesFileStoreMaxBytes", c.cesFileStoreMaxBytes, false);
  kv(o, "computeMaxInstances", c.computeMaxInstances, false);
  kv(o, "computePortBase", c.computePortBase, false);
  kv(o, "computePortCount", c.computePortCount, false);
  kv(o, "computeClientPoolSize", static_cast<uint64_t>(c.computeClientPoolSize), false);
  kv(o, "feeNetByteSent", c.feeNetByteSent, false);
  kv(o, "feeNetByteReceived", c.feeNetByteReceived, false);
  kv(o, "feeNetChannelSec", c.feeNetChannelSec, false);
  kv(o, "feeNetMemByteDay", c.feeNetMemByteDay, false);
  kv(o, "feeFileRent", static_cast<uint64_t>(c.feeFileRent), false);
  kv(o, "feeFileWrite", static_cast<uint64_t>(c.feeFileWrite), false);
  kv(o, "feeFileRead", static_cast<uint64_t>(c.feeFileRead), false);
  kv(o, "feeComputeSlotSec", static_cast<uint64_t>(c.feeComputeSlotSec), false);
  kv(o, "feeComputeCpuSec", static_cast<uint64_t>(c.feeComputeCpuSec), false);
  kv(o, "feeComputeRssByteDay", static_cast<uint64_t>(c.feeComputeRssByteDay), false);
  kv(o, "feeComputeNetByte", static_cast<uint64_t>(c.feeComputeNetByte), false);
  kv(o, "feeBucketByteSec", static_cast<uint64_t>(c.feeBucketByteSec), false);
  o << "},\"feeDiscountEnabled\":" << (c.feeDiscountEnabled ? "true" : "false");
  // Per-FeeKind live discount multipliers (basis points 0..10000).
  static const std::pair<const char*, FeeKind> kinds[] = {
    {"Tx", FeeKind::Tx}, {"Query", FeeKind::Query},
    {"AccountRent", FeeKind::AccountRent}, {"AssetRent", FeeKind::AssetRent},
    {"VMMult", FeeKind::VMMult}, {"ComputeSlot", FeeKind::ComputeSlot},
    {"ComputeCpu", FeeKind::ComputeCpu}, {"ComputeRss", FeeKind::ComputeRss},
    {"BucketByteSec", FeeKind::BucketByteSec}, {"Net", FeeKind::Net},
  };
  o << ",\"multipliers\":{";
  bool first = true;
  for (auto& [name, k] : kinds) {
    if (!first) o << ",";
    first = false;
    o << jstr(name) << ":" << s.getFeeMult(k);
  }
  o << "}}";
  return o.str();
}

// File-store monitoring: feature flag, cap, and live usage from .store.toml.
std::string buildFileStore(CesServer& s) {
  const CesConfig& c = s._config();
  std::ostringstream o;
  uint64_t files = 0, bytes = 0;
  bool enabled = fileHandlerStoreStats(files, bytes);
  o << "{\"enabled\":" << (enabled ? "true" : "false")
    << ",\"maxBytes\":" << c.cesFileStoreMaxBytes
    << ",\"totalFiles\":" << files
    << ",\"totalBytes\":" << bytes
    << ",\"dir\":" << jstr(c.cesFileStoreDir) << "}";
  return o.str();
}

// Compute monitoring: feature flags, port range, and a snapshot of every
// running instance (CPU basis points, RSS, uptime, assigned ports).
std::string buildCompute(CesServer& s) {
  const CesConfig& c = s._config();
  std::ostringstream o;
  o << "{\"enabled\":" << (c.computeMaxInstances > 0 ? "true" : "false")
    << ",\"maxInstances\":" << c.computeMaxInstances
    << ",\"portBase\":" << c.computePortBase
    << ",\"portCount\":" << c.computePortCount
    << ",\"processMemMax\":" << c.computeProcessMemMax
    << ",\"instances\":[";
  auto insts = computeHandlerSnapshot();
  bool first = true;
  for (auto& i : insts) {
    if (!first) o << ",";
    first = false;
    o << "{\"pid\":" << i.pid
      << ",\"source\":" << jstr(i.source)
      << ",\"cpuBp\":" << i.cpuBasisPoints
      << ",\"rssBytes\":" << i.rssBytes
      << ",\"uptimeSecs\":" << i.uptimeSecs
      << ",\"clientPort\":" << i.clientPort
      << ",\"rpcPort\":" << i.rpcPort << "}";
  }
  o << "]}";
  return o.str();
}

// Global extension funding budget: the rate in effect + the live remaining
// allowance (both raw units; the dashboard divides by PRICE_UNIT to show credits).
std::string buildFunding(CesServer& s) {
  std::ostringstream o;
  o << "{\"perDay\":" << s.extFundingPerDay()
    << ",\"remaining\":" << s.extFundingRemaining() << "}";
  return o.str();
}

std::string buildExtensions(CesServer& s) {
  std::ostringstream o;
  o << "{\"catalog\":" << (s._config().cesExtensionsDir.empty() ? "false" : "true")
    << ",\"items\":[";
  bool first = true;
  for (auto& it : extensionList(&s)) {
    if (!first) o << ",";
    first = false;
    o << "{\"name\":" << jstr(it.name)
      << ",\"displayName\":" << jstr(it.displayName)
      << ",\"available\":" << (it.available ? "true" : "false")
      << ",\"installed\":" << (it.installed ? "true" : "false")
      << ",\"enabled\":" << (it.enabled ? "true" : "false")
      << ",\"pid\":" << it.pid
      << ",\"isExtension\":" << (it.isExtension ? "true" : "false")
      << ",\"caps\":" << static_cast<int>(it.caps)
      << ",\"version\":" << jstr(it.version)
      << ",\"description\":" << jstr(it.description)
      << ",\"commands\":[";
    bool cf = true;
    for (auto& cmd : it.commands) {
      if (!cf) o << ",";
      cf = false;
      o << "{\"id\":" << jstr(cmd.first) << ",\"label\":" << jstr(cmd.second) << "}";
    }
    o << "]}";
  }
  o << "]}";
  return o.str();
}

std::string buildExtensionStatus(CesServer& s, const std::string& name) {
  std::vector<std::pair<std::string, std::string>> kv;
  bool ok = extensionStatus(&s, name, kv);
  std::ostringstream o;
  o << "{\"ok\":" << (ok ? "true" : "false") << ",\"kv\":[";
  bool f = true;
  for (auto& p : kv) {
    if (!f) o << ",";
    f = false;
    o << "[" << jstr(p.first) << "," << jstr(p.second) << "]";
  }
  o << "]}";
  return o.str();
}

std::string buildExtensionConfig(CesServer& s, const std::string& name) {
  return std::string("{\"text\":") + jstr(extensionConfigGet(&s, name)) + "}";
}

std::string buildAccount(CesServer& s, const std::string& keyHex) {
  minx::Hash key;
  if (!parseHash64(keyHex, key))
    return "{\"error\":\"key must be 64 hex chars\"}";
  auto a = s._adminQueryAccount(key);
  std::ostringstream o;
  o << "{\"exists\":" << (a.exists ? "true" : "false")
    << ",\"prefixTaken\":" << (a.prefixTaken ? "true" : "false");
  if (a.exists) {
    o << ",\"balance\":" << a.balance
      << ",\"nonce\":" << a.nonce
      << ",\"lastXferDest\":" << jstr(hexOfPrefix(a.lastXferDest))
      << ",\"lastXferAmount\":" << a.lastXferAmount
      << ",\"lastXferTime\":" << a.lastXferTime;
  }
  o << "}";
  return o.str();
}

std::string buildAsset(CesServer& s, const std::string& keyHex) {
  minx::Hash key;
  if (!parseHash64(keyHex, key))
    return "{\"error\":\"key must be 64 hex chars\"}";
  auto a = s._adminQueryAsset(key);
  std::ostringstream o;
  o << "{\"exists\":" << (a.exists ? "true" : "false");
  if (a.exists) {
    uint16_t days = a.balance & 0x1FFF;
    bool immutable = (a.balance & 0x2000) != 0;
    bool assetOwned = (a.balance & 0x4000) != 0;
    bool isPrivate = (a.balance & 0x8000) != 0;
    o << ",\"owner\":" << jstr(hexOfPrefix(a.owner))
      << ",\"rawBalance\":" << a.balance
      << ",\"days\":" << days
      << ",\"immutable\":" << (immutable ? "true" : "false")
      << ",\"assetOwned\":" << (assetOwned ? "true" : "false")
      << ",\"private\":" << (isPrivate ? "true" : "false")
      << ",\"price\":" << a.price
      << ",\"content\":" << jstr(hexOf(std::span<const uint8_t>(
                                a.content.data(), a.content.size())));
  }
  o << "}";
  return o.str();
}

// L2 file STAT lookup (public). enabled=false when the file feature is off.
std::string buildFileStat(CesServer& s, const std::string& path) {
  if (path.empty()) return "{\"error\":\"path required\"}";
  auto f = s._fileStat(path);
  std::ostringstream o;
  o << "{\"enabled\":" << (f.enabled ? "true" : "false")
    << ",\"found\":" << (f.found ? "true" : "false");
  if (f.found) {
    o << ",\"owner\":" << jstr(hexOf(std::span<const uint8_t>(
                              f.ownerPubkey.data(), f.ownerPubkey.size())))
      << ",\"size\":" << f.size
      << ",\"fileBalance\":" << f.fileBalance
      << ",\"pricePerKb\":" << f.pricePerKb
      << ",\"createdUs\":" << f.createdUs
      << ",\"modifiedUs\":" << f.modifiedUs;
  }
  o << "}";
  return o.str();
}

std::string buildLogs(const std::string& query) {
  auto q = parseKV(query);
  uint64_t sinceSeq = 0;
  parseU64(getParam(q, "since"), sinceSeq);
  uint64_t hi = 0;
  auto lines = LogRing::instance().since(sinceSeq, hi);
  std::ostringstream o;
  o << "{\"hi\":" << hi << ",\"level\":" << blog::fast_min_level
    << ",\"lines\":[";
  for (size_t i = 0; i < lines.size(); ++i) {
    if (i) o << ",";
    o << "{\"seq\":" << lines[i].seq
      << ",\"ts\":" << lines[i].ts
      << ",\"text\":" << jstr(lines[i].text) << "}";
  }
  o << "]}";
  return o.str();
}

std::string buildInspect(CesServer& s, const std::string& address, bool paid) {
  if (address.empty()) return "{\"error\":\"address required\"}";
  // Free handshake by default (instant): pubkey + difficulty + reachability,
  // which is all you need to add a peer. The paid server-info query only
  // returns anything once you hold a balance there, and blocks on a timeout
  // otherwise — so it's opt-in, not on the discovery path.
  auto info = s._inspectRemoteServer(address, paid);
  std::ostringstream o;
  o << "{\"address\":" << jstr(address)
    << ",\"reachable\":" << (info.reachable ? "true" : "false");
  if (info.reachable) {
    o << ",\"serverKey\":" << jstr(hexOfHash(info.serverKey))
      << ",\"minDifficulty\":" << static_cast<unsigned>(info.minDifficulty)
      << ",\"info\":{";
    for (size_t i = 0; i < info.entries.size(); ++i) {
      if (i) o << ",";
      o << jstr(info.entries[i].key) << ":" << jstr(info.entries[i].value);
    }
    o << "}";
  }
  o << "}";
  return o.str();
}

std::string buildMine(CesServer& s, const std::string& address, int count) {
  if (address.empty()) return "{\"error\":\"address required\"}";
  auto r = s._mineRemoteServer(address, count);
  std::ostringstream o;
  o << "{\"ok\":" << (r.ok ? "true" : "false")
    << ",\"credit\":" << r.credit
    << ",\"status\":" << r.status
    << ",\"error\":" << jstr(r.error) << "}";
  return o.str();
}

std::string buildHello(CesServer& s) {
  std::string served = s._getHello();
  bool existed = false;
  s._loadHelloFile(existed);
  std::ostringstream o;
  o << "{\"hello\":" << jstr(served)
    << ",\"fileExists\":" << (existed ? "true" : "false")
    << ",\"max\":" << CesServer::HELLO_MAX_BYTES << "}";
  return o.str();
}

extern const char* kDashboardHtml;  // defined at the bottom of this file

}  // namespace

// =============================================================================
// WebAdminSession
// =============================================================================

WebAdminSession::WebAdminSession(Socket socket, CesServer& server)
  : socket_(std::move(socket)), server_(server) {}

void WebAdminSession::start() { doRead(); }

void WebAdminSession::doRead() {
  auto self = shared_from_this();
  socket_.async_read_some(boost::asio::buffer(readChunk_),
    [this, self](boost::system::error_code ec, size_t n) {
      if (ec) return;  // client closed / error — drop the session
      request_.append(readChunk_.data(), n);
      if (request_.size() > 4 * 1024 * 1024) {  // request too large
        respond(413, "text/plain", "request too large");
        return;
      }
      if (requestComplete()) handleRequest();
      else doRead();
    });
}

bool WebAdminSession::requestComplete() {
  if (headerEnd_ == 0) {
    auto pos = request_.find("\r\n\r\n");
    if (pos == std::string::npos) return false;
    headerEnd_ = pos + 4;
    // Content-Length (case-insensitive header scan over the header block).
    std::string head = request_.substr(0, headerEnd_);
    for (auto& ch : head) ch = static_cast<char>(::tolower(ch));
    auto cl = head.find("content-length:");
    if (cl != std::string::npos) {
      size_t p = cl + 15;
      while (p < head.size() && (head[p] == ' ' || head[p] == '\t')) ++p;
      uint64_t v = 0;
      while (p < head.size() && head[p] >= '0' && head[p] <= '9')
        v = v * 10 + (head[p++] - '0');
      contentLength_ = static_cast<size_t>(v);
    }
  }
  return request_.size() >= headerEnd_ + contentLength_;
}

void WebAdminSession::handleRequest() {
  // Request line: METHOD SP TARGET SP HTTP/x
  std::string method, target;
  {
    size_t sp1 = request_.find(' ');
    size_t sp2 = (sp1 == std::string::npos) ? std::string::npos
                                            : request_.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) {
      respond(400, "text/plain", "bad request");
      return;
    }
    method = request_.substr(0, sp1);
    target = request_.substr(sp1 + 1, sp2 - sp1 - 1);
  }
  std::string path = target, query;
  if (auto qm = target.find('?'); qm != std::string::npos) {
    path = target.substr(0, qm);
    query = target.substr(qm + 1);
  }
  std::string body = request_.substr(headerEnd_, contentLength_);
  try {
    route(method, path, query, body);
  } catch (std::exception& e) {
    respondJson(std::string("{\"error\":") + jstr(e.what()) + "}");
  }
}

void WebAdminSession::route(const std::string& method, const std::string& path,
                          const std::string& query, const std::string& body) {
  // ---- UI ----
  if (method == "GET" && (path == "/" || path == "/index.html")) {
    respond(200, "text/html; charset=utf-8", kDashboardHtml);
    return;
  }
  if (method == "GET" && path == "/favicon.ico") {
    respond(204, "image/x-icon", "");
    return;
  }

  // ---- GET JSON ----
  if (method == "GET") {
    if (path == "/api/status")  { respondJson(buildStatus(server_)); return; }
    if (path == "/api/peers")   { respondJson(buildPeers(server_)); return; }
    if (path == "/api/netbill") { respondJson(buildNetbill(server_)); return; }
    if (path == "/api/config")  { respondJson(buildConfig(server_)); return; }
    if (path == "/api/filestore") { respondJson(buildFileStore(server_)); return; }
    if (path == "/api/compute") { respondJson(buildCompute(server_)); return; }
    if (path == "/api/extensions") { respondJson(buildExtensions(server_)); return; }
    if (path == "/api/funding") { respondJson(buildFunding(server_)); return; }
    if (path == "/api/extension_status") {
      respondJson(buildExtensionStatus(server_, getParam(parseKV(query), "name")));
      return;
    }
    if (path == "/api/extension_config") {
      respondJson(buildExtensionConfig(server_, getParam(parseKV(query), "name")));
      return;
    }
    if (path == "/api/logs")    { respondJson(buildLogs(query)); return; }
    if (path == "/api/hello")   { respondJson(buildHello(server_)); return; }
    if (path == "/api/account") {
      respondJson(buildAccount(server_, getParam(parseKV(query), "key")));
      return;
    }
    if (path == "/api/asset") {
      respondJson(buildAsset(server_, getParam(parseKV(query), "key")));
      return;
    }
    if (path == "/api/filestat") {
      respondJson(buildFileStat(server_, getParam(parseKV(query), "path")));
      return;
    }
  }

  // ---- POST actions ----
  if (method == "POST") {
    auto form = parseKV(body);

    if (path == "/api/credit" || path == "/api/debit") {
      uint64_t amount = 0;
      minx::Hash key;
      if (!parseU64(getParam(form, "amount"), amount) || amount == 0 ||
          amount > static_cast<uint64_t>(INT64_MAX)) {
        respondJson("{\"error\":\"amount must be a positive integer (<= int64 max)\"}");
        return;
      }
      if (!parseHash64(getParam(form, "pubkey"), key)) {
        respondJson("{\"error\":\"pubkey must be 64 hex chars\"}");
        return;
      }
      int64_t signedAmt = static_cast<int64_t>(amount);
      if (path == "/api/credit") {
        server_._brr(key, signedAmt);
        respondJson(std::string("{\"ok\":true,\"message\":\"minted ") +
                    std::to_string(amount) + "\"}");
      } else {
        server_._burn(key, signedAmt);
        respondJson(std::string("{\"ok\":true,\"message\":\"burned ") +
                    std::to_string(amount) + "\"}");
      }
      return;
    }

    if (path == "/api/transfer") {
      uint64_t amount = 0;
      minx::Hash dest;
      if (!parseU64(getParam(form, "amount"), amount) || amount == 0 ||
          amount > static_cast<uint64_t>(INT64_MAX)) {
        respondJson("{\"error\":\"amount must be a positive integer (<= int64 max)\"}");
        return;
      }
      if (!parseHash64(getParam(form, "pubkey"), dest)) {
        respondJson("{\"error\":\"pubkey must be 64 hex chars\"}");
        return;
      }
      bool ok = server_._walletSend(dest, amount);
      respondJson(ok ? std::string("{\"ok\":true,\"message\":\"sent ") +
                         std::to_string(amount) + "\"}"
                     : "{\"ok\":false,\"error\":\"server balance can't cover it\"}");
      return;
    }

    if (path == "/api/snapshot") {
      // Offload the wait to a worker thread; the snapshot fork runs on the
      // logic strand and the cb wakes us.
      runAsync([&server = server_]() -> std::string {
        std::promise<std::string> pr;
        server.liveSnapshot([&pr](bool ok, std::string msg) {
          pr.set_value(std::string("{\"ok\":") + (ok ? "true" : "false") +
                       ",\"message\":" + jstr(msg) + "}");
        });
        return pr.get_future().get();
      });
      return;
    }

    if (path == "/api/peer_add") {
      minx::Hash key;
      std::string address = getParam(form, "address");
      if (!parseHash64(getParam(form, "key"), key)) {
        respondJson("{\"error\":\"key must be 64 hex chars\"}");
        return;
      }
      if (address.empty()) {
        respondJson("{\"error\":\"address required\"}");
        return;
      }
      // Verify the key against what the remote actually reports BEFORE adding.
      // A wrong key is otherwise silent and costly: the peer is still mined
      // toward, burning PoW to build a reserve under a key that isn't really
      // the server's, which no cross-transfer can ever use. Free handshake on a
      // worker thread (it blocks); reject a mismatch or an unreachable target.
      runAsync([&server = server_, key, address]() -> std::string {
        auto info = server._inspectRemoteServer(address, /*paid=*/false);
        if (!info.reachable) {
          return std::string("{\"error\":") +
                 jstr("could not reach " + address +
                      " to verify its key — not added") + "}";
        }
        if (!(info.serverKey == key)) {
          return std::string("{\"error\":") +
                 jstr("key mismatch: " + address + " reports " +
                      hexOfHash(info.serverKey) +
                      " — check the key; not added") + "}";
        }
        server._addOutboundPeer(key, address);
        return std::string(
          "{\"ok\":true,\"message\":\"key verified — peer added\"}");
      });
      return;
    }

    if (path == "/api/peer_remove") {
      minx::Hash key;
      if (!parseHash64(getParam(form, "key"), key)) {
        respondJson("{\"error\":\"key must be 64 hex chars\"}");
        return;
      }
      bool removed = server_._removePeer(key);
      respondJson(std::string("{\"ok\":") + (removed ? "true" : "false") +
                  ",\"message\":" + jstr(removed ? "peer removed" : "peer not found") + "}");
      return;
    }

    if (path == "/api/peer_target") {
      uint64_t target = 0;
      if (!parseU64(getParam(form, "target"), target)) {
        respondJson("{\"error\":\"target must be a non-negative integer\"}");
        return;
      }
      server_._setPeerTarget(target);
      respondJson("{\"ok\":true,\"message\":\"target set\"}");
      return;
    }

    if (path == "/api/config_export") {
      std::string err;
      std::string p = server_._exportConfig(&err);
      if (p.empty()) {
        respondJson(std::string("{\"ok\":false,\"error\":") +
                    jstr(err.empty() ? "export failed (see logs)" : err) + "}");
        return;
      }
      respondJson(std::string("{\"ok\":true,\"path\":") + jstr(p) + "}");
      return;
    }

    if (path == "/api/config_set") {
      std::string key = getParam(form, "key");
      uint64_t value = 0;
      if (!parseU64(getParam(form, "value"), value)) {
        respondJson("{\"ok\":false,\"error\":\"value must be a non-negative integer\"}");
        return;
      }
      bool ok = server_._setConfigKnob(key, value);
      respondJson(ok ? "{\"ok\":true}"
                     : "{\"ok\":false,\"error\":\"unknown or non-editable knob\"}");
      return;
    }

    // ---- Extension lifecycle (dynamic; Config -> Export to persist enabled set).
    if (path == "/api/extension_install" || path == "/api/extension_enable" ||
        path == "/api/extension_disable" || path == "/api/extension_uninstall" ||
        path == "/api/extension_config_reset") {
      std::string name = getParam(form, "name");
      bool ok = false;
      if (path == "/api/extension_install")        ok = extensionInstall(&server_, name);
      else if (path == "/api/extension_enable")    ok = extensionEnable(&server_, name);
      else if (path == "/api/extension_disable")   ok = extensionDisable(&server_, name);
      else if (path == "/api/extension_uninstall") ok = extensionUninstall(&server_, name);
      else                                         ok = extensionConfigReset(&server_, name);
      respondJson(ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"action failed\"}");
      return;
    }
    if (path == "/api/extension_command") {
      std::string out;
      bool ok = extensionCommand(&server_, getParam(form, "name"),
                                 getParam(form, "id"), getParam(form, "arg"), out);
      respondJson(ok ? std::string("{\"ok\":true,\"result\":") + jstr(out) + "}"
                     : "{\"ok\":false,\"error\":\"command failed\"}");
      return;
    }
    if (path == "/api/extension_config_set") {
      bool ok = extensionConfigSet(&server_, getParam(form, "name"),
                                   getParam(form, "text"));
      respondJson(ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"save failed\"}");
      return;
    }

    // Set the global extension funding rate (raw units/day; the dashboard sends
    // raw = credits × PRICE_UNIT). Operator-only by being on this loopback UI.
    if (path == "/api/funding_set") {
      uint64_t v = 0;
      if (!parseU64(getParam(form, "perday"), v)) {
        respondJson("{\"ok\":false,\"error\":\"perday must be a non-negative integer\"}");
        return;
      }
      server_.extFundingSetPerDay(v);
      respondJson("{\"ok\":true}");
      return;
    }

    if (path == "/api/loglevel") {
      std::string lv = getParam(form, "level");
      int n = -1;
      if (lv == "trace" || lv == "0") n = 0;
      else if (lv == "debug" || lv == "1") n = 1;
      else if (lv == "info" || lv == "2") n = 2;
      else if (lv == "warning" || lv == "warn" || lv == "3") n = 3;
      else if (lv == "error" || lv == "4") n = 4;
      if (n < 0) { respondJson("{\"ok\":false,\"error\":\"bad level\"}"); return; }
      blog::set_level(static_cast<blog::severity_level>(n));
      respondJson(std::string("{\"ok\":true,\"level\":") +
                  std::to_string(blog::fast_min_level) + "}");
      return;
    }

    if (path == "/api/hello_save") {
      std::string saved = server_._setHello(getParam(form, "text"));
      std::ostringstream o;
      o << "{\"ok\":true,\"hello\":" << jstr(saved)
        << ",\"bytes\":" << saved.size() << "}";
      respondJson(o.str());
      return;
    }

    if (path == "/api/hello_load") {
      bool existed = false;
      std::string content = server_._loadHelloFile(existed);
      std::ostringstream o;
      o << "{\"ok\":true,\"hello\":" << jstr(content)
        << ",\"fileExists\":" << (existed ? "true" : "false") << "}";
      respondJson(o.str());
      return;
    }

    if (path == "/api/inspect") {
      std::string address = getParam(form, "address");
      bool paid = getParam(form, "paid") == "1";
      runAsync([&server = server_, address, paid]() {
        return buildInspect(server, address, paid);
      });
      return;
    }

    if (path == "/api/mine") {
      std::string address = getParam(form, "address");
      uint64_t count = 1;
      parseU64(getParam(form, "count"), count);
      if (count < 1) count = 1;
      if (count > 32) count = 32;  // a sane manual cap; mining is heavy
      int n = static_cast<int>(count);
      runAsync([&server = server_, address, n]() {
        return buildMine(server, address, n);
      });
      return;
    }
  }

  respond(404, "application/json", "{\"error\":\"not found\"}");
}

void WebAdminSession::runAsync(std::function<std::string()> work) {
  auto self = shared_from_this();
  addWorker(std::thread([this, self, work = std::move(work)]() {
    std::string body;
    try {
      body = work();
    } catch (std::exception& e) {
      body = std::string("{\"error\":") + jstr(e.what()) + "}";
    } catch (...) {
      // A detached worker must never std::terminate the whole server.
      body = "{\"error\":\"internal error\"}";
    }
    // Marshal the reply back onto the session's executor (the web io thread),
    // so all socket writes stay single-threaded like the rest of the server.
    boost::asio::post(socket_.get_executor(),
      [this, self, body = std::move(body)]() {
        respond(200, "application/json", body);
      });
  }));
}

void WebAdminSession::respondJson(const std::string& json) {
  respond(200, "application/json", json);
}

void WebAdminSession::respond(int status, const std::string& contentType,
                            const std::string& body) {
  if (responded_) return;
  responded_ = true;
  const char* reason = "OK";
  switch (status) {
    case 204: reason = "No Content"; break;
    case 400: reason = "Bad Request"; break;
    case 404: reason = "Not Found"; break;
    case 413: reason = "Payload Too Large"; break;
    case 500: reason = "Internal Server Error"; break;
    default: reason = "OK"; break;
  }
  auto out = std::make_shared<std::string>();
  *out = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n" +
         "Content-Type: " + contentType + "\r\n" +
         "Content-Length: " + std::to_string(body.size()) + "\r\n" +
         "Connection: close\r\n" +
         "Cache-Control: no-store\r\n" +
         "\r\n" + body;
  auto self = shared_from_this();
  boost::asio::async_write(socket_, boost::asio::buffer(*out),
    [this, self, out](boost::system::error_code ec, size_t) {
      boost::system::error_code ic;
      socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ic);
      socket_.close(ic);
      (void)ec;
    });
}

// =============================================================================
// WebAdmin
// =============================================================================

WebAdmin::WebAdmin(boost::asio::io_context& io, CesServer& server)
  : io_(io), server_(server) {}

WebAdmin::~WebAdmin() { stop(); }

bool WebAdmin::listen(const std::string& bindAddr, uint16_t port) {
  boost::system::error_code ec;
  auto addr = boost::asio::ip::make_address(bindAddr, ec);
  if (ec) {
    LOGERROR << "web dashboard: bad bind address" << SVAR(bindAddr)
             << SVAR(ec.message());
    return false;
  }
  if (!addr.is_loopback()) {
    LOGWARNING << "web dashboard bind address is NOT loopback — the dashboard "
                  "has NO authentication; anyone who can reach this address "
                  "controls the server" << SVAR(bindAddr);
  }
  try {
    boost::asio::ip::tcp::endpoint ep(addr, port);
    acceptor_ = std::make_unique<boost::asio::ip::tcp::acceptor>(io_);
    acceptor_->open(ep.protocol());
    acceptor_->set_option(boost::asio::socket_base::reuse_address(true));
    acceptor_->bind(ep);
    acceptor_->listen();
    boundPort_ = acceptor_->local_endpoint().port();
    g_webStartUnix = minx::getSecsSinceEpoch();
    installLogSink();
    logSinkInstalled_ = true;
    LOGINFO << "web dashboard listening (NO AUTH)"
            << SVAR(bindAddr) << VAR(port);
    doAccept();
    return true;
  } catch (std::exception& e) {
    LOGERROR << "web dashboard listen failed" << SVAR(bindAddr) << VAR(port)
             << SVAR(e.what());
    acceptor_.reset();
    return false;
  }
}

void WebAdmin::stop() {
  if (acceptor_) {
    boost::system::error_code ec;
    acceptor_->close(ec);
    acceptor_.reset();
  }
  // Join any in-flight inspect/mine workers before the server they reference
  // is destroyed (main stops the dashboard before CesServer::stop()).
  joinWorkers();
  if (logSinkInstalled_) {
    removeLogSink();
    logSinkInstalled_ = false;
  }
}

void WebAdmin::doAccept() {
  acceptor_->async_accept(
    [this](boost::system::error_code ec,
           boost::asio::ip::tcp::socket socket) {
      if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
          LOGDEBUG << "web accept error" << SVAR(ec.message());
        }
        return;
      }
      std::make_shared<WebAdminSession>(std::move(socket), server_)->start();
      doAccept();
    });
}

namespace {

const char* kDashboardHtml = R"DASH(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CES Server Dashboard</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpolygon points='12,1.5 21,6.75 21,17.25 12,22.5 3,17.25 3,6.75' fill='none' stroke='%2336d399' stroke-width='2'/%3E%3C/svg%3E">
<style>
:root{
  --bg:#0a0d14; --panel:#121826; --panel2:#0e1320; --bd:#222b3d; --bd2:#2d3850;
  --tx:#cbd5e8; --muted:#697489; --accent:#36d399; --accent2:#56a8ff;
  --warn:#f5b942; --danger:#ff6b6b; --gold:#ffd166;
  --mono:'SFMono-Regular',ui-monospace,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
  font-size:14px;line-height:1.5}
a{color:var(--accent2);text-decoration:none}
.mono{font-family:var(--mono)}
.muted{color:var(--muted)}
.num{font-family:var(--mono);font-variant-numeric:tabular-nums}

/* top bar */
header{position:sticky;top:0;z-index:20;background:linear-gradient(180deg,#0d1320,#0a0d14);
  border-bottom:1px solid var(--bd);padding:12px 22px;display:flex;align-items:center;gap:18px}
.logo{font-weight:700;font-size:18px;letter-spacing:.5px;display:flex;align-items:center;gap:8px}
.logo .hex{color:var(--accent);font-size:20px}
.ident{display:flex;flex-direction:column;line-height:1.25}
.ident .nm{font-weight:600}
.ident .ky{font-family:var(--mono);font-size:12px;color:var(--muted);cursor:pointer}
.spacer{flex:1}
.pill{font-size:12px;padding:3px 9px;border-radius:20px;border:1px solid var(--bd2);color:var(--muted)}
.live{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--danger);box-shadow:0 0 0 0 rgba(54,211,153,.6)}
.dot.ok{background:var(--accent);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(54,211,153,.5)}70%{box-shadow:0 0 0 7px rgba(54,211,153,0)}100%{box-shadow:0 0 0 0 rgba(54,211,153,0)}}


/* tabs */
nav.tabs{display:flex;gap:2px;padding:0 16px;background:#0c111c;border-bottom:1px solid var(--bd);
  overflow-x:auto}
.tab{padding:11px 16px;cursor:pointer;color:var(--muted);border-bottom:2px solid transparent;
  white-space:nowrap;font-weight:500}
.tab:hover{color:var(--tx)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}

main{padding:22px;max-width:1180px;margin:0 auto}
.panel{display:none}
.panel.active{display:block;animation:fade .25s}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}

/* cards & grid */
.grid{display:grid;gap:14px}
.cards{grid-template-columns:repeat(auto-fill,minmax(110px,1fr));grid-auto-flow:dense}
.card{background:var(--panel);border:1px solid var(--bd);border-radius:12px;padding:16px;min-width:0}
.card.wide{grid-column:span 2}
.card.ultrawide{grid-column:span 4}
.card h3{margin:0 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.stat{font-size:20px;font-weight:700;font-family:var(--mono);font-variant-numeric:tabular-nums;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.stat.green{color:var(--accent)}
.section{background:var(--panel);border:1px solid var(--bd);border-radius:12px;padding:18px;margin-bottom:18px}
.section h2{margin:0 0 14px;font-size:15px;display:flex;align-items:center;gap:8px}
.section h2 .sub{font-size:12px;color:var(--muted);font-weight:400}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.kvtable{width:100%;border-collapse:collapse}
.kvtable td{padding:5px 8px;border-bottom:1px solid var(--panel2)}
.kvtable td:first-child{color:var(--muted);width:46%}

/* gauges */
.gauge{margin:9px 0}
.gauge .lbl{display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;color:var(--muted)}
.bar{height:8px;background:#0a0f1a;border-radius:6px;overflow:hidden}
.bar i{display:block;height:100%;border-radius:6px;background:var(--accent);transition:width .4s,background .4s}

/* feature pills */
.feats{display:flex;gap:8px;flex-wrap:wrap}
.feat{font-size:12px;padding:5px 11px;border-radius:8px;border:1px solid var(--bd2);color:var(--muted)}
.feat.on{color:var(--accent);border-color:rgba(54,211,153,.4);background:rgba(54,211,153,.08)}

/* forms */
input,select,textarea,button{font-family:inherit;font-size:14px}
input[type=text],input[type=number],select,textarea{background:var(--panel2);border:1px solid var(--bd2);
  color:var(--tx);border-radius:8px;padding:9px 11px;outline:none}
input[type=text]:focus,input[type=number]:focus,textarea:focus{border-color:var(--accent2)}
input.k{font-family:var(--mono);min-width:320px;flex:1}
input.addr{min-width:200px}
textarea{width:100%;resize:vertical;font-family:var(--mono)}
label.fld{display:flex;flex-direction:column;gap:5px;font-size:12px;color:var(--muted)}
button{background:var(--accent2);color:#04121f;border:none;border-radius:8px;padding:9px 16px;
  font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.08)}
button.green{background:var(--accent);color:#04140d}
button.warn{background:var(--warn);color:#1a1400}
button.danger{background:var(--danger);color:#220505}
button.ghost{background:transparent;border:1px solid var(--bd2);color:var(--tx)}
button.sm{padding:5px 10px;font-size:12px}
button:disabled{opacity:.5;cursor:not-allowed}
/* click feedback: a quick geometry-neutral opacity dip on every button press. */
@keyframes btnflash{0%{opacity:.4}100%{opacity:1}}
button.flash{animation:btnflash .22s ease-out}

/* extensions: table of rows, each expands into a control center */
#extList{border:1px solid var(--bd);border-radius:12px;overflow:hidden;background:var(--panel)}
.extrow{border-bottom:1px solid var(--bd)}
.extrow:last-child{border-bottom:none}
.extrow.open{background:var(--panel2)}
.exthead{display:flex;align-items:center;gap:10px;padding:11px 14px}
.extname{flex:1;display:flex;align-items:center;gap:9px;cursor:pointer;user-select:none;min-width:0}
.extname:hover .extchev{color:var(--tx)}
.extttl{font-weight:600}
.extver{font-size:12px;color:var(--muted);font-weight:400}
.extfile{font-size:12px;color:var(--muted);font-weight:400;opacity:.65}
.extchev{width:11px;flex:none;color:var(--muted);font-size:11px}
.extbadge{font-size:11px;padding:2px 9px;border-radius:20px;font-weight:500}
.extbtns{display:flex;gap:7px;flex:none}
.extbody{padding:2px 16px 16px 34px}
.extbody h4{margin:16px 0 7px;font-size:11px;letter-spacing:.7px;text-transform:uppercase;color:var(--muted);font-weight:600}
.extbody h4:first-child{margin-top:6px}
.extbody .kvtable td:first-child{width:38%}
.extcfg textarea{width:100%;height:140px;margin:6px 0;font-family:var(--mono);font-size:12.5px;resize:vertical}
.extcmdout{margin-top:7px;color:var(--muted);font-size:12px;min-height:1em}

/* tables */
table.data{width:100%;border-collapse:collapse;font-size:13px}
table.data th{text-align:left;color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;
  letter-spacing:.5px;padding:8px 10px;border-bottom:1px solid var(--bd2);position:sticky;top:0;background:var(--panel)}
table.data td{padding:8px 10px;border-bottom:1px solid var(--panel2);vertical-align:middle}
table.data tr:hover td{background:rgba(86,168,255,.04)}
.badge{font-size:11px;padding:2px 7px;border-radius:6px;font-weight:600}
.badge.out{background:rgba(86,168,255,.14);color:var(--accent2)}
.badge.in{background:rgba(255,209,102,.14);color:var(--gold)}
.lvlbtns{display:inline-flex;gap:0;border:1px solid var(--bd2);border-radius:8px;overflow:hidden}
.lvlbtns button{background:transparent;color:var(--muted);border:none;border-right:1px solid var(--bd2);border-radius:0;padding:5px 11px;font-size:12px;font-weight:600}
.lvlbtns button:last-child{border-right:none}
.lvlbtns button:hover{background:rgba(255,255,255,.04);color:var(--tx)}
.lvlbtns button.active{background:var(--accent2);color:#04121f}
.sdot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--danger)}
.sdot.ok{background:var(--accent)}
.copy{cursor:pointer;color:var(--muted)}
.copy:hover{color:var(--accent2)}

/* logs */
#logbox{background:#06090f;border:1px solid var(--bd);border-radius:10px;height:60vh;overflow:auto;
  padding:10px 12px;font-family:var(--mono);font-size:12.5px;line-height:1.5;white-space:pre-wrap;word-break:break-word}
.lg{display:block}
.lg .t{color:#46506a;margin-right:8px}
.lg.TRC{color:#6b7689}.lg.DBG{color:#8893a8}.lg.INF{color:#a9d8ff}
.lg.WRN{color:var(--warn)}.lg.ERR{color:var(--danger)}.lg.FTL{color:#ff9de2}

/* toast */
#toast{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:8px;z-index:50}
.tmsg{background:var(--panel);border:1px solid var(--bd2);border-left:3px solid var(--accent2);
  padding:11px 15px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.4);max-width:380px;animation:fade .2s}
.tmsg.ok{border-left-color:var(--accent)}.tmsg.err{border-left-color:var(--danger)}
.hint{font-size:12px;color:var(--muted);margin:4px 0 12px}
.flash{animation:flash .8s}
@keyframes flash{0%{background:rgba(54,211,153,.25)}100%{background:transparent}}
.flash-red{animation:flashred .8s}
@keyframes flashred{0%{background:rgba(255,107,107,.25)}100%{background:transparent}}
.foot{text-align:center;color:var(--muted);font-size:12px;padding:24px 0 8px}
@media(max-width:760px){
  main{padding:14px}
  .grid[style*="1fr 1fr"]{grid-template-columns:1fr!important}
  input.k,input.addr{min-width:0;width:100%}
  header{flex-wrap:wrap;gap:10px}
}
</style>
</head>
<body>
<header>
  <div class="logo"><span class="hex">&#x2B22;</span> CES</div>
  <div class="ident">
    <span class="nm" id="srvName">&hellip;</span>
    <span class="ky" id="srvKey" title="click to copy">&hellip;</span>
  </div>
  <div class="spacer"></div>
  <span class="pill" id="srvPorts">&hellip;</span>
  <span class="pill" id="srvVer"></span>
  <span class="pill" id="upPill">up &hellip;</span>
  <div class="live"><span class="dot" id="liveDot"></span><span id="liveTxt">connecting</span></div>
</header>

<nav class="tabs" id="tabs">
  <div class="tab active" data-tab="overview">Overview</div>
  <div class="tab" data-tab="peers">Peers</div>
  <div class="tab" data-tab="inspect">Inspect</div>
  <div class="tab" data-tab="wallet">Wallet</div>
  <div class="tab" data-tab="lookup">Lookup</div>
  <div class="tab" data-tab="billing">Billing</div>
  <div class="tab" data-tab="fees">Fees</div>
  <div class="tab" data-tab="file">File</div>
  <div class="tab" data-tab="compute">Compute</div>
  <div class="tab" data-tab="extensions">Extensions</div>
  <div class="tab" data-tab="logs">Logs</div>
  <div class="tab" data-tab="config">Config</div>
</nav>

<main>
  <!-- OVERVIEW -->
  <section class="panel active" id="panel-overview">
    <div class="grid cards" id="ovCards"></div>
    <div class="grid" style="grid-template-columns:1fr 1fr;margin-top:16px">
      <div class="section"><h2>Load gauges</h2><div id="ovGauges"></div></div>
      <div class="section"><h2>Identity &amp; features</h2><div id="ovIdent"></div><div class="feats" id="ovFeats" style="margin-top:12px"></div></div>
    </div>
  </section>

  <!-- PEERS -->
  <section class="panel" id="panel-peers">
    <div class="section">
      <h2>Peering target <span class="sub">credits to maintain on each outbound peer</span></h2>
      <div class="row" style="align-items:center">
        <input type="number" id="peerTarget" class="addr" min="0" step="any" placeholder="credits, e.g. 0.5">
        <button class="green" id="setTargetBtn" onclick="setTarget()">Set target</button>
        <span class="muted">current: <b id="curTarget" class="mono">&mdash;</b></span>
        <span id="minerState" class="pill"></span>
      </div>
    </div>
    <div class="section">
      <h2>Add an outbound peer</h2>
      <div class="row">
        <input type="text" id="addKey" class="k" placeholder="peer public key (64 hex)">
        <input type="text" id="addAddr" class="addr" placeholder="host:port">
        <button class="green" id="addPeerBtn" onclick="addPeer()">Add peer</button>
      </div>
      <p class="hint">Don&#39;t know the key? Use the <b>Inspect</b> tab to discover a server by address, then add it from there.</p>
    </div>
    <div class="section">
      <h2>Peer table <span class="sub" id="peerCount"></span></h2>
      <div class="row" id="peerSummary" style="gap:10px;margin-bottom:12px"></div>
      <div style="overflow:auto"><table class="data" id="peerTbl"></table></div>
    </div>
  </section>

  <!-- INSPECT -->
  <section class="panel" id="panel-inspect">
    <div class="section">
      <h2>Inspect a server <span class="sub">discover &middot; mine &middot; peer</span></h2>
      <div class="row">
        <input type="text" id="inspAddr" class="addr" placeholder="host:port (use an IP, e.g. 127.0.0.1:14003)" style="flex:1">
        <button onclick="doInspect()" id="inspBtn">Inspect</button>
      </div>
      <label class="muted" style="display:flex;align-items:center;gap:6px;margin-top:8px"><input type="checkbox" id="inspPaid">also fetch paid server-info (only returns data if you hold a balance there — slower)</label>
      <p class="hint">A free, instant handshake probe: pubkey, min-difficulty, reachability — all you need to add it as a peer. Then mine to bootstrap a reserve.</p>
      <div id="inspResult"></div>
    </div>
  </section>

  <!-- WALLET -->
  <section class="panel" id="panel-wallet">
    <div class="section">
      <h2>Transfer <span class="sub">send from this node&#39;s account</span></h2>
      <div id="walletBal" class="hint" style="font-size:13px">node balance: <b>&hellip;</b></div>
      <label class="fld">destination account (64 hex)
        <input type="text" id="xferKey" class="k" placeholder="64 hex chars" oninput="checkXferAcct()"></label>
      <div id="xferAcct" class="hint" style="min-height:18px"></div>
      <div class="row" style="margin-top:6px">
        <input type="number" id="xferAmt" class="addr" min="0" step="any" placeholder="credits (e.g. 100.5)" style="flex:1">
        <button class="green" id="xferBtn" onclick="doXfer()" disabled>Send</button>
      </div>
    </div>
    <div class="section">
      <h2>&#x1F5A8;&#xFE0F; Mint <span class="sub">create credits</span></h2>
      <label class="fld">account public key (64 hex)
        <input type="text" id="mintKey" class="k" placeholder="64 hex chars" oninput="checkMintAcct()"></label>
      <div id="mintAcct" class="hint" style="min-height:18px"></div>
      <div class="row" style="margin-top:6px">
        <input type="number" id="mintAmt" class="addr" min="0" step="any" placeholder="credits (e.g. 100.5)" style="flex:1">
        <button class="green" id="mintBtn" onclick="mint('credit')" disabled>Mint</button>
      </div>
    </div>
    <div class="section">
      <h2>Burn <span class="sub">destroy credits</span></h2>
      <label class="fld">account public key (64 hex)
        <input type="text" id="burnKey" class="k" placeholder="64 hex chars" oninput="checkBurnAcct()"></label>
      <div id="burnAcct" class="hint" style="min-height:18px"></div>
      <div class="row" style="margin-top:6px">
        <input type="number" id="burnAmt" class="addr" min="0" step="any" placeholder="credits (e.g. 100.5)" style="flex:1">
        <button class="danger" id="burnBtn" onclick="mint('debit')" disabled>Burn</button>
      </div>
    </div>
  </section>

  <!-- LOOKUP -->
  <section class="panel" id="panel-lookup">
    <div class="section">
      <h2>Account lookup</h2>
      <div class="row">
        <input type="text" id="accKey" class="k" placeholder="account public key (64 hex)">
        <button onclick="lookupAccount()">Query</button>
      </div>
      <div id="accResult"></div>
    </div>
    <div class="section">
      <h2>Asset lookup</h2>
      <div class="row">
        <input type="text" id="astKey" class="k" placeholder="asset key (64 hex)">
        <button onclick="lookupAsset()">Query</button>
      </div>
      <div id="astResult"></div>
    </div>
    <div class="section" id="fileLookupSec" style="display:none">
      <h2>File lookup <span class="sub">L2 file store &middot; STAT</span></h2>
      <div class="row">
        <input type="text" id="fileLookupPath" class="k" placeholder="/h/&lt;hex&gt;/path, /f/&lt;name&gt;/path, /p/&hellip;, or /s/name">
        <button onclick="lookupFile()">Query</button>
      </div>
      <div id="fileResult"></div>
    </div>
  </section>

  <!-- BILLING -->
  <section class="panel" id="panel-billing">
    <div class="section">
      <h2>Channel metering <span class="sub">per-channel RUDP usage (CesPlex)</span></h2>
      <div style="overflow:auto"><table class="data" id="billTbl"></table></div>
      <div id="billNote" class="hint"></div>
    </div>
    <div class="section">
      <h2>Net metering rates <span class="sub">applied immediately &middot; export to persist</span></h2>
      <div id="billFees"></div>
      <div class="row" style="margin-top:10px"><div class="spacer"></div><button class="green" id="billFeesBtn" onclick="applyNetFees()">Apply rates</button><span id="billFeesState" class="mono"></span></div>
    </div>
  </section>

  <!-- LOGS -->
  <section class="panel" id="panel-logs">
    <div class="section">
      <h2>Live log tail</h2>
      <div class="row" style="margin-bottom:10px;align-items:center;gap:8px">
        <span id="srvLevelBtns" class="lvlbtns">
          <button data-lvl="0" onclick="setSrvLevel(0)">TRACE</button>
          <button data-lvl="1" onclick="setSrvLevel(1)">DEBUG</button>
          <button data-lvl="2" onclick="setSrvLevel(2)">INFO</button>
          <button data-lvl="3" onclick="setSrvLevel(3)">WARN</button>
          <button data-lvl="4" onclick="setSrvLevel(4)">ERROR</button>
        </span>
      </div>
      <div class="row" style="margin-bottom:10px">
        <input type="text" id="logFilter" class="addr" placeholder="filter substring" oninput="renderLogs()" style="flex:1">
        <select id="logLevel" onchange="renderLogs()">
          <option value="0">all</option><option value="1">debug+</option>
          <option value="2">info+</option><option value="3">warn+</option><option value="4">error+</option>
        </select>
        <label class="muted" style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="logPause">pause</label>
        <label class="muted" style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="logAuto" checked>autoscroll</label>
        <button class="ghost sm" onclick="clearLogs()">clear</button>
      </div>
      <div id="logbox"></div>
    </div>
  </section>

  <!-- FEES -->
  <section class="panel" id="panel-fees">
    <div class="section">
      <h2>Base fees <span class="sub">applied immediately &middot; export to persist</span></h2>
      <div id="feesBase"></div>
      <div class="row" style="align-items:center;gap:10px;margin-top:10px">
        <label class="muted" style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="cfgDiscToggle">congestion discount enabled</label>
        <div class="spacer"></div>
        <button class="green" id="feesBaseBtn" onclick="applyBaseFees()">Apply fees</button>
        <span id="feesBaseState" class="mono"></span>
      </div>
      <p class="hint">Raw credit units (100,000,000 = 1 credit).</p>
    </div>
    <div class="section">
      <h2>Live fee multipliers <span class="sub">congestion pricing &middot; % of full fee</span></h2>
      <div id="feesMult"></div>
      <div id="feesDiscNote" class="hint"></div>
    </div>
  </section>

  <!-- FILE -->
  <section class="panel" id="panel-file">
    <div id="fileStats" class="grid cards" style="margin-bottom:6px"></div>
    <div id="fileOff" class="hint"></div>
    <div class="section">
      <h2>File fees <span class="sub">applied immediately &middot; export to persist</span></h2>
      <div id="fileFees"></div>
      <div class="row" style="margin-top:10px"><div class="spacer"></div><button class="green" id="fileFeesBtn" onclick="applyFileFees()">Apply fees</button><span id="fileFeesState" class="mono"></span></div>
    </div>
    <div class="section">
      <h2>Capacity <span class="sub">cap is live &middot; export to persist</span></h2>
      <div id="fileCapEdit"></div>
      <table class="kvtable" id="fileCap"></table>
    </div>
  </section>

  <!-- COMPUTE -->
  <section class="panel" id="panel-compute">
    <div id="computeStats" class="grid cards" style="margin-bottom:6px"></div>
    <div id="computeOff" class="hint"></div>
    <div class="section">
      <h2>Compute fees <span class="sub">applied immediately &middot; export to persist</span></h2>
      <div id="computeFees"></div>
      <div class="row" style="margin-top:10px"><div class="spacer"></div><button class="green" id="computeFeesBtn" onclick="applyComputeFees()">Apply fees</button><span id="computeFeesState" class="mono"></span></div>
    </div>
    <div class="section">
      <h2>Limits <span class="sub">max-instances is live &middot; export to persist</span></h2>
      <div id="computeCapEdit"></div>
      <table class="kvtable" id="computeCap"></table>
    </div>
    <div class="section">
      <h2>Running instances <span class="sub">builtin:compute</span></h2>
      <div style="overflow:auto"><table class="data" id="computeTbl"></table></div>
    </div>
  </section>

  <!-- EXTENSIONS -->
  <section class="panel" id="panel-extensions">
    <div id="extOff" class="hint"></div>
    <div class="section" id="extFundingBox">
      <h2>Funding budget <span class="sub">global — all extensions, all remotes</span></h2>
      <div class="hint">Credits/day the server will grant programs that call <span class="mono">request_funds</span> to fund themselves at remote peers. <b>0 = off</b> (the secure default): a program can spend nothing until you open a budget.</div>
      <div class="row" style="align-items:center">
        <input id="fundRate" type="number" min="0" step="1" placeholder="credits / day" style="width:150px">
        <button class="green sm" onclick="fundingApply()">Apply</button>
        <span id="fundState" class="mono"></span>
      </div>
    </div>
    <div id="extList"></div>
  </section>

  <!-- CONFIG -->
  <section class="panel" id="panel-config">
    <div class="section">
      <h2>Config persistence <span class="sub">runtime values → a file you can feed back</span></h2>
      <p class="hint">A booted server reads its config once, but the dashboard changes some values live (the peer target). Rather than rewrite your hand-edited config, <b>export</b> the current effective config to <span class="mono">&lt;data_dir&gt;/ces.toml</span>, then boot with <span class="mono">ces --config &lt;data_dir&gt;/ces.toml</span> to persist them.</p>
      <div class="row"><button class="green" onclick="exportConfig()" id="cfgExportBtn">Export config to data dir</button><span id="cfgExportState" class="mono"></span></div>
    </div>
    <div class="section">
      <h2>Maintenance <span class="sub">ledger snapshot</span></h2>
      <button class="ghost" onclick="snapshot()" id="snapBtn">Write snapshot now</button>
      <p class="hint">Forks and writes a full ledger snapshot, compacting the event log.</p>
    </div>
    <div class="section">
      <h2>Minimum PoW difficulty <span class="sub">live &middot; export to persist</span></h2>
      <div class="row" style="align-items:center;gap:10px">
        <label class="muted" style="width:150px">min_difficulty</label>
        <input type="number" min="1" max="54" class="addr" id="cfgMinDiff" style="flex:1">
        <button class="green" id="cfgMinDiffBtn" onclick="applyMinDiff()">Apply</button>
        <span id="cfgMinDiffState" class="mono"></span>
      </div>
    </div>
    <div class="section">
      <h2>Hello banner <span class="sub">your server&#39;s greeting to the network</span></h2>
      <p class="hint">Served in <span class="mono">CES_QUERY_SERVER_INFO</span> as the <span class="mono">hello</span> field. Stored in <span class="mono">&lt;data_dir&gt;/hello.txt</span>. UTF-8, capped at <b id="helloMax">160</b> bytes (trimmed on a codepoint boundary).</p>
      <textarea id="helloText" rows="4" placeholder="Welcome to my CES node&hellip;" oninput="helloCount()"></textarea>
      <div class="row" style="margin-top:10px">
        <span id="helloBytes" class="num muted">0 / 160 bytes</span>
        <div class="spacer"></div>
        <button class="ghost" onclick="helloLoad()">Load from file</button>
        <button class="green" onclick="helloSave()">Save</button>
      </div>
      <div id="helloState" class="hint"></div>
    </div>
    <div class="section"><h2>Server knobs</h2><table class="kvtable" id="cfgKnobs"></table></div>
  </section>

</main>
<div id="toast"></div>

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
// A quick opacity dip on every button press, so a click that then blocks still
// shows it registered.
document.addEventListener('click',e=>{
  const b=e.target.closest('button');
  if(b){b.classList.remove('flash');void b.offsetWidth;b.classList.add('flash');}
},true);
async function api(p,ms){const c=new AbortController();const t=setTimeout(()=>c.abort(),ms||8000);
  try{const r=await fetch(p,{signal:c.signal});if(!r.ok)throw new Error('HTTP '+r.status);return await r.json();}finally{clearTimeout(t);}}
async function post(p,o,ms){const c=new AbortController();const t=setTimeout(()=>c.abort(),ms||20000);
  try{const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(o).toString(),signal:c.signal});return await r.json();}finally{clearTimeout(t);}}
function toast(msg,kind){const t=document.createElement('div');t.className='tmsg '+(kind||'');t.textContent=msg;$('#toast').appendChild(t);setTimeout(()=>t.remove(),4200);}
function fmtNum(n){if(n===undefined||n===null)return '-';return Number(n).toLocaleString();}
const PRICE_UNIT=100000000; // raw credit units per 1 credit (8 decimals)
function fmtCredits(raw){return (Number(raw)/PRICE_UNIT).toLocaleString('en-US',{minimumFractionDigits:8,maximumFractionDigits:8});}
function fmtBytes(b){b=Number(b)||0;if(b<1024)return b+' B';const u=['KB','MB','GB','TB'];let i=-1;do{b/=1024;i++;}while(b>=1024&&i<3);return b.toFixed(1)+' '+u[i];}
function shortKey(k){return k?k.slice(0,10)+'…'+k.slice(-6):'-';}
function copy(txt){navigator.clipboard&&navigator.clipboard.writeText(txt);toast('copied','ok');}
function fmtDur(s){s=Number(s)||0;const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);s%=3600;const m=Math.floor(s/60);
  if(d)return d+'d '+h+'h';if(h)return h+'h '+m+'m';if(m)return m+'m';return (Number(s)|0)+'s';}
function ago(ts){if(!ts)return 'never';const d=Math.floor(Date.now()/1000)-Number(ts);if(d<0)return 'now';
  if(d<60)return d+'s ago';if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago';}
function esc(s){return (s+'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function setLive(ok){const d=$('#liveDot');d.className='dot'+(ok?' ok':'');$('#liveTxt').textContent=ok?'live':'offline';}

/* tabs */
let activeTab='overview',timer=null,extStatusTimer=null;
const REFRESH={overview:2000,peers:5000,wallet:3000,billing:3000,fees:3000,file:4000,compute:3000,extensions:3000,logs:1500};
function showTab(n){activeTab=n;try{history.replaceState(null,'','#'+n);}catch(e){}
  $$('.tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===n));
  $$('.panel').forEach(p=>p.classList.toggle('active',p.id==='panel-'+n));
  if(timer)clearInterval(timer);timer=null;
  if(extStatusTimer)clearInterval(extStatusTimer);extStatusTimer=null;
  loadTab(n);
  if(REFRESH[n])timer=setInterval(()=>loadTab(n),REFRESH[n]);
  // Status is cheap; poll expanded extension rows fast. Only while this tab is
  // showing (timer torn down on switch) and only for expanded rows (extPollStatus
  // iterates extExpanded). A collapsed or unseen card is never polled.
  if(n==='extensions')extStatusTimer=setInterval(extPollStatus,500);}
function loadTab(n){({overview:loadOverview,peers:loadPeers,wallet:loadWallet,lookup:loadLookup,billing:loadBilling,fees:loadFees,file:loadFile,compute:loadCompute,extensions:loadExtensions,logs:pollLogs,config:loadConfig}[n]||(()=>{}))();}
$('#tabs').addEventListener('click',e=>{const t=e.target.closest('.tab');if(t)showTab(t.dataset.tab);});

/* header + overview */
// The header identity is static per server but must paint regardless of which
// tab is open, so the always-on heartbeat drives it — not loadOverview alone.
// A node with no serverName still has a usable identity: its first reachable
// address (non-loopback first) and the main port.
function boundAddrs(s){return (s.boundAddrs||[]).map(a=>a.indexOf(':')>=0?('['+a+']:'+s.port):(a+':'+s.port));}
function setHeader(s){
  const ba=boundAddrs(s);
  $('#srvName').textContent=s.serverName||ba[0]||'(unnamed node)';
  document.title=(s.serverName||ba[0]||'CES')+' · dashboard';
  const k=$('#srvKey');k.textContent=shortKey(s.pubkey);k.onclick=()=>copy(s.pubkey);
  $('#srvVer').textContent=s.version?('v '+s.version):'';
  $('#srvPorts').textContent='udp '+s.port+(s.rpcPort?(' · rpc '+s.rpcPort):'');
  $('#upPill').textContent='up '+fmtDur(s.uptime);
}
async function loadOverview(){
  let s;try{s=await api('/api/status');}catch(e){setLive(false);return;}
  setLive(true);
  setHeader(s);
  const cards=[
    ['Credits in circulation',fmtCredits(s.circulating),'green','ultrawide'],
    ['Accounts',fmtNum(s.accounts),'','wide'],
    ['Assets',fmtNum(s.assets),'','wide'],
    ['Transactions',fmtNum(s.txCount),'','wide'],
    ['TPS',fmtNum(s.tps),'','wide'],
    ['Peers',fmtNum(s.peerCount!==undefined?s.peerCount:'-'),''],
    ['Min diff',s.minDifficulty,'']];
  $('#ovCards').innerHTML=cards.map(c=>`<div class="card${c[3]?' '+c[3]:''}"><h3>${c[0]}</h3><div class="stat ${c[2]||''}">${c[1]}</div></div>`).join('');
  const g=s.gauges,gl=[['L1 CPU',g.l1cpu],['L2 CPU',g.l2cpu],['Mem (acct)',g.l1memac],['Mem (asset)',g.l1memas],['Mem (L2)',g.l2mem],['Network',g.net]];
  $('#ovGauges').innerHTML=gl.map(x=>gaugeHtml(x[0],x[1])).join('');
  $('#ovIdent').innerHTML=`<table class="kvtable">
    <tr><td>public key</td><td class="mono" style="word-break:break-all">${esc(s.pubkey)}</td></tr>
    <tr><td>server name</td><td>${esc(s.serverName||'—')}</td></tr>
    <tr><td>bound address</td><td class="mono">${(()=>{const b=boundAddrs(s);return b.length?b.map(esc).join('<br>'):'—';})()}</td></tr>
    <tr><td>version</td><td class="mono">${esc(s.version||'—')}</td></tr>
    <tr><td>CES / RPC ports</td><td class="num">${s.port} / ${s.rpcPort||'off'}</td></tr>
    <tr><td>peer target</td><td class="num">${fmtCredits(s.peerTarget)}${s.minerRunning?' <span class="muted">(miner on)</span>':''}</td></tr></table>`;
  const f=s.features,fl=[['RPC/CesPlex',f.rpc],['File store',f.file],['Compute',f.compute],['Peering',f.peering],['PoW ready',f.powReady]];
  $('#ovFeats').innerHTML=fl.map(x=>`<span class="feat ${x[1]?'on':''}">${x[0]}</span>`).join('');
}
function gaugeColor(bp){if(bp>=7500)return 'var(--danger)';if(bp>=4000)return 'var(--warn)';return 'var(--accent)';}
function gaugeHtml(lbl,bp){bp=Number(bp)||0;const pct=(bp/100).toFixed(1);
  return `<div class="gauge"><div class="lbl"><span>${lbl}</span><span class="num">${pct}%</span></div>
    <div class="bar"><i style="width:${pct}%;background:${gaugeColor(bp)}"></i></div></div>`;}

/* peers */
// Click a peer's address: copy it and load both the key and address into the
// Add-peer form up top (replacing whatever's there).
function useAddr(key,addr){const k=$('#addKey'),a=$('#addAddr');if(k)k.value=key;if(a)a.value=addr;copy(addr);}
async function loadPeers(){
  let d;try{d=await api('/api/peers');}catch(e){return;}
  $('#curTarget').textContent=fmtCredits(d.target)+' cr';
  $('#peerCount').textContent=d.peers.length+' peer(s)';
  const cOut=d.peers.filter(p=>p.outbound).length,cIn=d.peers.filter(p=>p.inbound).length,cRch=d.peers.filter(p=>p.reachable).length;
  const ms=$('#minerState');
  if(d.miningActive){
    const D=d.miningDifficulty,iters=Math.pow(2,D);
    const cn=n=>n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'k':Math.round(n).toString();
    let t='⛏ mining '+esc(d.miningPeer)+' @ diff '+D+' · ~'+cn(iters)+' iters avg';
    if(d.miningElapsedSecs!=null)t+=' · '+d.miningElapsedSecs+'s in';
    if(d.hashRate>0){const exp=Math.max(1,Math.round(iters/d.hashRate));
      t+=' · ~'+cn(d.hashRate)+' H/s · ~'+exp+'s expected'+(d.miningElapsedSecs>2*exp?' (unlucky!)':'');}
    ms.textContent=t;ms.style.color='var(--accent)';}
  else if(d.minerRunning){ms.textContent='↻ loop alive · '+d.cycles+' cycles'+(d.lastCycle?(' · last '+ago(d.lastCycle)):' · starting…')+' · not hashing';ms.style.color='var(--muted)';}
  else if(cOut>0){ms.textContent='⚠ idle — set a target to start probing/mining';ms.style.color='var(--warn)';}
  else{ms.textContent='miner idle';ms.style.color='var(--muted)';}
  const reachCell=p=>{
    if(!p.lastCheckTime)return '<span class="muted">not checked</span>';
    if(p.reachable)return '<span class="sdot ok"></span> '+(p.verified?'verified':'<span style="color:var(--warn)">unverified</span>');
    return '<span class="sdot"></span> <span style="color:var(--danger)">down ('+(p.pingFailures||0)+')</span>';
  };
  $('#peerSummary').innerHTML=`<span class="feat on">${cOut} outbound</span><span class="feat ${cIn?'on':''}">${cIn} inbound</span><span class="feat ${cRch?'on':''}">${cRch} reachable</span>`;
  const dir=p=>{let b='';if(p.outbound)b+='<span class="badge out">OUT</span> ';if(p.inbound)b+='<span class="badge in">IN</span>';return b||'<span class="muted">—</span>';};
  $('#peerTbl').innerHTML=`<tr><th>dir</th><th>address</th><th>key</th><th>reach</th><th title="our reserve on them — what they owe us">our bal (cr)</th><th title="their vostro here — what we owe them">their bal (cr)</th><th title="our lifetime PoW on them (H_out)">our PoW (cr)</th><th title="their lifetime PoW on us (H_in)">their PoW (cr)</th><th>last check</th><th>fails</th><th></th></tr>`+
    (d.peers.length?d.peers.map(p=>`<tr>
      <td>${dir(p)}</td>
      <td class="copy" title="click: copy address + load it (with the key) into Add peer" onclick="useAddr('${esc(p.key)}','${esc(p.address||'')}')">${esc(p.address||'—')}${(p.resolvedIP&&!(p.address||'').includes(p.resolvedIP))?'<br><span class="muted mono" style="font-size:11px">&rarr; '+esc(p.resolvedIP)+'</span>':''}</td>
      <td class="mono copy" title="${esc(p.key)}" onclick="copy('${esc(p.key)}')">${shortKey(p.key)}</td>
      <td>${reachCell(p)}</td>
      <td class="num">${p.ourBalanceThere<0?'<span class="muted">?</span>':fmtCredits(p.ourBalanceThere)}</td>
      <td class="num">${fmtCredits(p.theirBalanceHere)}</td>
      <td class="num">${fmtCredits(p.totalOutboundPoW)}</td>
      <td class="num">${fmtCredits(p.totalInboundPoW)}</td>
      <td class="muted">${ago(p.lastCheckTime)}</td>
      <td class="num">${p.pingFailures||0}</td>
      <td><button class="danger sm" onclick="rmPeer('${esc(p.key)}')">remove</button></td></tr>`).join('')
     :`<tr><td colspan="11" class="muted" style="text-align:center;padding:20px">no peers yet</td></tr>`);
}
async function setTarget(){
  const credits=parseFloat($('#peerTarget').value||'0');
  if(!isFinite(credits)||credits<0){toast('enter a non-negative number of credits','err');return;}
  const raw=Math.round(credits*PRICE_UNIT);
  const b=$('#setTargetBtn');b.disabled=true;b.textContent='Setting…';
  try{const r=await post('/api/peer_target',{target:String(raw)});
    if(r.ok){toast('peer target set to '+fmtCredits(raw)+' cr','ok');$('#peerTarget').value='';loadPeers();}
    else toast(r.error||'failed','err');}
  catch(e){toast('set target failed — server not responding','err');}
  finally{b.disabled=false;b.textContent='Set target';}}
async function addPeer(){const key=$('#addKey').value.trim(),addr=$('#addAddr').value.trim();
  if(!key||!addr){toast('key and address required','err');return;}
  const b=$('#addPeerBtn');b.disabled=true;b.textContent='Verifying…';
  try{const r=await post('/api/peer_add',{key,address:addr});
    if(r.ok){toast(r.message||'peer added','ok');$('#addKey').value='';$('#addAddr').value='';loadPeers();}else toast(r.error||'failed','err');}
  catch(e){toast('add peer failed — server not responding','err');}
  finally{b.disabled=false;b.textContent='Add peer';}}
async function rmPeer(key){if(!confirm('Remove this peer?'))return;const r=await post('/api/peer_remove',{key});r.ok?toast('peer removed','ok'):toast(r.message||'not found','err');loadPeers();}

/* inspect */
async function doInspect(){const addr=$('#inspAddr').value.trim();if(!addr){toast('address required','err');return;}
  const b=$('#inspBtn');b.disabled=true;b.textContent='Inspecting…';$('#inspResult').innerHTML='';
  try{const r=await post('/api/inspect',{address:addr,paid:$('#inspPaid').checked?'1':''});
    if(r.error){toast(r.error,'err');return;}
    if(!r.reachable){$('#inspResult').innerHTML=`<div class="section" style="margin-top:14px;border-color:var(--danger)"><b style="color:var(--danger)">unreachable</b> &mdash; ${esc(addr)} did not respond.</div>`;return;}
    let info='';if(r.info){for(const k in r.info)info+=`<tr><td>${esc(k)}</td><td class="mono" style="word-break:break-all">${esc(r.info[k])}</td></tr>`;}
    $('#inspResult').innerHTML=`<div class="section" style="margin-top:14px">
      <div class="row" style="justify-content:space-between"><b style="color:var(--accent)">&#x25CF; reachable</b><span class="muted">min difficulty ${r.minDifficulty}</span></div>
      <table class="kvtable" style="margin-top:10px">
        <tr><td>server key</td><td class="mono" style="word-break:break-all">${esc(r.serverKey)}</td></tr>${info}</table>
      <div class="row" style="margin-top:14px">
        <input type="number" id="mineCount" class="addr" value="1" min="1" max="32" style="width:90px">
        <button class="warn" onclick="mineRemote('${esc(addr)}')" id="mineBtn">Mine on it</button>
        <button class="green" onclick="addInspected('${esc(r.serverKey)}','${esc(addr)}')">Add as outbound peer</button>
      </div>
      <p class="hint">Mining bootstraps a reserve balance here (RandomX &mdash; may take a moment). Adding it as a peer lets the miner maintain your target automatically.</p>
      <div id="mineResult"></div></div>`;
  }catch(e){toast('inspect failed','err');}finally{b.disabled=false;b.textContent='Inspect';}}
async function mineRemote(addr){const c=$('#mineCount').value||'1';const b=$('#mineBtn');b.disabled=true;b.textContent='Mining…';
  try{const r=await post('/api/mine',{address:addr,count:c});
    if(r.ok)$('#mineResult').innerHTML=`<div class="hint" style="color:var(--accent)">mined ${fmtCredits(r.credit)} credits</div>`;
    else $('#mineResult').innerHTML=`<div class="hint" style="color:var(--danger)">mining failed${r.error?': '+esc(r.error):' (status '+r.status+')'}</div>`;
    r.ok?toast('mined '+fmtCredits(r.credit),'ok'):toast('mining failed','err');
  }catch(e){toast('mine failed','err');}finally{b.disabled=false;b.textContent='Mine on it';}}
async function addInspected(key,addr){const r=await post('/api/peer_add',{key,address:addr});
  r.ok?toast('added as peer — see Peers tab','ok'):toast(r.error||'failed','err');}

/* mint */
function isHash64(s){return /^[0-9a-fA-F]{64}$/.test(s);}
async function mint(kind){const isBurn=kind==='debit';
  const kEl=isBurn?'#burnKey':'#mintKey',aEl=isBurn?'#burnAmt':'#mintAmt';
  const key=$(kEl).value.trim(),amt=$(aEl).value.trim();
  if(!isHash64(key)||!amt){toast('valid 64-hex key and amount required','err');return;}
  const cr=parseFloat(amt);
  if(!(cr>0)){toast('amount must be a positive number of credits','err');return;}
  const raw=Math.round(cr*PRICE_UNIT);  // credits (dot notation) → raw ledger units
  const r=await post('/api/'+kind,{pubkey:key,amount:String(raw)});
  if(r.ok){toast(r.message,'ok');$(aEl).value='';const c=$(aEl).closest('.section'),fc=isBurn?'flash-red':'flash';if(c){c.classList.remove(fc);void c.offsetWidth;c.classList.add(fc);}
    isBurn?checkBurnAcct():checkMintAcct();}  // re-query so the shown balance updates
  else toast(r.error||'failed','err');}
// Live account check: validate the key is a 64-hex hash, query it, show the
// balance (or that it doesn't exist), and reveal the action button only when
// actionable — Mint for any valid key (it creates the account), Burn only when
// the account exists. Stale-guarded so a fast edit can't be overwritten by an
// in-flight reply.
async function checkMintAcct(){
  const key=$('#mintKey').value.trim(),st=$('#mintAcct'),btn=$('#mintBtn');
  if(!isHash64(key)){st.textContent='';btn.disabled=true;return;}
  st.textContent='checking…';st.style.color='var(--muted)';
  try{const a=await api('/api/account?key='+key);
    if($('#mintKey').value.trim()!==key)return;
    if(a.prefixTaken){st.innerHTML='&#9888; prefix <b>'+esc(key.slice(0,16))+'&hellip;</b> already taken by a different account';st.style.color='var(--danger)';btn.disabled=true;return;}
    if(a.exists){st.innerHTML='account exists &middot; balance <b>'+fmtCredits(a.balance)+'</b>';st.style.color='var(--accent)';}
    else{st.textContent='new account — Mint will create it';st.style.color='var(--muted)';}
    btn.disabled=false;
  }catch(e){if($('#mintKey').value.trim()===key){st.textContent='lookup failed';st.style.color='var(--danger)';btn.disabled=true;}}
}
async function checkBurnAcct(){
  const key=$('#burnKey').value.trim(),st=$('#burnAcct'),btn=$('#burnBtn');
  if(!isHash64(key)){st.textContent='';btn.disabled=true;return;}
  st.textContent='checking…';st.style.color='var(--muted)';
  try{const a=await api('/api/account?key='+key);
    if($('#burnKey').value.trim()!==key)return;
    if(a.prefixTaken){st.innerHTML='&#9888; prefix <b>'+esc(key.slice(0,16))+'&hellip;</b> already taken by a different account';st.style.color='var(--danger)';btn.disabled=true;return;}
    if(a.exists){st.innerHTML='balance <b>'+fmtCredits(a.balance)+'</b>';st.style.color='var(--accent)';btn.disabled=false;}
    else{st.textContent="account doesn't exist — nothing to burn";st.style.color='var(--danger)';btn.disabled=true;}
  }catch(e){if($('#burnKey').value.trim()===key){st.textContent='lookup failed';st.style.color='var(--danger)';btn.disabled=true;}}
}
// Wallet: show this node's own account balance live, validate the transfer
// destination the same way as mint/burn, and send from the node's account.
let walletPubkey='';
async function loadWallet(){
  try{if(!walletPubkey){const s=await api('/api/status');walletPubkey=s.pubkey;}
    const a=await api('/api/account?key='+walletPubkey);
    $('#walletBal').innerHTML='node balance: <b>'+fmtCredits(a.exists?a.balance:0)+'</b>';
  }catch(e){}
}
async function checkXferAcct(){
  const key=$('#xferKey').value.trim(),st=$('#xferAcct'),btn=$('#xferBtn');
  if(!isHash64(key)){st.textContent='';btn.disabled=true;return;}
  st.textContent='checking…';st.style.color='var(--muted)';
  try{const a=await api('/api/account?key='+key);
    if($('#xferKey').value.trim()!==key)return;
    if(a.prefixTaken){st.innerHTML='&#9888; prefix <b>'+esc(key.slice(0,16))+'&hellip;</b> already taken by a different account';st.style.color='var(--danger)';btn.disabled=true;return;}
    if(a.exists){st.innerHTML='destination exists &middot; balance <b>'+fmtCredits(a.balance)+'</b>';st.style.color='var(--accent)';}
    else{st.textContent='new account — will be created';st.style.color='var(--muted)';}
    btn.disabled=false;
  }catch(e){if($('#xferKey').value.trim()===key){st.textContent='lookup failed';st.style.color='var(--danger)';btn.disabled=true;}}
}
async function doXfer(){
  const key=$('#xferKey').value.trim(),amt=$('#xferAmt').value.trim();
  if(!isHash64(key)||!amt){toast('valid 64-hex destination and amount required','err');return;}
  const cr=parseFloat(amt);if(!(cr>0)){toast('amount must be a positive number of credits','err');return;}
  const raw=Math.round(cr*PRICE_UNIT);
  const r=await post('/api/transfer',{pubkey:key,amount:String(raw)});
  if(r.ok){toast(r.message,'ok');$('#xferAmt').value='';const c=$('#xferAmt').closest('.section');if(c){c.classList.remove('flash');void c.offsetWidth;c.classList.add('flash');}
    loadWallet();checkXferAcct();}  // refresh node balance + destination balance
  else toast(r.error||'failed','err');}
async function snapshot(){const b=$('#snapBtn');b.disabled=true;b.textContent='Snapshotting…';
  try{const r=await post('/api/snapshot',{});r.ok?toast(r.message||'snapshot done','ok'):toast(r.message||'failed','err');}
  catch(e){toast('snapshot failed','err');}finally{b.disabled=false;b.textContent='Write snapshot now';}}

/* lookup */
async function lookupAccount(){const key=$('#accKey').value.trim();if(key.length!==64){toast('need 64 hex chars','err');return;}
  const r=await api('/api/account?key='+encodeURIComponent(key));const e=$('#accResult');
  if(r.error){e.innerHTML=`<p class="hint" style="color:var(--danger)">${esc(r.error)}</p>`;return;}
  if(!r.exists){e.innerHTML='<p class="hint">account not found</p>';return;}
  e.innerHTML=`<table class="kvtable" style="margin-top:10px">
    <tr><td>balance</td><td class="num">${fmtCredits(r.balance)}${r.balance<0?' <span class="badge in">payment acct</span>':''}</td></tr>
    <tr><td>nonce</td><td class="num">${fmtNum(r.nonce)}</td></tr>
    <tr><td>last transfer to</td><td class="mono">${esc(r.lastXferDest)}</td></tr>
    <tr><td>last transfer amount</td><td class="num">${fmtNum(r.lastXferAmount)}</td></tr>
    <tr><td>last transfer time</td><td>${r.lastXferTime?new Date(r.lastXferTime*1000).toLocaleString():'—'}</td></tr></table>`;}
async function lookupAsset(){const key=$('#astKey').value.trim();if(key.length!==64){toast('need 64 hex chars','err');return;}
  const r=await api('/api/asset?key='+encodeURIComponent(key));const e=$('#astResult');
  if(r.error){e.innerHTML=`<p class="hint" style="color:var(--danger)">${esc(r.error)}</p>`;return;}
  if(!r.exists){e.innerHTML='<p class="hint">asset not found</p>';return;}
  const flags=[r.immutable?'immutable':'',r.assetOwned?'asset-owned':'',r.private?'private':''].filter(Boolean).join(', ')||'none';
  e.innerHTML=`<table class="kvtable" style="margin-top:10px">
    <tr><td>owner prefix</td><td class="mono">${esc(r.owner)}</td></tr>
    <tr><td>days remaining</td><td class="num">${fmtNum(r.days)}</td></tr>
    <tr><td>flags</td><td>${flags}</td></tr>
    <tr><td>price (units)</td><td class="num">${fmtNum(r.price)}</td></tr>
    <tr><td>content (hex)</td><td class="mono" style="word-break:break-all;font-size:11px">${esc((r.content||'').slice(0,200))}${r.content&&r.content.length>200?'…':''}</td></tr></table>`;}
// File lookup: only show the section when the file feature is on.
async function loadLookup(){
  try{const s=await api('/api/status');$('#fileLookupSec').style.display=(s.features&&s.features.file)?'':'none';}catch(e){}
}
async function lookupFile(){const p=$('#fileLookupPath').value.trim();if(!p){toast('path required','err');return;}
  const e=$('#fileResult');
  try{const f=await api('/api/filestat?path='+encodeURIComponent(p));
    if(f.error){e.innerHTML=`<p class="hint" style="color:var(--danger)">${esc(f.error)}</p>`;return;}
    if(!f.enabled){e.innerHTML='<p class="hint">file feature disabled on this node</p>';return;}
    if(!f.found){e.innerHTML='<p class="hint" style="color:var(--danger)">no file at that path</p>';return;}
    e.innerHTML=`<table class="kvtable" style="margin-top:10px">
      <tr><td>path</td><td class="mono">${esc(p)}</td></tr>
      <tr><td>owner</td><td class="mono" style="word-break:break-all;font-size:11px">${esc(f.owner)}</td></tr>
      <tr><td>size</td><td class="num">${fmtBytes(f.size)}</td></tr>
      <tr><td>file_balance</td><td class="num">${fmtCredits(f.fileBalance)}</td></tr>
      <tr><td>price / KB</td><td class="num">${fmtCredits(f.pricePerKb)}</td></tr>
      <tr><td>created</td><td class="muted">${ago(Math.floor(f.createdUs/1e6))}</td></tr>
      <tr><td>modified</td><td class="muted">${ago(Math.floor(f.modifiedUs/1e6))}</td></tr></table>`;
  }catch(err){toast('lookup failed','err');}}

/* billing */
async function loadBilling(){let d;try{d=await api('/api/netbill');}catch(e){return;}
  if(!d.active){$('#billTbl').innerHTML='';$('#billNote').textContent='Channel metering inactive — the rpc port (CesPlex) is disabled.';}
  else{
    $('#billNote').textContent=d.rows.length?'':'No bound channels right now.';
    $('#billTbl').innerHTML=`<tr><th>peer</th><th>cid</th><th>tag</th><th>payer</th><th>sent</th><th>recv</th><th>mem·s</th><th>Δsnd</th><th>Δrcv</th><th>Δage</th></tr>`+
      d.rows.map(r=>`<tr><td class="mono" style="font-size:11px">${esc(r.peer)}</td><td class="num">${r.channelId}</td>
        <td>${esc(r.tag)}</td><td class="mono" title="${esc(r.payer)}">${esc(r.payer.slice(0,12))}</td>
        <td class="num">${fmtNum(r.bytesSent)}</td><td class="num">${fmtNum(r.bytesReceived)}</td><td class="num">${fmtNum(r.memByteSec)}</td>
        <td class="num">${fmtNum(r.dSent)}</td><td class="num">${fmtNum(r.dRecv)}</td><td class="num">${r.dAge}s</td></tr>`).join('');
  }
  if(!billReady){try{const cfg=await api('/api/config');$('#billFees').innerHTML=feeRows(FEES_NET);fillFees(cfg.knobs,FEES_NET);billReady=true;}catch(e){}}}

/* logs */
let logLines=[],logSince=0,srvLevel=-1;
async function pollLogs(){if($('#logPause').checked)return;
  try{const d=await api('/api/logs?since='+logSince);
    if(d.level!==undefined&&d.level!==srvLevel){srvLevel=d.level;highlightSrvLevel();}
    if(d.lines.length){logLines=logLines.concat(d.lines);if(logLines.length>3000)logLines=logLines.slice(-3000);logSince=d.hi;renderLogs();}}catch(e){}}
async function setSrvLevel(n){const r=await post('/api/loglevel',{level:String(n)}).catch(()=>null);
  if(r&&r.ok){srvLevel=r.level;highlightSrvLevel();toast('server now emits '+['TRACE','DEBUG','INFO','WARN','ERROR'][n]+'+','ok');}
  else toast('could not set log level','err');}
function highlightSrvLevel(){document.querySelectorAll('#srvLevelBtns button').forEach(b=>b.classList.toggle('active',+b.dataset.lvl===srvLevel));}
function sevRank(t){const s=(t||'').slice(0,3);return {TRC:0,DBG:1,INF:2,WRN:3,ERR:4,FTL:5}[s]!==undefined?{TRC:0,DBG:1,INF:2,WRN:3,ERR:4,FTL:5}[s]:2;}
function renderLogs(){const flt=$('#logFilter').value.toLowerCase(),lvl=+$('#logLevel').value,box=$('#logbox');
  const atBottom=box.scrollHeight-box.scrollTop-box.clientHeight<40;
  box.innerHTML=logLines.filter(l=>sevRank(l.text)>=lvl&&(!flt||l.text.toLowerCase().includes(flt)))
    .map(l=>{const sev=(l.text||'').slice(0,3);const tm=new Date(l.ts*1000).toLocaleTimeString();
      return `<span class="lg ${sev}"><span class="t">${tm}</span>${esc(l.text)}</span>`;}).join('');
  if($('#logAuto').checked&&atBottom)box.scrollTop=box.scrollHeight;}
function clearLogs(){logLines=[];renderLogs();}

/* hello */
let helloMax=160;
async function loadHello(){try{const d=await api('/api/hello');helloMax=d.max||160;$('#helloMax').textContent=helloMax;
  $('#helloText').value=d.hello||'';helloCount();
  $('#helloState').textContent=d.fileExists?'hello.txt exists on disk.':'No hello.txt yet — saving will create it.';}catch(e){}}
function utf8len(s){return new TextEncoder().encode(s).length;}
function helloCount(){const n=utf8len($('#helloText').value);const el=$('#helloBytes');el.textContent=n+' / '+helloMax+' bytes';
  el.style.color=n>helloMax?'var(--danger)':'var(--muted)';}
async function helloSave(){const r=await post('/api/hello_save',{text:$('#helloText').value});
  if(r.ok){$('#helloText').value=r.hello;helloCount();toast('hello saved ('+r.bytes+' bytes)','ok');$('#helloState').textContent='Saved to hello.txt.';}
  else toast(r.error||'failed','err');}
async function helloLoad(){const r=await post('/api/hello_load',{});
  if(r.ok){$('#helloText').value=r.hello;helloCount();toast(r.fileExists?'loaded from file':'no file on disk',r.fileExists?'ok':'');}
  else toast('failed','err');}

/* config */
// Editable fee groups: [snake_key (config_set), camel_knob_key (/api/config), label].
const FEES_BASE=[['fee_account','feeAccount','Account rent / day'],['fee_asset','feeAsset','Asset rent / day'],['fee_tx','feeTx','Per signed op'],['fee_query','feeQuery','Per signed query'],['fee_vm_mult','feeVmMult','VM gas multiplier']];
const FEES_NET=[['fee_net_byte_sent','feeNetByteSent','Per byte sent (S→C)'],['fee_net_byte_received','feeNetByteReceived','Per byte received (C→S)'],['fee_net_channel_sec','feeNetChannelSec','Per channel-second open'],['fee_net_mem_byte_day','feeNetMemByteDay','Per RUDP mem byte-day']];
const FEES_FILE=[['fee_file_rent','feeFileRent','Rent / byte-day'],['fee_file_write','feeFileWrite','Write / KB'],['fee_file_read','feeFileRead','Read / KB']];
const FEES_COMPUTE=[['fee_compute_slot_sec','feeComputeSlotSec','Slot / sec'],['fee_compute_cpu_sec','feeComputeCpuSec','CPU / core-sec'],['fee_compute_rss_byte_day','feeComputeRssByteDay','RSS / byte-day'],['fee_compute_net_byte','feeComputeNetByte','Net / byte'],['fee_bucket_byte_sec','feeBucketByteSec','Bucket / byte-sec']];
// Render a fee-editor group; input id = fee_<camel>, config key shown in mono.
function feeRows(fields){return fields.map(f=>`<div class="row" style="align-items:center;gap:8px;margin-bottom:6px"><label style="width:210px"><div class="mono">${f[0]}</div><div class="muted" style="font-size:11px">${f[2]}</div></label><input type="number" min="0" class="addr" id="fee_${f[1]}" style="flex:1"></div>`).join('');}
function fillFees(knobs,fields){fields.forEach(f=>{const el=$('#fee_'+f[1]);if(el)el.value=knobs[f[1]];});}
// Apply one fee group: POST each key, optionally run `extra`, then reload its tab.
async function applyFeeGroup(fields,btnId,stateId,reloadFn,extra){
  const b=$('#'+btnId),s=$('#'+stateId);b.disabled=true;const t=b.textContent;b.textContent='Applying…';s.textContent='';
  try{
    for(const f of fields){const v=$('#fee_'+f[1]).value||'0';const r=await post('/api/config_set',{key:f[0],value:v});if(!r.ok)throw new Error(r.error||f[0]);}
    if(extra)await extra();
    s.textContent='✓ applied';s.style.color='var(--accent)';toast('applied — export to persist','ok');reloadFn&&reloadFn();
  }catch(e){s.textContent='failed';s.style.color='var(--danger)';toast('apply failed','err');}
  finally{b.disabled=false;b.textContent=t;}
}
// Editor inputs fill once per page load (and persist their DOM values across tab
// switches); the live stats/multipliers around them refresh on the tab's tick,
// but a refresh must never clobber what the operator is typing.
let feesReady=false,billReady=false,fileReady=false,computeReady=false;
async function loadConfig(){let d;try{d=await api('/api/config');}catch(e){return;}
  $('#cfgKnobs').innerHTML=Object.entries(d.knobs).map(([k,v])=>`<tr><td>${esc(k)}</td><td class="num">${fmtNum(v)}</td></tr>`).join('');
  $('#cfgMinDiff').value=d.knobs.minDifficulty;
  loadHello();}
async function loadFees(){let d;try{d=await api('/api/config');}catch(e){return;}
  if(!feesReady){$('#feesBase').innerHTML=feeRows(FEES_BASE);fillFees(d.knobs,FEES_BASE);$('#cfgDiscToggle').checked=!!d.feeDiscountEnabled;feesReady=true;}
  $('#feesMult').innerHTML=Object.entries(d.multipliers).map(([k,v])=>gaugeHtml(k,v)).join('');
  $('#feesDiscNote').textContent=d.feeDiscountEnabled?'Discount enabled: idle → cheaper, saturated → full price.':'Discount disabled: every fee pinned at full price (100%).';}
async function applyBaseFees(){applyFeeGroup(FEES_BASE,'feesBaseBtn','feesBaseState',()=>{feesReady=false;loadFees();},async()=>{await post('/api/config_set',{key:'fee_discount_enabled',value:$('#cfgDiscToggle').checked?'1':'0'});});}
async function applyNetFees(){applyFeeGroup(FEES_NET,'billFeesBtn','billFeesState',null);}
async function applyFileFees(){applyFeeGroup(FEES_FILE,'fileFeesBtn','fileFeesState',null);}
async function applyComputeFees(){applyFeeGroup(FEES_COMPUTE,'computeFeesBtn','computeFeesState',null);}
// Live cap editor (file-store bytes / compute max-instances). The 0 boundary is
// frozen server-side (binds at boot), so the input is min 1 and a 0 is rejected.
function capEditorHtml(cfgKey,inputId,applyFn){return `<div class="row" style="align-items:center;gap:8px;margin-bottom:6px"><label style="width:210px"><div class="mono">${cfgKey}</div><div class="muted" style="font-size:11px">live &middot; &ge; 1 (can't be zeroed live)</div></label><input type="number" min="1" class="addr" id="${inputId}" style="flex:1"><button class="green" id="${inputId}Btn" onclick="${applyFn}()">Apply</button><span id="${inputId}St" class="mono"></span></div>`;}
async function applyCap(key,inputId){const b=$('#'+inputId+'Btn'),s=$('#'+inputId+'St');b.disabled=true;const t=b.textContent;b.textContent='…';s.textContent='';
  try{const v=$('#'+inputId).value||'0';const r=await post('/api/config_set',{key,value:v});if(!r.ok)throw 0;s.textContent='✓ applied';s.style.color='var(--accent)';toast('applied — export to persist','ok');}
  catch(e){s.textContent='rejected';s.style.color='var(--danger)';toast('rejected — must be ≥ 1 (crossing 0 needs a restart)','err');}
  finally{b.disabled=false;b.textContent=t;}}
async function applyFileCap(){applyCap('file_store_max_bytes','capFileMax');}
async function applyComputeCap(){applyCap('compute_max_instances','capCompMax');}
async function loadFile(){let fs,cfg;try{fs=await api('/api/filestore');cfg=await api('/api/config');}catch(e){return;}
  if(fs.enabled){const pct=fs.maxBytes>0?Math.min(100,fs.totalBytes/fs.maxBytes*100):0;
    $('#fileStats').innerHTML=[['Files',fmtNum(fs.totalFiles)],['Bytes used',fmtBytes(fs.totalBytes)],['Capacity',fs.maxBytes>0?fmtBytes(fs.maxBytes):'∞'],['Used',fs.maxBytes>0?pct.toFixed(1)+'%':'—']].map(c=>`<div class="card wide"><h3>${c[0]}</h3><div class="stat">${c[1]}</div></div>`).join('');
    $('#fileOff').textContent='';
  }else{$('#fileStats').innerHTML='';$('#fileOff').innerHTML='<b>File store disabled.</b> Set <span class="mono">cesFileStoreMaxBytes</span> &gt; 0 and restart.';}
  if(!fileReady){$('#fileFees').innerHTML=feeRows(FEES_FILE);fillFees(cfg.knobs,FEES_FILE);
    if(fs.enabled){$('#fileCapEdit').innerHTML=capEditorHtml('cesFileStoreMaxBytes','capFileMax','applyFileCap');$('#capFileMax').value=fs.maxBytes;}
    else $('#fileCapEdit').innerHTML='<p class="hint"><span class="mono">cesFileStoreMaxBytes = 0</span> — file store off. The 0 boundary (enable/disable) binds the handler at boot, so crossing it needs a restart.</p>';
    fileReady=true;}
  $('#fileCap').innerHTML=[['store dir',esc(fs.dir||'—')]].map(r=>`<tr><td class="mono">${r[0]}</td><td class="num">${r[1]}</td></tr>`).join('');}
async function loadCompute(){let cp,cfg;try{cp=await api('/api/compute');cfg=await api('/api/config');}catch(e){return;}
  if(cp.enabled){
    $('#computeStats').innerHTML=[['Running',fmtNum(cp.instances.length)],['Max',fmtNum(cp.maxInstances)],['Port range',cp.portCount>0?(cp.portBase+'–'+(cp.portBase+cp.portCount-1)):'none','wide']].map(c=>`<div class="card${c[2]?' '+c[2]:''}"><h3>${c[0]}</h3><div class="stat">${c[1]}</div></div>`).join('');
    $('#computeTbl').innerHTML='<tr><th>pid</th><th>source</th><th class="num">CPU</th><th class="num">RSS</th><th class="num">uptime</th><th class="num" title="outbound CES-client port / inbound /ces/luarpc/1 host port (0 = none)">ports (CES/rpc)</th></tr>'+(cp.instances.length?cp.instances.map(i=>`<tr><td class="mono">${i.pid}</td><td class="mono">${esc(i.source)}</td><td class="num">${(i.cpuBp/100).toFixed(0)}%</td><td class="num">${fmtBytes(i.rssBytes)}</td><td class="num">${fmtDur(i.uptimeSecs)}</td><td class="num">${i.clientPort||'-'} / ${i.rpcPort||'-'}</td></tr>`).join(''):'<tr><td colspan="6" class="muted">no running instances</td></tr>');
    $('#computeOff').textContent='';
  }else{$('#computeStats').innerHTML='';$('#computeTbl').innerHTML='';$('#computeOff').innerHTML='<b>Compute disabled.</b> Set <span class="mono">computeMaxInstances</span> &gt; 0 (needs the file store) and restart.';}
  if(!computeReady){$('#computeFees').innerHTML=feeRows(FEES_COMPUTE);fillFees(cfg.knobs,FEES_COMPUTE);
    if(cp.enabled){$('#computeCapEdit').innerHTML=capEditorHtml('computeMaxInstances','capCompMax','applyComputeCap');$('#capCompMax').value=cp.maxInstances;}
    else $('#computeCapEdit').innerHTML='<p class="hint"><span class="mono">computeMaxInstances = 0</span> — compute off. The 0 boundary (enable/disable) binds the handler at boot, so crossing it needs a restart.</p>';
    computeReady=true;}
  $('#computeCap').innerHTML=[['computePortBase',cfg.knobs.computePortBase],['computePortCount',cfg.knobs.computePortCount],['computeClientPoolSize',cfg.knobs.computeClientPoolSize],['processMemMax',fmtBytes(cp.processMemMax)]].map(r=>`<tr><td class="mono">${r[0]}</td><td class="num">${typeof r[1]==='number'?fmtNum(r[1]):r[1]}</td></tr>`).join('');}
async function applyMinDiff(){const b=$('#cfgMinDiffBtn');b.disabled=true;b.textContent='Applying…';$('#cfgMinDiffState').textContent='';
  try{const v=$('#cfgMinDiff').value||'0';const r=await post('/api/config_set',{key:'min_difficulty',value:v});
    if(!r.ok)throw new Error(r.error||'min_difficulty');
    $('#cfgMinDiffState').textContent='✓ applied';$('#cfgMinDiffState').style.color='var(--accent)';toast('min difficulty set — export to persist','ok');loadConfig();}
  catch(e){$('#cfgMinDiffState').textContent='rejected (range 1–54)';$('#cfgMinDiffState').style.color='var(--danger)';toast('apply failed','err');}
  finally{b.disabled=false;b.textContent='Apply';}}
async function exportConfig(){const b=$('#cfgExportBtn');b.disabled=true;b.textContent='Exporting…';
  try{const r=await post('/api/config_export',{});
    if(r.ok){$('#cfgExportState').textContent='✓ wrote '+r.path;$('#cfgExportState').style.color='var(--accent)';toast('config exported','ok');}
    else{$('#cfgExportState').textContent=r.error||'failed';$('#cfgExportState').style.color='var(--danger)';toast(r.error||'export failed','err');}
  }catch(e){$('#cfgExportState').textContent='server not responding';$('#cfgExportState').style.color='var(--danger)';toast('export failed — server not responding','err');}finally{b.disabled=false;b.textContent='Export config to data dir';}}

function onEnter(id,fn){const el=$('#'+id);if(el)el.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();fn();}});}
onEnter('inspAddr',doInspect);onEnter('accKey',lookupAccount);onEnter('astKey',lookupAsset);onEnter('fileLookupPath',lookupFile);
onEnter('addAddr',addPeer);onEnter('addKey',addPeer);onEnter('peerTarget',setTarget);

/* extensions - table-like rows; each row expands inline into a control center */
let extExpanded=new Set(), extSig='', extOpenConfig=null;
function cssid(n){return (n+'').replace(/[^a-zA-Z0-9_-]/g,'_');}
function extBadge(it){
  const b=it.enabled?['enabled','#16351f','#5fd38a']:it.installed?['installed','#2a2410','#d9b44a']:['available','#1a2536','#7e94b4'];
  return `<span class="extbadge" style="background:${b[1]};color:${b[2]}">${b[0]}</span>`;
}
function extRow(it){
  const id=cssid(it.name), open=extExpanded.has(it.name);
  // Title: the manifest name (falls back to filename), then version, then the
  // backing .lua filename grayed in parens.
  const title=`<b class="extttl">${esc(it.displayName||it.name)}</b>`
    +(it.version?` <span class="extver">v${esc(it.version)}</span>`:'')
    +` <span class="extfile">(${esc(it.name)}.lua)</span>`;
  let btns='';
  if(it.available&&!it.installed) btns+=`<button class="green sm" onclick="extAct('install','${esc(it.name)}')">Install</button>`;
  if(it.installed&&!it.enabled) btns+=`<button class="green sm" onclick="extAct('enable','${esc(it.name)}')">Enable</button>`;
  if(it.enabled) btns+=`<button class="warn sm" onclick="extAct('disable','${esc(it.name)}')">Disable</button>`;
  if(it.installed) btns+=`<button class="danger sm" onclick="extAct('uninstall','${esc(it.name)}')">Uninstall</button>`;
  let body;
  if(it.enabled&&!it.isExtension){
    body=`<div class="muted">Does not implement the extension contract — nothing to configure or command (N/A).</div>`;
  }else if(it.enabled){
    // Render only the sections this program actually registered (caps bits:
    // 1=status 2=commands 4=config_defaults 8=on_config). No empty N/A sections.
    body='';
    if(it.caps&1) body+=`<h4>Status</h4><div id="extStatus-${id}"><span class="muted">…</span></div>`;
    if(it.caps&2&&it.commands.length) body+=`<h4>Commands</h4><div class="row">${it.commands.map(c=>`<button class="sm" onclick="extCmd('${esc(it.name)}','${esc(c.id)}')">${esc(c.label||c.id)}</button>`).join('')}</div><div id="extCmdOut-${id}" class="extcmdout mono"></div>`;
    if(it.caps&12) body+=`<h4>Config</h4><button class="green sm" onclick="extConfigToggle('${esc(it.name)}',${(it.caps&4)?1:0})">Edit</button><div class="extcfg" id="extCfg-${id}"></div>`;
    if(!body) body=`<div class="muted">Running — implements no status, commands, or config.</div>`;
  }else{
    body=`<div class="muted">${it.installed?'Installed, not running — Enable to interact.':'Available — Install to use.'}</div>`;
  }
  const desc=it.description?`<div class="muted" style="margin-top:4px">${esc(it.description)}</div>`:'';
  return `<div class="extrow${open?' open':''}">`
    +`<div class="exthead">`
    +`<div class="extname" onclick="extToggle('${esc(it.name)}')"><span class="extchev" id="extChev-${id}">${open?'▾':'▸'}</span>`
    +`${title} ${extBadge(it)}${it.enabled?`<span class="mono extfile">pid ${it.pid}</span>`:''}</div>`
    +`<div class="extbtns">${btns}</div></div>`
    +`<div class="extbody" id="extBody-${id}" style="${open?'':'display:none'}">${desc}${body}</div></div>`;
}
function extFetchStatus(name){
  api('/api/extension_status?name='+encodeURIComponent(name)).then(s=>{
    const el=$('#extStatus-'+cssid(name));if(!el)return;
    el.innerHTML=(s.ok&&s.kv.length)?`<table class="kvtable">${s.kv.map(p=>`<tr><td class="mono">${esc(p[0])}</td><td class="mono">${esc(p[1])}</td></tr>`).join('')}</table>`:'<span class="muted">no status</span>';
  }).catch(()=>{});
}
// Global funding budget control (one knob, all extensions). Polls the rate + the
// live remaining allowance; prefills the input once so the operator sees it.
let fundPrefilled=false;
async function loadFunding(){
  let d;try{d=await api('/api/funding');}catch(e){return;}
  const perDayC=Number(d.perDay)/PRICE_UNIT, remC=Number(d.remaining)/PRICE_UNIT;
  $('#fundState').innerHTML = perDayC>0
    ? `in effect: <b>${perDayC.toLocaleString()}</b> /day &middot; <b style="color:var(--accent)">${remC.toLocaleString(undefined,{maximumFractionDigits:4})}</b> remaining now`
    : `<span style="color:var(--warn)">OFF</span> &mdash; programs cannot spend at remotes`;
  const inp=$('#fundRate');
  if(!fundPrefilled && document.activeElement!==inp){ inp.value = perDayC>0?perDayC:''; fundPrefilled=true; }
}
async function fundingApply(){
  const c=Number($('#fundRate').value);
  if(!(c>=0)){toast('enter credits/day (0 = off)','err');return;}
  const raw=Math.round(c*PRICE_UNIT);
  try{const r=await post('/api/funding_set',{perday:String(raw)});
    toast(r.ok?(c>0?'funding budget set':'funding disabled'):(r.error||'failed'),r.ok?'ok':'err');}
  catch(e){toast('server error','err');}
  loadFunding();
}
async function loadExtensions(){
  loadFunding();
  let d;try{d=await api('/api/extensions');}catch(e){return;}
  $('#extOff').innerHTML=d.catalog?'':'<b>No catalog.</b> Set <span class="mono">extensions_dir</span> to a folder of single-file .lua extensions to install from. Installed /s/ extensions still appear.';
  // Rebuild the rows only on a real structural change (state/caps/pid), and NOT
  // while a config editor is open (a rebuild would clobber the textarea). Status
  // fetches below only touch the status divs, so they keep ticking live even
  // with an editor open or a row collapsed.
  const sig=d.items.map(it=>[it.name,it.available,it.installed,it.enabled,it.pid,it.caps].join(':')).join('|');
  if(sig!==extSig && !extOpenConfig){$('#extList').innerHTML=d.items.length?d.items.map(extRow).join(''):'<p class="muted">No extensions found.</p>';extSig=sig;}
  extPollStatus();
}
// Poll status for expanded rows only. The status div exists only for an enabled,
// contract-implementing, status-capable row, so guarding on it means a collapsed
// card (not in extExpanded) or a non-status row never issues a request.
function extPollStatus(){
  for(const name of extExpanded) if($('#extStatus-'+cssid(name))) extFetchStatus(name);
}
function extToggle(name){
  const id=cssid(name), open=!extExpanded.has(name);
  if(open) extExpanded.add(name); else extExpanded.delete(name);
  const body=$('#extBody-'+id); if(body) body.style.display=open?'':'none';
  const chev=$('#extChev-'+id); if(chev) chev.textContent=open?'▾':'▸';
  const row=body&&body.closest('.extrow'); if(row) row.classList.toggle('open',open);
  if(open) extFetchStatus(name);
}
async function extAct(action,name){
  try{const r=await post('/api/extension_'+action,{name});toast(r.ok?action+' ok':(r.error||action+' failed'),r.ok?'ok':'err');}
  catch(e){toast('server error','err');}
  extOpenConfig=null;extSig='';setTimeout(loadExtensions,500);
}
async function extCmd(name,id){
  const el=$('#extCmdOut-'+cssid(name));
  try{const r=await post('/api/extension_command',{name,id,arg:''});
    if(el)el.textContent=r.ok?(r.result||'(ok)'):(r.error||'failed');toast(r.ok?'command ok':'command failed',r.ok?'ok':'err');}
  catch(e){if(el)el.textContent='server error';toast('server error','err');}
}
async function extConfigToggle(name,hasDefaults){
  const id=cssid(name),el=$('#extCfg-'+id);if(!el)return;
  if(extOpenConfig===name){el.innerHTML='';extOpenConfig=null;return;}
  extOpenConfig=name;
  let d;try{d=await api('/api/extension_config?name='+encodeURIComponent(name));}catch(e){d={text:''};}
  const reset=hasDefaults?`<button class="green sm" onclick="extConfigReset('${esc(name)}')">Reset to defaults</button>`:'';
  el.innerHTML=`<textarea id="extCfgTa-${id}" spellcheck="false">${esc(d.text)}</textarea><div class="row"><button class="green sm" onclick="extConfigSave('${esc(name)}')">Save</button>${reset}<button class="green sm" onclick="extConfigToggle('${esc(name)}',${hasDefaults?1:0})">Close</button></div>`;
}
async function extConfigSave(name){
  const ta=$('#extCfgTa-'+cssid(name));if(!ta)return;
  try{const r=await post('/api/extension_config_set',{name,text:ta.value});toast(r.ok?'config saved + applied':(r.error||'save failed'),r.ok?'ok':'err');}
  catch(e){toast('server error','err');}
}
async function extConfigReset(name){
  try{const r=await post('/api/extension_config_reset',{name});
    if(!r.ok){toast(r.error||'reset failed','err');return;}
    toast('reset to defaults + applied','ok');
    const d=await api('/api/extension_config?name='+encodeURIComponent(name));
    const ta=$('#extCfgTa-'+cssid(name));if(ta)ta.value=d.text;}
  catch(e){toast('server error','err');}
}

const TABS=['overview','peers','inspect','wallet','lookup','billing','fees','file','compute','extensions','logs','config'];
const initTab=(location.hash||'').slice(1);
showTab(TABS.includes(initTab)?initTab:'overview');
// Liveness heartbeat: always on, independent of the selected tab — 1 user on 1
// private server, so just poll. Fires immediately (no waiting, no click needed)
// and every 2s; drives the live dot and uptime, and flips to
// "offline" on its own the moment the server stops answering.
async function heartbeat(){
  try{const s=await api('/api/status');setLive(true);setHeader(s);}
  catch(e){setLive(false);}
}
heartbeat();
setInterval(heartbeat,2000);
</script>
</body>
</html>
)DASH";

}  // namespace

}  // namespace ces
