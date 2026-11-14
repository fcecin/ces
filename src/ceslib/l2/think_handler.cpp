// think_handler.cpp - see think_handler.h.

#include <ces/l2/think_handler.h>

#include <ces/buffer.h>
#include <ces/cesplex/session.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/ledger_txn.h>
#include <ces/ramfilestore.h>   // ces::sha256
#include <ces/server.h>
#include <ces/util/log.h>
#ifdef CES_THINK
#include <ces/l2/think_https.h>
#endif

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <future>
#include <sstream>
#include <stdexcept>

LOG_MODULE("think")

namespace ces {

namespace {

constexpr uint8_t kVerbThink = 1;
constexpr uint64_t kMillion = 1'000'000;
__extension__ typedef unsigned __int128 U128;   // exact token * fee sums

uint64_t clampU64(U128 v) {
  return v > UINT64_MAX ? UINT64_MAX : static_cast<uint64_t>(v);
}

// ceil(tokens * fee / 1M), summed exactly before the one rounding.
uint64_t priceOf(uint64_t uncachedIn, uint64_t cachedIn, uint64_t out,
                 const ThinkFees& f) {
  U128 micro =
      static_cast<U128>(uncachedIn) * f.in +
      static_cast<U128>(cachedIn) * f.cachedIn +
      static_cast<U128>(out) * f.out;
  return clampU64((micro + kMillion - 1) / kMillion);
}

ThinkFees feesOf(const CesConfig& c) {
  return ThinkFees{c.thinkFeeIn, c.thinkFeeCachedIn, c.thinkFeeOut};
}

std::string readKeyFile(const std::string& path) {
  std::ifstream f(path);
  if (!f) return {};
  std::stringstream ss;
  ss << f.rdbuf();
  std::string k = ss.str();
  const char* ws = " \t\r\n";
  size_t a = k.find_first_not_of(ws);
  if (a == std::string::npos) return {};
  size_t b = k.find_last_not_of(ws);
  return k.substr(a, b - a + 1);
}

// Wire codes of the file verbs, as FileExecReq takes them (file_handler.cpp).
constexpr uint8_t kFileVerbRead   = 0x03;
constexpr uint8_t kFileVerbStat   = 0x04;
constexpr uint8_t kFileVerbAppend = 0x09;
constexpr uint32_t kFileReadChunk = 1024 * 1024;   // the READ limit

// Run one file verb through FileHandler::exec on the rpc thread, where every
// flat-file verb runs (so this never races a wire verb on the same file),
// and wait for it. Call from a worker thread only.
FileExecResp fileOp(CesServer* server, const ThinkFile& f, uint8_t verb,
                    uint64_t offset = 0, uint32_t length = 0,
                    ces::Bytes body = {}) {
  FileExecResp fail;
  FileHandler* fh = server->fileHandler();
  if (!fh) { fail.status = CES_ERROR_DISABLED; return fail; }
  FileExecReq req;
  req.ownerPubkey = f.caller;
  req.sourceName = f.sourceName;
  req.payByAccount = f.payByAccount;
  req.payerAccount = f.payerAccount;
  req.verb = verb;
  req.name = f.path;
  req.offset = offset;
  req.length = length;
  req.body = std::move(body);
  auto pr = std::make_shared<std::promise<FileExecResp>>();
  auto fut = pr->get_future();
  auto ex = server->_rpcTaskIOExecutor();
  boost::asio::post(ex, [fh, req = std::move(req), pr, ex]() {
    fh->exec(req, [pr](FileExecResp r) { pr->set_value(std::move(r)); }, ex);
  });
  if (fut.wait_for(std::chrono::seconds(30)) != std::future_status::ready) {
    fail.status = CES_ERROR_TIMEOUT;
    return fail;
  }
  return fut.get();
}

// Read a whole conversation file of at most `max` bytes. CES_OK or the
// verb's status (BAD_INPUT when the file is too big).
uint8_t readWhole(CesServer* server, const ThinkFile& f, uint64_t max,
                  std::string& out) {
  FileExecResp st = fileOp(server, f, kFileVerbStat);
  if (st.status != CES_OK) return st.status;
  if (st.size > max) return CES_ERROR_BAD_INPUT;
  out.clear();
  out.reserve(st.size);
  for (uint64_t off = 0; off < st.size;) {
    uint32_t n = static_cast<uint32_t>(
        std::min<uint64_t>(kFileReadChunk, st.size - off));
    FileExecResp rd = fileOp(server, f, kFileVerbRead, off, n);
    if (rd.status != CES_OK) return rd.status;
    out.append(rd.data.begin(), rd.data.end());
    off += n;
  }
  return CES_OK;
}

// The THINK verb's sink: reply frames on the bound channel. On OK the signed
// preamble is [u64 charged][32 sha256(reply)][u8 updated].
class PlexSink : public ThinkSink {
 public:
  explicit PlexSink(std::shared_ptr<CesPlexReplyStream> r) : r_(std::move(r)) {}
  bool open() override { return !r_->dead(); }
  void piece(std::string_view t) override {
    r_->write(ces::Bytes(t.begin(), t.end()));
  }
  void finish(uint8_t status, uint64_t charged, const std::string& text,
              bool updated) override {
    if (status != CES_OK) {
      r_->finish(status);
      return;
    }
    ces::Bytes pre;
    ces::Buffer::put<uint64_t>(pre, charged);
    minx::Hash h = ces::sha256(reinterpret_cast<const uint8_t*>(text.data()),
                               text.size());
    pre.insert(pre.end(), h.begin(), h.end());
    ces::Buffer::put<uint8_t>(pre, updated ? 1 : 0);
    r_->finish(CES_OK, std::move(pre));
  }

 private:
  std::shared_ptr<CesPlexReplyStream> r_;
};

// Read and drop `left` body bytes, then finish the reply with `status`.
void drainThenFinish(std::shared_ptr<CesPlexRequest> req,
                     std::shared_ptr<CesPlexReplyStream> reply, uint64_t left,
                     uint8_t status) {
  if (left == 0) {
    reply->finish(status);
    return;
  }
  auto chunk = std::make_shared<ces::Bytes>(
      static_cast<size_t>(std::min<uint64_t>(left, 64 * 1024)));
  boost::asio::async_read(
    *req->stream, boost::asio::buffer(*chunk),
    [req, reply, chunk, left, status](const boost::system::error_code& ec,
                                      std::size_t n) {
      if (ec) return;   // stream dead
      drainThenFinish(req, reply, left - n, status);
    });
}

// THINK. The prompt streams as the request body (hash-committed in the
// preamble, like mail SEND). Preamble (after nonce): [u32 textLen][32 hash].
void dispatchThink(std::shared_ptr<CesPlexRequest> req, ces::Bytes pre,
                   ThinkHandler* self) {
  auto reply = std::make_shared<CesPlexReplyStream>(req);
  ces::Buffer buf(std::move(pre));
  uint32_t textLen = 0;
  std::array<uint8_t, 32> textHash{};
  std::string path;
  try {
    textLen = buf.get<uint32_t>();
    textHash = buf.get<std::array<uint8_t, 32>>();
    if (buf.remaining() > 0) {   // optional conversation file
      uint16_t pathLen = buf.get<uint16_t>();
      path = buf.getBytes<std::string>(pathLen);
    }
  } catch (const std::out_of_range&) {
    reply->finishAndClose(CES_ERROR_BAD_INPUT);   // body length unknown
    return;
  }
  const auto& cfg = static_cast<CesServer*>(req->host)->_config();
  if (textLen == 0) {
    reply->finish(CES_ERROR_BAD_INPUT);
    return;
  }
  if (textLen > cfg.thinkMaxInputBytes) {
    // Read past the body so the channel stays usable. The channel meter
    // bills the signer for the bytes.
    drainThenFinish(req, reply, textLen, CES_ERROR_BAD_INPUT);
    return;
  }
  auto text = std::make_shared<ces::Bytes>(textLen);
  boost::asio::async_read(
    *req->stream, boost::asio::buffer(*text),
    [req, reply, text, textHash, path, self](
        const boost::system::error_code& ec, std::size_t) {
      if (ec) return;   // stream dead
      minx::Hash got = ces::sha256(text->data(), text->size());
      if (std::memcmp(got.data(), textHash.data(), 32) != 0) {
        reply->finish(CES_ERROR_BAD_INPUT);
        return;
      }
      // The signer is the file's caller and pays its fees, as on the wire.
      const minx::Hash signer = req->bound.boundPubkey.getHash();
      ThinkFile file;
      file.path = path;
      std::memcpy(file.caller.data(), signer.data(), 32);
      file.payByAccount = true;
      file.payerAccount = file.caller;
      self->submit(signer, std::string(text->begin(), text->end()),
                   std::make_shared<PlexSink>(reply), std::move(file));
    });
}

}  // namespace

uint64_t thinkCost(const ThinkFees& fees, const ThinkUsage& u) {
  uint64_t cached = std::min(u.cachedTokens, u.promptTokens);
  return priceOf(u.promptTokens - cached, cached, u.outputTokens, fees);
}

uint64_t thinkHold(const ThinkFees& fees, uint64_t promptBytes,
                   uint32_t maxOut) {
  return priceOf(promptBytes + kThinkPromptOverhead, 0, maxOut, fees);
}

uint64_t thinkEstimate(const ThinkFees& fees, uint64_t promptBytes,
                       uint64_t replyBytes) {
  return priceOf(promptBytes / 3 + kThinkPromptOverhead, 0,
                 replyBytes / 3 + 1, fees);
}

ThinkHandler::ThinkHandler(CesServer* server) : server_(server) {
  const auto& cfg = server_->_config();
  HeatSubsidy::Config sc;
  sc.budget = cfg.thinkSubsidyBudget;
  sc.tauSecs = cfg.thinkSubsidyTauSecs;
  sc.floorBp = cfg.thinkSubsidyFloorBp;
  if (!cfg.dataDir.empty())
    sc.statePath = (cfg.dataDir / "think_subsidy.state").string();
  subsidy_ = std::make_unique<HeatSubsidy>(std::move(sc));
  if (cfg.thinkApiKeyFile.empty()) return;
#ifdef CES_THINK
  std::string key = readKeyFile(cfg.thinkApiKeyFile);
  if (key.empty()) {
    LOGWARNING << "think: API key file unreadable or empty; THINK disabled"
               << SVAR(cfg.thinkApiKeyFile);
    return;
  }
  ThinkHttpsConfig hc;
  hc.baseUrl = cfg.thinkBaseUrl;
  hc.apiKey = std::move(key);
  hc.model = cfg.thinkModel;
  hc.reasoning = cfg.thinkReasoning;
  hc.timeout = std::chrono::seconds(cfg.thinkTimeoutSecs);
  auto b = std::make_shared<ThinkHttpsBackend>(std::move(hc));
  if (!b->valid()) {
    LOGWARNING << "think: bad think_base_url; THINK disabled"
               << SVAR(cfg.thinkBaseUrl);
    return;
  }
  backend_ = std::move(b);
  LOGINFO << "think: backend ready" << SVAR(cfg.thinkBaseUrl)
          << SVAR(cfg.thinkModel);
#else
  (void)readKeyFile;
  LOGWARNING << "think: this build has no HTTPS backend (build with --think);"
                " THINK disabled";
#endif
}

ThinkHandler::~ThinkHandler() { stop(); }

void ThinkHandler::serve(std::shared_ptr<minx::RudpStream> stream,
                         BoundChannelContext bound) {
  ThinkHandler* self = this;
  CesPlexProtocol proto;
  proto.accepts = [this](uint8_t verb) {
    return !stopped_.load() && verb == kVerbThink;
  };
  proto.dispatch = [self](std::shared_ptr<CesPlexRequest> req,
                          ces::Bytes pre) {
    dispatchThink(req, std::move(pre), self);
  };
  cesPlexServe(std::move(stream), std::move(bound), server_, std::move(proto));
}

void ThinkHandler::stop() {
  stopped_ = true;
  std::list<std::shared_ptr<Job>> jobs;
  {
    std::lock_guard<std::mutex> lk(mu_);
    jobs.swap(jobs_);
  }
  for (auto& j : jobs) j->stop = true;
  for (auto& j : jobs)
    if (j->thread.joinable()) j->thread.join();
}

bool ThinkHandler::enabled() const {
  const auto& cfg = server_->_config();
  std::lock_guard<std::mutex> lk(mu_);
  return backend_ && cfg.thinkFeeIn > 0 && cfg.thinkFeeOut > 0;
}

size_t ThinkHandler::active() {
  std::lock_guard<std::mutex> lk(mu_);
  reapLocked();
  return jobs_.size();
}

void ThinkHandler::_testSetBackend(std::shared_ptr<ThinkBackend> backend) {
  std::lock_guard<std::mutex> lk(mu_);
  backend_ = std::move(backend);
}

void ThinkHandler::reapLocked() {
  for (auto it = jobs_.begin(); it != jobs_.end();) {
    if ((*it)->done.load()) {
      if ((*it)->thread.joinable()) (*it)->thread.join();
      it = jobs_.erase(it);
    } else {
      ++it;
    }
  }
}

void ThinkHandler::submit(const minx::Hash& payer, std::string prompt,
                          std::shared_ptr<ThinkSink> sink, ThinkFile file) {
  const auto& cfg = server_->_config();
  if (stopped_.load() || !enabled()) {
    sink->finish(CES_ERROR_DISABLED, 0, {}, false);
    return;
  }
  if (prompt.empty() || prompt.size() > cfg.thinkMaxInputBytes ||
      !thinkValidUtf8(prompt)) {
    sink->finish(CES_ERROR_BAD_INPUT, 0, {}, false);
    return;
  }
  std::shared_ptr<ThinkBackend> backend;
  auto job = std::make_shared<Job>();
  std::lock_guard<std::mutex> lk(mu_);
  reapLocked();
  if (jobs_.size() >= cfg.thinkMaxConcurrent ||
      (!file.path.empty() && busyPaths_.count(file.path))) {
    sink->finish(CES_ERROR_QUEUE_FULL, 0, {}, false);
    return;
  }
  backend = backend_;
  if (!file.path.empty()) busyPaths_.insert(file.path);
  jobs_.push_back(job);
  // The call runs on its own thread: the file read, the hold, the backend,
  // the settle, the append. Every exit ends in one sink->finish.
  job->thread = std::thread([this, job, sink, backend, payer,
                             prompt = std::move(prompt),
                             file = std::move(file)]() mutable {
    run(*job, *backend, payer, std::move(prompt), file, *sink);
    if (!file.path.empty()) {
      std::lock_guard<std::mutex> g(mu_);
      busyPaths_.erase(file.path);
    }
    job->done = true;
  });
}

void ThinkHandler::run(Job& job, ThinkBackend& backend,
                       const minx::Hash& payer, std::string prompt,
                       const ThinkFile& file, ThinkSink& sink) {
  CesServer* server = server_;
  const auto& cfg = server->_config();
  const ThinkFees fees = feesOf(cfg);
  const uint32_t maxOut = cfg.thinkMaxOutTokens;

  // The backend gets the file's content, then the new text.
  std::string input;
  if (!file.path.empty()) {
    uint8_t rc = readWhole(server, file, cfg.thinkMaxInputBytes, input);
    if (rc == CES_OK && (input.size() + prompt.size() > cfg.thinkMaxInputBytes ||
                         !thinkValidUtf8(input)))
      rc = CES_ERROR_BAD_INPUT;
    if (rc != CES_OK) {
      sink.finish(rc, 0, {}, false);
      return;
    }
  }
  input += prompt;

  // The subsidy discounts the hold too, so a cool service lets an account
  // with almost nothing start a call. Its share is reserved as heat now, so
  // calls in flight together cannot take more than the budget.
  const uint64_t fullHold = thinkHold(fees, input.size(), maxOut);
  uint64_t reserved = 0;
  const uint16_t mult = subsidy_->reserve(fullHold, reserved);   // 10000 = full
  const uint64_t hold = fullHold - reserved;
  bool held = false;
  server->_l2Transact([&](LedgerTxn& tx) {
    held = tx.debitAccount(payer, hold);   // burned; the unused part returns
  });
  if (!held) {
    subsidy_->release(reserved);
    sink.finish(CES_ERROR_INSUFFICIENT_BALANCE, 0, {}, false);
    return;
  }

  std::string text;
  auto onText = [&](std::string_view piece) {
    if (job.stop.load() || !sink.open()) return false;
    text.append(piece.data(), piece.size());
    sink.piece(piece);
    return true;
  };
  ThinkOutcome o;
  if (job.stop.load()) {
    o.status = CES_ERROR_DISABLED;   // stop() ran during the read or hold
  } else {
    try {
      o = backend.run(input, maxOut, job.stop, onText);
    } catch (const std::exception& e) {
      o.status = CES_ERROR_INTERNAL;
      o.billing = ThinkOutcome::kEstimate;
      o.detail = e.what();
    }
  }
  // The full cost of what was used, then the subsidy's share at the
  // reserved multiplier. full <= fullHold, so the share is <= reserved and
  // the charge is <= hold.
  uint64_t full = 0;
  if (o.billing == ThinkOutcome::kUsage) full = thinkCost(fees, o.usage);
  else if (o.billing == ThinkOutcome::kEstimate)
    full = thinkEstimate(fees, input.size(), text.size());
  if (full > fullHold) full = fullHold;
  const uint64_t subsidized =
      static_cast<uint64_t>(static_cast<U128>(full) * (10000u - mult) / 10000u);
  const uint64_t charge = full - subsidized;
  if (reserved > subsidized) subsidy_->release(reserved - subsidized);
  if (hold > charge) server->_brr(payer, static_cast<int64_t>(hold - charge));

  // A complete reply goes into the file with the text that asked for it.
  // The APPEND is the caller's own verb: it fails (and the file stays as
  // it was) when the caller is not the owner or cannot pay for it.
  bool updated = false;
  if (o.status == CES_OK && !file.path.empty()) {
    ces::Bytes turn(prompt.begin(), prompt.end());
    turn.insert(turn.end(), text.begin(), text.end());
    updated = fileOp(server, file, kFileVerbAppend, 0, 0, std::move(turn))
                  .status == CES_OK;
  }
  LOGINFO << "think: call done" << VAR(int(o.status))
          << VAR(o.usage.promptTokens) << VAR(o.usage.cachedTokens)
          << VAR(o.usage.outputTokens) << VAR(full) << VAR(mult)
          << VAR(charge) << VAR(updated) << SVAR(o.detail);
  sink.finish(o.status, charge, text, updated);
}

}  // namespace ces
