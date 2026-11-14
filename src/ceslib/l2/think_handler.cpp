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
  // 0 = queued, 1 = started, 2 = given up. An op that the wait gave up on
  // does not start later, so a TIMEOUT means the op did not run.
  auto state = std::make_shared<std::atomic<int>>(0);
  auto ex = server->_rpcTaskIOExecutor();
  boost::asio::post(ex, [fh, req = std::move(req), pr, ex, state]() {
    int queued = 0;
    if (!state->compare_exchange_strong(queued, 1)) return;
    fh->exec(req, [pr](FileExecResp r) { pr->set_value(std::move(r)); }, ex);
  });
  if (fut.wait_for(std::chrono::seconds(30)) != std::future_status::ready) {
    int queued = 0;
    if (state->compare_exchange_strong(queued, 2)) {
      fail.status = CES_ERROR_TIMEOUT;
      return fail;
    }
    fut.wait();   // it started: wait for its real result
  }
  return fut.get();
}

// Read a whole conversation file of `st.size` bytes (its STAT), at most
// `max`. CES_OK or the verb's status (BAD_INPUT when the file is too big).
uint8_t readWhole(CesServer* server, const ThinkFile& f,
                  const FileExecResp& st, uint64_t max, std::string& out) {
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
// preamble is [u64 charged][32 sha256(reply)][u8 appendError].
class PlexSink : public ThinkSink {
 public:
  explicit PlexSink(std::shared_ptr<CesPlexReplyStream> r) : r_(std::move(r)) {}
  bool open() override { return !r_->dead(); }
  void piece(std::string_view t) override {
    r_->write(ces::Bytes(t.begin(), t.end()));
  }
  void finish(uint8_t status, uint64_t charged, const std::string& text,
              uint8_t appendError) override {
    if (status != CES_OK) {
      r_->finish(status);
      return;
    }
    ces::Bytes pre;
    ces::Buffer::put<uint64_t>(pre, charged);
    minx::Hash h = ces::sha256(reinterpret_cast<const uint8_t*>(text.data()),
                               text.size());
    pre.insert(pre.end(), h.begin(), h.end());
    ces::Buffer::put<uint8_t>(pre, appendError);
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
// preamble, like mail SEND). Preamble (after nonce): [u32 textLen][32 hash]
// then optionally [u16 pathLen][path] (the conversation file).
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
      const minx::Hash signer = req->bound.boundPubkey.getHash();
      // fee_query and replay dedup, as for every signed verb. A replay of a
      // THINK runs nothing and costs the signer nothing.
      auto* server = static_cast<CesServer*>(req->host);
      const auto& c = server->_config();
      uint8_t rc = CES_OK;
      server->_l2Transact([&](LedgerTxn& t) {
        const bool nonceless = req->reqNonce == CES_NONCELESS;
        if (nonceless && t.isReplay(req->reqSigHash)) {
          rc = CES_ERROR_WRONG_NONCE;
          return;
        }
        rc = t.signerSpend(signer, static_cast<uint64_t>(c.feeQuery),
                           req->reqNonce,
                           static_cast<int64_t>(c.getFeeError()));
        if (rc == CES_OK && nonceless) t.recordDedup(req->reqSigHash);
      });
      if (rc != CES_OK) {
        reply->finish(rc);
        return;
      }
      // A call can be silent for longer than the channel idle time (a long
      // wait for the first token), so keep the channel busy while it runs.
      const uint32_t idle = c.rpcRudpChannelIdleSecs > 0
                                ? c.rpcRudpChannelIdleSecs : 60;
      reply->keepAlive(std::min<std::chrono::milliseconds>(
          std::chrono::seconds(20), std::chrono::milliseconds(idle * 1000 / 3)));
      // The signer is the file's caller and pays the caller-side fees, as on
      // the wire.
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
  return priceOf(promptBytes + kThinkPromptOverhead, 0, replyBytes / 3 + 1,
                 fees);
}

uint64_t thinkExpected(const ThinkFees& fees, uint64_t promptBytes,
                       uint32_t maxOut) {
  return priceOf(promptBytes / 3 + kThinkPromptOverhead, 0, maxOut, fees);
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

void ThinkHandler::submit(const ThinkPayer& payer, std::string prompt,
                          std::shared_ptr<ThinkSink> sink, ThinkFile file) {
  const auto& cfg = server_->_config();
  if (stopped_.load() || !enabled()) {
    sink->finish(CES_ERROR_DISABLED, 0, {}, CES_OK);
    return;
  }
  if (prompt.empty() || prompt.size() > cfg.thinkMaxInputBytes ||
      !thinkValidUtf8(prompt)) {
    sink->finish(CES_ERROR_BAD_INPUT, 0, {}, CES_OK);
    return;
  }
  // The /m/ mail zone is private: no status may tell whether a file there
  // exists, as for the wire STAT.
  if (file.path.size() > 1 && file.path.rfind("/m/", 0) == 0) {
    sink->finish(CES_ERROR_NOT_OWNER, 0, {}, CES_OK);
    return;
  }
  std::shared_ptr<ThinkBackend> backend;
  auto job = std::make_shared<Job>();
  std::lock_guard<std::mutex> lk(mu_);
  reapLocked();
  if (stopped_.load()) {   // stop() ran since the check above
    sink->finish(CES_ERROR_DISABLED, 0, {}, CES_OK);
    return;
  }
  if (jobs_.size() >= cfg.thinkMaxConcurrent) {
    sink->finish(CES_ERROR_QUEUE_FULL, 0, {}, CES_OK);
    return;
  }
  backend = backend_;
  jobs_.push_back(job);
  // The call runs on its own thread: the file read, the hold, the backend,
  // the settle, the append. Every exit ends in one sink->finish.
  try {
    job->thread = std::thread([this, job, sink, backend, payer,
                               prompt = std::move(prompt),
                               file = std::move(file)]() mutable {
      try {
        run(*job, *backend, payer, std::move(prompt), file, *sink);
      } catch (const std::exception& e) {
        LOGERROR << "think: call failed" << SVAR(e.what());
        sink->finish(CES_ERROR_INTERNAL, 0, {}, CES_OK);
      } catch (...) {
        LOGERROR << "think: call failed";
        sink->finish(CES_ERROR_INTERNAL, 0, {}, CES_OK);
      }
      job->done = true;
    });
  } catch (const std::system_error&) {
    jobs_.pop_back();
    sink->finish(CES_ERROR_QUEUE_FULL, 0, {}, CES_OK);
  }
}

void ThinkHandler::run(Job& job, ThinkBackend& backend,
                       const ThinkPayer& payer, std::string prompt,
                       const ThinkFile& file, ThinkSink& sink) {
  CesServer* server = server_;
  const auto& cfg = server->_config();

  // The backend gets the file's content, then the new text. Only the owner
  // can append, so only the owner's call locks the path, from the read to
  // the append.
  std::string input;
  bool locked = false;
  auto unlock = [&] {
    if (!locked) return;
    std::lock_guard<std::mutex> g(mu_);
    busyPaths_.erase(file.path);
    locked = false;
  };
  struct OnExit {
    std::function<void()> f;
    ~OnExit() { f(); }
  } onExit{unlock};
  if (!file.path.empty()) {
    FileExecResp st = fileOp(server, file, kFileVerbStat);
    uint8_t rc = st.status;
    if (rc == CES_OK && st.ownerPubkey == file.caller) {
      std::lock_guard<std::mutex> g(mu_);
      if (busyPaths_.count(file.path)) rc = CES_ERROR_QUEUE_FULL;
      else locked = busyPaths_.insert(file.path).second;
    }
    if (rc == CES_OK)
      rc = readWhole(server, file, st, cfg.thinkMaxInputBytes, input);
    if (rc == CES_OK && (input.size() + prompt.size() > cfg.thinkMaxInputBytes ||
                         !thinkValidUtf8(input)))
      rc = CES_ERROR_BAD_INPUT;
    if (rc != CES_OK) {
      unlock();
      sink.finish(rc, 0, {}, CES_OK);
      return;
    }
  }
  input += prompt;

  std::string text;
  uint64_t charge = 0;
  ThinkOutcome o = callAndSettle(job, backend, payer, input, sink, text, charge);

  // A complete reply goes into the file with the text that asked for it.
  // The APPEND is the caller's own verb: it fails (and the file stays as
  // it was) when the caller is not the owner, or when the file's balance
  // cannot pay for the growth. appendError carries its status.
  uint8_t appendError = CES_OK;
  if (o.status == CES_OK && !file.path.empty()) {
    ces::Bytes turn(prompt.begin(), prompt.end());
    turn.insert(turn.end(), text.begin(), text.end());
    appendError =
        fileOp(server, file, kFileVerbAppend, 0, 0, std::move(turn)).status;
  }
  // The next turn on the file may start as soon as the caller sees this one
  // end, so free the path first.
  unlock();
  sink.finish(o.status, charge, text, appendError);
}

ThinkOutcome ThinkHandler::callAndSettle(Job& job, ThinkBackend& backend,
                                         const ThinkPayer& payer,
                                         const std::string& input,
                                         ThinkSink& sink, std::string& text,
                                         uint64_t& charge) {
  CesServer* server = server_;
  const auto& cfg = server->_config();
  const ThinkFees fees = feesOf(cfg);
  const uint32_t maxOut = cfg.thinkMaxOutTokens;
  charge = 0;

  // The subsidy discounts the hold too, so a cool service lets an account
  // with almost nothing start a call. Its share of the expected cost is
  // reserved as heat now, so calls in flight together cannot take more than
  // the budget, and a long prompt does not reserve for a worst case that
  // does not come.
  const uint64_t fullHold = thinkHold(fees, input.size(), maxOut);
  const uint64_t expected =
      std::min(fullHold, thinkExpected(fees, input.size(), maxOut));
  uint64_t reserved = 0;
  const uint16_t mult = subsidy_->reserve(expected, reserved);  // 10000 = full
  const uint64_t hold = fullHold - reserved;
  // List the hold before the burn, so no exhaustion check sees the account
  // without it.
  server->accountHolds().add(payer.account, hold);
  bool held = false;
  server->_l2Transact([&](LedgerTxn& tx) {
    held = tx.debitAccount(payer.account, hold);   // burned; the unused part returns
  });
  ThinkOutcome o;
  if (!held) {
    server->accountHolds().remove(payer.account, hold);
    subsidy_->release(reserved);
    o.status = CES_ERROR_INSUFFICIENT_BALANCE;
    return o;
  }

  auto onText = [&](std::string_view piece) {
    if (job.stop.load() || !sink.open()) return false;
    text.append(piece.data(), piece.size());
    sink.piece(piece);
    return true;
  };
  if (job.stop.load()) {
    o.status = CES_ERROR_DISABLED;   // stop() ran during the read or hold
  } else {
    try {
      o = backend.run(input, maxOut, job.stop, onText);
    } catch (const std::exception& e) {
      o.status = CES_ERROR_INTERNAL;
      o.billing = ThinkOutcome::kEstimate;
      o.detail = e.what();
    } catch (...) {
      o.status = CES_ERROR_INTERNAL;
      o.billing = ThinkOutcome::kEstimate;
      o.detail = "backend threw";
    }
  }
  // The full cost of what was used, then the subsidy's share at the
  // reserved multiplier, never above what was reserved. full <= fullHold,
  // and the charge is <= hold (thinkExpected <= fullHold).
  uint64_t full = 0;
  if (o.billing == ThinkOutcome::kUsage) {
    full = thinkCost(fees, o.usage);
  } else if (o.billing == ThinkOutcome::kEstimate) {
    full = thinkEstimate(fees, input.size(),
                         std::max<uint64_t>(o.outBytes, text.size()));
  }
  if (full > fullHold) full = fullHold;
  const uint64_t subsidized = std::min<uint64_t>(
      reserved,
      static_cast<uint64_t>(static_cast<U128>(full) * (10000u - mult) / 10000u));
  charge = full - subsidized;
  if (charge > hold) charge = hold;
  if (reserved > subsidized) subsidy_->release(reserved - subsidized);

  // The refund lands before this returns (and before shutdown can drop it).
  // A program file that went away during the call has no account to take
  // it: the refund goes to the file's owner, as its balance did at DELETE.
  if (hold > charge) {
    minx::Hash to = payer.account;
    if (!payer.source.empty()) {
      std::array<uint8_t, 32> pk{};
      FileHandler* fh = server->fileHandler();
      if (!fh || !fh->readProgramPubkey(payer.source, pk) ||
          std::memcmp(pk.data(), payer.account.data(), 32) != 0)
        to = payer.owner;
    }
    const int64_t back = static_cast<int64_t>(hold - charge);
    server->_l2Transact([&](LedgerTxn& tx) { tx.credit(to, back); });
  }
  server->accountHolds().remove(payer.account, hold);
  LOGINFO << "think: call done" << VAR(int(o.status))
          << VAR(o.usage.promptTokens) << VAR(o.usage.cachedTokens)
          << VAR(o.usage.outputTokens) << VAR(full) << VAR(mult)
          << VAR(charge) << SVAR(o.detail);
  return o;
}

}  // namespace ces
