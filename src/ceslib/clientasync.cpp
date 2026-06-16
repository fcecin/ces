#include <ces/clientasync.h>
#include <minx/blog.h>
#include <minx/minx.h>

namespace ces {

CesClientAsync::CesClientAsync(boost::asio::io_context& io,
                               const boost::asio::ip::udp::endpoint& serverEndpoint,
                               const KeyPair& keyPair,
                               const Hash& peerServerKey,
                               size_t numChannels,
                               int maxRetries)
    : io_(io), socket_(io, boost::asio::ip::udp::v6()),
      serverEp_(serverEndpoint), sweepTimer_(io), keyPair_(keyPair),
      peerServerKey_(peerServerKey), maxRetries_(maxRetries) {
  boost::system::error_code ec;
  socket_.set_option(boost::asio::ip::v6_only(false), ec);
  // The socket is v6 dual-stack; a plain-IPv4 destination endpoint can't be sent
  // on it (the AF_INET sockaddr is rejected). Normalize a v4 endpoint to
  // v4-mapped-v6 (::ffff:a.b.c.d) so a peer whose address resolves to plain IPv4
  // — a v4 literal or a v4-first DNS result — is actually reachable. The CesPlex
  // session path already does this; settlement was the outbound path missing it.
  if (serverEp_.address().is_v4())
    serverEp_ = boost::asio::ip::udp::endpoint(
      boost::asio::ip::make_address_v6(boost::asio::ip::v4_mapped,
                                       serverEp_.address().to_v4()),
      serverEp_.port());
  channels_.resize(numChannels);
  LOGDEBUG << "CesClientAsync: " << numChannels << " channels to " << serverEp_;
  startReceive();
}

CesClientAsync::~CesClientAsync() { close(); }

void CesClientAsync::close() {
  if (closed_) return;
  closed_ = true;
  { boost::system::error_code ec; sweepTimer_.cancel(ec); }
  { boost::system::error_code ec; socket_.close(ec); }
  failAll(CES_ERROR_INTERNAL);
}

// ---- Public API ----

void CesClientAsync::openTransfer(const Hash& destKey, uint64_t amount, Callback cb) {
  boost::asio::post(io_, [this, destKey, amount, cb = std::move(cb)]() mutable {
    if (closed_) { cb(CES_ERROR_INTERNAL); return; }
    if (queue_.size() >= MAX_QUEUE) { cb(CES_ERROR_QUEUE_FULL); return; }
    ++pendingCount_;

    QueuedOp op;
    op.destKey = destKey;
    op.amount = amount;
    op.cb = std::move(cb);

    CesOpenTransfer msg;
    msg.originId = keyPair_.getPublicKeyAsHash();
    msg.serverId = Account::getMapKey(peerServerKey_);
    msg.reqNonce = CES_NONCELESS;
    msg.destKey = destKey;
    msg.amount = amount;
    msg.time = ces::getMicrosSinceEpoch();
    op.signedPayload = msg.toBytes(keyPair_);

    queue_.push_back(std::move(op));
    dispatch();
  });
}

// ---- Dispatch ----

void CesClientAsync::dispatch() {
  if (closed_ || queue_.empty()) return;

  for (auto& ch : channels_) {
    if (queue_.empty()) break;
    if (ch.state == ChState::Idle) {
      handshake(ch);
    } else if (ch.state == ChState::Ready) {
      ch.currentOp = std::move(queue_.front());
      queue_.pop_front();
      sendOp(ch);
    }
  }

  if (!queue_.empty())
    startSweepTimer();
}

// ---- Channel operations ----

void CesClientAsync::handshake(Channel& ch) {
  ch.state = ChState::Handshaking;
  ch.sentGPass = genPassword();
  ch.retries = 0;
  ch.sentAt = std::chrono::steady_clock::now();
  sendGetInfo(ch);
  startSweepTimer();
}

void CesClientAsync::sendGetInfo(Channel& ch) {
  minx::ArrayBuffer<64> buf;
  buf.put<uint8_t>(minx::MINX_GET_INFO);
  buf.put<uint8_t>(0);
  buf.put(ch.sentGPass);
  sendBuf(buf);
}

void CesClientAsync::sendOp(Channel& ch) {
  ch.state = ChState::Busy;
  ch.sentGPass = genPassword();
  ch.retries = 0;
  ch.sentAt = std::chrono::steady_clock::now();

  minx::ArrayBuffer<512> buf;
  buf.put<uint8_t>(minx::MINX_MESSAGE);
  buf.put<uint8_t>(0);
  buf.put(ch.sentGPass);
  buf.put(ch.ticket);
  ch.ticket = 0;
  auto& payload = ch.currentOp.signedPayload;
  buf.put(std::span<const uint8_t>(
    reinterpret_cast<const uint8_t*>(payload.data()), payload.size()));
  sendBuf(buf);

  startSweepTimer();
}

// ---- Receive ----

void CesClientAsync::startReceive() {
  if (closed_) return;
  socket_.async_receive_from(
    boost::asio::buffer(recvBuf_), recvEp_,
    [this](const boost::system::error_code& ec, size_t bytes) {
      onReceive(ec, bytes);
    });
}

void CesClientAsync::onReceive(const boost::system::error_code& ec, size_t bytes) {
  if (ec || closed_) return;
  if (bytes >= 1) {
    switch (recvBuf_[0]) {
    case minx::MINX_INFO:    handleInfo(recvBuf_.data(), bytes); break;
    case minx::MINX_MESSAGE: handleMessage(recvBuf_.data(), bytes); break;
    default: break;
    }
  }
  startReceive();
}

// MINX envelope preamble on the wire: code + version + gpassword + spassword.
// `parseMinxEnvelope` advances the buffer past these fields. INFO additionally
// carries a 32-byte server key and a 1-byte difficulty; MESSAGE carries at
// least one CES opcode byte of payload after the envelope.
static constexpr size_t MINX_ENVELOPE_BYTES =
  sizeof(uint8_t)              // code
  + sizeof(uint8_t)            // version
  + sizeof(uint64_t)           // gpassword
  + sizeof(uint64_t);          // spassword

static void parseMinxEnvelope(minx::ConstBuffer& buf,
                              uint64_t& gpass, uint64_t& spass) {
  buf.get<uint8_t>();  // code
  buf.get<uint8_t>();  // version
  gpass = buf.get<uint64_t>();
  spass = buf.get<uint64_t>();
}

void CesClientAsync::handleInfo(const uint8_t* data, size_t len) {
  constexpr size_t MIN =
    MINX_ENVELOPE_BYTES
    + sizeof(minx::Hash)       // skey
    + sizeof(uint8_t);         // difficulty
  if (len < MIN) return;

  minx::ConstBuffer buf(std::span<const uint8_t>(data, len));
  uint64_t gpass, spass;
  parseMinxEnvelope(buf, gpass, spass);
  minx::Hash skey = buf.get<minx::Hash>();

  for (auto& ch : channels_) {
    if (ch.state == ChState::Handshaking && ch.sentGPass == spass) {
      ch.ticket = gpass;
      ch.serverKey = skey;
      ch.state = ChState::Ready;
      dispatch();
      return;
    }
  }
}

void CesClientAsync::handleMessage(const uint8_t* data, size_t len) {
  constexpr size_t MIN =
    MINX_ENVELOPE_BYTES
    + sizeof(uint8_t);         // first CES opcode byte
  if (len < MIN) return;

  minx::ConstBuffer buf(std::span<const uint8_t>(data, len));
  uint64_t gpass, spass;
  parseMinxEnvelope(buf, gpass, spass);

  auto cesData = buf.getRemainingBytesSpan();
  if (cesData.empty() || cesData[0] != CES_OPEN_TRANSFER_RESULT) return;

  for (auto& ch : channels_) {
    if (ch.state != ChState::Busy || ch.sentGPass != spass) continue;

    PublicKey verifier(ch.serverKey);
    CesOpenTransferResult res;
    minx::Bytes cesBytes(cesData.begin(), cesData.end());
    if (!res.fromBytes(cesBytes, verifier)) {
      LOGDEBUG << "CesClientAsync: ch" << chIdx(ch) << " sig verify failed";
      return;
    }

    ch.ticket = gpass;
    ch.state = ChState::Ready;
    --pendingCount_;
    auto cb = std::move(ch.currentOp.cb);
    ch.currentOp = {};
    if (cb) cb(res.rcode);
    dispatch();
    return;
  }
}

// ---- Sweep ----

void CesClientAsync::sweep() {
  if (closed_) return;

  auto now = std::chrono::steady_clock::now();
  bool anyActive = false;

  for (auto& ch : channels_) {
    if (ch.state == ChState::Handshaking) {
      anyActive = true;
      if (now - ch.sentAt <= std::chrono::milliseconds(HANDSHAKE_RETRY_MS))
        continue;
      if (++ch.retries >= maxRetries_) {
        ch.state = ChState::Idle;
      } else {
        ch.sentGPass = genPassword();
        ch.sentAt = now;
        sendGetInfo(ch);
      }
    }

    else if (ch.state == ChState::Busy) {
      anyActive = true;
      if (now - ch.sentAt <= std::chrono::milliseconds(RETRY_MS))
        continue;
      if (++ch.retries >= maxRetries_) {
        --pendingCount_;
        auto cb = std::move(ch.currentOp.cb);
        ch.currentOp = {};
        ch.state = ChState::Idle;
        if (cb) cb(CES_ERROR_TIMEOUT);
      } else {
        queue_.push_front(std::move(ch.currentOp));
        ch.currentOp = {};
        handshake(ch);
      }
    }
  }

  dispatch();

  if (anyActive || !queue_.empty())
    startSweepTimer();
}

void CesClientAsync::startSweepTimer() {
  sweepTimer_.expires_after(std::chrono::seconds(1));
  sweepTimer_.async_wait([this](const boost::system::error_code& ec) {
    if (ec || closed_) return;
    sweep();
  });
}

// ---- Cleanup ----

void CesClientAsync::failAll(uint8_t rc) {
  for (auto& ch : channels_) {
    if (ch.state == ChState::Busy && ch.currentOp.cb)
      ch.currentOp.cb(rc);
    ch.state = ChState::Idle;
    ch.currentOp = {};
  }
  while (!queue_.empty()) {
    auto cb = std::move(queue_.front().cb);
    queue_.pop_front();
    if (cb) cb(rc);
  }
  pendingCount_.store(0, std::memory_order_relaxed);
}

// ---- Helpers ----

uint64_t CesClientAsync::genPassword() { return rngDist_(rng_); }

template <size_t N>
void CesClientAsync::sendBuf(minx::ArrayBuffer<N>& buf) {
  // Copy the framed bytes into a heap buffer owned by the completion handler.
  // async_send_to references the storage until the send completes, but `buf`
  // is a stack local in the caller and would be destroyed before then.
  auto span = buf.getBackingSpan();
  auto data = std::make_shared<ces::Bytes>(span.data(),
                                           span.data() + buf.getSize());
  socket_.async_send_to(
    boost::asio::buffer(*data), serverEp_,
    [data](const boost::system::error_code&, size_t) {});
}

} // namespace ces
