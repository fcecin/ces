#pragma once

#include <ces/account.h>
#include <ces/keys.h>
#include <ces/protocol.h>
#include <ces/types.h>
#include <minx/buffer.h>
#include <minx/types.h>

#include <boost/asio.hpp>

#include <deque>
#include <functional>
#include <random>
#include <vector>

namespace ces {

/**
 * Async CES client for server-to-server settlement.
 *
 * Runs entirely on an externally-provided io_context (no threads of its own).
 * Maintains N independent ticket channels to one peer server. Each channel
 * handles one operation at a time with proper MINX ticket chaining.
 * Operations are queued and dispatched to idle channels.
 */
class CesClientAsync {
public:
  using Callback = std::function<void(uint8_t rc)>;

  CesClientAsync(boost::asio::io_context& io,
                 const boost::asio::ip::udp::endpoint& serverEndpoint,
                 const KeyPair& keyPair,
                 const Hash& peerServerKey,
                 size_t numChannels = DEFAULT_CHANNELS,
                 int maxRetries = DEFAULT_MAX_RETRIES);

  ~CesClientAsync();

  void openTransfer(const Hash& destKey, uint64_t amount, Callback cb);

  // Queue fill percentage [0..100]. The server uses this to backpressure:
  // callers bounce with CES_ERROR_QUEUE_FULL around 95%.
  static constexpr int LOAD_PERCENT_SCALE = 100;
  int load() const {
    size_t n = pendingCount_.load(std::memory_order_relaxed);
    return n >= MAX_QUEUE ? LOAD_PERCENT_SCALE
                          : static_cast<int>(n * LOAD_PERCENT_SCALE / MAX_QUEUE);
  }

  void close();

  static constexpr size_t DEFAULT_CHANNELS = 16;
  static constexpr int DEFAULT_MAX_RETRIES = 7;

private:
  // Queued operation (not yet assigned to a channel)
  struct QueuedOp {
    Hash destKey;
    uint64_t amount;
    Callback cb;
    minx::Bytes signedPayload; // cached, stable across retries
  };

  // Per-channel state
  enum class ChState { Idle, Handshaking, Ready, Busy };

  struct Channel {
    ChState state = ChState::Idle;
    uint64_t ticket = 0;       // server's gpassword to spend next
    uint64_t sentGPass = 0;    // our gpassword on the in-flight packet
    minx::Hash serverKey{};    // server pubkey from INFO
    QueuedOp currentOp;        // the op we're working on (valid when Busy)
    int retries = 0;
    std::chrono::steady_clock::time_point sentAt;
  };

  void dispatch();
  void handshake(Channel& ch);
  void sendGetInfo(Channel& ch);
  void sendOp(Channel& ch);

  void startReceive();
  void onReceive(const boost::system::error_code& ec, size_t bytes);
  void handleInfo(const uint8_t* data, size_t len);
  void handleMessage(const uint8_t* data, size_t len);

  void sweep();
  void startSweepTimer();
  void failAll(uint8_t rc);

  size_t chIdx(const Channel& ch) const {
    return static_cast<size_t>(&ch - channels_.data());
  }

  uint64_t genPassword();

  template <size_t N>
  void sendBuf(minx::ArrayBuffer<N>& buf);

  boost::asio::io_context& io_;
  boost::asio::ip::udp::socket socket_;
  boost::asio::ip::udp::endpoint serverEp_;
  boost::asio::ip::udp::endpoint recvEp_;
  boost::asio::steady_timer sweepTimer_;

  KeyPair keyPair_;
  Hash peerServerKey_;

  std::vector<Channel> channels_;
  std::deque<QueuedOp> queue_;
  std::atomic<size_t> pendingCount_{0};

  std::array<uint8_t, 2048> recvBuf_;

  std::mt19937_64 rng_{std::random_device{}()};
  std::uniform_int_distribution<uint64_t> rngDist_{1,
    std::numeric_limits<uint64_t>::max()};

  bool closed_ = false;

  int maxRetries_;
  static constexpr int RETRY_MS = 3000;
  static constexpr int HANDSHAKE_RETRY_MS = 2000;
  static constexpr size_t MAX_QUEUE = 50000;
};

} // namespace ces
