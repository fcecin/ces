// endpoint.cpp — implementation of CesPlexEndpoint.
//
// This is purely the io harness: Minx + Rudp + two io threads + the Rudp
// tick. The CesPlex and ChannelMeter it drives already accept an external
// io_context, so they plug straight onto taskIO_ with no changes. The
// bring-up + teardown ordering mirrors CesServer's proven rpc path (which
// stays its own bespoke, multi-tenant strand and does NOT use this).

#include <ces/cesplex/endpoint.h>
#include <ces/types.h>          // getMicrosSinceEpoch
#include <ces/util/helpers.h>   // runGuardedThread

#include <minx/blog.h>
#include <minx/stdext.h>

#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/post.hpp>

#include <utility>

LOG_MODULE("plex");

namespace ces {

void CesPlexEndpoint::RudpListener::onSend(const minx::SockAddr& peer,
                                           const minx::Bytes& bytes) {
  // The bytes already carry the MinxStdExtensions routing key Rudp
  // prepended; sendExtension takes the payload as-is. Swallow the
  // "no socket" exception that Rudp can trigger (e.g. an HS_CLOSE) at any
  // point during teardown after the socket has closed.
  if (!ep_->minx_) return;
  try {
    ep_->minx_->sendExtension(peer, bytes);
  } catch (const std::exception&) {
    // Socket already closed; nothing to do.
  }
}

std::shared_ptr<minx::Rudp::ChannelHandler>
CesPlexEndpoint::RudpListener::onAccept(const minx::SockAddr& peer,
                                        uint32_t channelId) {
  // Inbound HS_OPEN → hand to CesPlex. A null cesplex (or one with no
  // resolved bindings) rejects silently. Outbound channels never fire
  // onAccept; this path is purely inbound.
  if (!ep_->cesplex_) return nullptr;
  return ep_->cesplex_->acceptInbound(peer, channelId);
}

CesPlexEndpoint::CesPlexEndpoint(uint16_t port,
                                 CesPlexHost* host,
                                 std::map<std::string, std::string> mounts,
                                 minx::MinxConfig minxCfg,
                                 minx::RudpConfig rudpCfg,
                                 std::chrono::seconds meterTick)
    : host_(host) {
  minx_ = std::make_unique<minx::Minx>(&minxListener_, std::move(minxCfg));
  minx_->setServerKey(host_->cesplexSigningKey().getPublicKeyAsHash());

  // Construct the Rudp transport before opening the socket so no packet can
  // hit an unwired handler. The Rudp::Listener forwards onSend to minx_ and
  // onAccept to cesplex_.
  rudp_ = std::make_unique<minx::Rudp>(&rudpListener_, std::move(rudpCfg),
                                       minx_.get());

  // ChannelMeter before CesPlex, so CesPlex's Session can track() each
  // channel as it binds. Both take taskIO_ as their external strand.
  meter_ = std::make_unique<ChannelMeter>(*rudp_, taskIO_, host_, meterTick);
  cesplex_ = std::make_unique<CesPlex>(mounts, *rudp_, taskIO_, host_,
                                       meter_.get());

  // Route inbound Rudp-family packets into the Rudp state machine.
  {
    minx::MinxStdExtensions stdExt;
    stdExt.registerExtension(
        minx::Rudp::KEY_V0,
        [this](const minx::SockAddr& peer, uint64_t key,
               const minx::Bytes& payload) {
          if (rudp_)
            rudp_->onPacket(peer, key, payload, getMicrosSinceEpoch());
        });
    minx_->setExtensionHandler(std::move(stdExt).build());
  }

  boundPort_ = minx_->openSocket(boost::asio::ip::address_v6::any(), port,
                                 netIO_, taskIO_);
  if (boundPort_ == 0) {
    LOGWARNING << "CesPlexEndpoint: failed to open socket" << VAR(port);
    // Nothing started yet — tear down in reverse construction order.
    cesplex_.reset();
    meter_.reset();
    rudp_.reset();
    minx_.reset();
    return;
  }

  LOGINFO << "CesPlexEndpoint listening" << VAR(boundPort_);
  netThread_ = std::thread(
    [this]() { runGuardedThread([this]{ netIO_.run(); }, "cesplexEndpointNetIO"); });
  taskThread_ = std::thread(
    [this]() { runGuardedThread([this]{ taskIO_.run(); }, "cesplexEndpointTaskIO"); });

  // Rudp tick pulse on taskIO_; reschedules itself until running_ clears.
  tickTimer_ = std::make_shared<boost::asio::steady_timer>(taskIO_);
  boost::asio::post(taskIO_, [this]() { scheduleTick(); });
}

CesPlexEndpoint::~CesPlexEndpoint() {
  running_.store(false);
  if (!minx_) return;   // socket never opened (or already torn down)

  if (tickTimer_) {
    boost::system::error_code ec;
    tickTimer_->cancel(ec);
  }
  minx_->closeSocket(false);
  netIO_.stop();
  taskIO_.stop();
  if (netThread_.joinable()) netThread_.join();
  if (taskThread_.joinable()) taskThread_.join();
  tickTimer_.reset();
  // Threads joined: no callback can race the destructors now. Tear down in
  // reverse construction order — CesPlex holds RudpStreams into rudp_, and
  // the meter references rudp_, so both go before rudp_.
  cesplex_.reset();
  meter_.reset();
  rudp_.reset();
  minx_.reset();
}

void CesPlexEndpoint::scheduleTick() {
  if (!tickTimer_ || !running_.load()) return;
  tickTimer_->expires_after(std::chrono::milliseconds(10));
  tickTimer_->async_wait([this](const boost::system::error_code& ec) {
    if (ec || !running_.load() || !rudp_) return;
    rudp_->tick(getMicrosSinceEpoch());
    scheduleTick();
  });
}

bool CesPlexEndpoint::hasAnyBinding() const {
  return cesplex_ && cesplex_->hasAnyBinding();
}

} // namespace ces
