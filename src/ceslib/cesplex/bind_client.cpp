// bind_client.cpp — the client side of the CesPlex bind. See
// include/ces/cesplex/bind_client.h.

#include <ces/cesplex/bind_client.h>
#include <ces/types.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <span>

namespace ces {

const char* bindErrorText(BindError e) {
  switch (e) {
    case BindError::None:        return "ok";
    case BindError::Unreachable: return "the server did not answer";
    case BindError::WrongServer: return "the server has another key";
    case BindError::Rejected:    return "the server refused the bind";
    case BindError::BadReply:    return "the bind reply does not verify";
  }
  return "bind failed";
}

void asyncStartBind(std::shared_ptr<minx::RudpStream> stream,
                    const std::string& protocol,
                    std::optional<minx::Hash> expected,
                    std::function<void(BindError, ServerHello)> done) {
  if (protocol.empty() || protocol.size() > CES_PLEX_MAX_NAME_LEN) {
    // The server drops such a name with no reply, so send nothing. Report
    // it from the executor, as every other outcome.
    stream->close();
    boost::asio::post(stream->get_executor(), [done = std::move(done)] {
      done(BindError::Rejected, ServerHello{});
    });
    return;
  }
  auto name = std::make_shared<minx::Bytes>(buildBindName(protocol));
  boost::asio::async_write(
    *stream, boost::asio::buffer(*name),
    [stream, name, expected, done = std::move(done)]
    (const boost::system::error_code& ec, std::size_t) mutable {
      if (ec) {
        stream->close();
        done(BindError::Unreachable, ServerHello{});
        return;
      }
      auto buf = std::make_shared<std::array<uint8_t, CES_PLEX_HELLO_SIZE>>();
      boost::asio::async_read(
        *stream, boost::asio::buffer(*buf),
        [stream, buf, expected, done = std::move(done)]
        (const boost::system::error_code& ec2, std::size_t) {
          if (ec2) {
            stream->close();
            done(BindError::Unreachable, ServerHello{});
            return;
          }
          ServerHello hello = parseServerHello(
            std::span<const uint8_t, CES_PLEX_HELLO_SIZE>(buf->data(), buf->size()));
          if (expected && *expected != hello.serverPubkey) {
            stream->close();
            done(BindError::WrongServer, hello);
            return;
          }
          done(BindError::None, hello);
        });
    });
}

void asyncFinishBind(std::shared_ptr<minx::RudpStream> stream,
                     minx::Bytes request,
                     ServerHello hello,
                     std::function<void(BindError, BindDigest)> done) {
  const auto found = bindRequestDigest(request);
  auto rest = bindRequestTail(request);
  if (!found || !rest) {
    // Not a request that buildBindRequest built. Report it from the
    // executor, as every other outcome.
    stream->close();
    boost::asio::post(stream->get_executor(),
                      [done = std::move(done)] {
                        done(BindError::BadReply, BindDigest{});
                      });
    return;
  }
  const auto digest = *found;
  auto req = std::make_shared<minx::Bytes>(std::move(*rest));
  boost::asio::async_write(
    *stream, boost::asio::buffer(*req),
    [stream, req, hello, digest, done = std::move(done)]
    (const boost::system::error_code& ec, std::size_t) mutable {
      if (ec) {
        stream->close();
        done(BindError::Unreachable, digest);
        return;
      }
      auto reply = std::make_shared<
        std::array<uint8_t, CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
      boost::asio::async_read(
        *stream, boost::asio::buffer(*reply),
        [stream, reply, hello, digest, done = std::move(done)]
        (const boost::system::error_code& ec2, std::size_t) {
          if (ec2) {
            stream->close();
            done(BindError::Unreachable, digest);
            return;
          }
          const ParsedBindReply r = parseBindReply(
            std::span<const uint8_t, CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
              reply->data(), reply->size()));
          // Check the reply before its status says anything: a NACK is a
          // refusal only if the server of the hello signed it for this
          // request and this challenge.
          BindError err = BindError::None;
          if (!verifyBindReply(r, std::span<const uint8_t>(
                digest.data(), digest.size())))
            err = BindError::BadReply;
          else if (r.serverPubkey != hello.serverPubkey ||
                   r.challenge != hello.challenge)
            err = BindError::BadReply;
          else if (r.status == CES_PLEX_NACK)
            err = BindError::Rejected;
          else if (r.status != CES_PLEX_OK)
            err = BindError::BadReply;
          if (err != BindError::None) stream->close();
          done(err, digest);
        });
    });
}

void asyncClientBind(std::shared_ptr<minx::RudpStream> stream,
                     std::string protocol,
                     KeyPair signer,
                     std::optional<minx::Hash> expected,
                     std::function<void(BindError, ServerHello, BindDigest)> done) {
  // The completion takes its own copy of `protocol`: it must not move from
  // the string that asyncStartBind reads in the same call.
  auto next =
    [stream, protocol, signer = std::move(signer),
     done = std::move(done)](BindError err, ServerHello hello) {
      if (err != BindError::None) {
        done(err, hello, BindDigest{});
        return;
      }
      asyncFinishBind(stream,
                      buildBindRequest(protocol, getMicrosSinceEpoch(), signer, hello),
                      hello,
                      [hello, done](BindError e, BindDigest digest) {
                        done(e, hello, digest);
                      });
    };
  asyncStartBind(stream, protocol, expected, std::move(next));
}

} // namespace ces
