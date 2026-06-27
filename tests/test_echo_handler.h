// Shared test-only CesPlex handler: a length-prefixed byte echo.
//
// After the select handshake completes, reads an 8-byte length prefix
// (u64 BE), then that many payload bytes, then writes the same length +
// payload back. Clean enough to assert "round-trip" on. Header-only so each
// test TU instantiates its OWN object and mounts it via the host's object
// mount path (there is no global handler registry).

#pragma once

#include <ces/buffer.h>
#include <ces/cesplex/mux.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cstdint>
#include <memory>

namespace ces {

class EchoHandler : public ces::CesPlexHandler {
public:
  void serve(std::shared_ptr<minx::RudpStream> stream,
             ces::BoundChannelContext /*bound*/) override {
    auto st = std::make_shared<State>();
    st->stream = std::move(stream);
    readLen(st);
  }

private:
  struct State {
    std::shared_ptr<minx::RudpStream> stream;
    std::array<uint8_t, 8> lenBuf{};
    ces::Bytes payload;
  };

  static void readLen(std::shared_ptr<State> st) {
    boost::asio::async_read(
      *st->stream, boost::asio::buffer(st->lenBuf),
      [st](const boost::system::error_code& ec, std::size_t) {
        if (ec) return;
        uint64_t n = ces::Buffer::peek<uint64_t>(st->lenBuf.data());
        if (n == 0 || n > 4096) return; // test bounds
        st->payload.resize(n);
        boost::asio::async_read(
          *st->stream, boost::asio::buffer(st->payload),
          [st](const boost::system::error_code& ec2, std::size_t) {
            if (ec2) return;
            writeBack(st);
          });
      });
  }

  static void writeBack(std::shared_ptr<State> st) {
    // Reuse lenBuf; it still holds the length from the read path.
    boost::asio::async_write(
      *st->stream, boost::asio::buffer(st->lenBuf),
      [st](const boost::system::error_code& ec, std::size_t) {
        if (ec) return;
        boost::asio::async_write(
          *st->stream, boost::asio::buffer(st->payload),
          [st](const boost::system::error_code&, std::size_t) {
            // Done. st drops; RudpStream closes when peer closes.
          });
      });
  }
};

} // namespace ces
