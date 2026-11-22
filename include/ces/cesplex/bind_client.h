// bind_client.h — the client side of the CesPlex bind, in one place.
//
// After a client opens a RUDP channel, the bind has four steps:
//   1. Write the protocol name. The client speaks first: the server sends
//      nothing to an address that has not proven itself on the channel.
//   2. Read the server hello: [32 server_pubkey][u64 challenge].
//   3. Write the rest of the bind request. It signs the protocol name, the
//      time, the client key, the server key and the challenge.
//   4. Read the signed bind reply, and check that it answers this request,
//      with the same server key and the same challenge.
// wire.h has the bytes.
//
// The client writes only the protocol name before it reads the hello. A
// client that expects a server key refuses a hello with another key, and
// signs nothing. A client with no expected key trusts the key in the hello.
//
// Threads: call each function on the thread that runs the stream's Rudp.
// `done` runs one time, on the stream's executor, never inside the call.
// On each error the function closes the stream before `done`. The
// functions hold the stream and their buffers until `done`, and nothing
// else. They hold no timer: the caller keeps its own deadline, and closes
// the stream when the deadline expires. The pending read then fails, and
// `done` gets Unreachable.

#pragma once

#include <ces/cesplex/wire.h>
#include <ces/keys.h>

#include <minx/rudp/rudp_stream.h>
#include <minx/types.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace ces {

enum class BindError : uint8_t {
  None,
  Unreachable,  // the stream ended before the hello or the reply came
  WrongServer,  // the hello has another key than the expected one
  Rejected,     // the server of the hello sent a NACK, signed for this bind,
                // or the protocol name has no valid length
  BadReply,     // the reply does not verify, has another key or challenge,
                // or has an unknown status
};

// A short text for a log or an error message.
const char* bindErrorText(BindError e);

// Steps 1 and 2. Write the name of `protocol`, and read the server hello.
// With `expected`, a hello with another key gives WrongServer.
void asyncStartBind(std::shared_ptr<minx::RudpStream> stream,
                    const std::string& protocol,
                    std::optional<minx::Hash> expected,
                    std::function<void(BindError, ServerHello)> done);

// Steps 3 and 4. `request` is what buildBindRequest or
// buildBindRequestSigned built for `hello`, for the same protocol: write its
// rest (the name went in step 1), and read the reply. With None, `done` gets
// the digest of the request: the per-op sigs of the channel sign it. With an
// error, the digest has no use.
void asyncFinishBind(std::shared_ptr<minx::RudpStream> stream,
                     minx::Bytes request,
                     ServerHello hello,
                     std::function<void(BindError, BindDigest)> done);

// All four steps, with the request signed by `signer` for `protocol`.
// `done` gets the hello and, with None, the digest of the bind request: the
// per-op sigs of the channel sign that digest. With an error, the digest has
// no use.
void asyncClientBind(std::shared_ptr<minx::RudpStream> stream,
                     std::string protocol,
                     KeyPair signer,
                     std::optional<minx::Hash> expected,
                     std::function<void(BindError, ServerHello, BindDigest)> done);

} // namespace ces
