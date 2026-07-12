// dial.h — `cesh dial <pid>` implementation entry point.
//
// Opens a bidirectional byte stream from the cesh client to a running
// compute instance over /ces/lua/1, then pipes stdin↔channel↔stdout.
// The behavior is `nc` shaped:
//   - byte-clean, no framing, no banners on stdout.
//   - stderr only for diagnostics; -v adds a single ATTACH-ok line.
//   - stdin EOF = stop sending, keep reading until peer closes (TCP
//     half-close style).
//   - SIGINT/SIGTERM = active stream close, exit 130/143.
//
// Exit codes:
//   0  clean (peer closed, or stdin EOF then peer closed)
//   1  generic / unknown error
//   2  CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND on ATTACH
//   3  CES_ERROR_NOT_LISTENING on ATTACH
//   4  bind handshake failure (network / sig / NACK)
//   5  ATTACH protocol error (sig/wire issue server-side)
//  130  SIGINT
//  143  SIGTERM
#pragma once

#include <ces/keys.h>

#include <minx/types.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace ces {

struct DialArgs {
  std::string serverHost;          // hostname or IP (no port)
  uint16_t    rpcPort = 0;         // CesPlex RUDP port (--rpc-port)
  uint64_t    pid = 0;
  KeyPair     signerKey;
  // If provided, the bind reply's server pubkey must match. If absent,
  // the first reply's pubkey is TOFU-accepted (logged once on stderr).
  std::optional<minx::Hash> expectedServerPk;
  bool        verbose = false;     // -v: print "ATTACH ok conn_id=N" once

  // External-signing mode (--extsign): no wallet/private key in this process.
  // The bind + ATTACH signatures are supplied over a tiny stdio control
  // handshake, so a tunneler (cesweb) keeps the key in the browser/gateway and
  // never hands it to cesh. When set, signerKey is unused; clientPubkeyHex names
  // the 32-byte client pubkey (64 hex) that signed. Control protocol:
  //   stdin  <- "BIND <timeUs> <bindSigHex>\n"
  //   stdout -> "TOKEN <sessionToken>\n"     (or "ERR <msg>\n" then exit)
  //   stdin  <- "ATTACH <attachSigHex>\n"
  //   stdout -> "READY\n"                     (or "ERR <msg>\n" then exit)
  // after which the channel is a raw byte pipe exactly like the wallet path.
  bool        extSign = false;
  std::string clientPubkeyHex;
};

int runDial(const DialArgs& args);

// A bound + ATTACHed /ces/lua/1 session that exchanges newline-delimited request/reply
// lines. Lets a caller drive an instance's line protocol (e.g. hylesolo) by reusing the
// exact CesPlex bind + ATTACH handshake runDial uses, without duplicating it. Not
// thread-safe: one request at a time from a single thread.
class DialLineSession {
public:
  DialLineSession();
  ~DialLineSession();
  DialLineSession(const DialLineSession&) = delete;
  DialLineSession& operator=(const DialLineSession&) = delete;

  // Bind + ATTACH to args.pid (signerKey / rpcPort / serverHost / expectedServerPk used;
  // extSign/verbose ignored). Returns "" on success, else an error message.
  std::string open(const DialArgs& args);

  // Send `line` (a '\n' is appended) and read back one reply line (without the trailing
  // '\n') into `reply`. Returns "" on success, else an error message.
  std::string request(const std::string& line, std::string& reply,
                      std::chrono::milliseconds timeout = std::chrono::seconds(15));

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace ces
