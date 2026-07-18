// cesh_hyle.inc -- client-side hyle verbs for cesh. Included by main.cpp only when built
// with --hyle (CES_HYLE). All hyle knowledge lives here in the shell; the CES client engine
// (ceslib) never links hyle. cesh builds + signs ops with hyle_services and relays them to a
// chain-hosting instance (hylesolo) over its /ces/lua/1 line protocol -- the same channel
// `cesh dial` opens. One chain, one connection: cross-chain aggregation is POST, not cesh.

#include "dial.h"

#include <ces/keys.h>
#include <ces/l2/compute_client.h>
#include <ces/types.h>

#include <minx/types.h>

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>
#include <hyle/services/ops.h>
#include <hyle/services/schema.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

struct HyleCli {
  std::string host;
  uint16_t rpcPort = 0;
  ces::KeyPair actorKey;
  std::optional<minx::Hash> expectedServerPk;
  std::string source = "/s/hylesolo.lua"; // `list`: which source's instances to enumerate
  std::vector<std::string> args;          // "list", or <pid> <verb> [operands]
  uint64_t fund = 0;                      // put: initial entry funding
  bool wait = false;                      // write verbs: poll txr until it settles
  bool quiet = false;                     // -q: data-only stdout
  std::vector<std::string> inTokens;      // put: --in value tokens (text/hex:/file:), appended
  std::string outPath;                    // get: --out file for the raw value bytes (else stdout)
  bool hexOut = false;                    // get: print the value as a hex string
};

std::string hyHex(const uint8_t* p, std::size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (std::size_t i = 0; i < n; i++) {
    s.push_back(d[p[i] >> 4]);
    s.push_back(d[p[i] & 15]);
  }
  return s;
}
std::string hyHex(const hyle::PubKey& k) { return hyHex(k.data(), k.size()); }
std::string hyHex(const hyle::wire::Bytes& b) { return hyHex(b.data(), b.size()); }

hyle::wire::View hySv(const std::string& s) {
  return hyle::wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// Pull the value of a "key=..." token out of an "ok ..." reply line.
std::string hyField(const std::string& line, const std::string& key) {
  const std::string k = " " + key + "=";
  const auto p = line.find(k);
  if (p == std::string::npos) return "";
  const auto start = p + k.size();
  const auto end = line.find(' ', start);
  return line.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

bool hyHexTo32(const std::string& hex, uint8_t* out) {
  if (hex.size() != 64) return false;
  auto nyb = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (int i = 0; i < 32; i++) {
    const int hi = nyb(hex[i * 2]), lo = nyb(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

// Concatenate the --in tokens into one value buffer via the shared appender (text/hex:/file:).
std::string hyComposeValue(const std::vector<std::string>& tokens) {
  ces::Bytes buf;
  for (const std::string& t : tokens) appendInToken(buf, t);
  return std::string(buf.begin(), buf.end());
}

int hyErr(const std::string& msg) {
  std::cerr << "Error: " << msg << "\n";
  return 1;
}

// True if the bytes are valid UTF-8 with no control chars other than tab/newline/CR.
bool hyIsText(const std::string& s) {
  std::size_t i = 0, n = s.size();
  while (i < n) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    std::size_t len;
    if (c < 0x80) {
      if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return false;
      len = 1;
    } else if ((c >> 5) == 0x6) len = 2;
    else if ((c >> 4) == 0xE) len = 3;
    else if ((c >> 3) == 0x1E) len = 4;
    else return false;
    if (i + len > n) return false;
    for (std::size_t k = 1; k < len; k++)
      if ((static_cast<unsigned char>(s[i + k]) >> 6) != 0x2) return false;
    i += len;
  }
  return true;
}

// Human display of a byte blob: the text if it is text, else hex:<hex> (N bytes).
// Display only; the exact bytes come from -q / --out / --hex.
std::string hyRenderBlob(const std::string& s) {
  if (s.empty()) return "(empty)";
  if (hyIsText(s)) return s;
  return "hex:" + hyHex(reinterpret_cast<const uint8_t*>(s.data()), s.size()) +
         " (" + std::to_string(s.size()) + " bytes)";
}

// Line-protocol name encoding: safe text rides bare; a name with whitespace, a control
// byte, or a leading "hex:" is sent as hex:<hex> so it round-trips unambiguously.
std::string hyWireName(const std::string& raw) {
  bool safe = !raw.empty() && raw.rfind("hex:", 0) != 0;
  for (unsigned char c : raw) if (c <= 0x20 || c == 0x7f) { safe = false; break; }
  return safe ? raw : "hex:" + hyHex(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
}

// Resolve a name argument through the shared text:/hex:/file:/bare grammar to raw bytes.
std::string hyResolveName(const std::string& arg) {
  ces::Bytes buf;
  appendInToken(buf, arg);
  return std::string(buf.begin(), buf.end());
}

// `cesh hyle list`: enumerate the instances of a source (default /s/hylesolo.lua) with their
// pids, so the operator picks one and names it explicitly on every other command. This tool
// does not guess a pid; a stateful client would cache the mapping.
int hyleList(const HyleCli& c) {
  ces::CesComputeClient cc;
  if (c.expectedServerPk) cc.setServerPubkey(*c.expectedServerPk);
  if (cc.connect(c.host, c.rpcPort, c.actorKey) != CES_OK) {
    cc.disconnect();
    return hyErr("connect failed (check --rpc-port)");
  }
  std::vector<ces::CesComputeClient::InstanceInfo> insts;
  const uint8_t rc = cc.instances(c.source, insts);
  cc.disconnect();
  if (rc != CES_OK) return hyErr("instances query failed rc=" + std::to_string(rc));
  if (insts.empty()) {
    if (!c.quiet) std::cout << "no instances of " << c.source << "\n";
    return 0;
  }
  for (const auto& e : insts) {
    if (c.quiet) {
      std::cout << e.pid << "\n";
    } else {
      std::cout << "pid=" << e.pid << " source=" << e.sourceName
                << " client_port=" << e.clientPort << " rpc_port=" << e.rpcPort << "\n";
    }
  }
  return 0;
}

// info|config|self|height|account|entry|txr|nodekey ride straight through: build the
// line, print the chain's reply verbatim. `get` is separate (extracts an entry's value as raw
// bytes); the write verbs build + sign ops. (nodekey is owner-gated at the program.)
const std::set<std::string>& hyRelayVerbs() {
  static const std::set<std::string> v = {"info", "config", "self", "height",
                                          "txr", "nodekey"};
  return v;
}

// Submit hexOps to the chain, print the tx id, and with --wait poll txr until it settles.
// Shared by the op-building verbs and the raw submit escape hatch.
int hySubmit(ces::DialLineSession& sess, const std::string& hexOps, const HyleCli& c) {
  std::string reply;
  if (std::string e = sess.request("submit " + hexOps, reply); !e.empty()) return hyErr(e);
  if (reply.rfind("ok ", 0) != 0) { std::cerr << reply << "\n"; return 1; }
  const auto sp = reply.find(' ', 3);
  const std::string txid = reply.substr(3, sp == std::string::npos ? std::string::npos : sp - 3);
  if (!c.wait) {
    std::cout << (c.quiet ? txid : ("submitted tx " + txid)) << "\n";
    return 0;
  }
  for (int i = 0; i < 200; i++) {
    std::string t;
    if (std::string e = sess.request("txr " + txid, t); !e.empty()) return hyErr(e);
    if (t.rfind("ok ", 0) == 0) {
      const bool applied = hyField(t, "applied") == "1";
      std::cout << (c.quiet ? (applied ? "1" : "0")
                            : ("tx " + txid + (applied ? " applied" : " rejected"))) << "\n";
      return applied ? 0 : 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return hyErr("tx " + txid + " did not settle in time");
}

int runHyle(const HyleCli& c) {
  if (c.args.empty())
    return hyErr("usage: cesh hyle list | cesh hyle <pid> <verb> [args]");

  // `list` is the only verb that does not name an instance; it is how you find the pids.
  if (c.args[0] == "list") return hyleList(c);

  uint64_t pid = 0;
  try { pid = std::stoull(c.args[0]); }
  catch (...) { return hyErr("first argument must be an instance pid, or 'list' (see: cesh hyle list)"); }
  if (pid == 0) return hyErr("instance pid required (see: cesh hyle list)");
  if (c.args.size() < 2)
    return hyErr("usage: cesh hyle <pid> <verb> [args] -- verb is one of info|config|self|height|"
                 "account|entry|get|txr|nodekey|put|del|give|rip|transfer|mint|seize|"
                 "propose|approve|submit");
  const std::string verb = c.args[1];
  const std::vector<std::string> op(c.args.begin() + 2, c.args.end());  // the verb's operands

  const bool isWrite = verb == "put" || verb == "del" || verb == "give" || verb == "transfer" ||
                       verb == "rip" || verb == "mint" || verb == "seize" ||
                       verb == "propose" || verb == "approve";
  // Writes act AS this hyle identity, so the key must be ed25519 (a CES ed25519 key IS a hyle
  // account at the same 32 bytes; a secp256k1 key has no hyle identity). Reads do not.
  if (isWrite && c.actorKey.getAlgorithm() != ces::KeyAlgo::ED25519)
    return hyErr("this verb acts as a hyle identity; use an ed25519 key (secp256k1 has none)");

  ces::DialArgs da;
  da.serverHost = c.host;
  da.rpcPort = c.rpcPort;
  da.pid = pid;
  da.signerKey = c.actorKey;
  da.expectedServerPk = c.expectedServerPk;

  ces::DialLineSession sess;
  if (std::string e = sess.open(da); !e.empty()) return hyErr("dial pid " + std::to_string(pid) + ": " + e);

  auto ask = [&](const std::string& line, std::string& reply) -> std::string {
    return sess.request(line, reply);
  };

  // get <name>: fetch an entry and emit its value bytes -- to --out (binary-safe), --hex, else
  // raw stdout. `entry` shows the record; `get` gives the content, matching cesh file get. The
  // name takes the text:/hex:/file: grammar and rides hyWireName, so binary keys round-trip.
  if (verb == "get") {
    if (op.empty()) return hyErr("get <name>");
    const std::string name = hyResolveName(op[0]);
    std::string reply;
    if (std::string e = ask("entry " + hyWireName(name), reply); !e.empty()) return hyErr(e);
    if (reply.rfind("ok ", 0) != 0) { std::cerr << reply << "\n"; return 1; }
    const ces::Bytes bytes = ces::parseHex(hyField(reply, "payload"));
    if (!c.outPath.empty()) {
      std::ofstream f(c.outPath, std::ios::binary);
      if (!f) return hyErr("cannot open --out " + c.outPath);
      f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
      if (!c.quiet) std::cout << "wrote " << bytes.size() << " bytes to " << c.outPath << "\n";
    } else if (c.hexOut) {
      std::cout << hyHex(bytes) << "\n";
    } else {
      std::cout.write(reinterpret_cast<const char*>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
    }
    return 0;
  }

  // submit: relay pre-signed op bytes (the carrier path). The op carries its own signature, so
  // this needs no identity. Bytes come from --in; put/del/give/transfer build them for you,
  // submit is the escape hatch for any op cesh does not model.
  if (verb == "submit") {
    if (c.inTokens.empty()) return hyErr("submit needs op bytes: --in <hex:|file:>");
    const std::string ops = hyComposeValue(c.inTokens);
    return hySubmit(sess, hyHex(reinterpret_cast<const uint8_t*>(ops.data()), ops.size()), c);
  }

  // account / entry pretty-print the record (with balance) in human mode; -q emits the raw
  // "ok k=v" line for piping. entry's name rides hyWireName so binary keys round-trip, and its
  // name/value render as text or hex:<...> for the eyes only.
  if (verb == "account") {
    if (op.empty()) return hyErr("account <pubkey-hex32>");
    std::string reply;
    if (std::string e = ask("account " + op[0], reply); !e.empty()) return hyErr(e);
    if (reply.rfind("ok ", 0) != 0) { std::cerr << reply << "\n"; return 1; }
    if (c.quiet) { std::cout << reply << "\n"; return 0; }
    print_header("Hyle Account");
    print_field("Pubkey", op[0]);
    print_field("Balance", hyField(reply, "balance"));
    print_field("Sequence", hyField(reply, "sequence"));
    print_field("Exists", hyField(reply, "exists") == "1" ? "yes" : "no");
    std::cout << std::endl;
    return 0;
  }
  if (verb == "entry") {
    if (op.empty()) return hyErr("entry <name>");
    const std::string name = hyResolveName(op[0]);
    std::string reply;
    if (std::string e = ask("entry " + hyWireName(name), reply); !e.empty()) return hyErr(e);
    if (reply.rfind("ok ", 0) != 0) { std::cerr << reply << "\n"; return 1; }
    if (c.quiet) { std::cout << reply << "\n"; return 0; }
    const ces::Bytes pl = ces::parseHex(hyField(reply, "payload"));
    print_header("Hyle Entry");
    print_field("Name", hyRenderBlob(name));
    print_field("Owner", hyField(reply, "owner"));
    print_field("Balance", hyField(reply, "balance"));
    print_field("Created", hyField(reply, "created"));
    print_field("Modified", hyField(reply, "modified"));
    print_field("Rent", hyField(reply, "rent"));
    print_field("Value", hyRenderBlob(std::string(pl.begin(), pl.end())));
    std::cout << std::endl;
    return 0;
  }

  if (hyRelayVerbs().count(verb)) {
    std::string line = verb;
    for (const auto& a : op) line += " " + a;
    std::string reply;
    if (std::string e = ask(line, reply); !e.empty()) return hyErr(e);
    if (reply.rfind("err ", 0) == 0) { std::cerr << reply << "\n"; return 1; }
    std::cout << reply << "\n";
    return 0;
  }

  if (!isWrite) return hyErr("unknown verb: " + verb);

  // Write verbs: build + sign an op, encode it, submit the opaque bytes. Signatures are
  // chain-bound, so learn the chain id first; the op's seq is the account's current sequence.
  const minx::Hash priv = c.actorKey.getPrivateKey();
  hyle::PrivKey secret{};
  std::memcpy(secret.data(), priv.data(), 32);
  const hyle::KeyPair hk = hyle::KeyPair::from_secret(secret);

  std::string info;
  if (std::string e = ask("info", info); !e.empty()) return hyErr(e);
  if (info.rfind("ok ", 0) != 0) return hyErr("info: " + info);
  const std::string chain = hyField(info, "chain");
  if (chain.empty()) return hyErr("could not read chain id from info");

  std::string acct;
  if (std::string e = ask("account " + hyHex(hk.pub), acct); !e.empty()) return hyErr(e);
  uint64_t seq = 0;
  if (acct.rfind("ok ", 0) == 0) {
    const std::string s = hyField(acct, "sequence");
    if (!s.empty()) seq = std::stoull(s);
  }

  // put/del/give/rip take an entry key as the first positional; the rest use their own operands.
  // The key takes the text:/hex:/file: grammar, so it can be UTF-8 or binary, then rides in the
  // signed op as raw bytes.
  std::string name;
  if (verb == "put" || verb == "del" || verb == "give" || verb == "rip") {
    if (op.empty()) return hyErr(verb + " needs a key: <name>");
    name = hyResolveName(op[0]);
  }

  hyle::services::Decoded d;
  try {
    if (verb == "put") {
      std::string value;
      if (!c.inTokens.empty()) value = hyComposeValue(c.inTokens);
      else if (op.size() >= 2) value = op[1];
      else return hyErr("put needs a value: <value> or --in <text:|hex:|file:>");
      d.entries.push_back(hyle::services::make_entry_put(
          hk, hySv(name), seq, c.fund, hySv(value), hySv(chain)));
    } else if (verb == "del") {
      d.entries.push_back(hyle::services::make_entry_del(hk, hySv(name), seq, hySv(chain)));
    } else if (verb == "give") {
      if (op.size() < 2) return hyErr("give <name> <newowner-hex32>");
      hyle::PubKey no{};
      if (!hyHexTo32(op[1], no.data())) return hyErr("bad newowner hex (need 64 hex chars)");
      d.entries.push_back(hyle::services::make_entry_give(hk, hySv(name), seq, no, hySv(chain)));
    } else if (verb == "transfer") {
      if (op.size() < 2) return hyErr("transfer <hex32|e:name> <amount>");
      hyle::wire::Bytes to;
      const std::string& dest = op[0];
      if (dest.rfind("e:", 0) == 0) {
        to.push_back(hyle::services::ENTRY_PREFIX);
        const std::string nm = dest.substr(2);
        to.insert(to.end(), nm.begin(), nm.end());
      } else {
        uint8_t pk[32];
        if (!hyHexTo32(dest, pk)) return hyErr("transfer dest: 64-hex account or e:<name>");
        to.push_back(hyle::services::ACCOUNT_PREFIX);
        to.insert(to.end(), pk, pk + 32);
      }
      d.transfers.push_back(hyle::services::make_transfer(
          hk, hyle::wire::View(to.data(), to.size()), std::stoull(op[1]), seq, hySv(chain)));
    } else if (verb == "rip") {
      // The permissionless cull: unsigned, chain-independent. The culler (this key) takes the
      // bounty; anyone may reap a rent-starved entry.
      d.entries.push_back(hyle::services::make_entry_rip(hySv(name), hk.pub));
    } else if (verb == "mint" || verb == "seize") {
      // Privileged sudo ops the signer must be a validator for (the chain gates it). mint moves
      // from the mint sentinel (creates credit); seize moves an account's real funds. The inner
      // is an unsigned transfer; the sudo vote authorizes it. On a one-validator chain the
      // proposer's own vote is quorum, so it executes at once.
      const bool isMint = verb == "mint";
      if (op.size() < (isMint ? 2u : 3u))
        return hyErr(isMint ? "mint <recipient-hex32> <amount>" : "seize <from-hex32> <to-hex32> <amount>");
      hyle::services::TransferOp t;
      uint8_t to[32];
      if (isMint) {
        t.from = hyle::services::MINT_SENTINEL;
        if (!hyHexTo32(op[0], to)) return hyErr("mint recipient must be 64 hex chars");
      } else {
        if (!hyHexTo32(op[0], t.from.data())) return hyErr("seize from must be 64 hex chars");
        if (!hyHexTo32(op[1], to)) return hyErr("seize to must be 64 hex chars");
      }
      t.to.push_back(hyle::services::ACCOUNT_PREFIX);
      t.to.insert(t.to.end(), to, to + 32);
      t.amount = std::stoull(op[isMint ? 1 : 2]);
      hyle::services::Decoded inner;
      inner.transfers.push_back(t);
      const hyle::wire::Bytes ib = hyle::services::encode_ops(inner);
      d.sudos.push_back(hyle::services::make_sudo_propose(
          hk, seq, hyle::wire::View(ib.data(), ib.size()), hySv(chain)));
    } else if (verb == "propose") {
      // General sudo propose: the inner op batch (any privileged act) comes via --in. The caller
      // builds it (mint/seize/entry acts); cesh signs the proposal as the validator.
      if (c.inTokens.empty()) return hyErr("propose --in <inner op bytes>");
      const std::string inner = hyComposeValue(c.inTokens);
      d.sudos.push_back(hyle::services::make_sudo_propose(
          hk, seq, hyle::wire::View(reinterpret_cast<const uint8_t*>(inner.data()), inner.size()),
          hySv(chain)));
    } else {  // approve: add this validator's vote to a proposer's open proposal, bound to the act
      if (op.empty() || c.inTokens.empty())
        return hyErr("approve <proposer-hex32> --in <the proposed inner op bytes>");
      hyle::PubKey proposer{};
      if (!hyHexTo32(op[0], proposer.data())) return hyErr("approve proposer must be 64 hex chars");
      const std::string inner = hyComposeValue(c.inTokens);
      const hyle::Hash ih = hyle::sha256(
          hyle::wire::View(reinterpret_cast<const uint8_t*>(inner.data()), inner.size()));
      d.sudos.push_back(hyle::services::make_sudo_approve(hk, seq, proposer, ih, hySv(chain)));
    }
  } catch (const std::exception& e) {
    return hyErr(std::string("bad argument: ") + e.what());
  }

  return hySubmit(sess, hyHex(hyle::services::encode_ops(d)), c);
}

}  // namespace
