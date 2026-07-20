// test_hylenet.cpp -- the multi-node hyle backend (ces.hyle.net).
//
// N real rpc-enabled CesServers in ONE process, made mutual CES peers over
// /ces/peer/1. Each runs a real cesluajitd child hosting a hylenet program with
// an IDENTICAL N-validator genesis (the N server pubkeys). The program signs
// consensus with its SERVER key (ces.server_secret) and rides the CES server
// peer mesh (ces.peer.*) as its transport. Milestone 0: the chain commits blocks
// across the nodes and they agree on AppHash -- i.e. CesPeerTransport + the
// ces.hyle.net driver reach BFT consensus with no dialing of their own.

#include "test_ext_common.h"
#include "test_lua_conn_common.h"
#include "test_e2e_common.h"

#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/l2/peer_handler.h>

#include <boost/asio/ip/address.hpp>
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace ces;
using namespace ces::exttest;

#ifdef CES_HYLE

#include <hyle/core/crypto.h>
#include <hyle/services/ops.h>
#include <hyle/services/schema.h>

namespace {

std::string hexBytes(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
  return s;
}
std::string hexStr(const std::string& s) {
  return hexBytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
hyle::wire::View sv(const std::string& s) {
  return hyle::wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
// The same 32-byte secret is a CES key and a hyle key: one identity, two ledgers.
hyle::KeyPair hyleKeyOf(const ces::KeyPair& k) {
  const minx::Hash priv = k.getPrivateKey();
  hyle::PrivKey s{};
  std::memcpy(s.data(), priv.data(), 32);
  return hyle::KeyPair::from_secret(s);
}
std::string encEntry(const hyle::services::EntryOp& op) {
  hyle::services::Decoded d;
  d.entries.push_back(op);
  const hyle::wire::Bytes b = hyle::services::encode_ops(d);
  return hexBytes(b.data(), b.size());
}
std::string encTransfer(const hyle::services::TransferOp& op) {
  hyle::services::Decoded d;
  d.transfers.push_back(op);
  const hyle::wire::Bytes b = hyle::services::encode_ops(d);
  return hexBytes(b.data(), b.size());
}
hyle::wire::Bytes acctDest(const hyle::PubKey& pk) {
  hyle::wire::Bytes b;
  b.push_back(hyle::services::ACCOUNT_PREFIX);
  b.insert(b.end(), pk.begin(), pk.end());
  return b;
}

// Raw bytes as a Lua string literal, \ddd escapes zero-padded so a digit run is
// never ambiguous.
std::string luaBytes(const uint8_t* p, size_t n) {
  std::string s;
  char buf[8];
  for (size_t i = 0; i < n; i++) {
    std::snprintf(buf, sizeof(buf), "\\%03u", static_cast<unsigned>(p[i]));
    s += buf;
  }
  return s;
}

std::string hexOf(const minx::Hash& h) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (uint8_t b : h) { s += d[b >> 4]; s += d[b & 15]; }
  return s;
}

// The hylenet program, identical on every node: start the net chain with the given
// validator set, pump it on a fine tick, and serve a one-line query protocol.
std::string hylenetSource(const std::vector<minx::Hash>& validators) {
  std::string v;
  for (const auto& pk : validators)
    v += "  \"" + luaBytes(pk.data(), pk.size()) + "\",\n";
  return
    "local V = {\n" + v + "}\n"
    "local ok, err = ces.hyle.net.start{\n"
    "  chain_id = 'm0', validators = V, block_pace_ms = 500, consensus_timeout_ms = 200,\n"
    "  fee_transfer = 1, fee_entry = 1, fee_sudo = 1, rent_rate = 0, rip_bounty = 0,\n"
    "  member_cap = 8, member_floor = 1,\n"
    "}\n"
    "if not ok then ces.log(4, 'net.start: ' .. tostring(err)) end\n"
    "ces.every(5, function() ces.hyle.net.tick() end)\n"
    "local function hex(s)\n"
    "  return (s:gsub('.', function(c) return string.format('%02x', c:byte()) end))\n"
    "end\n"
    "ces.conn.set_listener{\n"
    "  on_data = function(c, data)\n"
    "    local line = (data:gsub('%s+$', ''))\n"
    "    if line == 'height' then\n"
    "      c:write('ok ' .. tostring(ces.hyle.height() or 0) .. '\\n')\n"
    "    elseif line == 'info' then\n"
    "      local i = ces.hyle.info()\n"
    "      if not i then c:write('err no_chain\\n')\n"
    "      else c:write('ok height=' .. i.height .. ' app_hash=' .. hex(i.app_hash) .. '\\n') end\n"
    "    else c:write('err bad_verb\\n') end\n"
    "  end,\n"
    "}\n"
    "ces.run()\n";
}

// Deploy `src` to /s/hylenet.lua on node n and launch it; returns the instance pid.
uint64_t deployAndLaunch(ExtNode& n, const std::string& src) {
  const ces::KeyPair& srv = n.server->_serverKeyPair();
  const std::string path = "/s/hylenet.lua";
  {
    CesFileClient fc;
    fc.setServerPubkey(srv.getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", n.rpcPort, srv));
    uint64_t bal = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, src.size(), 0, 100'000'000ULL, bal, cost));
    const ces::Bytes content(src.begin(), src.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, bal));
    fc.disconnect();
  }
  uint64_t pid = 0;
  {
    CesComputeClient cc;
    cc.setServerPubkey(srv.getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", n.rpcPort, srv));
    uint64_t startedAt = 0;
    CES_REQUIRE_OK(cc.launch(path, pid, startedAt));
    cc.disconnect();
  }
  BOOST_REQUIRE(pid > 0);
  return pid;
}

// A dialed line-protocol session to one node's hylenet instance.
struct Line {
  std::unique_ptr<PlexLuaPeer> peer;
  std::unique_ptr<PlexLineReader> lines;
  void open(ExtNode& n, uint64_t pid) {
    const ces::KeyPair& srv = n.server->_serverKeyPair();
    peer = std::make_unique<PlexLuaPeer>();
    BOOST_REQUIRE(peer->start() != 0);
    uint64_t token = 0;
    BOOST_REQUIRE(peer->bind(n.rpcPort, srv, token));
    auto r = peer->attach(srv, token, pid);
    CES_REQUIRE_RC_EQ(r.status, CES_OK);
    lines = std::make_unique<PlexLineReader>(*peer);
  }
  std::string cmd(const std::string& line) {
    const std::string out = line + "\n";
    BOOST_REQUIRE(peerWrite(*peer, ces::Bytes(out.begin(), out.end())));
    return lines->nextLine(std::chrono::seconds(10));
  }
};

std::string field(const std::string& line, const std::string& key) {
  const std::string k = " " + key + "=";
  const auto p = line.find(k);
  if (p == std::string::npos) return "";
  const auto start = p + k.size();
  const auto end = line.find(' ', start);
  return line.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

// Submit signed op bytes to a node and wait for the chain's verdict:
//   1 = applied, 0 = committed in a block but rejected, -1 = admission refused / never committed.
int submitOutcome(Line& l, const std::string& hexops) {
  const std::string r = l.cmd("submit " + hexops);
  if (r.rfind("ok ", 0) != 0) return -1;
  const std::string txid = r.substr(3);
  // Real 4-node BFT chain sharing one box with ~890 other cases: a commit can see a multi-second
  // tail under load, so allow headroom. The systematic stall causes (tick-gated progress, timeout
  // delivery, tx self-heal) are fixed; normal commits return in well under a second.
  for (int t = 0; t < 300; t++) {
    const std::string tr = l.cmd("txr " + txid);
    if (tr.rfind("ok ", 0) == 0) return field(tr, "applied") == "1" ? 1 : 0;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return -1;
}
bool submitApplied(Line& l, const std::string& hexops) { return submitOutcome(l, hexops) == 1; }

// startExtNode derives each node's server key from a private half filled with 0x41+idx, so the
// pubkeys are computable before the servers exist -- lets us bake the validator set into a conf.
minx::Hash serverPubOf(int idx) {
  minx::Hash priv;
  priv.fill(static_cast<uint8_t>(0x41 + idx));
  return ces::KeyPair(priv, ces::KeyAlgo::ED25519).getPublicKeyAsHash();
}

uint64_t waitForInstance(ExtNode& n, const std::string& srcPath) {
  for (int t = 0; t < 200; t++) {
    CesComputeClient cc;
    cc.setServerPubkey(n.server->_serverKeyPair().getPublicKeyAsHash());
    std::vector<CesComputeClient::InstanceInfo> insts;
    const bool ok = cc.connect("localhost", n.rpcPort, n.server->_serverKeyPair()) == CES_OK &&
                    cc.instances(srcPath, insts) == CES_OK && !insts.empty();
    const uint64_t pid = ok ? insts[0].pid : 0;
    cc.disconnect();
    if (pid) return pid;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return 0;
}

// Make all nodes mutual CES peers over /ces/peer/1 (the hyle transport) and wait for a full mesh.
void meshPeers(std::vector<std::unique_ptr<ExtNode>>& nodes) {
  const int N = static_cast<int>(nodes.size());
  const auto v6lo = boost::asio::ip::address(boost::asio::ip::address_v6::loopback());
  for (int i = 0; i < N; i++)
    for (int j = 0; j < N; j++)
      if (i != j)
        nodes[i]->server->_testAddPeerWithRpc(
            nodes[j]->pub, "[::1]:" + std::to_string(nodes[j]->rpcPort), v6lo, nodes[j]->rpcPort);
  for (auto& n : nodes) n->server->peerHandler()->reconcileNow();
  bool meshed = false;
  for (int t = 0; t < 200 && !meshed; t++) {
    meshed = true;
    for (int i = 0; i < N && meshed; i++)
      for (int j = 0; j < N && meshed; j++)
        if (i != j && !nodes[i]->server->peerHandler()->isLinked(nodes[j]->pub)) meshed = false;
    if (!meshed) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(meshed, "the nodes did not form a full peer mesh");
}

// Poll the dialed nodes until all commit to `target` (proves consensus carried votes over the
// mesh), then require a common height where every node reports the same AppHash (BFT safety).
void pollCommitAndAgree(std::vector<Line>& ls, uint64_t target) {
  const int N = static_cast<int>(ls.size());
  bool reached = false;
  for (int t = 0; t < 400 && !reached; t++) {
    reached = true;
    for (int i = 0; i < N; i++) {
      const std::string h = ls[i].cmd("height");
      if (!(h.rfind("ok ", 0) == 0 && std::stoull(h.substr(3)) >= target)) { reached = false; break; }
    }
    if (!reached) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(reached, "the chain did not commit to height " + std::to_string(target) +
                                     " on all nodes");
  bool agreed = false;
  std::string lastRow;
  for (int t = 0; t < 200 && !agreed; t++) {
    std::string h0, a0;
    bool same = true;
    lastRow.clear();
    for (int i = 0; i < N; i++) {
      const std::string info = ls[i].cmd("info");
      const std::string h = field(info, "height");
      const std::string a = field(info, "app_hash");
      lastRow += " n" + std::to_string(i) + "(h=" + h + ",a=" + a.substr(0, 12) + ")";
      if (i == 0) { h0 = h; a0 = a; }
      else if (h != h0 || a != a0) same = false;
    }
    if (same && !h0.empty() && h0 != "0" && !a0.empty()) { agreed = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  if (!agreed) BOOST_TEST_MESSAGE("last sample:" << lastRow);
  BOOST_TEST(agreed, "nodes never agreed on an AppHash at a common height");
}

// A running N-validator hylenet chain for the ported feature suite. Users are funded the ONLY
// real way -- by burning CES to buy hyle from a validator -- never by a validator handout.
struct NetChain {
  int N;
  int numVal;  // the first numVal nodes are genesis validators; any beyond are followers
  std::string chain = "netfix";
  std::vector<std::unique_ptr<ExtNode>> nodes;
  std::vector<Line> ls;
  std::vector<uint64_t> pids;

  NetChain(int n, int nv = -1, uint64_t rentRate = 0, uint64_t feeEntry = 10, uint64_t maxStateBytes = 0)
      : N(n), numVal((nv < 0 || nv > n) ? n : nv) {
    const std::string bin = ces::e2e::findBinary("cesluajitd");
    std::string vhex;
    for (int i = 0; i < numVal; i++) { if (i) vhex += " "; vhex += hexOf(serverPubOf(i)); }
    const std::string conf =
      "chain_id = " + chain + "\nvalidators = " + vhex + "\nblock_pace_ms = 300\n"
      "consensus_timeout_ms = 200\n"  // in-process RTT is microseconds; fast round timeout
      "fee_transfer = 10\nfee_entry = " + std::to_string(feeEntry) + "\nfee_sudo = 1\n"
      "rent_rate = " + std::to_string(rentRate) + "\nrip_bounty = 10\n"
      "credit_autofill_ceiling = 100000000\nrefill_rate = 10000000\n"
      "max_state_bytes = " + std::to_string(maxStateBytes) + "\n"
      "member_cap = 16\nmember_floor = 1\nautostart = 1\n";
    for (int i = 0; i < N; i++) {
      auto nn = std::make_unique<ExtNode>();
      startExtNode(*nn, i, bin, "hylenet", conf);
      nodes.push_back(std::move(nn));
    }
    meshPeers(nodes);
    ls.resize(N);
    pids.assign(N, 0);
    for (int i = 0; i < N; i++) {
      pids[i] = waitForInstance(*nodes[i], "/s/hylenet.lua");
      BOOST_REQUIRE_MESSAGE(pids[i] != 0, "hylenet never launched on node " + std::to_string(i));
      ls[i].open(*nodes[i], pids[i]);
    }
    for (int i = 0; i < numVal; i++) {  // wait only for the genesis validators; followers sync later
      bool up = false;
      for (int t = 0; t < 400 && !up; t++) {
        const std::string h = ls[i].cmd("height");
        up = h.rfind("ok ", 0) == 0 && std::stoull(h.substr(3)) >= 1;
        if (!up) std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      BOOST_REQUIRE_MESSAGE(up, "chain not up on node " + std::to_string(i));
    }
  }

  // Wait until node 0 reports the active validator count == want.
  bool waitValidatorCount(int want) {
    for (int t = 0; t < 400; t++) {
      if (field(cmd(0, "info"), "validators") == std::to_string(want)) return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
  }
  ~NetChain() {
    for (auto& l : ls) if (l.peer) l.peer->stop();
    for (auto& n : nodes) if (n) stopExt(*n);
  }

  // Take a validator offline (server + dial), leaving it null so the dtor skips it.
  void stopNode(int i) {
    if (ls[i].peer) { ls[i].peer->stop(); ls[i].peer.reset(); }
    if (nodes[i]) { stopExt(*nodes[i]); nodes[i].reset(); }
  }

  hyle::wire::View cv() const { return sv(chain); }
  std::string cmd(int node, const std::string& line) { return ls[node].cmd(line); }
  uint64_t balOf(int node, const hyle::PubKey& pk) {
    const std::string b = field(cmd(node, "account " + hexOf(pk)), "balance");
    return b.empty() ? 0 : std::stoull(b);
  }

  // The only on-ramp: a fresh user burns CES via a paid CALL to node 0, the validator sells it
  // `amount` hyle, and the credit lands in the user's own account. `settleAll` waits for every node
  // to apply the sale; pass false when a node is deliberately behind (an unsynced follower) so the
  // wait does not burn its whole budget polling a node that cannot credit until it syncs.
  hyle::KeyPair buyHyle(uint64_t amount, bool settleAll = true) {
    ces::KeyPair userCes = ces::KeyPair::generate();  // ed25519 -> its hyle account too
    hyle::KeyPair user = hyleKeyOf(userCes);
    nodes[0]->server->_brr(userCes.getPublicKeyAsHash(), amount + 1'000'000);
    const std::string sellerHex = hexOf(serverPubOf(0));
    for (int t = 0; t < 400; t++) {
      const std::string b = field(cmd(0, "account " + sellerHex), "balance");
      if (!b.empty() && std::stoull(b) >= amount) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    {
      CesComputeClient cc;
      cc.setServerPubkey(nodes[0]->server->_serverKeyPair().getPublicKeyAsHash());
      CES_REQUIRE_OK(cc.connect("localhost", nodes[0]->rpcPort, userCes));
      ces::Bytes reply;
      CES_REQUIRE_RC_EQ(cc.call(pids[0], amount, ces::Bytes{'b', 'u', 'y'}, reply), CES_OK);
      cc.disconnect();
    }
    // Best-effort: give every node a chance to apply the purchase, since a later op may be submitted
    // to any node and mempool admission rejects a transfer whose sender is not yet in that node's
    // committed state. Only node 0 (where the sale committed) is REQUIRED -- a single validator can
    // lag under load and, absent state sync, may not catch up, but the chain proceeds on quorum.
    const int settleNodes = settleAll ? N : 1;
    for (int t = 0; t < 300; t++) {
      bool all = true;
      for (int n = 0; n < settleNodes; n++) if (balOf(n, user.pub) < amount) { all = false; break; }
      if (all) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    BOOST_REQUIRE_MESSAGE(balOf(0, user.pub) >= amount, "the CES->hyle purchase never credited the buyer");
    return user;
  }

  // Poll `entry <name>` on `node` until its owner matches `owner`; returns the record line ("" on
  // timeout). Proves replication when read from a node other than where the op was submitted.
  std::string waitEntryOwned(int node, const std::string& name, const hyle::PubKey& owner) {
    for (int t = 0; t < 200; t++) {
      const std::string e = cmd(node, "entry " + name);
      if (e.rfind("ok ", 0) == 0 && field(e, "owner") == hexOf(owner)) return e;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return "";
  }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(HyleNetTests)

// Inline program: N mutual-peer servers, each running a minimal hylenet program with an identical
// N-validator genesis, commit blocks over the peer mesh and agree on AppHash. The mechanism proof.
BOOST_AUTO_TEST_CASE(FourValidatorsCommitAndAgree) {
  const std::string bin = ces::e2e::findBinary("cesluajitd");
  const int N = 4;
  std::vector<std::unique_ptr<ExtNode>> nodes;
  for (int i = 0; i < N; i++) {
    auto n = std::make_unique<ExtNode>();
    startExtNode(*n, i, bin, "", "");  // plain node; we deploy the hylenet program ourselves
    nodes.push_back(std::move(n));
  }
  std::vector<minx::Hash> vals;
  for (auto& n : nodes) vals.push_back(n->pub);  // the validator set = the N server pubkeys
  const std::string src = hylenetSource(vals);

  meshPeers(nodes);
  std::vector<Line> ls(N);
  for (int i = 0; i < N; i++) {
    const uint64_t pid = deployAndLaunch(*nodes[i], src);
    ls[i].open(*nodes[i], pid);
  }
  pollCommitAndAgree(ls, 3);

  for (auto& l : ls) if (l.peer) l.peer->stop();
  for (auto& n : nodes) stopExt(*n);
}

// The SHIPPED extensions/hylenet.lua, auto-launched from a conf whose validators list is the N
// server pubkeys. Proves the deployable artifact -- config parsing, net.start, the pump tick and
// line protocol -- reaches consensus over the peer mesh exactly like the inline program.
BOOST_AUTO_TEST_CASE(FourValidatorsViaShippedExtension) {
  const std::string bin = ces::e2e::findBinary("cesluajitd");
  const int N = 4;
  std::string vhex;
  for (int i = 0; i < N; i++) { if (i) vhex += " "; vhex += hexOf(serverPubOf(i)); }
  const std::string conf =
    "chain_id = shipped\nvalidators = " + vhex + "\nblock_pace_ms = 500\n"
    "consensus_timeout_ms = 200\n"
    "fee_transfer = 1\nfee_entry = 1\nfee_sudo = 1\nrent_rate = 0\nrip_bounty = 0\n"
    "member_cap = 8\nmember_floor = 1\nautostart = 1\n";

  std::vector<std::unique_ptr<ExtNode>> nodes;
  for (int i = 0; i < N; i++) {
    auto n = std::make_unique<ExtNode>();
    startExtNode(*n, i, bin, "hylenet", conf);  // deploys extensions/hylenet.lua + autostarts it
    BOOST_REQUIRE_MESSAGE(n->pub == serverPubOf(i), "server pubkey was not deterministic as assumed");
    nodes.push_back(std::move(n));
  }
  meshPeers(nodes);
  std::vector<Line> ls(N);
  for (int i = 0; i < N; i++) {
    const uint64_t pid = waitForInstance(*nodes[i], "/s/hylenet.lua");
    BOOST_REQUIRE_MESSAGE(pid != 0, "hylenet extension never launched on node " + std::to_string(i));
    ls[i].open(*nodes[i], pid);
  }
  pollCommitAndAgree(ls, 3);

  for (auto& l : ls) if (l.peer) l.peer->stop();
  for (auto& n : nodes) stopExt(*n);
}

// The name-system use case: an EXTERNAL client (not a validator) registers a K,V on ONE node,
// signing its own op offline, and the mapping is READABLE from a DIFFERENT node. Proves the whole
// path the consensus-agreement tests skip: the tx gossips to the proposer, commits, and REPLICATES.
BOOST_AUTO_TEST_CASE(NameWrittenOnOneNodeReadsBackFromAnother) {
  const std::string bin = ces::e2e::findBinary("cesluajitd");
  const int N = 4;
  std::string vhex;
  for (int i = 0; i < N; i++) { if (i) vhex += " "; vhex += hexOf(serverPubOf(i)); }
  const std::string chain = "kvchain";
  // User-funding model: autofill funds the validators through consensus (no alloc, no faucet); the
  // user BUYS hyle from a validator with CES via a paid compute CALL, the credit lands in its 'a',
  // and only then can it register an 'e' (hyle apply_entry requires the account to exist) and pay
  // fee_entry. This is the only user on-ramp.
  const std::string conf =
    "chain_id = " + chain + "\nvalidators = " + vhex + "\nblock_pace_ms = 500\n"
    "consensus_timeout_ms = 200\n"
    "fee_transfer = 1\nfee_entry = 10\nfee_sudo = 1\nrent_rate = 0\nrip_bounty = 0\n"
    "credit_autofill_ceiling = 1000000\nrefill_rate = 100000\n"
    "member_cap = 8\nmember_floor = 1\nautostart = 1\n";

  std::vector<std::unique_ptr<ExtNode>> nodes;
  for (int i = 0; i < N; i++) {
    auto n = std::make_unique<ExtNode>();
    startExtNode(*n, i, bin, "hylenet", conf);
    nodes.push_back(std::move(n));
  }
  meshPeers(nodes);
  std::vector<Line> ls(N);
  std::vector<uint64_t> pids(N, 0);
  for (int i = 0; i < N; i++) {
    pids[i] = waitForInstance(*nodes[i], "/s/hylenet.lua");
    BOOST_REQUIRE_MESSAGE(pids[i] != 0, "hylenet never launched on node " + std::to_string(i));
    ls[i].open(*nodes[i], pids[i]);
  }

  // Wait until validator 0 (the seller) is autofilled, so it has hyle to sell. We only read its
  // balance -- the test never holds any validator key; funding comes from the buyer burning CES.
  const std::string sellerHex = hexOf(serverPubOf(0));
  bool sellerFunded = false;
  for (int t = 0; t < 400 && !sellerFunded; t++) {
    const std::string bal = field(ls[0].cmd("account " + sellerHex), "balance");
    sellerFunded = !bal.empty() && std::stoull(bal) >= 1000;
    if (!sellerFunded) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(sellerFunded, "validator 0 never got autofilled credit to sell");

  // The user BUYS hyle with CES: fund its CES account, then a paid compute CALL to node 0's hylenet
  // instance sells it hyle 1:1 into its 'a' (one key, two ledgers). The only user on-ramp.
  ces::KeyPair userCes = ces::KeyPair::generate();  // ed25519 -> also its hyle account
  hyle::KeyPair user = hyleKeyOf(userCes);
  nodes[0]->server->_brr(userCes.getPublicKeyAsHash(), 1'000'000);  // CES credits to spend
  {
    CesComputeClient cc;
    cc.setServerPubkey(nodes[0]->server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", nodes[0]->rpcPort, userCes));
    ces::Bytes reply;
    CES_REQUIRE_RC_EQ(cc.call(pids[0], /*value=*/1000, ces::Bytes{'b', 'u', 'y'}, reply), CES_OK);
    BOOST_TEST(std::string(reply.begin(), reply.end()).rfind("ok", 0) == 0u);
    cc.disconnect();
  }
  bool bought = false;
  for (int t = 0; t < 200 && !bought; t++) {
    const std::string bal = field(ls[0].cmd("account " + hexOf(user.pub)), "balance");
    bought = !bal.empty() && std::stoull(bal) >= 1000;
    if (!bought) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(bought, "the CES->hyle purchase never credited the buyer's account");

  // The funded user registers bob -> "value-of-bob", paying fee_entry from its bought credit.
  BOOST_REQUIRE_MESSAGE(
      submitApplied(ls[0], encEntry(hyle::services::make_entry_put(
          user, sv("bob"), /*seq=*/0, /*fund=*/0, sv("value-of-bob"), sv(chain)))),
      "the user's entry-put never applied on node 0");

  // The mapping must be readable from a DIFFERENT node with the same owner and value: replication.
  bool replicated = false;
  std::string last;
  for (int t = 0; t < 200 && !replicated; t++) {
    last = ls[3].cmd("entry bob");
    if (last.rfind("ok ", 0) == 0 && field(last, "owner") == hexOf(user.pub)) {
      BOOST_TEST(field(last, "payload") == hexStr("value-of-bob"));
      replicated = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(replicated, "the name did not replicate to node 3: " + last);

  for (auto& l : ls) if (l.peer) l.peer->stop();
  for (auto& n : nodes) stopExt(*n);
}

// ---- The HyleSolo feature suite, ported to the real multi-node chain. Every actor is funded by
// buying hyle with CES; ops are submitted on one node and their effects read from another. ----

BOOST_AUTO_TEST_CASE(NetPublishUpdateAndProtectOwnership) {
  NetChain nc(4);
  hyle::KeyPair u = nc.buyHyle(100000);

  BOOST_REQUIRE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_put(u, sv("site"), 0, 0, sv("v1"), nc.cv()))));
  const std::string e1 = nc.waitEntryOwned(3, "site", u.pub);  // replicated to another node
  BOOST_REQUIRE_MESSAGE(!e1.empty(), "publish did not replicate");
  BOOST_TEST(field(e1, "payload") == hexStr("v1"));

  BOOST_REQUIRE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_put(u, sv("site"), 1, 0, sv("v2"), nc.cv()))));

  // A stranger -- also a paying user -- cannot overwrite someone else's key.
  hyle::KeyPair s = nc.buyHyle(100000);
  BOOST_TEST(submitOutcome(nc.ls[1],
      encEntry(hyle::services::make_entry_put(s, sv("site"), 0, 0, sv("hax"), nc.cv()))) == 0);

  std::string e2;
  for (int t = 0; t < 200; t++) { e2 = nc.cmd(2, "entry site"); if (field(e2, "payload") == hexStr("v2")) break; std::this_thread::sleep_for(std::chrono::milliseconds(50)); }
  BOOST_TEST(field(e2, "payload") == hexStr("v2"));
  BOOST_TEST(field(e2, "owner") == hexOf(u.pub));
}

BOOST_AUTO_TEST_CASE(NetOwnershipGivenAwayThenDeleted) {
  NetChain nc(4);
  hyle::KeyPair owner = nc.buyHyle(100000);
  hyle::KeyPair heir = nc.buyHyle(100000);

  BOOST_REQUIRE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_put(owner, sv("dom"), 0, 500, sv("x"), nc.cv()))));
  BOOST_REQUIRE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_give(owner, sv("dom"), 1, heir.pub, nc.cv()))));
  BOOST_REQUIRE_MESSAGE(!nc.waitEntryOwned(2, "dom", heir.pub).empty(), "give did not replicate");

  // The old owner can no longer delete; the new owner can, and gets the residual balance back.
  BOOST_TEST(submitOutcome(nc.ls[1],
      encEntry(hyle::services::make_entry_del(owner, sv("dom"), 2, nc.cv()))) == 0);
  const uint64_t before = nc.balOf(0, heir.pub);
  BOOST_REQUIRE(submitApplied(nc.ls[1],
      encEntry(hyle::services::make_entry_del(heir, sv("dom"), 0, nc.cv()))));
  bool gone = false;
  for (int t = 0; t < 300 && !gone; t++) {
    if (nc.cmd(3, "entry dom").rfind("err", 0) == 0) gone = true;
    else std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(gone, "the delete did not replicate to node 3");
  // Refund lands in the del block; poll node 0 (where `before` was read) until it applies that
  // block -- the del was confirmed on node 1 and observed gone on node 3, so node 0 may lag.
  const uint64_t want = before + 500u - 10u;  // refund of the entry balance, less fee_entry
  uint64_t after = 0;
  for (int t = 0; t < 300; t++) { after = nc.balOf(0, heir.pub); if (after == want) break; std::this_thread::sleep_for(std::chrono::milliseconds(50)); }
  BOOST_TEST(after == want);
}

BOOST_AUTO_TEST_CASE(NetAnyoneFundsSomeoneElsesKey) {
  NetChain nc(4);
  hyle::KeyPair owner = nc.buyHyle(100000);
  hyle::KeyPair patron = nc.buyHyle(100000);

  BOOST_REQUIRE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_put(owner, sv("k"), 0, 10, sv("v"), nc.cv()))));
  // A third party funds the entry via a transfer to 'e'+name; it stays owned by the creator.
  hyle::wire::Bytes ed;
  ed.push_back(hyle::services::ENTRY_PREFIX);
  { const char* nm = "k"; ed.insert(ed.end(), nm, nm + 1); }
  BOOST_REQUIRE(submitApplied(nc.ls[1],
      encTransfer(hyle::services::make_transfer(patron, hyle::wire::View(ed.data(), ed.size()), 700, 0, nc.cv()))));
  std::string e;
  for (int t = 0; t < 200; t++) { e = nc.cmd(2, "entry k"); if (field(e, "balance") == "710") break; std::this_thread::sleep_for(std::chrono::milliseconds(50)); }
  BOOST_TEST(field(e, "balance") == "710");
  BOOST_TEST(field(e, "owner") == hexOf(owner.pub));
}

BOOST_AUTO_TEST_CASE(NetTransferBetweenAccounts) {
  NetChain nc(4);
  hyle::KeyPair a = nc.buyHyle(100000);
  ces::KeyPair bCes = ces::KeyPair::generate();
  hyle::KeyPair b = hyleKeyOf(bCes);

  const uint64_t a0 = nc.balOf(0, a.pub);
  const hyle::wire::Bytes bd = acctDest(b.pub);
  BOOST_REQUIRE(submitApplied(nc.ls[0],
      encTransfer(hyle::services::make_transfer(a, hyle::wire::View(bd.data(), bd.size()), 500, 0, nc.cv()))));
  for (int t = 0; t < 200; t++) { if (nc.balOf(3, b.pub) == 500) break; std::this_thread::sleep_for(std::chrono::milliseconds(50)); }
  BOOST_TEST(nc.balOf(3, b.pub) == 500u);
  BOOST_TEST(nc.balOf(0, a.pub) == a0 - 500u - 10u);  // amount + fee_transfer
}

BOOST_AUTO_TEST_CASE(NetUnfundedSignerRejected) {
  NetChain nc(4);
  // A key that never bought anything has no account, so it cannot register.
  ces::KeyPair poorCes = ces::KeyPair::generate();
  hyle::KeyPair poor = hyleKeyOf(poorCes);
  BOOST_TEST(submitOutcome(nc.ls[0],
      encEntry(hyle::services::make_entry_put(poor, sv("nope"), 0, 0, sv("v"), nc.cv()))) != 1);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  BOOST_TEST(nc.cmd(0, "entry nope").rfind("err", 0) == 0u);
}

BOOST_AUTO_TEST_CASE(NetRentStarvesAKeyAndAnyoneReapsIt) {
  NetChain nc(4, 4, /*rentRate=*/1000);  // high rent drains an entry in a couple seconds
  hyle::KeyPair u = nc.buyHyle(200000);
  BOOST_REQUIRE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_put(u, sv("doomed"), 0, /*fund=*/20000, sv("x"), nc.cv()))));

  // A rip needs no signature, sequence, or funds -- the culler is a stranger who never paid.
  ces::KeyPair cullerCes = ces::KeyPair::generate();
  hyle::KeyPair culler = hyleKeyOf(cullerCes);
  bool reaped = false;
  for (int i = 0; i < 80 && !reaped; i++) {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    nc.cmd(0, "submit " + encEntry(hyle::services::make_entry_rip(sv("doomed"), culler.pub)));
    for (int j = 0; j < 10 && !reaped; j++) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      reaped = nc.cmd(3, "entry doomed") == "err not_found";
    }
  }
  BOOST_REQUIRE_MESSAGE(reaped, "the starved entry was never reaped");
  // The rip and its bounty land in the same block. Read the bounty on the SAME node that saw the
  // reap (node 3) so both reflect one committed view, and poll: a cross-node read can lag a block
  // under load (node 0 may not have applied the rip block node 3 already committed).
  uint64_t bounty = 0;
  for (int j = 0; j < 200 && bounty == 0; j++) {
    bounty = nc.balOf(3, culler.pub);
    if (bounty == 0) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_TEST(bounty == 10u);  // rip_bounty, to a key that never signed or paid
}

BOOST_AUTO_TEST_CASE(NetGarbageIsRejectedNotCrashed) {
  NetChain nc(4);
  BOOST_TEST(nc.cmd(0, "submit zzzz").rfind("ok ", 0) != 0u);          // bad hex
  BOOST_TEST(nc.cmd(0, "submit 00ff00ff").rfind("ok ", 0) != 0u);      // valid hex, not ops
  // The chain is unharmed and still commits.
  const uint64_t h = std::stoull(nc.cmd(0, "height").substr(3));
  bool advanced = false;
  for (int t = 0; t < 200 && !advanced; t++) {
    advanced = std::stoull(nc.cmd(0, "height").substr(3)) > h;
    if (!advanced) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_TEST(advanced);
}

// ---- Multi-node-specific: the coverage a single-validator dev net cannot have. ----

// With 4 validators (quorum 3), the chain keeps committing after one goes down: 2f+1 tolerance.
BOOST_AUTO_TEST_CASE(NetToleratesAValidatorDown) {
  NetChain nc(4);
  hyle::KeyPair u = nc.buyHyle(100000);
  BOOST_REQUIRE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_put(u, sv("before"), 0, 0, sv("x"), nc.cv()))));

  nc.stopNode(3);  // one validator offline; 3 of 4 remain = quorum

  // A new op still commits on the survivors, and replicates among them.
  BOOST_REQUIRE_MESSAGE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_put(u, sv("after"), 1, 0, sv("y"), nc.cv()))),
      "the chain stalled after a single validator went down");
  BOOST_REQUIRE_MESSAGE(!nc.waitEntryOwned(1, "after", u.pub).empty(),
      "the post-failure entry did not replicate to a survivor");
}

// Membership shrink: a quorum of validators votes one out; the active set drops and the chain
// keeps committing with the smaller set.
BOOST_AUTO_TEST_CASE(NetMembershipRemove) {
  NetChain nc(4);
  const std::string victim = hexOf(serverPubOf(3));
  for (int i = 0; i < 3; i++)  // 3 of 4 = quorum
    BOOST_TEST(nc.cmd(i, "vote_remove " + victim).rfind("ok", 0) == 0u);
  BOOST_REQUIRE_MESSAGE(nc.waitValidatorCount(3), "the validator set did not shrink to 3");

  // The now-3-validator chain still commits (buy from node 0, register, read on a survivor). Settle
  // only against node 0: the voted-out node stops applying commits, so waiting on it burns the budget.
  hyle::KeyPair u = nc.buyHyle(100000, /*settleAll=*/false);
  BOOST_REQUIRE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_put(u, sv("post"), 0, 0, sv("x"), nc.cv()))));
  BOOST_REQUIRE_MESSAGE(!nc.waitEntryOwned(1, "post", u.pub).empty(),
      "the 3-validator chain did not commit + replicate");
}

// THE test that defines a chain: a fifth validator that started at genesis as a follower (zero
// state) is voted in, must SYNC the history it never had, catch up to head, and then actively
// validate -- proven by making its vote necessary for quorum. Before blocksync this STALLED (a
// joined validator could not obtain the blocks it missed); it now catches up over the live
// transport (ValueReq/ValueResp, driven by request_sync) and participates.
BOOST_AUTO_TEST_CASE(NetMembershipAdd) {
  NetChain nc(5, 4);  // 5 nodes, genesis validators = first 4; node 4 follows from height 0
  const std::string newbie = hexOf(serverPubOf(4));
  for (int i = 0; i < 3; i++)  // 3 of the 4 current validators = quorum
    BOOST_TEST(nc.cmd(i, "vote_add " + newbie).rfind("ok", 0) == 0u);
  BOOST_REQUIRE_MESSAGE(nc.waitValidatorCount(5), "the vote did not grow the validator set to 5");

  // node 4 started at height 0 while the chain ran ahead. It must SYNC to head. Poll until its
  // applied height reaches an original validator's.
  bool caught = false;
  for (int t = 0; t < 400 && !caught; t++) {
    const uint64_t h4 = std::stoull(nc.cmd(4, "height").substr(3));
    const uint64_t h0 = std::stoull(nc.cmd(0, "height").substr(3));
    caught = (h0 > 0 && h4 >= h0);
    if (!caught) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(caught, "the newly-added validator never synced to head");

  // Prove it genuinely PARTICIPATES, not that the original quorum carries a passive member. Fund
  // while all five are up (fast), then take an ORIGINAL offline, leaving {0,2,3,4}=4=quorum for
  // n=5: a commit is now IMPOSSIBLE without node 4's vote.
  hyle::KeyPair u = nc.buyHyle(100000);
  nc.stopNode(1);
  BOOST_REQUIRE_MESSAGE(submitApplied(nc.ls[0],
      encEntry(hyle::services::make_entry_put(u, sv("grown"), 0, 0, sv("x"), nc.cv()))),
      "the chain stalled with the newly-added validator required for quorum (sync/participation failed)");
  BOOST_REQUIRE_MESSAGE(!nc.waitEntryOwned(4, "grown", u.pub).empty(),
      "the newly-added validator does not have the committed state");
}

// A joiner's catch-up must move state larger than one transport message, so the bulk chunker splits
// it into pieces, each its own message. The mesh then routes each piece independently by its size --
// not load-spreading, just a per-message lane pick: a full ~64 KiB piece clears the bulk threshold
// and rides the bulk lane, the smaller tail piece falls under it and rides control. So one logical
// artifact arrives across two independently-ordered lanes, out of order, and the offset-addressed
// chunker must still reassemble it byte-for-byte on the follower.
BOOST_AUTO_TEST_CASE(NetJoinerReassemblesMultiPieceState) {
  NetChain nc(5, 4);  // 4 genesis validators + follower node 4 (syncs from height 0)

  // Grow committed state well past a single 64 KiB piece: several 40 KiB entries. Each block stays a
  // normal-sized proposal, but their retained batch (snapshots default off) is chunked into several
  // pieces; the mesh size-routes each one on its own, so full pieces go to bulk and the smaller tail
  // to control. Fund from node 0 only -- the follower is deliberately behind and cannot yet credit.
  hyle::KeyPair u = nc.buyHyle(100000, /*settleAll=*/false);
  const std::string blob(40 * 1024, '\xA7');
  const int kEntries = 4;  // ~160 KiB of entry payload => a multi-piece, split catch-up artifact
  for (int i = 0; i < kEntries; i++) {
    const std::string name = "bulk" + std::to_string(i);
    BOOST_REQUIRE_MESSAGE(submitApplied(nc.ls[0],
        encEntry(hyle::services::make_entry_put(u, sv(name), i, 0, sv(blob), nc.cv()))),
        "large entry " + name + " never applied");
  }

  // vote the follower in; it must SYNC the multi-piece state before it can be a working validator.
  const std::string newbie = hexOf(serverPubOf(4));
  for (int i = 0; i < 3; i++)
    BOOST_TEST(nc.cmd(i, "vote_add " + newbie).rfind("ok", 0) == 0u);
  BOOST_REQUIRE_MESSAGE(nc.waitValidatorCount(5), "the vote did not grow the validator set to 5");

  // The follower must catch up over the multi-piece artifact. Capture a height that already holds the
  // big entries, then wait for the follower to reach it -- a threshold, not a live-height equality
  // (the chain keeps advancing, so two separate info reads race and rarely read equal under load).
  const uint64_t head = std::stoull(nc.cmd(0, "height").substr(3));
  bool caught = false;
  for (int t = 0; t < 600 && !caught; t++) {
    const std::string h = nc.cmd(4, "height");
    caught = h.rfind("ok ", 0) == 0 && std::stoull(h.substr(3)) >= head;
    if (!caught) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_REQUIRE_MESSAGE(caught, "the follower never caught up to head over the multi-piece sync");

  // Every big value reassembled byte-for-byte on the follower: the split, out-of-order pieces landed
  // at their offsets and the whole artifact is exact. A chunker that assumed sequence would strand it.
  const std::string want = hexStr(blob);
  for (int i = 0; i < kEntries; i++) {
    const std::string name = "bulk" + std::to_string(i);
    const std::string e = nc.waitEntryOwned(4, name, u.pub);
    BOOST_REQUIRE_MESSAGE(!e.empty(), "the follower is missing synced entry " + name);
    BOOST_TEST((field(e, "payload") == want));  // 40 KiB payload, byte-exact
  }
}

BOOST_AUTO_TEST_SUITE_END()

#endif  // CES_HYLE
