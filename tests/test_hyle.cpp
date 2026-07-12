// ===========================================================================
// HyleSolo end to end: the K,V service over a real blockchain, carried by CES.
// ===========================================================================
//
// A real CesServer runs the shipped /s/hylesolo.lua extension in a real cesluajitd,
// which hosts a real hyle chain. The test is an ordinary user: it binds /ces/lua/1,
// ATTACHes to the instance, and speaks the extension's line protocol.
//
// The test SIGNS ITS OWN OPS: it encodes a hyle EntryOp offline, hands the bytes over,
// and the program relays them without reading them and without ever holding the key.
// That is the whole service:
//
//   publish  K,V      entry put on a name nobody owns yet
//   update   K,V->V2  entry put by the owner
//   give     K,V      entry give
//   delete   K,V      entry del
//   fund     K,V      transfer whose destination is the entry
//
// plus rent, the permissionless cull, and sudo (which is what the faucet is).
//
// Only built with --hyle: without it there is no ces.hyle to drive.

#ifdef CES_HYLE

#include "test_ext_common.h"
#include "test_lua_conn_common.h"

#include <hyle/core/crypto.h>
#include <hyle/services/ops.h>
#include <hyle/services/schema.h>

#include <boost/test/unit_test.hpp>

#include <unistd.h>

#include <cctype>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using ces::exttest::ExtNode;
using ces::exttest::startExtNode;
using ces::exttest::stopExt;

namespace {

const char* kChain = "hyletest";

std::string hexOf(const uint8_t* p, std::size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (std::size_t i = 0; i < n; i++) {
    s.push_back(d[p[i] >> 4]);
    s.push_back(d[p[i] & 15]);
  }
  return s;
}
std::string hexOf(const hyle::wire::Bytes& b) { return hexOf(b.data(), b.size()); }
std::string hexOf(const hyle::PubKey& k) { return hexOf(k.data(), k.size()); }
std::string hexOf(const std::string& s) {
  return hexOf(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

hyle::wire::View sv(const std::string& s) {
  return hyle::wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void unhex(const std::string& h, uint8_t* out, std::size_t n) {
  auto nyb = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
  };
  for (std::size_t i = 0; i < n && i * 2 + 1 < h.size(); i++)
    out[i] = static_cast<uint8_t>((nyb(h[i * 2]) << 4) | nyb(h[i * 2 + 1]));
}

// The invariant the whole design rests on: a CES ed25519 identity IS a hyle identity.
// Both derive the public half from the same 32-byte secret with the same primitive, so
// one key addresses two ledgers and a payment on one can authorize a mint on the other
// with nothing to look up.
hyle::KeyPair hyleKeyOf(const ces::KeyPair& k) {
  const minx::Hash priv = k.getPrivateKey();
  hyle::PrivKey s{};
  std::memcpy(s.data(), priv.data(), 32);
  return hyle::KeyPair::from_secret(s);
}

hyle::wire::Bytes acctDest(const hyle::PubKey& pk) {
  hyle::wire::Bytes b;
  b.push_back(hyle::services::ACCOUNT_PREFIX);
  b.insert(b.end(), pk.begin(), pk.end());
  return b;
}
hyle::wire::Bytes entryDest(const std::string& name) {
  hyle::wire::Bytes b;
  b.push_back(hyle::services::ENTRY_PREFIX);
  b.insert(b.end(), name.begin(), name.end());
  return b;
}

// Encode an op the way a real client does: offline, signed with its own key, opaque to
// everything between here and the chain.
std::string encEntry(const hyle::services::EntryOp& op) {
  hyle::services::Decoded d;
  d.entries.push_back(op);
  return hexOf(hyle::services::encode_ops(d));
}
std::string encTransfer(const hyle::services::TransferOp& op) {
  hyle::services::Decoded d;
  d.transfers.push_back(op);
  return hexOf(hyle::services::encode_ops(d));
}

std::string confFor(uint64_t rentRate) {
  std::ostringstream s;
  s << "chain_id = " << kChain << "\n"
    << "block_pace_ms = 40\n"
    << "autostart = 1\n"
    << "alloc = 1000000000\n"
    << "fee_transfer = 10\n"
    << "fee_entry = 10\n"
    << "fee_mint = 1\n"
    << "reward_base = 2\n"
    << "rent_rate = " << rentRate << "\n"
    << "rip_bounty = 10\n";
  return s.str();
}

struct HyleFixture {
  ExtNode node;
  ces::KeyPair userKey;  // binds the CES channel AND owns the hyle account: same 32 bytes
  hyle::KeyPair user;
  hyle::KeyPair validator;  // the node key, read via nodekey; the only key that may mint
  uint64_t pid = 0;
  std::unique_ptr<PlexLuaPeer> peer;
  std::unique_ptr<PlexLineReader> lines;

  explicit HyleFixture(uint64_t rentRate = 0) : user(hyleKeyOf(userKey)) {
    const std::string bin = ces::e2e::findBinary("cesluajitd");
    startExtNode(node, 0, bin, "hylesolo", confFor(rentRate));
    node.server->_brr(userKey.getPublicKeyAsHash(), 10'000'000'000);
    node.server->_drainLogic();

    for (int i = 0; i < 150 && pid == 0; i++) {
      CesComputeClient cc;
      cc.setServerPubkey(node.server->_serverKeyPair().getPublicKeyAsHash());
      std::vector<CesComputeClient::InstanceInfo> insts;
      if (cc.connect("localhost", node.rpcPort, userKey) == CES_OK &&
          cc.instances("/s/hylesolo.lua", insts) == CES_OK && !insts.empty())
        pid = insts[0].pid;
      cc.disconnect();
      if (pid == 0) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    BOOST_REQUIRE_MESSAGE(pid != 0, "hylesolo extension never launched");

    peer = std::make_unique<PlexLuaPeer>();
    BOOST_REQUIRE(peer->start() != 0);
    uint64_t token = 0;
    BOOST_REQUIRE(peer->bind(node.rpcPort, userKey, token));
    auto r = peer->attach(userKey, token, pid);
    CES_REQUIRE_RC_EQ(r.status, CES_OK);
    lines = std::make_unique<PlexLineReader>(*peer);

    // Read the node/validator private key over an owner-authenticated channel (the server is the
    // extension owner). Only this key can mint; the fixture uses it to fund test accounts.
    {
      PlexLuaPeer sp;
      BOOST_REQUIRE(sp.start() != 0);
      uint64_t st = 0;
      BOOST_REQUIRE(sp.bind(node.rpcPort, node.server->_serverKeyPair(), st));
      auto sr = sp.attach(node.server->_serverKeyPair(), st, pid);
      CES_REQUIRE_RC_EQ(sr.status, CES_OK);
      PlexLineReader sl(sp);
      const std::string q = "nodekey\n";
      BOOST_REQUIRE(peerWrite(sp, ces::Bytes(q.begin(), q.end())));
      const std::string nk = sl.nextLine(std::chrono::seconds(10));
      BOOST_REQUIRE_MESSAGE(nk.rfind("ok ", 0) == 0, "nodekey failed: " + nk);
      hyle::PrivKey vsec{};
      unhex(nk.substr(3), vsec.data(), 32);
      validator = hyle::KeyPair::from_secret(vsec);
      sp.stop();
    }

    // The chain autostarts. A refused genesis is the likely reason it did not, and the
    // program reports it, so surface that rather than time out on a bare "no chain".
    std::string last;
    for (int i = 0; i < 100; i++) {
      last = cmd("height");
      if (last.rfind("ok ", 0) == 0 && std::stoull(last.substr(3)) >= 1) return;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    BOOST_FAIL("chain never produced a block: " + last);
  }

  ~HyleFixture() {
    if (peer) peer->stop();
    stopExt(node);
  }

  std::string cmd(const std::string& line) {
    const std::string out = line + "\n";
    const ces::Bytes b(out.begin(), out.end());
    BOOST_REQUIRE(peerWrite(*peer, b));
    return lines->nextLine(std::chrono::seconds(10));
  }

  static std::string field(const std::string& line, const std::string& key) {
    const std::string k = " " + key + "=";
    const auto p = line.find(k);
    if (p == std::string::npos) return "";
    const auto start = p + k.size();
    const auto end = line.find(' ', start);
    return line.substr(start, end == std::string::npos ? std::string::npos : end - start);
  }
  static uint64_t numField(const std::string& line, const std::string& key) {
    const std::string v = field(line, key);
    return v.empty() ? 0 : std::stoull(v);
  }

  uint64_t seqOf(const hyle::PubKey& pk) {
    return numField(cmd("account " + hexOf(pk)), "sequence");
  }
  uint64_t balOf(const hyle::PubKey& pk) {
    return numField(cmd("account " + hexOf(pk)), "balance");
  }

  // Submit signed op bytes and block until the chain says what happened to them.
  bool submitApplied(const std::string& hexOps) {
    const std::string r = cmd("submit " + hexOps);
    if (r.rfind("ok ", 0) != 0) return false;
    const std::string txid = r.substr(3);
    for (int i = 0; i < 120; i++) {
      const std::string t = cmd("txr " + txid);
      if (t.rfind("ok ", 0) == 0) return numField(t, "applied") == 1;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
  }

  // Mint to the user, signed by the node/validator key: a sudo propose whose act is an unsigned
  // transfer from the mint sentinel. On a one-validator chain the propose is its own quorum.
  bool faucet(uint64_t amount) { return mintTo(user.pub, amount); }

  bool mintTo(const hyle::PubKey& to, uint64_t amount) {
    hyle::services::Decoded inner;
    hyle::services::TransferOp t;
    t.from = hyle::services::MINT_SENTINEL;
    t.to = acctDest(to);
    t.amount = amount;
    inner.transfers.push_back(t);
    const hyle::wire::Bytes ib = hyle::services::encode_ops(inner);
    hyle::services::Decoded d;
    d.sudos.push_back(hyle::services::make_sudo_propose(
        validator, seqOf(validator.pub), hyle::wire::View(ib.data(), ib.size()), sv(kChain)));
    return submitApplied(hexOf(hyle::services::encode_ops(d)));
  }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(HyleSoloTests)

// One key, two ledgers. If CES ever mints program or user keys as secp256k1, this is the
// assertion that fails loudly instead of silently addressing a different account.
BOOST_AUTO_TEST_CASE(ACesIdentityIsAHyleIdentity) {
  ces::KeyPair k;
  const hyle::KeyPair h = hyleKeyOf(k);
  const minx::Hash cesPub = k.getPublicKeyAsHash();
  BOOST_TEST(hexOf(h.pub) == hexOf(cesPub.data(), cesPub.size()));
}

BOOST_AUTO_TEST_CASE(TheChainRunsAndReportsItself) {
  HyleFixture f;
  const std::string i = f.cmd("info");
  BOOST_REQUIRE(i.rfind("ok ", 0) == 0);
  BOOST_TEST(HyleFixture::field(i, "chain") == kChain);
  BOOST_TEST(HyleFixture::numField(i, "height") >= 1u);
  BOOST_TEST(HyleFixture::numField(i, "validators") == 1u);
  BOOST_TEST(HyleFixture::numField(i, "quorum") == 1u);  // one validator IS a supermajority
  BOOST_TEST(HyleFixture::field(i, "self") == f.cmd("self").substr(3));

  const std::string c = f.cmd("config");
  BOOST_REQUIRE(c.rfind("ok ", 0) == 0);
  BOOST_TEST(HyleFixture::numField(c, "fee_entry") == 10u);
  BOOST_TEST(HyleFixture::numField(c, "rip_bounty") == 10u);
}

// Sudo, exercised through the faucet: the program proposes a mint on its own chain, and on
// a one-validator chain its own vote is the supermajority. It mints to conn.pubkey -- the
// key CES authenticated at bind -- which is also, byte for byte, the caller's hyle account.
BOOST_AUTO_TEST_CASE(FaucetSudoMintsToTheBoundCaller) {
  HyleFixture f;
  BOOST_TEST(f.balOf(f.user.pub) == 0u);
  BOOST_TEST(HyleFixture::numField(f.cmd("info"), "sudo_minted") == 0u);

  BOOST_REQUIRE(f.faucet(10000));
  for (int i = 0; i < 60 && f.balOf(f.user.pub) == 0; i++)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

  BOOST_TEST(f.balOf(f.user.pub) == 10000u);
  const std::string i2 = f.cmd("info");
  BOOST_TEST(HyleFixture::numField(i2, "sudo_minted") == 10000u);
  BOOST_TEST(HyleFixture::numField(i2, "sudo_pending") == 0u);  // executed, nothing left open

  BOOST_TEST(f.cmd("faucet 999999999").rfind("err", 0) == 0);  // capped
}

// The service: an outside signer publishes K,V. The program relays bytes it cannot read
// and could not have signed.
BOOST_AUTO_TEST_CASE(SignerPublishesAndUpdatesAKeyValue) {
  HyleFixture f;
  BOOST_REQUIRE(f.faucet(10000));
  for (int i = 0; i < 60 && f.balOf(f.user.pub) == 0; i++)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

  BOOST_REQUIRE(f.submitApplied(encEntry(hyle::services::make_entry_put(
      f.user, sv("greeting"), f.seqOf(f.user.pub), /*fund=*/500, sv("hello"), sv(kChain)))));

  std::string e = f.cmd("entry greeting");
  BOOST_REQUIRE(e.rfind("ok ", 0) == 0);
  BOOST_TEST(HyleFixture::field(e, "owner") == hexOf(f.user.pub));
  BOOST_TEST(HyleFixture::field(e, "payload") == hexOf(std::string("hello")));
  BOOST_TEST(HyleFixture::numField(e, "balance") == 500u);

  // update: same name, same owner, new value
  BOOST_REQUIRE(f.submitApplied(encEntry(hyle::services::make_entry_put(
      f.user, sv("greeting"), f.seqOf(f.user.pub), 0, sv("goodbye"), sv(kChain)))));

  e = f.cmd("entry greeting");
  BOOST_TEST(HyleFixture::field(e, "payload") == hexOf(std::string("goodbye")));
  BOOST_TEST(HyleFixture::field(e, "owner") == hexOf(f.user.pub));
}

BOOST_AUTO_TEST_CASE(AStrangerCannotOverwriteYourKey) {
  HyleFixture f;
  BOOST_REQUIRE(f.faucet(10000));
  for (int i = 0; i < 60 && f.balOf(f.user.pub) == 0; i++)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

  BOOST_REQUIRE(f.submitApplied(encEntry(hyle::services::make_entry_put(
      f.user, sv("mine"), f.seqOf(f.user.pub), 0, sv("v1"), sv(kChain)))));

  // A second, funded identity tries to take the name. It is admitted (well-formed and
  // paid for) but the owner gate rejects it at apply.
  ces::KeyPair otherCes;
  const hyle::KeyPair other = hyleKeyOf(otherCes);
  BOOST_REQUIRE(f.submitApplied(encTransfer(hyle::services::make_transfer(
      f.user, hyle::wire::View(acctDest(other.pub)), 5000, f.seqOf(f.user.pub), sv(kChain)))));

  const std::string r = f.cmd("submit " + encEntry(hyle::services::make_entry_put(
      other, sv("mine"), f.seqOf(other.pub), 0, sv("stolen"), sv(kChain))));
  BOOST_REQUIRE(r.rfind("ok ", 0) == 0);
  const std::string txid = r.substr(3);
  bool applied = true;
  for (int i = 0; i < 120; i++) {
    const std::string t = f.cmd("txr " + txid);
    if (t.rfind("ok ", 0) == 0) { applied = HyleFixture::numField(t, "applied") == 1; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_TEST(!applied);

  const std::string e = f.cmd("entry mine");
  BOOST_TEST(HyleFixture::field(e, "owner") == hexOf(f.user.pub));
  BOOST_TEST(HyleFixture::field(e, "payload") == hexOf(std::string("v1")));
}

BOOST_AUTO_TEST_CASE(OwnershipIsGivenAwayAndTheNewOwnerDeletes) {
  HyleFixture f;
  BOOST_REQUIRE(f.faucet(10000));
  for (int i = 0; i < 60 && f.balOf(f.user.pub) == 0; i++)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

  ces::KeyPair heirCes;
  const hyle::KeyPair heir = hyleKeyOf(heirCes);

  BOOST_REQUIRE(f.submitApplied(encEntry(hyle::services::make_entry_put(
      f.user, sv("estate"), f.seqOf(f.user.pub), /*fund=*/700, sv("deed"), sv(kChain)))));

  BOOST_REQUIRE(f.submitApplied(encEntry(hyle::services::make_entry_give(
      f.user, sv("estate"), f.seqOf(f.user.pub), heir.pub, sv(kChain)))));
  BOOST_TEST(HyleFixture::field(f.cmd("entry estate"), "owner") == hexOf(heir.pub));

  // the heir needs credit of its own to pay the entry fee
  BOOST_REQUIRE(f.submitApplied(encTransfer(hyle::services::make_transfer(
      f.user, hyle::wire::View(acctDest(heir.pub)), 100, f.seqOf(f.user.pub), sv(kChain)))));

  // delete refunds the entry's remaining balance to whoever owns it now
  const uint64_t before = f.balOf(heir.pub);
  BOOST_REQUIRE(f.submitApplied(encEntry(hyle::services::make_entry_del(
      heir, sv("estate"), f.seqOf(heir.pub), sv(kChain)))));

  BOOST_TEST(f.cmd("entry estate") == "err not_found");
  BOOST_TEST(f.balOf(heir.pub) == before + 700u - 10u);  // refund, less fee_entry
}

// Funding a mapping is a transfer whose destination is the entry itself, so anyone can
// keep someone else's K,V alive without owning it.
BOOST_AUTO_TEST_CASE(AnyoneCanFundSomeoneElsesKey) {
  HyleFixture f;
  BOOST_REQUIRE(f.faucet(10000));
  for (int i = 0; i < 60 && f.balOf(f.user.pub) == 0; i++)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

  BOOST_REQUIRE(f.submitApplied(encEntry(hyle::services::make_entry_put(
      f.user, sv("shared"), f.seqOf(f.user.pub), /*fund=*/100, sv("data"), sv(kChain)))));
  BOOST_TEST(HyleFixture::numField(f.cmd("entry shared"), "balance") == 100u);

  ces::KeyPair patronCes;
  const hyle::KeyPair patron = hyleKeyOf(patronCes);
  BOOST_REQUIRE(f.submitApplied(encTransfer(hyle::services::make_transfer(
      f.user, hyle::wire::View(acctDest(patron.pub)), 5000, f.seqOf(f.user.pub), sv(kChain)))));

  BOOST_REQUIRE(f.submitApplied(encTransfer(hyle::services::make_transfer(
      patron, hyle::wire::View(entryDest("shared")), 400, f.seqOf(patron.pub), sv(kChain)))));

  const std::string e = f.cmd("entry shared");
  BOOST_TEST(HyleFixture::numField(e, "balance") == 500u);
  BOOST_TEST(HyleFixture::field(e, "owner") == hexOf(f.user.pub));  // funding buys no control
}

// With rent on, a starved entry can be reaped by anyone.
BOOST_AUTO_TEST_CASE(RentStarvesAKeyAndAnyoneMayReapIt) {
  HyleFixture f(/*rentRate=*/1000);
  BOOST_REQUIRE(f.faucet(50000));
  for (int i = 0; i < 60 && f.balOf(f.user.pub) == 0; i++)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // footprint = 1 + name + 64 + payload; at rate 1000 this drains thousands per second
  BOOST_REQUIRE(f.submitApplied(encEntry(hyle::services::make_entry_put(
      f.user, sv("doomed"), f.seqOf(f.user.pub), /*fund=*/20000, sv("x"), sv(kChain)))));
  BOOST_TEST(f.cmd("entry doomed").rfind("ok ", 0) == 0);

  // a rip needs no signature, no sequence and no funds: the culler can be a stranger
  ces::KeyPair cullerCes;
  const hyle::KeyPair culler = hyleKeyOf(cullerCes);

  bool reaped = false;
  for (int i = 0; i < 40 && !reaped; i++) {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    f.cmd("submit " + encEntry(hyle::services::make_entry_rip(sv("doomed"), culler.pub)));
    for (int j = 0; j < 10 && !reaped; j++) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      reaped = f.cmd("entry doomed") == "err not_found";
    }
  }
  BOOST_TEST(reaped);
  BOOST_TEST(f.balOf(culler.pub) == 10u);  // rip_bounty, paid to a key that never signed
}

BOOST_AUTO_TEST_CASE(AnUnfundedSignerIsRejected) {
  HyleFixture f;
  ces::KeyPair brokeCes;
  const hyle::KeyPair broke = hyleKeyOf(brokeCes);
  const std::string r = f.cmd("submit " + encEntry(hyle::services::make_entry_put(
      broke, sv("nope"), 0, 0, sv("v"), sv(kChain))));
  BOOST_TEST(r.rfind("err", 0) == 0);
  BOOST_TEST(f.cmd("entry nope") == "err not_found");
}

BOOST_AUTO_TEST_CASE(GarbageIsRejectedNotCrashed) {
  HyleFixture f;
  BOOST_TEST(f.cmd("submit zzzz") == "err bad_hex");
  BOOST_TEST(f.cmd("submit deadbeef").rfind("err", 0) == 0);
  BOOST_TEST(f.cmd("nonsense") == "err unknown_command");
  BOOST_TEST(f.cmd("account 00") == "err bad_pubkey");
  BOOST_TEST(f.cmd("entry never-existed") == "err not_found");
  BOOST_TEST(f.cmd("info").rfind("ok ", 0) == 0);  // still alive
}

// ---------------------------------------------------------------------------
// The rest of the binding: the surface a program uses when it acts on its OWN behalf
// (ces.hyle.op.*) and when it governs (ces.hyle.sudo.*, vote_*). The tests above go
// through hylesolo, which deliberately exposes none of that to the network -- a service
// that let a caller seize funds would not be a service. So this drives it from inside:
// a privileged /s/ program that exercises the surface, checks itself, and reports.
// ---------------------------------------------------------------------------

namespace {

const char* kOpsProgram = R"LUA(
local out = {}
local function ok(name, cond, detail)
  out[#out + 1] = (cond and "PASS " or "FAIL ") .. name ..
                  (detail ~= nil and (" [" .. tostring(detail) .. "]") or "")
end
local function tick(n)
  for _ = 1, (n or 2) do ces.hyle.solo.tick() end
end

-- The identity invariant, from the program's own side: its CES account key and the chain
-- validator key it derives are the same 32 bytes.
ok("self is program_pubkey", ces.hyle.self() == ces.program_pubkey())

local started, err = ces.hyle.solo.start{
  chain_id = "opstest", alloc = 1000000, fee_transfer = 10, fee_entry = 10,
  fee_mint = 1, reward_base = 2, rent_rate = 0, rip_bounty = 10,
}
ok("start", started == true, err)
tick(2)

ok("height", ces.hyle.height() >= 1)
ok("chain_id", ces.hyle.chain_id() == "opstest")
ok("running", ces.hyle.running() == true)
ok("quorum is 1", ces.hyle.sudo.quorum() == 1)
ok("mint_key is 32B", #ces.hyle.mint_key() == 32)
ok("config", ces.hyle.config().fee_entry == 10 and ces.hyle.config().rent_rate == 0)

local me = ces.hyle.self()
local vs = ces.hyle.validators()
ok("one validator, me", #vs == 1 and vs[1] == me)
ok("genesis alloc", ces.hyle.account(me).balance == 1000000)

-- Acting as itself: publish, update, fund, give, delete.
local ids, e = ces.hyle.submit(ces.hyle.op.entry_put{ name = "prog", payload = "v1", fund = 500 })
ok("op.entry_put", ids ~= nil, e)
tick(2)
local ent = ces.hyle.entry("prog")
ok("published", ent ~= nil and ent.owner == me and ent.payload == "v1" and ent.balance == 500)
if ids then
  local r = ces.hyle.tx_result(ids[1])
  ok("tx_result", r ~= nil and r.applied == true and r.height >= 1)
end

ok("op.entry_put update", ces.hyle.submit(ces.hyle.op.entry_put{ name = "prog", payload = "v2" }) ~= nil)
tick(2)
ok("updated", ces.hyle.entry("prog").payload == "v2")

ok("op.fund", ces.hyle.submit(ces.hyle.op.fund{ name = "prog", amount = 250 }) ~= nil)
tick(2)
ok("funded", ces.hyle.entry("prog").balance == 750, ces.hyle.entry("prog").balance)

local stranger = ces.random_bytes(32)
ok("op.entry_give", ces.hyle.submit(ces.hyle.op.entry_give{ name = "prog", to = stranger }) ~= nil)
tick(2)
ok("given away", ces.hyle.entry("prog").owner == stranger)

ok("op.entry_put tmp", ces.hyle.submit(ces.hyle.op.entry_put{ name = "tmp", payload = "x" }) ~= nil)
tick(2)
ok("op.entry_del", ces.hyle.submit(ces.hyle.op.entry_del{ name = "tmp" }) ~= nil)
tick(2)
ok("deleted", ces.hyle.entry("tmp") == nil)

-- Sudo. On this one-validator chain the program is the whole quorum, so a propose executes
-- in the next block. Vote accumulation across a larger set is covered by hyle's SudoTests
-- (a chain that needs a second approver cannot be a single running node). sudo.submit is
-- propose; the program ticks to commit it.
ok("nothing pending", ces.hyle.sudo.pending(me) == nil)
ok("sudo.mint", ces.hyle.sudo.submit(ces.hyle.sudo.op.mint{ to = stranger, amount = 4242 }) == true)
tick(2)
ok("minted", ces.hyle.account(stranger).balance == 4242, ces.hyle.account(stranger).balance)
ok("sudo_minted", ces.hyle.info().sudo_minted == 4242)
ok("executed, not left pending", ces.hyle.sudo.pending(me) == nil)

ok("sudo.seize",
   ces.hyle.sudo.submit(ces.hyle.sudo.op.seize{ from = stranger, to = me, amount = 242 }) == true)
tick(2)
ok("seized", ces.hyle.account(stranger).balance == 4000, ces.hyle.account(stranger).balance)
ok("seizing mints nothing", ces.hyle.info().sudo_minted == 4242)

-- Sudo can force an entry onto a key that never signed anything.
local ghost = ces.random_bytes(32)
ok("sudo.entry_put",
   ces.hyle.sudo.submit(ces.hyle.sudo.op.entry_put{ name = "forced", owner = ghost,
                                                    payload = "p", fund = 99 }) == true)
tick(2)
local fe = ces.hyle.entry("forced")
ok("forced onto a stranger", fe ~= nil and fe.owner == ghost and fe.balance == 99)

ok("sudo.entry_give",
   ces.hyle.sudo.submit(ces.hyle.sudo.op.entry_give{ name = "forced", to = stranger }) == true)
tick(2)
ok("forced give", ces.hyle.entry("forced").owner == stranger)

ok("sudo.entry_del", ces.hyle.sudo.submit(ces.hyle.sudo.op.entry_del{ name = "forced" }) == true)
tick(2)
ok("forced delete", ces.hyle.entry("forced") == nil)

-- Sudo refuses to strand an entry on the sentinel, and refuses proof-of-work as governance.
ok("sudo refuses the sentinel as owner",
   ces.hyle.sudo.submit(ces.hyle.sudo.op.entry_put{ name = "orphan", payload = "x" }) == nil)

-- The vote lane exists and is callable. It is NOT exercised further here on purpose:
-- admitting a validator that does not exist raises the quorum to 2 on a chain with one
-- node, and the chain stops producing. Done last for that reason.
ok("vote_add", ces.hyle.vote_add(ces.random_bytes(32)) == true)

out[#out + 1] = "DONE"

ces.conn.set_listener{
  on_open = function(c) c:write(table.concat(out, "\n") .. "\n") end,
}
ces.run()
)LUA";

}  // namespace

BOOST_AUTO_TEST_CASE(TheProgramFacingSurfaceOfTheBinding) {
  ExtNode n;
  const std::string bin = ces::e2e::findBinary("cesluajitd");
  startExtNode(n, 1, bin, "", "");  // plain node; we deploy our own /s/ program

  const ces::KeyPair& srv = n.server->_serverKeyPair();
  ces::KeyPair user;
  n.server->_brr(user.getPublicKeyAsHash(), 10'000'000'000);
  n.server->_drainLogic();

  // /s/ is operator-only: the server's own key is the one that may write there.
  const std::string path = "/s/hyleops.lua";
  const std::string src = kOpsProgram;
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

  // The program runs its whole script before it opens the accept gate, and a refused
  // ATTACH closes the channel, so each attempt needs a fresh one.
  std::unique_ptr<PlexLuaPeer> peer;
  PlexLuaPeer::AttachResult r{};
  for (int i = 0; i < 40 && r.status != CES_OK; i++) {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    peer = std::make_unique<PlexLuaPeer>();
    if (peer->start() == 0) continue;
    uint64_t token = 0;
    if (!peer->bind(n.rpcPort, user, token)) {
      peer->stop();
      continue;
    }
    r = peer->attach(user, token, pid);
    if (r.status != CES_OK) peer->stop();
  }
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  PlexLineReader lines(*peer);
  std::vector<std::string> report;
  for (int i = 0; i < 200; i++) {
    const std::string line = lines.nextLine(std::chrono::seconds(10));
    if (line.empty() || line == "DONE") break;
    report.push_back(line);
  }
  peer->stop();

  BOOST_REQUIRE_MESSAGE(!report.empty(), "the program reported nothing");
  for (const std::string& line : report)
    BOOST_TEST(line.rfind("PASS ", 0) == 0, line);
  BOOST_TEST_MESSAGE("binding surface checks: " << report.size());

  stopExt(n);
}

// The client side, end to end: the real cesh binary's `hyle` verbs against a live hylesolo
// chain. Proves the shell builds + signs ops with hyle_services, speaks the line protocol over
// /ces/lua/1, and that a CES ed25519 identity owns the hyle entry it publishes. cesh links
// hyle_services; the CES client engine (ceslib) does not.
BOOST_FIXTURE_TEST_CASE(CeshClientDrivesTheChain, HyleFixture) {
  namespace e2e = ces::e2e;
  const std::string cesh = e2e::findCeshBinary();
  const std::string wallet = "00" + hexOf(userKey.getPrivateKey().data(), 32);
  const std::string userHex = hexOf(user.pub);
  const std::string srvKey = hexOf(node.server->_serverKeyPair().getPublicKeyAsHash());
  auto conn = [&](const std::string& w) {
    return "CESH_WALLET=\"" + w + "\" " + cesh + " -l fatal --server localhost:" +
           std::to_string(node.mainPort) + " --rpc-port " + std::to_string(node.rpcPort) +
           " --server-key " + srvKey + " hyle ";
  };
  const std::string base = conn(wallet);
  // `list` enumerates instances; every other verb names one by pid on the command line.
  const std::string ph = base + std::to_string(pid) + " ";

  // Enumerate: list shows the instance and its pid.
  e2e::assertContains(e2e::runExpect(base + "list").out, "pid=" + std::to_string(pid), "list");

  // Reads relay through untouched.
  e2e::assertContains(e2e::runExpect(ph + "info").out, "ok chain=", "info");
  e2e::assertContains(e2e::runExpect(ph + "self").out, "ok ", "self");
  e2e::assertContains(e2e::runExpect(ph + "height").out, "ok ", "height");
  e2e::assertContains(e2e::runExpect(ph + "config").out, "fee_transfer=", "config");
  e2e::assertContains(e2e::runExpect(ph + "config").out, "member_cap=", "config exposes consensus params");
  e2e::assertContains(e2e::runExpect(ph + "mintkey").out, "ok ", "mintkey");
  e2e::assertContains(e2e::runExpect(ph + "account " + userHex).out, "exists=", "account");

  // Money exists only through the validator. The node operator = the extension owner = the
  // server key; it reads the validator private key via the owner-gated `nodekey`, loads it into
  // cesh, and mints as the validator. A non-owner cannot read the node key.
  const ces::KeyPair& srvKp = node.server->_serverKeyPair();
  const std::string srvDec = (srvKp.getAlgorithm() == ces::KeyAlgo::SECP256K1) ? "01" : "00";
  const std::string srvWallet = srvDec + hexOf(srvKp.getPrivateKey().data(), 32);
  e2e::assertContains(e2e::runShell(ph + "nodekey").out, "not_owner", "nodekey is owner-gated");
  const std::string nk = e2e::runExpect(conn(srvWallet) + std::to_string(pid) + " nodekey").out;
  std::string vpriv;
  if (const auto p = nk.find("ok "); p != std::string::npos)
    for (char ch : nk.substr(p + 3)) {
      if (std::isxdigit(static_cast<unsigned char>(ch))) vpriv.push_back(ch);
      else break;
    }
  BOOST_REQUIRE_MESSAGE(vpriv.size() == 64u, "owner reads a 32-byte node key: " + nk);
  const ces::KeyPair vkey(vpriv, ces::KeyAlgo::ED25519);
  node.server->_brr(vkey.getPublicKeyAsHash(), 10'000'000'000);  // fund the operator's channel
  node.server->_drainLogic();
  const std::string opPh = conn("00" + vpriv) + std::to_string(pid) + " ";

  // The operator mints to the user account; the recipient is any key.
  e2e::assertContains(e2e::runExpect(opPh + "mint " + userHex + " 10000000 --wait").out, "applied",
                      "the validator mints");
  e2e::assertContains(e2e::runExpect(ph + "account " + userHex).out, "balance=10000000",
                      "mint credited the recipient");

  // Sudo, general form: the operator proposes an arbitrary inner act via --in. Here the act is a
  // mint to a fresh key; on a one-validator chain the propose is its own quorum and executes, so
  // the raw propose path and the specialized `mint` verb converge on the same effect.
  {
    const hyle::KeyPair pro = hyleKeyOf(ces::KeyPair::generate());
    hyle::services::Decoded inner;
    hyle::services::TransferOp t;
    t.from = hyle::services::MINT_SENTINEL;
    t.to = acctDest(pro.pub);
    t.amount = 777;
    inner.transfers.push_back(t);
    const std::string innerHex = hexOf(hyle::services::encode_ops(inner));
    e2e::assertContains(e2e::runExpect(opPh + "propose --in hex:" + innerHex + " --wait").out,
                        "applied", "a general sudo propose executes");
    e2e::assertContains(e2e::runExpect(ph + "account " + hexOf(pro.pub)).out, "balance=777",
                        "the proposed mint credited the recipient");
  }

  // Sudo seize: the operator moves real credit out of an account it does not own. Fund a victim
  // first, then seize part of it to the user; the mint sentinel is not involved, so the money
  // must already exist.
  {
    const hyle::KeyPair vic = hyleKeyOf(ces::KeyPair::generate());
    const std::string vicHex = hexOf(vic.pub);
    e2e::assertContains(e2e::runExpect(opPh + "mint " + vicHex + " 5000 --wait").out, "applied",
                        "fund the victim");
    e2e::assertContains(e2e::runExpect(opPh + "seize " + vicHex + " " + userHex + " 2000 --wait").out,
                        "applied", "seize");
    e2e::assertContains(e2e::runExpect(ph + "account " + vicHex).out, "balance=3000",
                        "seize removed the victim's funds");
  }

  // Sudo approve: on a one-validator chain a propose already reached quorum, so an approve finds no
  // open proposal. The shell must still build a well-formed Approve the chain admits and processes;
  // multi-validator vote accumulation is covered by hyle's own SudoTests.
  {
    hyle::services::Decoded inner;
    hyle::services::TransferOp t;
    t.from = hyle::services::MINT_SENTINEL;
    t.to = acctDest(user.pub);
    t.amount = 1;
    inner.transfers.push_back(t);
    const std::string innerHex = hexOf(hyle::services::encode_ops(inner));
    e2e::assertContains(
        e2e::runShell(opPh + "approve " + hexOf(validator.pub) + " --in hex:" + innerHex + " --wait")
            .out,
        "tx ", "approve builds and submits a valid sudo op");
  }

  // Publish a key with value "hello" (68656c6c6f), owned by the CES identity.
  const auto putR = e2e::runExpect(ph + "put greeting hello --fund 500 --wait");
  e2e::assertContains(putR.out, "applied", "put");
  {
    const auto r = e2e::runExpect(ph + "entry greeting");
    e2e::assertContains(r.out, "payload=68656c6c6f", "entry shows the value as hex");
    e2e::assertContains(r.out, "owner=" + userHex, "owner is the CES identity");
  }
  // get returns the value as raw bytes (no chrome), the content view of an entry.
  BOOST_TEST(e2e::runExpect(ph + "get greeting").out == "hello", "get emits the raw value");

  // A tx id names the applied transaction; txr reads its result back.
  std::string txid;
  if (const auto p = putR.out.find("tx "); p != std::string::npos)
    for (char ch : putR.out.substr(p + 3)) {
      if (std::isxdigit(static_cast<unsigned char>(ch))) txid.push_back(ch);
      else break;
    }
  BOOST_TEST(txid.size() == 64u, "put reports a 32-byte tx id");
  if (txid.size() == 64u)
    e2e::assertContains(e2e::runExpect(ph + "txr " + txid).out, "applied=1", "txr");

  // Owner updates the value to "goodbye" (676f6f64627965).
  e2e::assertContains(e2e::runExpect(ph + "put greeting goodbye --wait").out, "applied", "update");
  BOOST_TEST(e2e::runExpect(ph + "get greeting").out == "goodbye", "get sees the update");

  // Value from hex, read back through the record and through get --out.
  e2e::assertContains(e2e::runExpect(ph + "put hx --in hex:deadbeef --wait").out, "applied",
                      "put hex value");
  e2e::assertContains(e2e::runExpect(ph + "entry hx").out, "payload=deadbeef", "hex stored");

  // Binary value: put every byte 0x00..0xff from a file, read it back to a file, compare.
  {
    const std::string blobPath = "/tmp/ceshyle-blob-" + std::to_string(::getpid());
    const std::string outPath = "/tmp/ceshyle-out-" + std::to_string(::getpid());
    std::string blob;
    for (int b = 0; b < 256; b++) blob.push_back(static_cast<char>(b));
    std::ofstream(blobPath, std::ios::binary).write(blob.data(), blob.size());

    e2e::assertContains(
        e2e::runExpect(ph + "put blob --in file:" + blobPath + " --fund 500 --wait").out,
        "applied", "put binary value from a file");
    e2e::runExpect(ph + "get blob --out " + outPath);
    std::ifstream in(outPath, std::ios::binary);
    const std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    BOOST_TEST(got == blob, "binary value round-trips through --in file: and get --out");
    ::unlink(blobPath.c_str());
    ::unlink(outPath.c_str());
  }

  // Raw submit: relay an op the client encoded and signed itself, opaque to cesh (carrier path).
  {
    hyle::services::Decoded d;
    d.entries.push_back(hyle::services::make_entry_put(
        user, sv("raw"), seqOf(user.pub), /*fund=*/500, sv("viaraw"), sv(kChain)));
    const std::string opsHex = hexOf(hyle::services::encode_ops(d));
    e2e::assertContains(e2e::runExpect(ph + "submit --in hex:" + opsHex + " --wait").out,
                        "applied", "raw submit of a client-signed op");
    BOOST_TEST(e2e::runExpect(ph + "get raw").out == "viaraw", "raw-submitted value is readable");
  }

  // Transfer credit to a fresh account, which the transfer creates.
  const std::string dstHex = hexOf(hyleKeyOf(ces::KeyPair::generate()).pub);
  e2e::assertContains(e2e::runExpect(ph + "transfer " + dstHex + " 1000 --wait").out, "applied",
                      "transfer");
  e2e::assertContains(e2e::runExpect(ph + "account " + dstHex).out, "balance=1000",
                      "transfer credited the destination");

  // Give ownership of a key away; the record's owner changes.
  e2e::assertContains(e2e::runExpect(ph + "give greeting " + dstHex + " --wait").out, "applied",
                      "give");
  e2e::assertContains(e2e::runExpect(ph + "entry greeting").out, "owner=" + dstHex,
                      "ownership transferred");

  // Delete a key the caller still owns; the entry is then gone.
  e2e::assertContains(e2e::runExpect(ph + "del hx --wait").out, "applied", "del");
  e2e::assertContains(e2e::runShell(ph + "entry hx").out, "not_found", "entry gone after delete");

  // Error paths.
  e2e::assertContains(e2e::runShell(base + "info").out, "instance pid", "a verb without a pid");
  e2e::assertContains(e2e::runShell(ph + "put novalue").out, "needs a value", "put without a value");
  e2e::assertContains(e2e::runShell(ph + "entry nonesuch").out, "not_found", "read a missing key");
  const std::string secpWallet =
      "01" + hexOf(ces::KeyPair::generate(ces::KeyAlgo::SECP256K1).getPrivateKey().data(), 32);
  e2e::assertContains(e2e::runShell(conn(secpWallet) + std::to_string(pid) + " put k v").out,
                      "ed25519", "a secp256k1 key cannot act as a hyle identity");
  // Minting is validator-only: a funded non-validator's sudo is admitted but rejected at apply.
  e2e::assertContains(e2e::runShell(ph + "mint " + userHex + " 100 --wait").out, "rejected",
                      "a non-validator mint is refused by the chain");
}

// The permissionless cull, driven by the shell's `rip` verb: a rent-starved entry is reaped by a
// caller who signs nothing on the chain (a rip carries no signature) and collects the bounty. Rent
// only bites with rent_rate > 0, so this stands up its own high-rent chain.
BOOST_AUTO_TEST_CASE(CeshRipsAStarvedEntry) {
  namespace e2e = ces::e2e;
  HyleFixture f(/*rentRate=*/1000);
  const std::string cesh = e2e::findCeshBinary();
  const std::string wallet = "00" + hexOf(f.userKey.getPrivateKey().data(), 32);
  const std::string srvKey = hexOf(f.node.server->_serverKeyPair().getPublicKeyAsHash());
  const std::string ph = "CESH_WALLET=\"" + wallet + "\" " + cesh + " -l fatal --server localhost:" +
                         std::to_string(f.node.mainPort) + " --rpc-port " +
                         std::to_string(f.node.rpcPort) + " --server-key " + srvKey + " hyle " +
                         std::to_string(f.pid) + " ";

  BOOST_REQUIRE(f.faucet(50000));
  for (int i = 0; i < 60 && f.balOf(f.user.pub) == 0; i++)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // A small fund against a live footprint drains thousands per second: the entry starves in
  // seconds. Fund is charged to the owner up front, so capture the balance after the put.
  e2e::assertContains(e2e::runExpect(ph + "put doomed x --fund 20000 --wait").out, "applied",
                      "put a doomed entry");
  e2e::assertContains(e2e::runExpect(ph + "entry doomed").out, "ok ", "the entry exists");
  const uint64_t before = f.balOf(f.user.pub);

  bool reaped = false;
  for (int i = 0; i < 40 && !reaped; i++) {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    e2e::runShell(ph + "rip doomed");
    reaped = e2e::runShell(ph + "entry doomed").out.find("not_found") != std::string::npos;
  }
  BOOST_TEST(reaped, "the shell's rip verb reaped the starved entry");
  // The culler (this wallet's hyle identity) collected the bounty; a rip refunds the owner nothing.
  BOOST_TEST(f.balOf(f.user.pub) == before + 10);
}

// The operator funds many fresh identities from the node key; they then act independently --
// publish their own keys, transfer credit between each other, and gift ownership.
BOOST_FIXTURE_TEST_CASE(OperatorFundsManyIdentitiesWhoInteract, HyleFixture) {
  constexpr int N = 8;
  std::vector<hyle::KeyPair> id;
  for (int i = 0; i < N; i++) id.push_back(hyleKeyOf(ces::KeyPair::generate()));

  for (const auto& k : id) BOOST_REQUIRE(mintTo(k.pub, 1000000));
  for (const auto& k : id) BOOST_TEST(balOf(k.pub) == 1000000u);

  auto put = [&](const hyle::KeyPair& k, const std::string& name, const std::string& val) {
    hyle::services::Decoded d;
    d.entries.push_back(hyle::services::make_entry_put(
        k, sv(name), seqOf(k.pub), 500, sv(val), sv(kChain)));
    return submitApplied(hexOf(hyle::services::encode_ops(d)));
  };

  for (int i = 0; i < N; i++) BOOST_REQUIRE(put(id[i], "k" + std::to_string(i), "v"));
  for (int i = 0; i < N; i++)
    BOOST_TEST(field(cmd("entry k" + std::to_string(i)), "owner") == hexOf(id[i].pub));

  // id0 pays id1.
  const uint64_t before = balOf(id[1].pub);
  {
    hyle::services::Decoded d;
    d.transfers.push_back(hyle::services::make_transfer(
        id[0], hyle::wire::View(acctDest(id[1].pub)), 250000, seqOf(id[0].pub), sv(kChain)));
    BOOST_REQUIRE(submitApplied(hexOf(hyle::services::encode_ops(d))));
  }
  BOOST_TEST(balOf(id[1].pub) == before + 250000u);

  // id2 gifts its key to id3; ownership moves.
  {
    hyle::services::Decoded d;
    d.entries.push_back(hyle::services::make_entry_give(
        id[2], sv("k2"), seqOf(id[2].pub), id[3].pub, sv(kChain)));
    BOOST_REQUIRE(submitApplied(hexOf(hyle::services::encode_ops(d))));
  }
  BOOST_TEST(field(cmd("entry k2"), "owner") == hexOf(id[3].pub));
}

BOOST_AUTO_TEST_SUITE_END()

#endif  // CES_HYLE
