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

#include <cstring>
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
    << "rip_bounty = 10\n"
    << "faucet_max = 1000000\n";
  return s.str();
}

struct HyleFixture {
  ExtNode node;
  ces::KeyPair userKey;  // binds the CES channel AND owns the hyle account: same 32 bytes
  hyle::KeyPair user;
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

  bool faucet(uint64_t amount) {
    return cmd("faucet " + std::to_string(amount)).rfind("ok ", 0) == 0;
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

BOOST_AUTO_TEST_SUITE_END()

#endif  // CES_HYLE
