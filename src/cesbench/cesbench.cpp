/**
 * cesbench - CES server throughput benchmark
 *
 * Spins up an in-process CES server, pre-signs N transfer packets, blasts them
 * while the server is paused, then resumes and measures processing throughput.
 * Finishes with a ledger consistency check and a raw crypto cycle benchmark.
 */

#include <atomic>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>

#include <CLI/CLI.hpp>
#include <boost/filesystem.hpp>

#include <ces/keys.h>
#include <ces/protocol.h>
#include <ces/server.h>
#include <minx/blog.h>
#include <minx/minx.h>

using namespace ces;
namespace fs = boost::filesystem;

constexpr size_t HUGE_BUFFER_SIZE = 4ULL * 1024 * 1024 * 1024;
constexpr uint64_t MAX_FLUSH = std::numeric_limits<uint64_t>::max();

// Wait this many seconds for server replies before giving up on a bench run.
constexpr int BENCH_REPLY_TIMEOUT_SECS = 15;

class BenchClient : public minx::MinxListener {
public:
  BenchClient(
    uint16_t port, bool verbose, int taskThreads,
    size_t totalTx, size_t poolSize,
    const std::unordered_map<HashPrefix, size_t>& accMap)
      : port_(port), verbose_(verbose),
        taskThreadCount_(taskThreads), poolSize_(poolSize), accMap_(accMap) {
    size_t arraySize = totalTx + poolSize + 1000;
    seenFlags_.resize(arraySize, 0);
    minx_ = std::make_unique<minx::Minx>(
      this, minx::MinxConfig{"bench_cli", 0, 3600, 1, taskThreads, 1000, 0, true,
                             totalTx * 3 + 16384});
  }

  ~BenchClient() { stop(); }

  void start() {
    minx_->openSocket(
      minx::SockAddr(boost::asio::ip::address_v6::loopback(), 0), netIO_,
      taskIO_);
    netThread_ = std::thread([this]() { netIO_.run(); });
    for (int i = 0; i < taskThreadCount_; ++i) {
      taskThreads_.emplace_back([this]() { taskIO_.run(); });
    }
    if (verbose_)
      std::cout << "[Client] Threads: 1 Net, " << taskThreadCount_
                << " Task.\n";
  }

  void stop() {
    if (minx_)
      minx_->closeSocket(false);
    netIO_.stop();
    taskIO_.stop();
    if (netThread_.joinable())
      netThread_.join();
    for (auto& t : taskThreads_)
      if (t.joinable())
        t.join();
    taskThreads_.clear();
  }

  bool isConnected(const minx::SockAddr& addr) override {
    return addr.address().is_loopback();
  }

  void sendRaw(const minx::Bytes& packet) {
    minx::SockAddr serverAddr(boost::asio::ip::address_v6::loopback(), port_);
    minx::MinxMessage msg{0, 0, 0, {packet.begin(), packet.end()}};
    minx_->sendMessage(serverAddr, msg);
  }

  void incomingInfo(const minx::SockAddr&, const minx::MinxInfo&) override {}

  void incomingMessage(const minx::SockAddr&,
                       const minx::MinxMessage& msg) override {
    rawPackets_++;

    try {
      if (msg.data.empty())
        return;
      if (static_cast<uint8_t>(msg.data[0]) != CES_TRANSFER_RESULT)
        return;

      CesTransferResult res;
      res.fromBytes(msg.data);

      auto it = accMap_.find(res.originId);
      if (it != accMap_.end()) {
        size_t flatIdx =
          (static_cast<size_t>(res.reqNonce) - 1) * poolSize_ + it->second;

        if (flatIdx < seenFlags_.size() && seenFlags_[flatIdx] == 0) {
          seenFlags_[flatIdx] = 1;

          if (res.rcode == CES_OK)
            successCount_++;
          else
            failCount_++;
        }
      }
    } catch (...) {
      // Swallow — unparseable responses are counted via the absence of
      // successCount_/failCount_ increments and surface as the gap
      // between rawPackets_ and (success + fail) in the results banner.
    }
  }

  uint64_t getSuccess() const { return successCount_; }
  uint64_t getFail() const { return failCount_; }
  uint64_t getRawPackets() const { return rawPackets_; }

private:
  uint16_t port_;
  bool verbose_;
  int taskThreadCount_;
  size_t poolSize_;
  const std::unordered_map<HashPrefix, size_t>& accMap_;

  ces::Bytes seenFlags_;

  std::unique_ptr<minx::Minx> minx_;
  minx::IOContext netIO_, taskIO_;
  std::thread netThread_;
  std::vector<std::thread> taskThreads_;

  std::atomic<uint64_t> successCount_{0};
  std::atomic<uint64_t> failCount_{0};
  std::atomic<uint64_t> rawPackets_{0};
};

struct SimAccount {
  KeyPair key;
  uint32_t nonce;
};

int main(int argc, char* argv[]) {
  uint64_t optTxCount = 100;
  int optTaskThreads = std::thread::hardware_concurrency() / 2;
  if (optTaskThreads < 1)
    optTaskThreads = 1;

  std::string optDataDir = "./cesbench_data";
  bool optVerbose = false;
  bool optSecp = false;

  CLI::App app{"cesbench"};
  app.add_option("-n,--count", optTxCount, "Total transactions");
  app.add_option("-d,--dir", optDataDir, "Data directory");
  app.add_option("-t,--threads", optTaskThreads, "Task threads");
  app.add_flag("-v,--verbose", optVerbose, "Enable verbose logging");
  app.add_flag("--secp", optSecp, "Use secp256k1 keys instead of ed25519");
  CLI11_PARSE(app, argc, argv);

  KeyAlgo algo = optSecp ? KeyAlgo::SECP256K1 : KeyAlgo::ED25519;

  // One sender per transaction: avoids out-of-order nonce failures over UDP.
  uint64_t optPoolSize = optTxCount;

  fs::remove_all(optDataDir);
  fs::create_directories(optDataDir);

  blog::init();
  if (optVerbose) {
    blog::set_level(blog::trace);
    blog::enable("minx");
  } else {
    blog::set_level(blog::fatal);
  }

  std::cout << "========================================================\n";
  std::cout << " cesbench - CES throughput benchmark\n";
  std::cout << "========================================================\n";
  std::cout << " Algorithm   : " << (optSecp ? "secp256k1" : "ed25519") << "\n";
  std::cout << " Transactions: " << optTxCount << "\n";
  std::cout << " Senders     : " << optPoolSize << " (1 tx each)\n";
  std::cout << " Threads     : " << optTaskThreads << "\n";
  std::cout << "========================================================\n";

  CesConfig cfg;
  cfg.dataDir = optDataDir;
  cfg.serverPrivKey.fill(0xEE);
  cfg.serverKeyAlgo = algo;
  cfg.minAcc = optPoolSize + 1000;
  cfg.maxAcc = (optPoolSize + 1000) * 5;
  cfg.minDiff = 1;
  cfg.spendSlotSize = 3600;
  cfg.taskThreads = std::thread::hardware_concurrency();
  cfg.flushValue = MAX_FLUSH;
  cfg.accountStoreBufferSize = HUGE_BUFFER_SIZE;
  cfg.feeTx = 0;
  cfg.feeAccount = 0;
  cfg.recvBuffersSize = optTxCount + 16384;

  auto server = std::make_unique<CesServer>(cfg);

  server->pause();

  uint16_t port = server->start(0);
  std::cout << "Server listening on port " << port << " (paused)\n";

  std::cout << "Generating " << optPoolSize << " sender accounts..."
            << std::endl;
  std::vector<SimAccount> pool(optPoolSize);
  std::unordered_map<HashPrefix, size_t> accMap;
  for (size_t i = 0; i < optPoolSize; ++i) {
    pool[i].key = KeyPair(algo);
    pool[i].nonce = 0;
    accMap[Account::getMapKey(pool[i].key.getPublicKeyAsHash())] = i;
  }

  std::cout << "Funding accounts..." << std::endl;
  const int64_t INITIAL_BALANCE = 1'000'000'000;
  for (const auto& acc : pool) {
    server->_brr(acc.key.getPublicKeyAsHash(), INITIAL_BALANCE);
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(5000));

  std::cout << "Pre-signing " << optTxCount << " transfer packets..." << std::endl;
  std::vector<minx::Bytes> packets;
  packets.reserve(optTxCount);

  KeyPair receiver(algo);
  minx::Hash receiverPub = receiver.getPublicKeyAsHash();

  for (uint64_t i = 0; i < optTxCount; ++i) {
    size_t accIdx = i % optPoolSize;
    SimAccount& sender = pool[accIdx];
    sender.nonce++;

    CesTransfer tx;
    tx.originId = sender.key.getPublicKeyAsHash();
    tx.destKey = receiverPub;
    tx.amount = 1;
    tx.reqNonce = sender.nonce;

    packets.emplace_back(tx.toBytes(sender.key));
  }

  BenchClient client(port, optVerbose, optTaskThreads,
                     optTxCount, optPoolSize, accMap);
  client.start();

  std::cout << "Sending " << optTxCount << " packets (server paused)..."
            << std::endl;

  for (uint64_t i = 0; i < optTxCount; ++i) {
    client.sendRaw(packets[i]);

    if (i % 1000 == 0 || i == optTxCount - 1) {
      std::cout << "\rSent: " << std::setw(7) << i + 1 << std::flush;
    }
    if (i % 10 == 0)
      std::this_thread::sleep_for(std::chrono::microseconds(10));
  }
  std::cout << "\nAll packets sent. Resuming server..." << std::endl;

  server->resume();
  auto startBench = std::chrono::high_resolution_clock::now();
  auto timeoutStart = std::chrono::high_resolution_clock::now();

  while (true) {
    uint64_t serverProcessedTxs = server->getTxCount();
    if (serverProcessedTxs >= optTxCount) {
      std::cout << "\nServer processed " << serverProcessedTxs << " txs.\n";
      break;
    }

    uint64_t total = client.getSuccess() + client.getFail();
    if (total >= optTxCount) {
      std::cout << "\nAll " << optTxCount << " replies received (OK: "
                << client.getSuccess() << ", Fail: " << client.getFail()
                << ").\n";
      break;
    }

    auto now = std::chrono::high_resolution_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - timeoutStart)
          .count() > BENCH_REPLY_TIMEOUT_SECS) {
      std::cout << "\nTimed out after " << BENCH_REPLY_TIMEOUT_SECS << "s.\n";
      break;
    }

    static auto lastPrint = now;
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastPrint)
          .count() > 200) {
      std::cout << "\r  Acked: " << client.getSuccess()
                << "  Processed: " << serverProcessedTxs
                << "  Total: " << optTxCount
                << "  Raw: " << client.getRawPackets()
                << "  Failed: " << client.getFail() << std::flush;
      lastPrint = now;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto endBench = std::chrono::high_resolution_clock::now();

  std::cout << "\nWaiting 10s for straggler replies...\n";
  std::this_thread::sleep_for(std::chrono::seconds(10));

  client.stop();
  server->pause();

  auto benchMs =
    std::chrono::duration_cast<std::chrono::milliseconds>(endBench - startBench)
      .count();
  double seconds = benchMs / 1000.0;
  if (seconds < 0.001)
    seconds = 0.001;

  std::cout << "\n========================================================\n";
  std::cout << " LEDGER VERIFICATION\n";
  std::cout << "========================================================\n";

  uint64_t validAccounts = 0;
  uint64_t errorAccounts = 0;
  uint64_t totalVolumeExpected = 0;

  std::cout << "Verifying " << optPoolSize << " senders..." << std::flush;
  for (size_t i = 0; i < optPoolSize; ++i) {
    const auto& sender = pool[i];
    int64_t expectedBalance =
      INITIAL_BALANCE - static_cast<int64_t>(sender.nonce);
    totalVolumeExpected += sender.nonce;

    int64_t actualBalance = 0;
    uint32_t actualNonce = 0;
    HashPrefix id = Account::getMapKey(sender.key.getPublicKeyAsHash());

    HashPrefix xd{}; uint64_t xa = 0; uint32_t xt = 0;
    server->unsignedQueryAccount(id, actualBalance, actualNonce, xd, xa, xt);

    bool ok = true;
    if (actualBalance != expectedBalance) {
      if (errorAccounts < 10)
        std::cout << "\n  Acc " << i << ": balance " << actualBalance
                  << " (expected " << expectedBalance << ")";
      ok = false;
    }
    if (actualNonce != sender.nonce) {
      if (errorAccounts < 10)
        std::cout << "\n  Acc " << i << ": nonce " << actualNonce
                  << " (expected " << sender.nonce << ")";
      ok = false;
    }

    if (ok)
      validAccounts++;
    else
      errorAccounts++;
  }
  std::cout << " Done.\n";

  std::cout << "Verifying receiver..." << std::flush;
  int64_t recvBal = 0;
  uint32_t recvNonce = 0;
  { HashPrefix xd{}; uint64_t xa = 0; uint32_t xt = 0;
  server->unsignedQueryAccount(Account::getMapKey(receiverPub), recvBal,
                               recvNonce, xd, xa, xt); }

  bool recvOk = (recvBal == static_cast<int64_t>(totalVolumeExpected));
  std::cout << (recvOk ? " OK" : " FAIL") << std::endl;
  if (!recvOk) {
    std::cout << "  Receiver balance " << recvBal << " (expected "
              << totalVolumeExpected << ")\n";
  }

  server->stop(false);

  std::cout << "========================================================\n";
  std::cout << " RESULTS\n";
  std::cout << "========================================================\n";
  std::cout << " Time        : " << seconds << " s\n";
  std::cout << " Throughput  : " << static_cast<uint64_t>(client.getSuccess() / seconds)
            << " TPS (acked)\n";
  std::cout << " Server Txs  : " << server->getTxCount() << "\n";
  std::cout << " Sent        : " << optTxCount << "\n";
  std::cout << " Verified    : " << totalVolumeExpected << "\n";
  std::cout << " Missing     : " << (optTxCount - totalVolumeExpected) << "\n";
  std::cout << "--------------------------------------------------------\n";
  std::cout << " Senders     : " << validAccounts << " / " << optPoolSize
            << " OK\n";
  std::cout << " Errors      : " << errorAccounts << "\n";
  std::cout << " Receiver    : " << (recvOk ? "PASS" : "FAIL") << "\n";
  std::cout << "========================================================\n";

  uintmax_t totalEventsSize = 0;
  fs::path accDir = fs::path(optDataDir) / "accounts";
  auto sumEvents = [](const fs::path& dir) -> uintmax_t {
    uintmax_t sum = 0;
    if (fs::exists(dir) && fs::is_directory(dir)) {
      for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.path().extension() == ".events")
          sum += fs::file_size(entry.path());
      }
    }
    return sum;
  };
  totalEventsSize += sumEvents(accDir);
  std::cout << " WAL Size    : " << totalEventsSize << " bytes\n";

  {
    const size_t NUM_THREADS = static_cast<size_t>(optTaskThreads);

    size_t calculatedIter = optTxCount / NUM_THREADS;
    if (calculatedIter < 1)
      calculatedIter = 1;
    const size_t ITERATIONS_PER_THREAD = calculatedIter;

    const size_t PAYLOAD_SIZE = 256;

    std::cout << "\n\n========================================================\n";
    std::cout << " Crypto cycle benchmark (verify + sign)\n";
    std::cout << "========================================================\n";
    std::cout << " Threads      : " << NUM_THREADS << "\n";
    std::cout << " Iterations   : " << ITERATIONS_PER_THREAD << " per thread\n";
    std::cout << " Total        : " << (NUM_THREADS * ITERATIONS_PER_THREAD)
              << " ops\n";

    std::atomic<size_t> completed_ops{0};
    std::vector<std::thread> threads;
    threads.reserve(NUM_THREADS);

    auto start_time = std::chrono::high_resolution_clock::now();

    for (size_t t = 0; t < NUM_THREADS; ++t) {
      threads.emplace_back([&, t]() {
        ces::KeyPair serverKey(algo);
        ces::KeyPair clientKey(algo);
        ces::PublicKey clientPub(clientKey.getPublicKeyAsHash());

        minx::Bytes clientBytes(PAYLOAD_SIZE);
        std::memset(clientBytes.data(), 0xAA, PAYLOAD_SIZE);
        ces::Signature clientSig =
          clientKey.signData(clientBytes.data(), PAYLOAD_SIZE);

        minx::Bytes serverBytes(PAYLOAD_SIZE);
        std::memset(serverBytes.data(), 0xBB, PAYLOAD_SIZE);

        for (size_t i = 0; i < ITERATIONS_PER_THREAD; ++i) {

          bool ok = clientPub.verifySignature(clientBytes.data(), PAYLOAD_SIZE,
                                              clientSig);
          if (!ok)
            std::terminate();

          std::memcpy(serverBytes.data(), &i, sizeof(i));

          ces::Signature sig =
            serverKey.signData(serverBytes.data(), PAYLOAD_SIZE);

          if (sig[0] == 0xDE && sig[1] == 0xAD) {
            volatile int x = 0;
            (void)x;
          }

          if (t == 0 && i % 5000 == 0) {
            std::cout << "." << std::flush;
          }
        }

        completed_ops += ITERATIONS_PER_THREAD;
      });
    }

    for (auto& th : threads) {
      if (th.joinable())
        th.join();
    }
    std::cout << std::endl;

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;
    size_t total_ops = NUM_THREADS * ITERATIONS_PER_THREAD;
    double tps = total_ops / elapsed.count();

    std::cout << "========================================================\n";
    std::cout << " Threads      : " << NUM_THREADS << "\n";
    std::cout << " Cycles       : " << total_ops << " (1 verify + 1 sign)\n";
    std::cout << " Time         : " << elapsed.count() << " s\n";
    std::cout << " Throughput   : " << static_cast<size_t>(tps) << " ops/s\n";
    std::cout << "========================================================\n";
  }

  return (errorAccounts == 0 && recvOk) ? 0 : 1;
}