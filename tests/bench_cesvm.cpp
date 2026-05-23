/**
 * CesVM opcode/syscall benchmark.
 *
 * Runs each opcode and syscall in a tight loop, measures wall-clock time,
 * and reports nanoseconds per iteration and relative cost vs baseline (ADD).
 *
 * Build: cmake target "cesvmbench" (in tests/)
 * Run:   ./cesvmbench
 *
 * This is NOT a unit test — it produces human-readable benchmark output.
 */

#include <ces/cesvm.h>
#include <ces/buffer.h>
#include <ces/keys.h>
#include <ces/types.h>

#include <cryptopp/sha.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <minx/blog.h>

using namespace ces;

// Opcodes and encoding constants live in cesvm.h as of the B9 cleanup.
static uint8_t sv(uint8_t val) {
  return static_cast<uint8_t>(CESVM_SHORT_VAL | (val & CESVM_MAX_SHORT_VAL));
}
static uint8_t rp(uint8_t val) {
  return static_cast<uint8_t>(CESVM_REG_PTR | CESVM_SHORT_VAL |
                               (val & CESVM_MAX_SHORT_VAL));
}
static constexpr uint8_t STACK = CESVM_OP_STACK;

static void push2(ces::Bytes& code, uint16_t val) {
  code.push_back(2);
  ces::Buffer::putLE<uint16_t>(code, val);
}

static void push4(ces::Bytes& code, uint32_t val) {
  code.push_back(4);
  ces::Buffer::putLE<uint32_t>(code, val);
}

// Null host for benchmarks: every read returns plausible-looking data and
// every write succeeds. Subclass of CesVMHost so calls go through the
// vtable just like the production CesServer::VmHost.
struct NullVmHost : CesVMHost {
  int64_t  readAccountBalance(const HashPrefix&) override { return 1000000; }
  uint32_t readAccountNonce  (const HashPrefix&) override { return 0; }
  bool readAsset(const minx::Hash&, HashPrefix& owner, AssetData& content,
                 uint16_t& balance, uint32_t& price) override {
    owner.fill(0x11);
    content.fill(0x22);
    balance = 100;
    price = 0;
    return true;
  }
  uint8_t transfer    (const minx::Hash&, uint64_t)              override { return CES_OK; }
  uint8_t createAsset (const minx::Hash&, const AssetData&, uint16_t) override { return CES_OK; }
  uint8_t updateAsset (const minx::Hash&, const AssetData&)      override { return CES_OK; }
  uint8_t fundAsset   (const minx::Hash&, uint16_t)              override { return CES_OK; }
  uint8_t buyAsset    (const minx::Hash&, uint64_t)              override { return CES_OK; }
  uint8_t giveAsset   (const minx::Hash&, const HashPrefix&)     override { return CES_OK; }
  void    sendUdp     (const std::string&, uint16_t, const uint8_t*, size_t) override {}
  uint8_t crossTransfer(const minx::Hash&, uint64_t, const std::string&)     override { return CES_OK; }
  uint8_t debitCaller (uint64_t) override                                     { return CES_OK; }
  bool    verifySig   (const uint8_t*, size_t, const uint8_t*, const uint8_t*) override { return true; }
};

static NullVmHost makeNullHost() {
  NullVmHost host;
  host.callerKey.fill(0xAA);
  host.selfAssetKey.fill(0xBB);
  return host;
}

// Build a program that loops N times executing the body, then TERMs.
// Body is inserted at a known position. Loop structure:
//   SET io[8] = N
//   <body>           ← bodyStart
//   DEC io[8]
//   JT io[8], bodyStart
//   TERM
// Encode index 200 as a 2-byte non-short operand (for SET/DEC target)
static void pushIdx200(ces::Bytes& code) {
  code.push_back(2);   // control: 2 bytes follow, no regptr, no shortval
  code.push_back(200);
  code.push_back(0);
}
// Encode dereferenced io[200] as a 2-byte regptr operand (for JT condition)
static void pushDeref200(ces::Bytes& code) {
  code.push_back(0x82); // control: regptr=1, shortval=0, 2 bytes follow
  code.push_back(200);
  code.push_back(0);
}

static ces::Bytes makeLoop(uint32_t n, const ces::Bytes& body) {
  ces::Bytes code;
  // Use io[200] as loop counter — safely above any benchmark operand range
  code.push_back(OP_SET);
  pushIdx200(code);
  if (n <= 63) {
    code.push_back(sv(n));
  } else if (n <= 65535) {
    push2(code, static_cast<uint16_t>(n));
  } else {
    push4(code, n);
  }
  uint16_t bodyStart = static_cast<uint16_t>(code.size());
  code.insert(code.end(), body.begin(), body.end());
  // DEC io[200]
  code.push_back(OP_DEC);
  pushIdx200(code);
  // JT io[200], bodyStart
  code.push_back(OP_JT);
  pushDeref200(code);
  ces::Buffer::putLE<uint16_t>(code, bodyStart);
  code.push_back(OP_TERM);
  return code;
}

struct BenchResult {
  std::string name;
  double nsPerIter;
  uint64_t opsExecuted;
  uint64_t budgetUsed;
};

static BenchResult runBench(const std::string& name, uint32_t iters,
                            const ces::Bytes& body,
                            CesVMHost& host,
                            uint64_t budget = 0) {
  if (budget == 0) budget = static_cast<uint64_t>(iters) * 10000 + 1000000;
  auto code = makeLoop(iters, body);
  CesVM vm;

  // Warmup
  vm.execute(code, host, budget);

  // Timed run
  auto t0 = std::chrono::high_resolution_clock::now();
  auto result = vm.execute(code, host, budget);
  auto t1 = std::chrono::high_resolution_clock::now();

  double totalNs = std::chrono::duration<double, std::nano>(t1 - t0).count();

  if (result.error != CESVM_OK) {
    std::cerr << "  WARNING: " << name << " ended with error " << result.error
              << " after " << result.opsExecuted << " ops\n";
  }

  // Subtract loop overhead: each iteration = body + DEC + JT = 3 loop ops
  // Total ops = iters * (bodyOps + 3) + setup + TERM
  double nsPerIter = totalNs / iters;

  return {name, nsPerIter, result.opsExecuted, result.budgetUsed};
}

// Same as runBench but for syscalls — the body sets up syscall args + HOST
static BenchResult runSyscallBench(const std::string& name, uint32_t iters,
                                    uint8_t syscallNum,
                                    const ces::Bytes& argSetup,
                                    CesVMHost& host) {
  ces::Bytes body;
  // SET io[3] = syscallNum
  body.push_back(OP_SET);
  body.push_back(sv(3));
  body.push_back(sv(syscallNum));
  // Arg setup
  body.insert(body.end(), argSetup.begin(), argSetup.end());
  // HOST
  body.push_back(OP_HOST);
  return runBench(name, iters, body, host);
}

int main() {
  blog::init();
  blog::set_level(blog::none);
  constexpr uint32_t N = 1'000'000;

  auto host = makeNullHost();

  std::vector<BenchResult> results;

  std::cout << "CesVM Benchmark — " << N << " iterations per test\n";
  std::cout << std::string(72, '=') << "\n\n";

  // ---- OPCODES ----
  std::cout << "OPCODES:\n";

  // Sanity check
  {
    auto code = makeLoop(3, {OP_NOP});
    CesVM vm;
    auto r = vm.execute(code, host, 100000);
    if (r.error != CESVM_OK || r.opsExecuted != 11) {
      std::cerr << "SANITY FAIL: error=" << r.error << " ops=" << r.opsExecuted << "\n";
      return 1;
    }
  }

  // Baseline: empty body (loop overhead only)
  results.push_back(runBench("(loop overhead)", N, {}, host));

  // NOP
  results.push_back(runBench("NOP", N, {OP_NOP}, host));

  // ADD (register mode)
  results.push_back(runBench("ADD reg", N, {OP_ADD, sv(16), sv(17)}, host));

  // ADD (stack mode)
  results.push_back(runBench("ADD stack", N, {
    OP_PUSH, sv(10), OP_PUSH, sv(20),
    static_cast<uint8_t>(OP_ADD | STACK),
    OP_POP, sv(9)  // pop result to avoid stack growth
  }, host));

  // SUB
  results.push_back(runBench("SUB reg", N, {OP_SUB, sv(17), sv(16)}, host));

  // MUL
  results.push_back(runBench("MUL reg", N, {OP_MUL, sv(16), sv(17)}, host));

  // DIV
  results.push_back(runBench("DIV reg", N, {
    OP_SET, sv(16), sv(42), OP_SET, sv(17), sv(7),
    OP_DIV, sv(16), sv(17)
  }, host));

  // MOD
  results.push_back(runBench("MOD reg", N, {
    OP_SET, sv(16), sv(42), OP_SET, sv(17), sv(7),
    OP_MOD, sv(16), sv(17)
  }, host));

  // EQ
  results.push_back(runBench("EQ reg", N, {OP_EQ, sv(16), sv(17)}, host));

  // GT
  results.push_back(runBench("GT reg", N, {OP_GT, sv(16), sv(17)}, host));

  // AND (bitwise)
  results.push_back(runBench("AND reg", N, {OP_AND, sv(16), sv(17)}, host));

  // OR (bitwise)
  results.push_back(runBench("OR reg", N, {OP_OR, sv(16), sv(17)}, host));

  // XOR
  results.push_back(runBench("XOR reg", N, {OP_XOR, sv(16), sv(17)}, host));

  // SHL
  results.push_back(runBench("SHL reg", N, {OP_SHL, sv(16), sv(3)}, host));

  // SHR
  results.push_back(runBench("SHR reg", N, {OP_SHR, sv(16), sv(3)}, host));

  // NOT
  results.push_back(runBench("NOT reg", N, {OP_NOT, sv(16)}, host));

  // NEG (bitwise negate)
  results.push_back(runBench("NEG reg", N, {OP_NEG, sv(16)}, host));

  // INC
  results.push_back(runBench("INC", N, {OP_INC, sv(16)}, host));

  // DEC
  results.push_back(runBench("DEC", N, {OP_DEC, sv(16)}, host));

  // SET
  results.push_back(runBench("SET", N, {OP_SET, sv(16), sv(42)}, host));

  // PUSH+POP
  results.push_back(runBench("PUSH+POP", N, {OP_PUSH, sv(42), OP_POP, sv(16)}, host));

  // CALL+RET — CALL jumps to a RET function at end of code, returns to DEC
  {
    ces::Bytes code;
    // SET io[200] = N
    code.push_back(OP_SET);
    pushIdx200(code);
    push4(code, N);
    // Loop body: CALL <funcAddr> (will be patched)
    uint16_t bodyStart = static_cast<uint16_t>(code.size());
    size_t callAddrPatch = code.size() + 1;
    code.push_back(OP_CALL);
    code.push_back(0x00);
    code.push_back(0x00);
    // After CALL returns here: DEC io[200], JT loop
    code.push_back(OP_DEC);
    pushIdx200(code);
    code.push_back(OP_JT);
    pushDeref200(code);
    ces::Buffer::putLE<uint16_t>(code, bodyStart);
    code.push_back(OP_TERM);
    // Function: just RET 0
    uint16_t funcAddr = static_cast<uint16_t>(code.size());
    code.push_back(OP_RET);
    code.push_back(sv(0));
    // Patch CALL target
    ces::Buffer::pokeLE<uint16_t>(code.data() + callAddrPatch, funcAddr);

    uint64_t bigBudget = static_cast<uint64_t>(N) * 10000 + 1000000;
    CesVM vm;
    vm.execute(code, host, bigBudget);
    auto t0 = std::chrono::high_resolution_clock::now();
    auto result = vm.execute(code, host, bigBudget);
    auto t1 = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
    results.push_back({"CALL+RET", ns / N, result.opsExecuted, result.budgetUsed});
  }

  // RND
  results.push_back(runBench("RND", N, {OP_RND}, host));

  // TIME
  results.push_back(runBench("TIME", N, {OP_TIME}, host));

  // LDB
  results.push_back(runBench("LDB", N, {OP_LDB, sv(24)}, host));

  // STB
  results.push_back(runBench("STB", N, {OP_STB, sv(24), sv(42)}, host));

  // MOV 1 cell
  results.push_back(runBench("MOV 1 cell", N, {OP_MOV, sv(20), sv(16), sv(1)}, host));

  // MOV 4 cells
  results.push_back(runBench("MOV 4 cells", N, {OP_MOV, sv(20), sv(16), sv(4)}, host));

  // MOV 32 cells (256 bytes)
  results.push_back(runBench("MOV 32 cells", N, {OP_MOV, sv(20), sv(16), sv(32)}, host));

  // CMP 1 cell
  results.push_back(runBench("CMP 1 cell", N, {OP_CMP, sv(16), sv(20), sv(1)}, host));

  // CMP 4 cells
  results.push_back(runBench("CMP 4 cells", N, {OP_CMP, sv(16), sv(20), sv(4)}, host));

  // FIL 1 cell
  results.push_back(runBench("FIL 1 cell", N, {OP_FIL, sv(16), sv(42), sv(1)}, host));

  // FIL 32 cells
  results.push_back(runBench("FIL 32 cells", N, {OP_FIL, sv(16), sv(42), sv(32)}, host));

  // ---- SYSCALLS ----
  std::cout << "\nSYSCALLS:\n";

  // SYS_NOP
  results.push_back(runSyscallBench("SYS_NOP", N, SYS_NOP, {}, host));

  // SYS_READ_ACCOUNT
  results.push_back(runSyscallBench("SYS_READ_ACCOUNT", N, SYS_READ_ACCOUNT, {
    OP_SET, sv(4), sv(16)  // prefix ptr
  }, host));

  // SYS_TRANSFER
  results.push_back(runSyscallBench("SYS_TRANSFER", N, SYS_TRANSFER, {
    OP_SET, sv(4), sv(16),  // dest key ptr
    OP_SET, sv(5), sv(42),  // amount
  }, host));

  // SYS_READ_ASSET
  results.push_back(runSyscallBench("SYS_READ_ASSET", N, SYS_READ_ASSET, {
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(24),  // owner out ptr
    OP_SET, sv(6), sv(48),  // content out ptr
  }, host));

  // SYS_CREATE_ASSET_RANDOM
  results.push_back(runSyscallBench("SYS_CREATE_ASSET_RND", N, SYS_CREATE_ASSET_RANDOM, {
    OP_SET, sv(4), sv(48),  // content ptr
    OP_SET, sv(5), sv(30),  // days
    OP_SET, sv(6), sv(16),  // key out ptr
  }, host));

  // SYS_UPDATE_ASSET
  results.push_back(runSyscallBench("SYS_UPDATE_ASSET", N, SYS_UPDATE_ASSET, {
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(48),  // content ptr
  }, host));

  // SYS_FUND_ASSET
  results.push_back(runSyscallBench("SYS_FUND_ASSET", N, SYS_FUND_ASSET, {
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(10),  // days
  }, host));

  // SYS_BUY_ASSET
  results.push_back(runSyscallBench("SYS_BUY_ASSET", N, SYS_BUY_ASSET, {
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(50),  // max price
  }, host));

  // SYS_GIVE_ASSET
  results.push_back(runSyscallBench("SYS_GIVE_ASSET", N, SYS_GIVE_ASSET, {
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(24),  // new owner ptr
  }, host));

  // SYS_SEND_UDP
  results.push_back(runSyscallBench("SYS_SEND_UDP", N, SYS_SEND_UDP, {
    OP_SET, sv(4), sv(16),  // addr ptr
    OP_SET, sv(5), sv(80),  // port
    OP_SET, sv(6), sv(24),  // data ptr
    OP_SET, sv(7), sv(8),   // data len
  }, host));

  // SYS_HASH (8 bytes)
  results.push_back(runSyscallBench("SYS_HASH 8B", N, SYS_HASH, {
    OP_SET, sv(4), sv(16),  // data ptr
    OP_SET, sv(5), sv(8),   // len
    OP_SET, sv(6), sv(24),  // out ptr
  }, host));

  // SYS_HASH (256 bytes)
  results.push_back(runSyscallBench("SYS_HASH 256B", std::max(N / 10, 1u), SYS_HASH, {
    OP_SET, sv(4), sv(16),
    OP_SET, sv(5), sv(0),   // need >63: use 2-byte encoding
  }, host));
  // Fix: can't set 256 with sv(). Build manually.
  {
    ces::Bytes body;
    body.push_back(OP_SET); body.push_back(sv(3)); body.push_back(sv(SYS_HASH));
    body.push_back(OP_SET); body.push_back(sv(4)); body.push_back(sv(16));
    // SET io[5] = 256
    body.push_back(OP_SET); body.push_back(sv(5));
    push2(body, 256);
    body.push_back(OP_SET); body.push_back(sv(6)); body.push_back(sv(48));
    body.push_back(OP_HOST);
    results.back() = runBench("SYS_HASH 256B", std::max(N / 10, 1u), body, host);
  }

  // SYS_HASH (1024 bytes)
  {
    ces::Bytes body;
    body.push_back(OP_SET); body.push_back(sv(3)); body.push_back(sv(SYS_HASH));
    body.push_back(OP_SET); body.push_back(sv(4)); body.push_back(sv(16));
    body.push_back(OP_SET); body.push_back(sv(5));
    push2(body, 1024);
    body.push_back(OP_SET); body.push_back(sv(6)); body.push_back(sv(48));
    body.push_back(OP_HOST);
    results.push_back(runBench("SYS_HASH 1024B", std::max(N / 10, 1u), body, host));
  }

  // SYS_VERIFY_SIG (32 bytes data)
  results.push_back(runSyscallBench("SYS_VERIFY_SIG 32B", std::max(N / 100, 1u), SYS_VERIFY_SIG, {
    OP_SET, sv(4), sv(16),  // data ptr
    OP_SET, sv(5), sv(32),  // data len
    OP_SET, sv(6), sv(24),  // sig ptr
    OP_SET, sv(7), sv(36),  // pubkey ptr
  }, host));

  // SYS_CROSS_TRANSFER
  results.push_back(runSyscallBench("SYS_CROSS_TRANSFER", N, SYS_CROSS_TRANSFER, {
    OP_SET, sv(4), sv(16),  // dest key ptr
    OP_SET, sv(5), sv(50),  // amount
    OP_SET, sv(6), sv(24),  // server addr ptr
  }, host));

  // SYS_LOAD_CODE (asset found)
  results.push_back(runSyscallBench("SYS_LOAD_CODE", 30, SYS_LOAD_CODE, {
    OP_SET, sv(4), sv(16),  // key ptr (readAsset returns true)
  }, host));

  // SYS_CREATE_ASSET
  results.push_back(runSyscallBench("SYS_CREATE_ASSET", N, SYS_CREATE_ASSET, {
    OP_SET, sv(4), sv(16),  // key ptr
    OP_SET, sv(5), sv(48),  // content ptr
    OP_SET, sv(6), sv(10),  // days
  }, host));

  // ---- REPORT ----
  std::cout << "\n" << std::string(72, '=') << "\n";
  std::cout << std::left << std::setw(25) << "Operation"
            << std::right << std::setw(12) << "ns/iter"
            << std::setw(10) << "rel"
            << std::setw(15) << "ops"
            << std::setw(15) << "budget"
            << "\n";
  std::cout << std::string(72, '-') << "\n";

  // Find ADD reg as baseline
  double baseline = 0;
  for (auto& r : results) {
    if (r.name == "ADD reg") {
      baseline = r.nsPerIter;
      break;
    }
  }
  if (baseline <= 0) baseline = 1;

  for (auto& r : results) {
    std::cout << std::left << std::setw(25) << r.name
              << std::right << std::fixed << std::setprecision(1)
              << std::setw(12) << r.nsPerIter
              << std::setw(10) << (r.nsPerIter / baseline)
              << std::setw(15) << r.opsExecuted
              << std::setw(15) << r.budgetUsed
              << "\n";
  }

  std::cout << "\nBaseline (ADD reg) = " << std::fixed << std::setprecision(1)
            << baseline << " ns/iter\n";

  // ---- RAW CRYPTO BENCHMARKS ----
  std::cout << "\n" << std::string(72, '=') << "\n";
  std::cout << "RAW CRYPTO (outside VM, direct API calls):\n";
  std::cout << std::string(72, '-') << "\n";

  constexpr int CRYPTO_ITERS = 10000;

  // Prepare test data
  ces::Bytes testData(32, 0x42);

  // ED25519 sign + verify
  {
    ces::KeyPair kp(ces::KeyAlgo::ED25519);
    // Sign benchmark
    auto data_span = std::span<const uint8_t>(testData.data(), testData.size());
    auto t0 = std::chrono::high_resolution_clock::now();
    ces::Signature lastSig;
    for (int i = 0; i < CRYPTO_ITERS; ++i) {
      lastSig = kp.signData(data_span);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double signNs = std::chrono::duration<double, std::nano>(t1 - t0).count() / CRYPTO_ITERS;

    // Verify benchmark
    ces::PublicKey pk(kp.getPublicKeyAsHash());

    t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < CRYPTO_ITERS; ++i) {
      pk.verifySignature(data_span, lastSig);
    }
    t1 = std::chrono::high_resolution_clock::now();
    double verifyNs = std::chrono::duration<double, std::nano>(t1 - t0).count() / CRYPTO_ITERS;

    std::cout << std::left << std::setw(25) << "ED25519 sign"
              << std::right << std::fixed << std::setprecision(1)
              << std::setw(12) << signNs << " ns"
              << std::setw(10) << (signNs / baseline) << "x\n";
    std::cout << std::left << std::setw(25) << "ED25519 verify"
              << std::right << std::setw(12) << verifyNs << " ns"
              << std::setw(10) << (verifyNs / baseline) << "x\n";
  }

  // SECP256K1 sign + verify
  {
    ces::KeyPair kp(ces::KeyAlgo::SECP256K1);
    // Sign benchmark
    auto data_span = std::span<const uint8_t>(testData.data(), testData.size());
    auto t0 = std::chrono::high_resolution_clock::now();
    ces::Signature lastSig;
    for (int i = 0; i < CRYPTO_ITERS; ++i) {
      lastSig = kp.signData(data_span);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double signNs = std::chrono::duration<double, std::nano>(t1 - t0).count() / CRYPTO_ITERS;

    // Verify benchmark
    ces::PublicKey pk(kp.getPublicKeyAsHash());

    t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < CRYPTO_ITERS; ++i) {
      pk.verifySignature(data_span, lastSig);
    }
    t1 = std::chrono::high_resolution_clock::now();
    double verifyNs = std::chrono::duration<double, std::nano>(t1 - t0).count() / CRYPTO_ITERS;

    std::cout << std::left << std::setw(25) << "SECP256K1 sign"
              << std::right << std::fixed << std::setprecision(1)
              << std::setw(12) << signNs << " ns"
              << std::setw(10) << (signNs / baseline) << "x\n";
    std::cout << std::left << std::setw(25) << "SECP256K1 verify"
              << std::right << std::setw(12) << verifyNs << " ns"
              << std::setw(10) << (verifyNs / baseline) << "x\n";
  }

  // SHA256 at various sizes (raw, outside VM)
  {
    CryptoPP::SHA256 hash;
    uint8_t digest[32];

    for (size_t sz : {32, 256, 1024}) {
      ces::Bytes data(sz, 0x42);
      auto t0 = std::chrono::high_resolution_clock::now();
      for (int i = 0; i < CRYPTO_ITERS * 10; ++i) {
        hash.CalculateDigest(digest, data.data(), data.size());
      }
      auto t1 = std::chrono::high_resolution_clock::now();
      double ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / (CRYPTO_ITERS * 10);

      std::string name = "SHA256 " + std::to_string(sz) + "B";
      std::cout << std::left << std::setw(25) << name
                << std::right << std::fixed << std::setprecision(1)
                << std::setw(12) << ns << " ns"
                << std::setw(10) << (ns / baseline) << "x\n";
    }
  }

  return 0;
}
