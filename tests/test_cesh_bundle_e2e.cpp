/**
 * E2E tests for `cesh asset deploy-bundle`.
 *
 * Compiles a program with the cesc binary (--bundle), deploys the
 * resulting directory through the cesh binary, and executes it on an
 * in-process server via `cesh asset run`.
 */

#include "test_e2e_common.h"

#include <ces/lang/cesl.h>

#include <fstream>

using namespace ces::e2e;

namespace {

// Compiles past the 210-byte boot block (pinned by a BOOST_REQUIRE), so
// cesc --bundle emits chunks and key tables and deploy-bundle exercises
// the full manifest walk. Expected output:
//   sum_series(10)    = sum of 3i+1 for i in 0..9 = 145
//   triple_plus(1000) = 3001
//   gcd(462, 1071)    = 21
//   collatz_steps(27) = 111
const char* kBigSource = R"(
fn triple_plus(x) {
  return x * 3 + 1;
}

fn sum_series(n) {
  let acc = 0;
  let i = 0;
  while (i < n) {
    acc = acc + triple_plus(i);
    i = i + 1;
  }
  return acc;
}

fn gcd(a, b) {
  while (b != 0) {
    let t = a % b;
    a = b;
    b = t;
  }
  return a;
}

fn collatz_steps(n) {
  let steps = 0;
  while (n != 1) {
    if (n % 2 == 0) {
      n = n / 2;
    } else {
      n = triple_plus(n);
    }
    steps = steps + 1;
  }
  return steps;
}

output[0] = sum_series(10);
output[1] = triple_plus(1000);
output[2] = gcd(462, 1071);
output[3] = collatz_steps(27);
output_len = 32;
)";

const char* kBigExpectedOutput =
  "9100000000000000b90b000000000000"
  "15000000000000006f00000000000000";

// Fits the boot block alone: the bundle manifest carries no chunk or
// table lines, only the boot one.
const char* kSmallSource = "output[0] = 42;\noutput_len = 8;\n";
const char* kSmallExpectedOutput = "2a00000000000000";

struct BundleE2EFixture : public E2EServerFixture {
  std::string cescBin;

  BundleE2EFixture() : E2EServerFixture("cesh_bundle_e2e") {
    cescBin = findBinary("cesc");
  }

  // Write `src` to <name>.cesl in the temp dir and run cesc --bundle on
  // it. Returns the bundle directory relative to the temp dir (where
  // every cmd() runs).
  std::string makeBundle(const std::string& name, const std::string& src,
                         const std::string& salt) {
    {
      std::ofstream f(tempDir / (name + ".cesl"));
      BOOST_REQUIRE(f);
      f << src;
    }
    std::string dir = name + "_bundle";
    auto r = runExpect(inTempDir(cescBin + " " + name + ".cesl --bundle " +
                                 dir + " --salt " + salt));
    BOOST_REQUIRE_EQUAL(r.exitCode, 0);
    return dir;
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(CeshBundleE2E, BundleE2EFixture)

BOOST_AUTO_TEST_CASE(DeployBundleAndRun) {
  BOOST_REQUIRE_GT(ces::ceslCompile(kBigSource).size(),
                   ces::AssetData{}.size());
  auto dir = makeBundle("big", kBigSource, "s1");

  auto dep = runExpect(cmd("asset deploy-bundle bigprog " + dir + " --days 2"));
  BOOST_CHECK_EQUAL(dep.exitCode, 0);
  assertContains(dep.out, "Bundle Deployed");
  assertContains(dep.out, "Blocks Reused:  0");

  auto run = runExpect(cmd("asset run bigprog --budget 1000000000"));
  BOOST_CHECK_EQUAL(run.exitCode, 0);
  assertContains(run.out, "Success");
  assertContains(run.out, kBigExpectedOutput);
}

BOOST_AUTO_TEST_CASE(RedeployReusesBlocksNewBootNameRuns) {
  auto dir = makeBundle("big", kBigSource, "s2");

  auto dep1 =
    runExpect(cmd("-q asset deploy-bundle prog_a " + dir + " --days 2"));
  BOOST_CHECK_EQUAL(dep1.exitCode, 0);
  assertContains(dep1.out, "\"blocksReused\":0");

  // Same bundle under a new boot name: every chunk and table is already
  // on the ledger at its content-derived key, so nothing is re-created.
  auto dep2 =
    runExpect(cmd("-q asset deploy-bundle prog_b " + dir + " --days 2"));
  BOOST_CHECK_EQUAL(dep2.exitCode, 0);
  assertContains(dep2.out, "\"blocksCreated\":0");

  auto run = runExpect(cmd("asset run prog_b --budget 1000000000"));
  BOOST_CHECK_EQUAL(run.exitCode, 0);
  assertContains(run.out, kBigExpectedOutput);

  // The boot name itself is not content-derived: reusing one is an error.
  auto dep3 = runShell(cmd("asset deploy-bundle prog_a " + dir + " --days 2"));
  BOOST_CHECK_NE(dep3.exitCode, 0);
  assertContains(dep3.out, "boot asset");
}

BOOST_AUTO_TEST_CASE(BootOnlyBundleDeploysAndRuns) {
  auto dir = makeBundle("small", kSmallSource, "s3");

  auto dep =
    runExpect(cmd("-q asset deploy-bundle smallprog " + dir + " --days 2"));
  BOOST_CHECK_EQUAL(dep.exitCode, 0);
  assertContains(dep.out, "\"blocksCreated\":0");
  assertContains(dep.out, "\"blocksReused\":0");

  auto run = runExpect(cmd("asset run smallprog --budget 1000000000"));
  BOOST_CHECK_EQUAL(run.exitCode, 0);
  assertContains(run.out, kSmallExpectedOutput);
}

BOOST_AUTO_TEST_CASE(MissingManifestFails) {
  auto r = runShell(cmd("asset deploy-bundle nope missing_dir --days 2"));
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "cannot read");
}

BOOST_AUTO_TEST_SUITE_END()
