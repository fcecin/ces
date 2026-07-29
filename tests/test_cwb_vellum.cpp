#include "test_ext_common.h"

#include <ces/l2/compute_client.h>

using namespace ces;
using namespace ces::exttest;

BOOST_AUTO_TEST_SUITE(CwbVellumTests)

BOOST_AUTO_TEST_CASE(ShippedServicesLaunchTogetherAndOwnLivePorts) {
  ExtNode n;
  const std::string child = ces::e2e::findBinary("cesluajitd");
  startExtNode(n, 91, child, std::vector<std::string>{"cwb", "vellum"},
               "", 8);

  KeyPair browser;
  n.server->_brr(browser.getPublicKeyAsHash(), 100'000'000'000ull);
  CesComputeClient cc;
  cc.setServerPubkey(n.pub);
  CES_REQUIRE_OK(cc.connect("127.0.0.1", n.rpcPort, browser));

  auto waitFor = [&cc](const std::string& source) {
    std::vector<CesComputeClient::InstanceInfo> rows;
    for (int i = 0; i < 100; ++i) {
      rows.clear();
      if (cc.instances(source, rows) == CES_OK && rows.size() == 1 &&
          rows.front().rpcPort != 0)
        return rows.front();
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    BOOST_FAIL("live service not discoverable: " + source);
    return CesComputeClient::InstanceInfo{};
  };

  const auto cwb = waitFor("/s/cwb.lua");
  const auto vellum = waitFor("/s/vellum.lua");
  BOOST_CHECK_NE(cwb.rpcPort, vellum.rpcPort);

  // Give Vellum's initial discovery/registration coroutine time to execute;
  // both services must remain alive afterward (a callback-yield regression
  // used to terminate or wedge this path).
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  std::vector<CesComputeClient::InstanceInfo> rows;
  CES_REQUIRE_OK(cc.instances("/s/cwb.lua", rows));
  BOOST_REQUIRE_EQUAL(rows.size(), 1u);
  CES_REQUIRE_OK(cc.instances("/s/vellum.lua", rows));
  BOOST_REQUIRE_EQUAL(rows.size(), 1u);
  const fs::path s = n.dir / "cesfilestore" / "s";
  BOOST_CHECK(!fs::exists(s / "cwb" / "index.html"));
  BOOST_CHECK(!fs::exists(s / "cwb" / "registry.log"));
  BOOST_CHECK(!fs::exists(s / "vellum" / "index.html"));
  BOOST_CHECK(!fs::exists(s / "vellum" / "stories.log"));
  cc.disconnect();
  n.server->stop();
}

BOOST_AUTO_TEST_SUITE_END()
