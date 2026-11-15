// ceshCapture (src/cesh/cesh_run.h): a cesh command runs in this process, with
// its stdout and stderr captured and the standard streams put back after it.
// cesh chat runs each command this way.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include "cesh_run.h"

#include <boost/test/unit_test.hpp>

#include <iostream>

BOOST_AUTO_TEST_SUITE(CeshRunTests)

BOOST_AUTO_TEST_CASE(Capture_OutputAndExitCode) {
  auto* outBuf = std::cout.rdbuf();
  auto* errBuf = std::cerr.rdbuf();
  auto* inBuf = std::cin.rdbuf();

  CeshResult r = ceshCapture({"man", "rent"});
  BOOST_CHECK_EQUAL(r.code, 0);
  BOOST_CHECK(r.out.rfind("# Rent and the file balance\n", 0) == 0);
  BOOST_CHECK(r.err.empty());

  r = ceshCapture({"man", "no-such-page"});
  BOOST_CHECK_EQUAL(r.code, 1);
  BOOST_CHECK(r.out.empty());
  BOOST_CHECK(r.err.find("No page or command") != std::string::npos);

  // The standard streams are the same after each run.
  BOOST_CHECK(std::cout.rdbuf() == outBuf);
  BOOST_CHECK(std::cerr.rdbuf() == errBuf);
  BOOST_CHECK(std::cin.rdbuf() == inBuf);
}

BOOST_AUTO_TEST_CASE(Capture_ParseErrorIsCaptured) {
  CeshResult r = ceshCapture({"transfer", "--no-such-flag"});
  BOOST_CHECK(r.code != 0);
  BOOST_CHECK(!(r.out + r.err).empty());
}

// A run does not leak its options into the next one: -q in one run does not
// make the next run quiet.
BOOST_AUTO_TEST_CASE(Capture_EachRunStartsClean) {
  CeshResult quiet = ceshCapture({"-q", "man", "no-such-page"});
  BOOST_CHECK_EQUAL(quiet.code, 1);
  CeshResult r = ceshCapture({"man"});
  BOOST_CHECK_EQUAL(r.code, 0);
  BOOST_CHECK(r.out.find("files/rent  ") != std::string::npos);
}

// --parse-only parses the command line and stops: it needs no server and does
// nothing. cesh chat checks each action with it.
BOOST_AUTO_TEST_CASE(ParseOnly_ChecksSyntaxOnly) {
  CeshResult ok = ceshCapture({"--parse-only", "--server", "localhost:1", "transfer", "@0", "5"});
  BOOST_CHECK_EQUAL(ok.code, 0);
  BOOST_CHECK(ok.out.empty());
  CeshResult bad = ceshCapture({"--parse-only", "transfer", "2", "--to", "@1"});
  BOOST_CHECK(bad.code != 0);
  BOOST_CHECK(!(bad.out + bad.err).empty());
}

BOOST_AUTO_TEST_SUITE_END()
