// readServerKeyFile: the server key from the file that server_key_file names.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/util/server_key_file.h>

#include <boost/test/unit_test.hpp>

#include <fstream>

namespace {

const std::string kHex = "1f2320380c9315d45a62f0c0b0ffe468eb04218d271a180ef3af60505bdbb347";

std::string fileWith(const fs::path& dir, const std::string& name, const std::string& text) {
  fs::path p = dir / name;
  std::ofstream(p.string()) << text;
  return p.string();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(ServerKeyFileTests)

BOOST_AUTO_TEST_CASE(TheHexAloneOrInATomlLine) {
  fs::path dir = makeUniqueTempDir("server_key_file");
  BOOST_CHECK_EQUAL(ces::readServerKeyFile(fileWith(dir, "raw", kHex + "\n")), kHex);
  BOOST_CHECK_EQUAL(ces::readServerKeyFile(fileWith(dir, "toml", "# the key\nserver_key = \"" + kHex + "\"\n")), kHex);
  fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(NoKeyGivesNothing) {
  fs::path dir = makeUniqueTempDir("server_key_file");
  BOOST_CHECK_EQUAL(ces::readServerKeyFile((dir / "missing").string()), "");
  BOOST_CHECK_EQUAL(ces::readServerKeyFile(fileWith(dir, "empty", " \n")), "");
  BOOST_CHECK_EQUAL(ces::readServerKeyFile(fileWith(dir, "other", "port = 53830\n")), "");
  fs::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()
