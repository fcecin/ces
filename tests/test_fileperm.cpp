// setSecurePermission (ces/util/fileperm.h): owner-only access. A file gets
// 0600. A directory gets 0700: without the execute bit, nobody can open the
// files in it, also not the owner (cesh made ~/.cesh that way, and then could
// not read ~/.cesh/CESH_WALLET).

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/util/fileperm.h>

#include <boost/test/unit_test.hpp>

#include <fstream>

namespace sfs = std::filesystem;

BOOST_AUTO_TEST_SUITE(FilePermTests)

#ifndef _WIN32
BOOST_AUTO_TEST_CASE(Directory_StaysUsable_File_IsOwnerReadWrite) {
  auto base = makeUniqueTempDir("fileperm");
  sfs::path dir = sfs::path(base.string()) / "home";
  sfs::create_directories(dir);
  BOOST_CHECK_EQUAL(ces::setSecurePermission(dir), "");
  BOOST_CHECK(sfs::status(dir).permissions() == sfs::perms::owner_all);

  sfs::path file = dir / "CESH_WALLET";
  std::ofstream(file) << "00ab\n";
  BOOST_CHECK(sfs::exists(file));   // the directory can be entered
  BOOST_CHECK_EQUAL(ces::setSecurePermission(file), "");
  BOOST_CHECK(sfs::status(file).permissions() ==
              (sfs::perms::owner_read | sfs::perms::owner_write));
  std::ifstream in(file);
  std::string line;
  BOOST_CHECK(std::getline(in, line) && line == "00ab");
}
#endif

BOOST_AUTO_TEST_SUITE_END()
