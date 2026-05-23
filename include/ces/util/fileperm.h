#pragma once

// Filesystem permission helper.

#include <exception>
#include <filesystem>
#include <string>
#include <system_error>

#ifdef _WIN32
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <sys/stat.h>
#endif

namespace ces {

// Restrict `path` to owner-only read/write. POSIX: 0600. Windows: ACL with
// Built-in Administrators + SYSTEM + Owner full-control. Returns "" on
// success, error string on failure.
inline std::string setSecurePermission(const std::filesystem::path& path) {
  try {
#ifdef _WIN32
    const wchar_t* sddl = L"D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;OW)";
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl, SDDL_REVISION_1, &pSD, nullptr)) {
      if (!SetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION, pSD)) {
        std::string err =
          "Error: " + std::system_category().message(GetLastError());
        LocalFree(pSD);
        return err;
      }
      LocalFree(pSD);
    }
#else
    std::filesystem::permissions(path,
                                 std::filesystem::perms::owner_read |
                                   std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
#endif
  } catch (const std::exception& e) {
    return std::string("Error: ") + e.what();
  }
  return "";
}

} // namespace ces
