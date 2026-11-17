#include "jail.h"

#include <fcntl.h>
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace ceshd {

namespace {

int createRuleset(const landlock_ruleset_attr* attr, size_t size, uint32_t flags) {
  return static_cast<int>(::syscall(SYS_landlock_create_ruleset, attr, size, flags));
}

int addRule(int ruleset, landlock_rule_type type, const void* attr) {
  return static_cast<int>(::syscall(SYS_landlock_add_rule, ruleset, type, attr, 0));
}

int restrictSelf(int ruleset) {
  return static_cast<int>(::syscall(SYS_landlock_restrict_self, ruleset, 0));
}

// The file rights of the ruleset for an ABI.
uint64_t handledFs(int abi) {
  uint64_t fs = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                LANDLOCK_ACCESS_FS_MAKE_SYM;
  if (abi >= 2)
    fs |= LANDLOCK_ACCESS_FS_REFER;
  if (abi >= 3)
    fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
  return fs;
}

// The rights that apply to a file that is not a directory.
uint64_t fileRights(uint64_t rights) {
  return rights & (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                   LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE);
}

// Allows `rights` beneath `path`. A path that does not exist is skipped.
// The path is opened with O_PATH, so a symlink (/etc/resolv.conf) gives
// the rights to its target.
std::string allow(int ruleset, const char* path, uint64_t rights) {
  int fd = ::open(path, O_PATH | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ENOENT)
      return {};
    return std::string("open ") + path + ": " + std::strerror(errno);
  }
  struct stat st{};
  if (::fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode))
    rights = fileRights(rights);
  landlock_path_beneath_attr pb{};
  pb.allowed_access = rights;
  pb.parent_fd = fd;
  int rc = addRule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &pb);
  int err = errno;
  ::close(fd);
  if (rc != 0)
    return std::string("landlock rule ") + path + ": " + std::strerror(err);
  return {};
}

std::string limit(int resource, uint64_t value, const char* name) {
  rlimit r{static_cast<rlim_t>(value), static_cast<rlim_t>(value)};
  if (::setrlimit(resource, &r) != 0)
    return std::string("setrlimit ") + name + ": " + std::strerror(errno);
  return {};
}

}  // namespace

int landlockAbi() {
  int abi = createRuleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
  return abi < 0 ? 0 : abi;
}

std::string confine(const std::string& dir, const Limits& limits) {
  std::string e;
  if (!(e = limit(RLIMIT_CPU, limits.cpuSecs, "cpu")).empty() ||
      !(e = limit(RLIMIT_AS, limits.memBytes, "as")).empty() ||
      !(e = limit(RLIMIT_FSIZE, limits.fileBytes, "fsize")).empty() ||
      !(e = limit(RLIMIT_CORE, 0, "core")).empty())
    return e;

  // Other processes of the same user cannot read the memory or the
  // environment (the wallet) of this one, and a ptrace cannot attach.
  if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
    return std::string("prctl dumpable: ") + std::strerror(errno);
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    return std::string("prctl no_new_privs: ") + std::strerror(errno);

  int abi = landlockAbi();
  if (abi < kMinLandlockAbi)
    return "landlock ABI " + std::to_string(abi) + ", ceshd needs " +
           std::to_string(kMinLandlockAbi);

  const uint64_t fs = handledFs(abi);
  landlock_ruleset_attr attr{};
  attr.handled_access_fs = fs;
  attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
  int ruleset = createRuleset(&attr, sizeof(attr), 0);
  if (ruleset < 0)
    return std::string("landlock ruleset: ") + std::strerror(errno);

  // No rule gives LANDLOCK_ACCESS_FS_EXECUTE, so the child cannot start a
  // program. It does not need to: it runs cesh in its own process (ceshRun).
  // A command that starts a program fails (cesh bootstrap starts a shell
  // at its end). The loader maps libraries with read access only.
  const uint64_t read = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  struct Rule { const char* path; uint64_t rights; };
  const Rule rules[] = {
    {"/usr", read},
    {"/lib", read},
    {"/lib64", read},
    {"/etc/hosts", read},
    {"/etc/host.conf", read},
    {"/etc/resolv.conf", read},
    {"/etc/nsswitch.conf", read},
    {"/etc/gai.conf", read},
    {"/etc/localtime", read},
    {"/dev/null", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE},
    {"/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE},
    {"/dev/random", LANDLOCK_ACCESS_FS_READ_FILE},
    {dir.c_str(), fs & ~static_cast<uint64_t>(LANDLOCK_ACCESS_FS_EXECUTE)},
  };
  for (const auto& r : rules) {
    if (!(e = allow(ruleset, r.path, r.rights)).empty()) {
      ::close(ruleset);
      return e;
    }
  }
  // No TCP rule: the ruleset handles TCP bind and connect, so both are denied.

  int rc = restrictSelf(ruleset);
  int err = errno;
  ::close(ruleset);
  if (rc != 0)
    return std::string("landlock restrict: ") + std::strerror(err);
  return {};
}

}  // namespace ceshd
