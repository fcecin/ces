// ---------------------------------------------------------------------------
// Startup: unix socket connect, uid drop, rlimits, Lua locking.
// ---------------------------------------------------------------------------

int connect_unix_socket(const char* path) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { std::perror("cesluajitd: socket"); return -1; }
  sockaddr_un a{};
  a.sun_family = AF_UNIX;
  if (std::strlen(path) >= sizeof(a.sun_path)) {
    std::fprintf(stderr, "cesluajitd: socket path too long\n");
    ::close(fd);
    return -1;
  }
  std::strncpy(a.sun_path, path, sizeof(a.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
    std::perror("cesluajitd: connect");
    ::close(fd);
    return -1;
  }
  return fd;
}

// If running as root AND user_name is non-empty, drop to that
// account (gid first, then uid). Non-fatal if we're already not
// root; fatal if the drop is requested and any step fails.
bool drop_privileges_if_root(const char* user_name) {
  if (::geteuid() != 0) return true; // already non-root, nothing to do
  if (user_name == nullptr || user_name[0] == '\0') {
    host_log(4, "running as root with no drop-to-user configured; refusing");
    return false;
  }
  struct passwd* pw = ::getpwnam(user_name);
  if (!pw) {
    host_log(4, std::string("unknown drop-to-user '") + user_name + "'");
    return false;
  }
  if (::setgroups(0, nullptr) < 0) {
    host_log(4, std::string("setgroups: ") + std::strerror(errno));
    return false;
  }
  if (::setgid(pw->pw_gid) < 0) {
    host_log(4, std::string("setgid: ") + std::strerror(errno));
    return false;
  }
  if (::setuid(pw->pw_uid) < 0) {
    host_log(4, std::string("setuid: ") + std::strerror(errno));
    return false;
  }
  if (::geteuid() == 0 || ::getegid() == 0) {
    host_log(4, "privilege drop didn't stick");
    return false;
  }
  return true;
}

void apply_rlimits(size_t mem_max_bytes) {
  // Cap glibc's per-thread malloc arenas. Each new thread otherwise gets its
  // own 64 MB virtual arena, and the transient CesClient behind the outbound
  // networking APIs (ces.ping / ces.remote_*) spawns IO threads per call --
  // a few of those reserve enough address space to trip RLIMIT_AS and throw
  // std::bad_alloc. Two arenas is plenty for a mostly single-threaded VM and
  // keeps outbound networking inside the documented mem ceiling.
  mallopt(M_ARENA_MAX, 2);
  // Hard ceilings that cannot be raised from inside Lua. RLIMIT_AS is
  // the merciless memory cap (from the server's compute_process_mem_max):
  // the kernel denies any allocation past it, so a runaway or malicious
  // program can never OOM the host. No RLIMIT_CPU — CPU is billed via
  // file_balance depletion, not capped; throttling a paying process
  // would be pointless.
  rlimit r{};
  r.rlim_cur = r.rlim_max = mem_max_bytes;
  ::setrlimit(RLIMIT_AS, &r);
  // Descriptor ceiling: stdio, the host UDS, and the outbound CesClient's
  // socket plus asio internals (epoll / eventfd / timerfd). Bounded, but
  // above the original no-network ceiling.
  r.rlim_cur = r.rlim_max = 64;
  ::setrlimit(RLIMIT_NOFILE, &r);
}

