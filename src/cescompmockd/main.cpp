// cescompmockd — stub compute child for the L2 compute feature.
//
// Takes a Unix domain socket path as argv[1]. Connects to it, then
// reads bytes from the socket in a loop and discards them. Exits on
// socket close, read error, or SIGKILL from the supervisor.
//
// A no-Lua regression stub: it lets the compute plumbing (CesPlex
// builtin:compute, IPC framing, supervisor, slot-fee accounting) be
// tested end-to-end without pulling in the LuaJIT runtime (cesluajitd).
//
// Deliberately minimal: no boost, no ceslib, no logging. A running
// instance should occupy a handful of kilobytes of RSS and essentially
// zero CPU. If you find yourself adding anything beyond libc + POSIX
// sockets here, ask whether it belongs in cesluajitd instead.

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <ipc-socket-path>\n",
                 argc > 0 ? argv[0] : "cescompmockd");
    return 2;
  }
  const char* sockPath = argv[1];

  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { std::perror("cescompmockd: socket"); return 1; }

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (std::strlen(sockPath) >= sizeof(addr.sun_path)) {
    std::fprintf(stderr, "cescompmockd: socket path too long\n");
    return 2;
  }
  std::strncpy(addr.sun_path, sockPath, sizeof(addr.sun_path) - 1);

  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr),
                sizeof(addr)) < 0) {
    std::perror("cescompmockd: connect");
    return 1;
  }

  char buf[4096];
  for (;;) {
    ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n == 0) return 0;            // EOF: supervisor closed channel
    if (n < 0) {
      if (errno == EINTR) continue;
      return 1;
    }
    // Discard. The mock has no program semantics.
  }
}
