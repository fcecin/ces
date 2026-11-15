// Run a cesh command inside the cesh process.
//
// ceshRun is the whole cesh command line: main() calls it once. cesh chat
// calls ceshCapture for each command that it runs, so a command runs through
// the same code as when a person types it, with the same wallet and keys,
// and its output comes back as text.

#pragma once

#include <string>
#include <vector>

// One cesh command. argv[0] is the program name.
int ceshRun(int argc, char* argv[]);

struct CeshResult {
  int code = 0;
  std::string out;   // what the command wrote to stdout
  std::string err;   // what the command wrote to stderr
};

// Run `cesh <args...>` in this process. stdin reads `input`; stdout and
// stderr are captured. The standard streams come back to their old state
// when the command ends, also when it throws. Not thread-safe: the standard
// streams are process-wide.
CeshResult ceshCapture(const std::vector<std::string>& args, const std::string& input = "");
