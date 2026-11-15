// The cesh program. All of cesh is in the ceshcore library, so the tests and
// cesh chat can run cesh commands in-process (cesh_run.h).

#include "cesh_run.h"

int main(int argc, char* argv[]) { return ceshRun(argc, argv); }
