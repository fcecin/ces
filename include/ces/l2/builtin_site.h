#pragma once

#include <string>
#include <vector>

namespace ces {

// A static file shipped INSIDE the CES binary and published into the file
// store's /s/ zone at boot, whenever the file feature is on. There is no switch:
// the demo site comes with the file feature and is overwritten on every boot, so
// it always matches the running binary (operators publish their own content
// elsewhere in /s/).
//
// relPath is the path under /s/ — e.g. "welcome/index.html" → CES name
// "/s/welcome/index.html".
struct BuiltinSiteFile {
  std::string relPath;
  std::string content;
};

// The bundled site (currently /s/welcome: a small "what am I looking at" page a
// gateway like cesweb serves out of the box).
std::vector<BuiltinSiteFile> builtinSiteFiles();

// True for a CES name that belongs to the bundled site. The file handler treats
// these as static server content (server-owned, no program account — like the
// generated /s/index.html catalog), so reconcile leaves them alone.
bool isBuiltinSitePath(const std::string& cesName);

}  // namespace ces
