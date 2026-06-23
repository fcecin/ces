// extension_manager.h - the /s/ extension lifecycle, driven by the webadmin
// Extensions page. Coordinates three subsystems it does not own: the file store
// (copy a catalog .lua into /s/, delete it, read/write /s/<name>.conf), the
// compute handler (launch / kill), and the ces.extension_admin contract IPC
// (status / command / config) exposed by compute_handler.
//
// Definitions:
//   available  - a single .lua present in the read-only catalog (extensions_dir)
//   installed  - a .lua present in /s/
//   enabled    - a running compute instance of /s/<name>.lua
//
// Names are bare basenames ([A-Za-z0-9._-], no path separators); anything else
// is rejected so a name can never escape the catalog or /s/.

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ces {

class CesServer;

struct ExtensionItem {
  std::string name;            // basename, no .lua — identity for all path ops
  std::string displayName;     // ces.manifest `name` (live); "" if not running/declared
  bool available = false;      // present in the catalog
  bool installed = false;      // present in /s/
  bool enabled = false;        // a running instance exists
  uint64_t pid = 0;            // running instance (if enabled)
  // From the running instance's ces.extension_admin{} registration (if enabled):
  bool isExtension = false;    // it called ces.extension_admin{} (else N/A everywhere)
  uint8_t caps = 0;            // kComputeExtCap* bits
  std::string version, description;
  std::vector<std::pair<std::string, std::string>> commands;  // {id, label}
};

// Catalog union installed, with live state folded in for the enabled ones.
std::vector<ExtensionItem> extensionList(CesServer* server);

bool extensionInstall(CesServer* server, const std::string& name);    // catalog -> /s/
bool extensionUninstall(CesServer* server, const std::string& name);  // kill + delete /s/ copy
bool extensionEnable(CesServer* server, const std::string& name);     // launch
bool extensionDisable(CesServer* server, const std::string& name);    // kill

// Live status k/v of a running extension. false if not enabled / not an
// extension / no status callback (the page renders that as N/A).
bool extensionStatus(CesServer* server, const std::string& name,
                     std::vector<std::pair<std::string, std::string>>& kv);

// Run a declared/freeform command on a running extension; `out` = its result.
bool extensionCommand(CesServer* server, const std::string& name,
                      const std::string& id, const std::string& arg,
                      std::string& out);

// /s/<name>.conf text ("" if none).
std::string extensionConfigGet(CesServer* server, const std::string& name);
// Persist text to /s/<name>.conf and push it live to the running instance.
bool extensionConfigSet(CesServer* server, const std::string& name,
                        const std::string& text);
// Reset config to the running extension's declared defaults (requires enabled).
bool extensionConfigReset(CesServer* server, const std::string& name);

}  // namespace ces
