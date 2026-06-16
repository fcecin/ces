#include <algorithm>
#include <thread>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

#include "dial.h"

#include <ces/account.h>
#include <ces/autoexec.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/ramfilestore.h>
#include <ces/util/log.h>
#include <ces/util/hex.h>
#include <ces/util/resolver.h>
#include <ces/util/fileperm.h>
#include <ces/util/wallet.h>

#include <minx/blog.h>

using namespace ces;

// Local UDP bind port for cesh; 0 = auto-assign, allows parallel instances.
constexpr uint16_t CESH_LOCAL_PORT = 0;

// =============================================================================
// HELPER: Formatting (CLI-only)
// =============================================================================

// Silent/pipe mode (-q/--quiet): stdout carries DATA ONLY — raw bytes for
// content fetches, JSON for structured results — with zero human chrome.
// Human messages and errors go to stderr (errors always do, both modes).
// The two human-output helpers below become no-ops in quiet mode, so the
// per-command quiet branches own everything that reaches stdout.
bool g_quiet = false;

void print_header(const std::string& title) {
  if (g_quiet) return;
  std::cout << "\n=== " << title << " ===\n";
}

void print_field(const std::string& key, const std::string& val) {
  if (g_quiet) return;
  std::cout << std::left << std::setw(16) << (key + ":") << val << "\n";
}

void print_field(const std::string& key, uint64_t val) {
  print_field(key, std::to_string(val));
}

// Minimal JSON string escaper for --quiet structured output. cesh has no
// JSON dependency and these objects are tiny, so we hand-roll.
std::string jesc(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 2);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\r': o += "\\r";  break;
      case '\t': o += "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          o += buf;
        } else {
          o += static_cast<char>(c);
        }
    }
  }
  return o;
}

// One compute instance as a JSON object (shared by compute ps/stat/instances
// in --quiet mode).
std::string instanceJson(const ces::CesComputeClient::InstanceInfo& e) {
  std::string o = "{";
  o += "\"instanceId\":"     + std::to_string(e.instanceId);
  o += ",\"sourceName\":\""  + jesc(e.sourceName) + "\"";
  o += ",\"startedAtUs\":"   + std::to_string(e.startedAtUs);
  o += ",\"fileBalance\":"   + std::to_string(e.fileBalance);
  o += ",\"cpuBasisPoints\":"+ std::to_string(e.cpuBasisPoints);
  o += ",\"rssBytes\":"      + std::to_string(e.rssBytes);
  o += ",\"clientPort\":"    + std::to_string(e.clientPort);
  o += ",\"rpcPort\":"       + std::to_string(e.rpcPort);
  o += "}";
  return o;
}

// Log level parsing lives in ces/logutil.h (setupLogger).
// Local wrapper ignores unknown levels (cesh's old behavior) by swallowing
// the exception — we don't want cesh to exit on a typo in --log.
static void setup_logger(const std::string& logLevel) {
  try { ces::setupLogger(logLevel); } catch (...) { /* tolerate */ }
}

// =============================================================================
// MAIN
// =============================================================================

int main(int argc, char* argv[]) {
  blog::enable("minx");
  blog::enable("powengine");

#ifndef CES_GIT_HASH
#define CES_GIT_HASH "unknown"
#endif
  CLI::App app{"cesh - CES shell client"};
  app.set_version_flag("--version", std::string(CES_GIT_HASH));
  app.require_subcommand(0, 1);
  app.fallthrough();
  app.set_help_all_flag("--help-all", "Show all help including global options");

  // ---- Global options ----

  std::string logLevel = "warning";
  const std::string defaultServerEndpoint =
    "localhost:" + std::to_string(ces::DEFAULT_PORT);
  std::string server_arg = defaultServerEndpoint;
  std::string proxy_arg;
  std::string actor_arg;
  std::string wallet_read_arg, wallet_save_arg;
  uint16_t clientPort = CESH_LOCAL_PORT;
  bool cacheOnly = false;
  bool opt_secp = false;

  app
    .add_option("-l,--log", logLevel,
                "Log level ([t]race, [d]ebug, [i]nfo, [w]arning, [e]rror, "
                "[f]atal)")
    ->default_val("warning");

  app
    .add_option("--server", server_arg,
                "Server endpoint (host:port)")
    ->default_val(defaultServerEndpoint);

  int tries_arg = 3;
  app.add_option("--tries", tries_arg, "Number of send attempts (1-16)")
    ->default_val(3)->check(CLI::Range(1, 16));

  app.add_option("--port", clientPort, "Local UDP port")
    ->default_val(CESH_LOCAL_PORT);

  app.add_option("--proxy", proxy_arg,
                 "TCP proxy endpoint (host:port). Overrides --server.");

  uint16_t rpcPort_arg = 0;
  app.add_option("--rpc-port", rpcPort_arg,
                 "Server's CesPlex/file-store UDP port "
                 "(required for 'file' subcommands)");

  app.add_option("-a,--actor", actor_arg,
                 "Acting account (pubkey hex or @index)");

  app
    .add_option("-r,--wallet", wallet_read_arg,
                "Load wallet from file")
    ->expected(0, 1);

  app.add_flag("--secp", opt_secp, "Use secp256k1 for key gen/import");

  app.add_flag("-c,--cache-only", cacheOnly, "Lightweight PoW engine (slow)");

  app.add_flag("-q,--quiet", g_quiet,
               "Silent/pipe mode: stdout is data only (raw bytes or JSON), "
               "no human messages; errors still go to stderr");

  // ---- Subcommand: keys ----

  auto* cmd_keys = app.add_subcommand("keys", "Key management");
  cmd_keys->require_subcommand(0, 1);
  cmd_keys->fallthrough();

  int gen_count = 1;
  auto* cmd_keys_gen =
    cmd_keys->add_subcommand("gen", "Generate new keys");
  cmd_keys_gen->add_option("count", gen_count, "Number of keys")
    ->default_val(1);
  cmd_keys_gen
    ->add_option("-w,--save", wallet_save_arg, "Save wallet after generating")
    ->expected(0, 1);

  bool keys_show_public = false;
  auto* cmd_keys_list =
    cmd_keys->add_subcommand("list", "List wallet keys");
  cmd_keys_list->add_flag("-p,--public", keys_show_public,
                          "Include public keys");

  std::string keys_add_arg;
  auto* cmd_keys_add =
    cmd_keys->add_subcommand("add", "Add existing private key");
  cmd_keys_add->add_option("key", keys_add_arg, "Private key hex")->required();
  cmd_keys_add
    ->add_option("-w,--save", wallet_save_arg, "Save wallet after adding")
    ->expected(0, 1);

  cmd_keys->add_subcommand("export", "Print CESH_WALLET export command");

  // ---- Subcommand: query ----

  std::string query_account_arg;
  auto* cmd_query = app.add_subcommand("query", "Unsigned account query");
  cmd_query->add_option("account", query_account_arg, "Account key or @index")
    ->required();

  // ---- Subcommand: squery ----

  std::string squery_account_arg;
  auto* cmd_squery =
    app.add_subcommand("squery", "Signed account query (paid)");
  cmd_squery
    ->add_option("account", squery_account_arg, "Account key or @index")
    ->required();

  // ---- Subcommand: transfer ----

  std::string transfer_dest_arg;
  uint64_t transfer_amount_arg = 0;
  bool transfer_open = false;
  auto* cmd_transfer = app.add_subcommand("transfer", "Transfer funds (safe: fails if dest not found)");
  cmd_transfer->add_option("dest", transfer_dest_arg, "Destination key or @index")
    ->required();
  cmd_transfer->add_option("amount", transfer_amount_arg, "Amount")->required();
  cmd_transfer->add_flag("--open", transfer_open,
                         "Auto-create destination account if not found");

  uint64_t payment_amount_arg = 0;
  int payment_days_arg = 1;
  std::string payment_dest_arg;
  auto* cmd_payment = app.add_subcommand("payment", "Create payment account");
  cmd_payment->add_option("dest", payment_dest_arg, "Destination key or @index")
    ->required();
  cmd_payment->add_option("amount", payment_amount_arg, "Amount")->required();
  cmd_payment->add_option("--days", payment_days_arg, "Payment days")
    ->default_val(1);

  std::string cross_dest_arg, cross_server_arg;
  uint64_t cross_amount_arg = 0;
  auto* cmd_cross = app.add_subcommand("cross",
    "Cross-server transfer (send to a key on a peer server)");
  cmd_cross->add_option("dest", cross_dest_arg, "Destination key or @index")
    ->required();
  cmd_cross->add_option("amount", cross_amount_arg, "Amount")->required();
  cmd_cross->add_option("server", cross_server_arg,
    "Destination server address (host:port)")->required();

  // ---- Subcommand: server-info ----

  auto* cmd_sinfo =
    app.add_subcommand("server-info", "Query extended server info (paid)");

  // ---- Subcommand: peer-info (unsigned, no actor needed) ----

  auto* cmd_peer_info = app.add_subcommand(
    "peer-info", "Read a server's peer-table slot (unsigned/free)");
  uint16_t peer_info_id_arg = 0;
  std::string peer_info_server_arg;
  cmd_peer_info->add_option("id", peer_info_id_arg, "Peer-table slot index")
    ->required();
  cmd_peer_info->add_option("server", peer_info_server_arg,
                            "Server endpoint (host:port)")->required();

  // ---- Subcommand: ping (unsigned, no actor needed) ----

  auto* cmd_ping = app.add_subcommand(
    "ping", "Connect and print server MINX+CES handshake info");

  // ---- Subcommand: mine ----

  auto* cmd_mine = app.add_subcommand("mine", "Mining mode");
  uint32_t mine_threads_arg = 1;
  cmd_mine->add_option("-t,--threads", mine_threads_arg,
                       "Number of RandomX hashing threads (default 1; "
                       "values >hardware_concurrency are clamped)");

  // ---- Subcommand: asset ----

  auto* cmd_asset = app.add_subcommand("asset", "Asset operations");
  cmd_asset->require_subcommand(0, 1);

  std::string asset_id_arg, asset_content_arg, asset_hexcontent_arg, asset_target_arg;
  uint16_t asset_days_arg = 0;
  uint64_t asset_price_arg = 0;
  uint64_t asset_buy_amount_arg = 0;

  bool asset_private_arg = false;
  bool asset_immutable_arg = false;
  auto* cmd_ac = cmd_asset->add_subcommand("create", "Create asset");
  cmd_ac->add_option("id", asset_id_arg, "Asset ID or name")->required();
  cmd_ac->add_option("--content", asset_content_arg, "Content (text string)");
  cmd_ac->add_option("--hexcontent", asset_hexcontent_arg, "Content (hex bytes)");
  cmd_ac->add_option("--days", asset_days_arg, "Days to fund")->required();
  cmd_ac->add_flag("--private", asset_private_arg, "Make asset private (content hidden from non-owner)");
  cmd_ac->add_flag("--immutable", asset_immutable_arg, "Seal content forever (cannot be updated; owner/price/funding still mutable)");

  auto* cmd_au = cmd_asset->add_subcommand("update", "Full asset update");
  cmd_au->add_option("id", asset_id_arg, "Asset ID or name")->required();
  cmd_au->add_option("--content", asset_content_arg, "Content (text string)");
  cmd_au->add_option("--hexcontent", asset_hexcontent_arg, "Content (hex bytes)");
  cmd_au->add_option("--price", asset_price_arg, "Price in whole credits (0=not for sale)");
  cmd_au->add_option("--target", asset_target_arg, "New owner (key or @index)");

  auto* cmd_am =
    cmd_asset->add_subcommand("meta", "Update asset metadata only");
  cmd_am->add_option("id", asset_id_arg, "Asset ID or name")->required();
  cmd_am->add_option("--price", asset_price_arg, "Price in whole credits (0=not for sale)");
  cmd_am->add_option("--target", asset_target_arg, "New owner (key or @index)");

  auto* cmd_af =
    cmd_asset->add_subcommand("fast", "Fast content-only update");
  cmd_af->add_option("id", asset_id_arg, "Asset ID or name")->required();
  cmd_af->add_option("--content", asset_content_arg, "Content (text string)");
  cmd_af->add_option("--hexcontent", asset_hexcontent_arg, "Content (hex bytes)");

  auto* cmd_afd = cmd_asset->add_subcommand("fund", "Fund asset");
  cmd_afd->add_option("id", asset_id_arg, "Asset ID or name")->required();
  cmd_afd->add_option("--days", asset_days_arg, "Days to add")->required();

  auto* cmd_ab = cmd_asset->add_subcommand("buy", "Buy asset");
  cmd_ab->add_option("id", asset_id_arg, "Asset ID or name")->required();
  cmd_ab->add_option("--amount", asset_buy_amount_arg, "Max price in whole credits")->required();

  auto* cmd_ag = cmd_asset->add_subcommand("give", "Give asset to new owner");
  cmd_ag->add_option("id", asset_id_arg, "Asset ID or name")->required();
  cmd_ag->add_option("--target", asset_target_arg, "New owner (key or @index)")
    ->required();

  std::string asset_run_input_arg;
  uint64_t asset_run_budget_arg = 0;
  uint64_t asset_run_allowance_arg = std::numeric_limits<uint64_t>::max();
  bool asset_run_nonceless = false;
  auto* cmd_ar = cmd_asset->add_subcommand("run", "Execute asset bytecode (VM)");
  cmd_ar->add_option("id", asset_id_arg, "Asset ID or name")->required();
  cmd_ar->add_option("--budget", asset_run_budget_arg, "Gas budget in credits")->required();
  cmd_ar->add_option("--allowance", asset_run_allowance_arg,
                    "Per-run cap on caller-account debits inside the VM "
                    "(default: unlimited). Programs read this as their "
                    "spend budget via io[CESVM_IO_ALLOWANCE]; e.g. "
                    "/b/dice uses it as the bet amount.");
  cmd_ar->add_option("--input", asset_run_input_arg, "Input data (hex string)");
  cmd_ar->add_flag("--nonceless", asset_run_nonceless, "Use auto-nonce (no sequential nonce)");

  auto* cmd_aq = cmd_asset->add_subcommand("query", "Unsigned asset query");
  cmd_aq->add_option("id", asset_id_arg, "Asset ID or name")->required();

  auto* cmd_asq =
    cmd_asset->add_subcommand("squery", "Signed asset query (paid)");
  cmd_asq->add_option("id", asset_id_arg, "Asset ID or name")->required();

  // ---- ramfile subcommands ----
  // In-ledger RAM-backed asset-chain file API (L1) — distinct from the
  // `file` command's L2 disk-backed store on rpc_port. Suited to small
  // VM-reachable files, not host-scale storage.
  auto* cmd_file = app.add_subcommand(
    "ramfile", "RAM-backed file storage (asset-chain, L1)");
  cmd_file->require_subcommand(1);

  std::string file_key_arg, file_path_arg, file_meta_arg;
  uint16_t file_days_arg = 30;

  // Shared composable data buffer — --in appends in CLI order
  // Prefix: "hex:" for hex bytes, "file:" for file, else text
  ces::Bytes file_composed_data;
  std::string file_in_arg; // CLI11 target
  auto inAppender = [&](const std::string& s) {
    if (s.substr(0, 4) == "hex:") {
      auto bytes = ces::parseHex(std::string_view(s).substr(4));
      file_composed_data.insert(file_composed_data.end(),
                                 bytes.begin(), bytes.end());
    } else if (s.substr(0, 5) == "file:") {
      std::ifstream ifs(s.substr(5), std::ios::binary);
      if (!ifs) throw std::runtime_error("cannot open " + s.substr(5));
      file_composed_data.insert(file_composed_data.end(),
        std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    } else if (s.substr(0, 5) == "text:") {
      auto text = s.substr(5);
      file_composed_data.insert(file_composed_data.end(), text.begin(), text.end());
    } else {
      file_composed_data.insert(file_composed_data.end(), s.begin(), s.end());
    }
  };

  auto* cmd_fp = cmd_file->add_subcommand("put", "Upload file");
  cmd_fp->add_option("key", file_key_arg, "File key (asset name)")->required();
  cmd_fp->add_option("--in", file_in_arg, "Data (repeatable): text, text:T, hex:XX, file:path")
    ->each(inAppender)->take_all();
  cmd_fp->add_option("--days", file_days_arg, "Days to fund (default 30)");
  cmd_fp->add_option("--meta", file_meta_arg, "Metadata string (up to 121 bytes)");

  auto* cmd_ft = cmd_file->add_subcommand("touch", "Create empty file");
  cmd_ft->add_option("key", file_key_arg, "File key (asset name)")->required();
  cmd_ft->add_option("--days", file_days_arg, "Days to fund (default 30)");
  cmd_ft->add_option("--meta", file_meta_arg, "Metadata string");

  auto* cmd_fg = cmd_file->add_subcommand("get", "Download file");
  cmd_fg->add_option("key", file_key_arg, "File key (asset name)")->required();
  cmd_fg->add_option("path", file_path_arg, "Local file path")->required();

  auto* cmd_fi = cmd_file->add_subcommand("info", "Show file metadata");
  cmd_fi->add_option("key", file_key_arg, "File key (asset name)")->required();

  auto* cmd_fs = cmd_file->add_subcommand("scan", "Scan chain and write .scan file");
  cmd_fs->add_option("key", file_key_arg, "File key (asset name)")->required();

  std::string file_outfile_arg;
  uint64_t file_offset_arg = 0, file_length_arg = 0;
  bool file_hex_output = false;

  auto* cmd_fr = cmd_file->add_subcommand("read", "Read bytes at offset (requires .scan)");
  cmd_fr->add_option("key", file_key_arg, "File key (asset name)")->required();
  cmd_fr->add_option("--offset", file_offset_arg, "Byte offset (default 0)");
  cmd_fr->add_option("--length", file_length_arg, "Bytes to read (0=all from offset)");
  cmd_fr->add_option("--out", file_outfile_arg, "Output file (default: stdout)");
  cmd_fr->add_flag("--hex", file_hex_output, "Output as hex string");

  auto* cmd_fw = cmd_file->add_subcommand("write", "Write bytes at offset (requires .scan)");
  cmd_fw->add_option("key", file_key_arg, "File key (asset name)")->required();
  cmd_fw->add_option("--offset", file_offset_arg, "Byte offset")->required();
  cmd_fw->add_option("--in", file_in_arg, "Data (repeatable): text, text:T, hex:XX, file:path")
    ->each(inAppender)->take_all();

  auto* cmd_fa = cmd_file->add_subcommand("append", "Append data to file (requires .scan)");
  cmd_fa->add_option("key", file_key_arg, "File key (asset name)")->required();
  cmd_fa->add_option("--in", file_in_arg, "Data (repeatable): text, text:T, hex:XX, file:path")
    ->each(inAppender)->take_all();
  cmd_fa->add_option("--days", file_days_arg, "Days for new chunks (default 30)");

  uint64_t file_newsize_arg = 0;
  auto* cmd_fz = cmd_file->add_subcommand("resize", "Resize file (requires .scan)");
  cmd_fz->add_option("key", file_key_arg, "File key (asset name)")->required();
  cmd_fz->add_option("size", file_newsize_arg, "New size in bytes")->required();
  cmd_fz->add_option("--days", file_days_arg, "Days for new chunks if extending");

  auto* cmd_fh = cmd_file->add_subcommand("rehash", "Recompute SHA256 after writes");
  cmd_fh->add_option("key", file_key_arg, "File key (asset name)")->required();

  auto* cmd_ff = cmd_file->add_subcommand("fund", "Extend all chunks (requires .scan)");
  cmd_ff->add_option("key", file_key_arg, "File key (asset name)")->required();
  cmd_ff->add_option("--days", file_days_arg, "Days to add (default 30)");

  // ---- file subcommands (L2 disk-backed file store over CesPlex) ----
  auto* cmd_dfile = app.add_subcommand(
    "file", "Disk-backed file storage (L2, via --rpc-port)");
  cmd_dfile->require_subcommand(1);

  std::string df_local_arg, df_remote_arg;
  uint64_t df_deposit_arg = 0;
  uint64_t df_amount_arg = 0;
  uint64_t df_price_arg = 0;

  auto* cmd_dfp = cmd_dfile->add_subcommand("put", "Upload a file");
  cmd_dfp->add_option("local", df_local_arg, "Local file path")->required();
  cmd_dfp->add_option("remote", df_remote_arg,
                      "Remote path (starts with /h/, /f/, or /p/ — or bare "
                      "name, auto-prepended with /h/<signer>/)")->required();
  cmd_dfp->add_option("--deposit", df_deposit_arg,
                      "Initial credits to deposit into the file's balance. "
                      "On CREATE: defaults to the 15-min upfront rent. "
                      "On re-upload of an existing file: always added as a "
                      "top-up DEPOSIT.");

  auto* cmd_dfg = cmd_dfile->add_subcommand("get", "Download a file");
  cmd_dfg->add_option("remote", df_remote_arg, "Remote path")->required();
  cmd_dfg->add_option("local", df_local_arg,
                      "Local destination path ('-' or omit = stdout)");

  auto* cmd_dfs = cmd_dfile->add_subcommand("stat", "Show file metadata");
  cmd_dfs->add_option("remote", df_remote_arg, "Remote path")->required();

  auto* cmd_dfrm = cmd_dfile->add_subcommand("rm", "Delete a file (owner only)");
  cmd_dfrm->add_option("remote", df_remote_arg, "Remote path")->required();

  auto* cmd_dfd = cmd_dfile->add_subcommand(
    "deposit", "Credit a file's balance");
  cmd_dfd->add_option("remote", df_remote_arg, "Remote path")->required();
  cmd_dfd->add_option("amount", df_amount_arg, "Amount")->required();

  auto* cmd_dfw = cmd_dfile->add_subcommand(
    "withdraw", "Withdraw from a file's balance (owner only)");
  cmd_dfw->add_option("remote", df_remote_arg, "Remote path")->required();
  cmd_dfw->add_option("amount", df_amount_arg, "Amount")->required();

  auto* cmd_dfsp = cmd_dfile->add_subcommand(
    "set-price", "Set per-kilobyte read price (owner only)");
  cmd_dfsp->add_option("remote", df_remote_arg, "Remote path")->required();
  cmd_dfsp->add_option("price", df_price_arg, "Credits per 1024 bytes")
    ->required();

  // ---- compute subcommands (L2 compute, via --rpc-port) ----
  auto* cmd_compute = app.add_subcommand(
    "compute", "L2 compute — launch/kill/list/stat a program instance "
               "(via --rpc-port)");
  cmd_compute->require_subcommand(1);

  std::string compute_path_arg;
  uint64_t compute_id_arg = 0;

  auto* cmd_clau = cmd_compute->add_subcommand(
    "launch", "Launch a fresh instance of the source file. Mints a new "
              "instance_id every call — multiple instances per source "
              "are allowed up to the server's compute_max_instances cap.");
  cmd_clau->add_option("remote", compute_path_arg,
                       "Source file path (/h/<hex>/…, /f/<name>/…, /p/…)")
    ->required();

  auto* cmd_ckil = cmd_compute->add_subcommand(
    "kill", "SIGKILL a running instance (owner only)");
  cmd_ckil->add_option("instance_id", compute_id_arg,
                       "Instance id returned from launch")->required();

  auto* cmd_cps = cmd_compute->add_subcommand(
    "ps", "List running instances owned by the signer");

  auto* cmd_cst = cmd_compute->add_subcommand(
    "stat", "Show status of an instance by id (owner only)");
  cmd_cst->add_option("instance_id", compute_id_arg,
                      "Instance id returned from launch")->required();

  auto* cmd_cinst = cmd_compute->add_subcommand(
    "instances",
    "List running instance ids for a given source path. Public — no "
    "owner check; useful for discovering services like /s/chat.lua. "
    "Prints one numeric id per line on stdout (empty output = none).");
  cmd_cinst->add_option("remote", compute_path_arg,
                        "Source file path (/h/<hex>/…, /f/<name>/…, "
                        "/p/…, or /s/…)")->required();

  // ---- dial (open a byte stream to a running compute instance) ----
  auto* cmd_dial = app.add_subcommand(
    "dial",
    "Open a bidirectional byte stream to a running compute instance "
    "over /ces/lua/1 (via --rpc-port). Pipes stdin↔channel↔stdout. "
    "stdin EOF half-closes the send side and drains the channel; "
    "SIGINT/SIGTERM tears down with exit 130/143.");
  uint64_t dial_instance_arg = 0;
  bool dial_verbose_arg = false;
  cmd_dial->add_option("instance_id", dial_instance_arg,
                       "Numeric uint64 returned by `cesh compute launch` "
                       "or shown in `cesh compute ps`.")->required();
  cmd_dial->add_flag("-v,--verbose", dial_verbose_arg,
                     "Print one ATTACH-ok line to stderr on success.");

  // ---- autoexec subcommands ----
  auto* cmd_autoexec = app.add_subcommand("autoexec", "Boot-time program execution");
  cmd_autoexec->require_subcommand(1);

  std::string autoexec_program_arg;
  uint64_t autoexec_budget_arg = 10000000;
  std::string autoexec_input_arg;

  uint16_t autoexec_days_arg = 30;
  auto* cmd_axi = cmd_autoexec->add_subcommand("install", "Install autoexec program");
  cmd_axi->add_option("program", autoexec_program_arg, "Program asset ID or name")->required();
  cmd_axi->add_option("--budget", autoexec_budget_arg, "Gas budget per boot execution");
  cmd_axi->add_option("--input", autoexec_input_arg,
    "Input data (hex string; <= ~40 bytes - must fit in the autoexec asset cell)");
  cmd_axi->add_option("--days", autoexec_days_arg, "Days to fund autoexec asset (default 30)");

  // ---- Parse ----

  try {
    if (argc <= 1)
      throw CLI::CallForHelp();
    app.parse(argc, argv);
  } catch (const CLI::RequiredError& e) {
    auto subs = app.get_subcommands();
    if (!subs.empty()) {
      auto* leaf = subs.back();
      auto leafSubs = leaf->get_subcommands();
      if (!leafSubs.empty())
        leaf = leafSubs.back();
      std::cout << leaf->help() << "\n";
    } else {
      std::cout << app.help() << "\n";
    }
    return 1;
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  }

  setup_logger(logLevel);

  // ---- Resolve server / proxy from env override ----

  if (const char* e = std::getenv("CESH_SERVER"))
    server_arg = e;
  if (const char* e = std::getenv("CESH_PROXY"))
    proxy_arg = e;

  bool useProxy = !proxy_arg.empty();
  boost::asio::ip::udp::endpoint server_endpoint;
  boost::asio::ip::tcp::endpoint proxy_endpoint;
  // `cesh dial` only talks /ces/lua/1 on --rpc-port; it never opens a
  // CesClient session and so doesn't need the main server endpoint.
  // Skip the resolver to allow `--server localhost` (no :port). peer-info
  // resolves its own positional <server>, so it skips this too.
  if (!cmd_dial->parsed() && !cmd_peer_info->parsed()) {
    try {
      if (useProxy) {
        proxy_endpoint = ces::Resolver::resolveTcp(proxy_arg);
      } else {
        server_endpoint = ces::Resolver::resolveUdp(server_arg);
      }
    } catch (std::exception& e) {
      std::cerr << "Resolve error: " << e.what() << "\n";
      return 1;
    }
  }

  // ---- Session factory ----

  auto makeSession = [&](const KeyPair* kp = nullptr)
    -> std::unique_ptr<ClientSession> {
    std::unique_ptr<ClientSession> s;
    if (useProxy)
      s = std::make_unique<ClientSession>(cacheOnly, proxy_endpoint, kp,
                                           tries_arg);
    else
      s = std::make_unique<ClientSession>(cacheOnly, clientPort,
                                           server_endpoint, kp, tries_arg);
    s->client().setTries(tries_arg);
    return s;
  };

  // ---- peer-info: positional <server>, unsigned/free, its own session ----
  if (cmd_peer_info->parsed()) {
    boost::asio::ip::udp::endpoint ep;
    try {
      ep = ces::Resolver::resolveUdp(peer_info_server_arg);
    } catch (std::exception& e) {
      std::cerr << "Resolve error: " << e.what() << "\n";
      return 1;
    }
    ClientSession sess(cacheOnly, clientPort, ep, nullptr, tries_arg);
    sess.client().setTries(tries_arg);
    uint16_t count = 0;
    bool found = false;
    minx::Hash pk{};
    std::string addr;
    uint8_t rc = sess.client().queryPeerInfo(peer_info_id_arg, count, found,
                                             pk, addr);
    if (rc != CES_OK) {
      std::cerr << "Peer-Info Failed: " << errorString(rc) << "\n";
      return 1;
    }
    print_header("Peer slot " + std::to_string(peer_info_id_arg));
    print_field("peers total", std::to_string(count));
    print_field("found", found ? std::string("yes") : std::string("no"));
    if (found) {
      print_field("pubkey", minx::hashToString(pk));
      print_field("address", addr);
    }
    return 0;
  }

  // ---- Load wallet ----
  //
  // cesh wallet resolution order:
  //   1. Explicit --wallet path from CLI
  //   2. CESH_WALLET env var (colon-separated keys)
  //   3. Default file: ~/.cesh/CESH_WALLET

  Wallet wallet;
  auto cesh_home = []() -> std::filesystem::path {
    const char* h = std::getenv("HOME");
    if (!h) h = std::getenv("USERPROFILE");
    return h ? std::filesystem::path(h) : std::filesystem::current_path();
  };

  auto cesh_resolve_path = [&](const std::string& arg) -> std::filesystem::path {
    const std::string defaultFilename = "CESH_WALLET";
    std::filesystem::path p = arg.empty()
      ? (cesh_home() / ".cesh") : std::filesystem::path(arg);
    if (arg.empty() && !std::filesystem::exists(p)) {
      try {
        std::filesystem::create_directories(p);
        setSecurePermission(p);
      } catch (...) {}
      return p / defaultFilename;
    }
    if (std::filesystem::is_directory(p))
      return p / defaultFilename;
    return p;
  };

  try {
    if (app.count("-r") || app.count("--wallet")) {
      auto wp = cesh_resolve_path(wallet_read_arg);
      if (std::filesystem::exists(wp))
        wallet.loadFromFile(wp);
    } else if (const char* envVal = std::getenv("CESH_WALLET")) {
      wallet.loadFromString(envVal);
    } else {
      auto wp = cesh_resolve_path("");
      if (std::filesystem::exists(wp))
        wallet.loadFromFile(wp);
    }
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    if (std::getenv("CESH_WALLET")) {
      std::cerr << "Hint: $CESH_WALLET is inline keys "
                   "(\"01abc...:00def...\"), not a file path.\n"
                   "      For a file, use --wallet /path/to/wallet.\n";
    }
    return 1;
  }

  // ---- Subcommand: keys ----

  if (cmd_keys->parsed()) {
    if (cmd_keys->get_subcommands().empty()) {
      std::cout << cmd_keys->help() << "\n";
      return 0;
    }

    KeyAlgo algo = opt_secp ? KeyAlgo::SECP256K1 : KeyAlgo::ED25519;

    if (cmd_keys_gen->parsed()) {
      int firstNew = wallet.generate(gen_count, algo);
      std::cout << "Generated " << gen_count << " "
                << (opt_secp ? "secp256k1" : "ed25519") << " keys.\n";
      for (int i = firstNew; i < wallet.size(); ++i) {
        KeyPair kp = wallet.keyPair(i);
        std::cout << "[@" << i << "] " << Wallet::algoLabel(kp) << " "
                  << wallet.keyHex(i) << " (" << kp.getPublicKeyHexStr()
                  << ")\n";
      }
    }

    if (cmd_keys_add->parsed()) {
      try {
        wallet.addKey(keys_add_arg, algo);
        std::cout << "Added "
                  << (opt_secp ? "secp256k1" : "ed25519")
                  << " key to wallet.\n";
      } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
      }
    }

    if (cmd_keys_list->parsed()) {
      for (int i = 0; i < wallet.size(); ++i) {
        KeyPair kp = wallet.keyPair(i);
        std::cout << "[@" << i << "] " << Wallet::algoLabel(kp) << " "
                  << wallet.keyHex(i)
                  << (keys_show_public ? (" (" + kp.getPublicKeyHexStr() + ")")
                                       : "")
                  << "\n";
      }
    }

    if (cmd_keys->get_subcommand("export")->parsed()) {
      std::cout << "export CESH_WALLET=\"";
      bool first = true;
      for (auto& k : wallet.keys()) {
        if (!first)
          std::cout << ":";
        std::cout << k;
        first = false;
      }
      std::cout << "\"\n";
    }

    if (cmd_keys_gen->count("-w") || cmd_keys_add->count("-w")) {
      auto savePath = cesh_resolve_path(wallet_save_arg);
      wallet.saveToFile(savePath);
      std::cout << "Saved wallet to " << savePath.string() << "\n";
    }

    return 0;
  }

  // ---- Subcommand: query (unsigned, no actor needed) ----

  if (cmd_query->parsed()) {
    try {
      auto sess = makeSession();
      auto& cc = sess->client();

      std::string hex = wallet.resolveKey(query_account_arg);
      minx::Hash h;
      minx::stringToHash(h, hex);
      int64_t b;
      uint32_t n;
      HashPrefix xd{};
      uint64_t xa = 0;
      uint32_t xt = 0;
      if (cc.queryAccount(Account::getMapKey(h), b, n, xd, xa, xt) == CES_OK) {
        if (g_quiet) {
          std::cout << "{\"key\":\"" << jesc(hex) << "\",\"balance\":" << b
                    << ",\"nonce\":" << n
                    << ",\"lastXferDest\":\"" << jesc(hashPrefixToString(xd))
                    << "\",\"lastXferAmount\":" << xa
                    << ",\"lastXferTime\":" << xt << "}\n";
        } else {
          print_header("Account (Unsigned)");
          print_field("Key", hex);
          print_field("Balance", b);
          print_field("Nonce", n);
          print_field("LastXferDest", hashPrefixToString(xd));
          print_field("LastXferAmount", xa);
          print_field("LastXferTime", xt);
          std::cout << std::endl;
        }
      } else {
        std::cerr << "Query failed (check logs)\n";
        return 1;
      }
    } catch (std::exception& e) {
      std::cerr << "Error: " << e.what() << "\n";
      return 1;
    }
    return 0;
  }

  // ---- Subcommand: ping (unsigned, no actor needed) ----

  if (cmd_ping->parsed()) {
    try {
      auto sess = makeSession();
      auto& cc = sess->client();
      if (g_quiet) {
        std::cout << "{\"status\":\"ok\""
                  << ",\"serverPublicKey\":\""
                  << minx::hashToString(cc.getServerKey())
                  << "\",\"serverId\":\"" << hashPrefixToString(cc.getServerId())
                  << "\",\"minDifficulty\":"
                  << static_cast<unsigned>(cc.getMinDifficulty())
                  << ",\"minSecsPoW\":"
                  << static_cast<unsigned>(cc.getMinSecsPoW())
                  << ",\"pendingPoWs\":" << cc.getPendingPoWs()
                  << ",\"tps\":" << cc.getTps()
                  << ",\"rpcPort\":" << cc.getServerRpcPort() << "}\n";
      } else {
        std::cout << "status=ok\n"
                  << "server_key=" << minx::hashToString(cc.getServerKey())
                  << "\n"
                  << "server_id=" << hashPrefixToString(cc.getServerId()) << "\n"
                  << "min_difficulty="
                  << static_cast<unsigned>(cc.getMinDifficulty()) << "\n"
                  << "min_secs_pow="
                  << static_cast<unsigned>(cc.getMinSecsPoW()) << "\n"
                  << "pending_pows=" << cc.getPendingPoWs() << "\n"
                  << "tps=" << cc.getTps() << "\n"
                  << "rpc_port=" << cc.getServerRpcPort() << "\n";
      }
    } catch (std::exception& e) {
      if (g_quiet)
        std::cerr << "{\"status\":\"error\",\"error\":\"" << jesc(e.what())
                  << "\"}\n";
      else
        std::cout << "status=error\nerror=" << e.what() << "\n";
      return 1;
    }
    return 0;
  }

  // ---- Subcommand: asset query (unsigned, no actor needed) ----

  if (cmd_aq->parsed()) {
    try {
      auto sess = makeSession();
      auto& cc = sess->client();

      auto aid = parseAssetKey(asset_id_arg);
      HashPrefix owner{};
      AssetData content{};
      uint16_t balance = 0;
      uint32_t price = 0;
      uint8_t rc = cc.queryAsset(aid, owner, content, balance, price);
      if (rc == CES_OK) {
        HashPrefix zero{};
        if (owner == zero) {
          std::cerr << "Asset not found.\n";
          return 1;
        }
        if (g_quiet) {
          std::cout << "{\"queryId\":\"" << jesc(asset_id_arg)
                    << "\",\"owner\":\"" << jesc(hashPrefixToString(owner))
                    << "\",\"days\":" << assetDays(balance)
                    << ",\"private\":"
                    << (isAssetPrivate(balance) ? "true" : "false")
                    << ",\"assetOwned\":"
                    << (isAssetOwned(balance) ? "true" : "false")
                    << ",\"immutable\":"
                    << (isAssetImmutable(balance) ? "true" : "false")
                    << ",\"price\":" << price
                    << ",\"contentHex\":\"" << ces::bytesToHex(content)
                    << "\"}\n";
        } else {
          std::string flagsStr;
          if (isAssetPrivate(balance))   flagsStr += " private";
          if (isAssetOwned(balance))     flagsStr += " asset-owned";
          if (isAssetImmutable(balance)) flagsStr += " immutable";
          print_header("Asset (Unsigned)");
          print_field("Query ID", asset_id_arg);
          print_field("Owner ID", hashPrefixToString(owner));
          print_field("Balance",
                      std::to_string(assetDays(balance)) + " days" + flagsStr);
          print_field("Price", price == 0 ? std::string("not for sale")
                                          : std::to_string(price) + " credits");
          print_field("Content", contentToDisplayString(content));
          std::cout << std::endl;
        }
      } else {
        std::cerr << "Query Failed: " << errorString(rc) << "\n";
        return 1;
      }
    } catch (std::exception& e) {
      std::cerr << "Error: " << e.what() << "\n";
      return 1;
    }
    return 0;
  }

  // ---- All remaining subcommands need an actor key ----

  if (cmd_asset->parsed() && cmd_asset->get_subcommands().empty()) {
    std::cout << cmd_asset->help() << "\n";
    return 0;
  }

  bool needs_actor =
    (cmd_squery->parsed() || cmd_transfer->parsed() || cmd_payment->parsed() ||
     cmd_cross->parsed() || cmd_sinfo->parsed() || cmd_mine->parsed() ||
     cmd_asset->parsed() || cmd_file->parsed() || cmd_autoexec->parsed() ||
     cmd_dfile->parsed() || cmd_compute->parsed() || cmd_dial->parsed());

  if (!needs_actor)
    return 0;

  KeyPair actorKey;
  try {
    actorKey = wallet.resolveActor(actor_arg);
  } catch (std::exception& e) {
    std::cerr << e.what() << "\n";
    return 1;
  }

  // ---- dial — bypass the main UDP CesClient (only needs --rpc-port) ----
  if (cmd_dial->parsed()) {
    DialArgs da;
    // server_arg may be "host" or "host:port"; the trailing :port (if
    // present) is the main CES port, not the rpc port. We only want
    // the host here.
    da.serverHost = server_arg;
    if (auto colon = da.serverHost.rfind(':');
        colon != std::string::npos)
      da.serverHost = da.serverHost.substr(0, colon);
    if (da.serverHost.empty()) da.serverHost = "localhost";
    da.rpcPort     = rpcPort_arg;
    da.instanceId  = dial_instance_arg;
    da.signerKey   = actorKey;
    da.verbose     = dial_verbose_arg;
    return runDial(da);
  }

  try {
    auto sess = makeSession(&actorKey);
    auto& cc = sess->client();

    // ---- handleAsset handler ----
    auto handleAsset = [&]() -> int {
    // Resolve content from --content (text) or --hexcontent (hex)
    auto resolveContent = [&]() -> AssetData {
      if (!asset_hexcontent_arg.empty())
        return parseHexContent(asset_hexcontent_arg);
      if (!asset_content_arg.empty())
        return parseAssetContent(asset_content_arg);
      throw std::runtime_error("Specify --content or --hexcontent");
    };

    if (cmd_ac->parsed()) {
      auto aid = parseAssetKey(asset_id_arg);
      auto ctn = resolveContent();
      uint8_t rc = cc.createAsset(aid, ctn, asset_days_arg,
                                  asset_private_arg, asset_immutable_arg);
      if (rc == CES_OK) {
        print_header("Asset Created");
        print_field("Asset", asset_id_arg);
        print_field("Days", asset_days_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Create Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_au->parsed()) {
      auto aid = parseAssetKey(asset_id_arg);
      auto ctn = resolveContent();
      HashPrefix own;
      if (asset_target_arg.empty())
        own = Account::getMapKey(actorKey.getPublicKeyAsHash());
      else {
        minx::Hash t;
        minx::stringToHash(t, wallet.resolveKey(asset_target_arg));
        own = Account::getMapKey(t);
      }
      uint32_t storedPrice;
      if (validatePrice(asset_price_arg, storedPrice) != 0) {
        std::cerr << "Invalid price. Max: " << UINT32_MAX << "\n";
        return 1;
      }
      uint8_t rc = cc.updateAsset(aid, own, ctn, storedPrice);
      if (rc == CES_OK) {
        print_header("Asset Updated");
        print_field("Asset", asset_id_arg);
        print_field("Price (whole credits)", asset_price_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Update Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_am->parsed()) {
      auto aid = parseAssetKey(asset_id_arg);
      HashPrefix own;
      if (asset_target_arg.empty())
        own = Account::getMapKey(actorKey.getPublicKeyAsHash());
      else {
        minx::Hash t;
        minx::stringToHash(t, wallet.resolveKey(asset_target_arg));
        own = Account::getMapKey(t);
      }
      uint32_t storedPrice;
      if (validatePrice(asset_price_arg, storedPrice) != 0) {
        std::cerr << "Invalid price. Max: " << UINT32_MAX << "\n";
        return 1;
      }
      uint8_t rc = cc.updateAssetMeta(aid, own, storedPrice);
      if (rc == CES_OK) {
        print_header("Asset Meta Updated");
        print_field("Asset", asset_id_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Meta Update Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_af->parsed()) {
      auto aid = parseAssetKey(asset_id_arg);
      auto ctn = resolveContent();
      uint8_t rc = cc.updateAssetFast(aid, ctn);
      if (rc == CES_OK) {
        print_header("Asset Fast-Updated");
        print_field("Asset", asset_id_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Fast Update Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_afd->parsed()) {
      auto aid = parseAssetKey(asset_id_arg);
      uint8_t rc = cc.fundAsset(aid, asset_days_arg);
      if (rc == CES_OK) {
        print_header("Asset Funded");
        print_field("Asset", asset_id_arg);
        print_field("Days Added", asset_days_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Fund Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_ab->parsed()) {
      auto aid = parseAssetKey(asset_id_arg);
      uint64_t realAmount = asset_buy_amount_arg * ces::PRICE_UNIT;
      uint8_t rc = cc.buyAsset(aid, realAmount);
      if (rc == CES_OK) {
        print_header("Asset Purchased");
        print_field("Asset", asset_id_arg);
        print_field("Paid (whole credits)", asset_buy_amount_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Buy Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_ag->parsed()) {
      auto aid = parseAssetKey(asset_id_arg);
      minx::Hash t;
      minx::stringToHash(t, wallet.resolveKey(asset_target_arg));
      uint8_t rc = cc.giveAsset(aid, Account::getMapKey(t));
      if (rc == CES_OK) {
        print_header("Asset Given");
        print_field("Asset", asset_id_arg);
        print_field("New Owner", asset_target_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Give Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_ar->parsed()) {
      auto aid = parseAssetKey(asset_id_arg);
      ces::Bytes input;
      if (!asset_run_input_arg.empty())
        input = ces::parseHex(asset_run_input_arg);
      uint64_t vmError = 0, budgetUsed = 0;
      ces::Bytes output;
      uint8_t rc = cc.runAsset(aid, asset_run_budget_arg, input,
                                vmError, budgetUsed, output,
                                asset_run_nonceless,
                                asset_run_allowance_arg);
      uint64_t allowanceUsed = cc.getLastRunAssetAllowanceUsed();
      if (rc == CES_OK) {
        print_header("Asset Executed");
        print_field("Asset", asset_id_arg);
        print_field("VM Error", std::to_string(vmError));
        print_field("Budget Used", std::to_string(budgetUsed));
        print_field("Allowance Used", std::to_string(allowanceUsed));
        if (!output.empty())
          print_field("Output", ces::bytesToHex(output));
        std::cout << "Success.\n";
      } else {
        print_header("Asset Execution Failed");
        print_field("Error", errorString(rc));
        print_field("VM Error", std::to_string(vmError));
        print_field("Budget Used", std::to_string(budgetUsed));
        print_field("Allowance Used", std::to_string(allowanceUsed));
        return 1;
      }

    } else if (cmd_asq->parsed()) {
      auto aid = parseAssetKey(asset_id_arg);
      std::vector<AssetEntry> vec;
      uint8_t rc = cc.queryAssetSigned(aid, 0, vec);
      if (rc == CES_OK && !vec.empty()) {
        const auto& a = vec[0];
        std::string flagsStr;
        if (isAssetPrivate(a.balance))   flagsStr += " private";
        if (isAssetOwned(a.balance))     flagsStr += " asset-owned";
        if (isAssetImmutable(a.balance)) flagsStr += " immutable";
        print_header("Asset (Signed)");
        print_field("Query ID", asset_id_arg);
        print_field("Owner ID", hashPrefixToString(a.ownerId));
        print_field("Balance", std::to_string(assetDays(a.balance)) + " days" + flagsStr);
        print_field("Price", a.price == 0 ? std::string("not for sale")
                                         : std::to_string(a.price) + " credits");
        print_field("Content", contentToDisplayString(a.content));
        std::cout << std::endl;
      } else {
        std::cerr << "Query Failed: " << errorString(rc) << "\n";
        return 1;
      }
    }
      return 0;
    };

    // ---- handleFile handler ----
    auto handleFile = [&]() -> int {
    if (cmd_fp->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      // file_composed_data was built by the --in callback (inAppender).
      auto& fileData = file_composed_data;

      size_t numChunks = fileData.empty() ? 0
        : (fileData.size() + RAMFILE_CHUNK_DATA_SIZE - 1) / RAMFILE_CHUNK_DATA_SIZE;

      uint8_t rc = ramfilePut(cc, fkey, fileData.data(), fileData.size(),
                            file_days_arg,
                            reinterpret_cast<const uint8_t*>(file_meta_arg.data()),
                            file_meta_arg.size(),
                            [&](size_t done, size_t total) {
                              std::cout << "\r  " << done << "/" << total
                                        << " chunks" << std::flush;
                            });
      std::cout << "\n";
      if (rc == CES_OK) {
        print_header("File Uploaded");
        print_field("Key", file_key_arg);
        print_field("Size", std::to_string(fileData.size()) + " bytes");
        print_field("Chunks", numChunks);
        print_field("Days", file_days_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Upload Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_ft->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      uint8_t rc = ramfilePut(cc, fkey, nullptr, 0, file_days_arg,
                            reinterpret_cast<const uint8_t*>(file_meta_arg.data()),
                            file_meta_arg.size());
      if (rc == CES_OK) {
        print_header("File Created");
        print_field("Key", file_key_arg);
        print_field("Days", file_days_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Touch Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_fg->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      ces::Bytes fileData;
      RamfileHeader header;
      bool mismatch = false;
      uint8_t rc = ramfileGet(cc, fkey, fileData, &header, &mismatch);
      if (rc == CES_OK) {
        std::ofstream ofs(file_path_arg, std::ios::binary);
        if (!ofs) {
          std::cerr << "Error: cannot write " << file_path_arg << "\n";
          return 1;
        }
        ofs.write(reinterpret_cast<const char*>(fileData.data()),
                  fileData.size());
        print_header("File Downloaded");
        print_field("Key", file_key_arg);
        print_field("Size", std::to_string(fileData.size()) + " bytes");
        if (mismatch)
          print_field("WARNING", "SHA256 mismatch (file may be dirty)");
        std::cout << "Success.\n";
      } else {
        std::cerr << "Download Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_fi->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      HashPrefix owner;
      AssetData headContent;
      uint16_t headBalance = 0;
      uint32_t headPrice = 0;
      uint8_t rc = cc.queryAsset(fkey, owner, headContent, headBalance, headPrice);
      if (rc != CES_OK) {
        std::cerr << "Info Failed: " << errorString(rc) << "\n";
        return 1;
      }
      auto header = parseRamfileHeader(headContent);
      if (!header.valid) {
        std::cerr << "Error: not a file (bad magic)\n";
        return 1;
      }
      print_header("File Info");
      print_field("Key", file_key_arg);
      print_field("Size", std::to_string(header.fileSize) + " bytes");
      print_field("SHA256", ces::bytesToHex(header.contentHash));
      if (header.createdTime)
        print_field("Created", std::to_string(header.createdTime) + " us");
      if (header.modifiedTime)
        print_field("Modified", std::to_string(header.modifiedTime) + " us");
      print_field("Head Days", assetDays(headBalance));
      // Display metadata if non-empty
      size_t metaLen = 0;
      for (size_t i = 0; i < RAMFILE_HEAD_META_SIZE; ++i)
        if (header.metadata[i]) metaLen = i + 1;
      if (metaLen > 0) {
        bool isText = true;
        for (size_t i = 0; i < metaLen; ++i)
          if (header.metadata[i] < 32 || header.metadata[i] > 126)
            isText = false;
        if (isText)
          print_field("Metadata",
            std::string(reinterpret_cast<const char*>(header.metadata.data()), metaLen));
        else
          print_field("Metadata", std::to_string(metaLen) + " bytes (binary)");
      }

    } else if (cmd_fr->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      auto scanPath = buildRamfileScanFilename(fkey, server_arg);
      auto keys = readRamfileScan(scanPath);
      if (keys.empty()) {
        std::cerr << "Error: scan file not found: " << scanPath << "\n";
        return 1;
      }
      uint64_t len = file_length_arg;
      if (len == 0) len = UINT64_MAX; // read all from offset
      ces::Bytes got;
      uint8_t rc = ramfileRead(cc, keys, file_offset_arg, len, got);
      if (rc != CES_OK) {
        std::cerr << "Read Failed: " << errorString(rc) << "\n";
        return 1;
      }
      if (!file_outfile_arg.empty()) {
        std::ofstream ofs(file_outfile_arg, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(got.data()), got.size());
        print_header("File Read");
        print_field("Bytes", got.size());
        print_field("Output", file_outfile_arg);
      } else if (file_hex_output) {
        std::cout << ces::bytesToHex(got) << "\n";
      } else {
        std::cout.write(reinterpret_cast<const char*>(got.data()), got.size());
      }

    } else if (cmd_fw->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      auto scanPath = buildRamfileScanFilename(fkey, server_arg);
      auto keys = readRamfileScan(scanPath);
      if (keys.empty()) {
        std::cerr << "Error: scan file not found: " << scanPath << "\n";
        return 1;
      }
      auto& wdata = file_composed_data;
      if (wdata.empty()) {
        std::cerr << "Error: specify --in <text|text:T|hex:XX|file:path>\n"; return 1;
      }
      uint8_t rc = ramfileWrite(cc, keys, file_offset_arg, wdata.data(), wdata.size());
      if (rc == CES_OK) {
        print_header("File Written");
        print_field("Offset", file_offset_arg);
        print_field("Bytes", wdata.size());
        std::cout << "Success.\n";
      } else {
        std::cerr << "Write Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_fa->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      auto scanPath = buildRamfileScanFilename(fkey, server_arg);
      auto keys = readRamfileScan(scanPath);
      if (keys.empty()) {
        std::cerr << "Error: scan file not found: " << scanPath << "\n";
        return 1;
      }
      auto& adata = file_composed_data;
      if (adata.empty()) {
        std::cerr << "Error: specify --in <text|text:T|hex:XX|file:path>\n"; return 1;
      }

      // Append is the composition of
      // (1) ramfileResize to grow the declared size (allocating new
      // chunks via the current chain's tail if needed) and (2)
      // ramfileWrite to place the appended bytes into the newly-grown
      // region. Read the current declared size from the head first
      // so we know where to start writing.
      HashPrefix headOwner;
      AssetData headContent;
      uint16_t headBalance = 0;
      uint32_t headPrice = 0;
      uint8_t rc = cc.queryAsset(keys[0], headOwner, headContent,
                                 headBalance, headPrice);
      if (rc != CES_OK) {
        std::cerr << "Append Failed (query head): "
                  << errorString(rc) << "\n";
        return 1;
      }
      RamfileHeader hdr = parseRamfileHeader(headContent);
      if (!hdr.valid) {
        std::cerr << "Append Failed: head is not a valid file header\n";
        return 1;
      }
      uint64_t oldSize = hdr.fileSize;

      rc = ramfileResize(cc, keys, oldSize + adata.size(), file_days_arg);
      if (rc != CES_OK) {
        std::cerr << "Append Failed (resize): "
                  << errorString(rc) << "\n";
        return 1;
      }

      rc = ramfileWrite(cc, keys, oldSize, adata.data(), adata.size());
      if (rc == CES_OK) {
        // Update scan file with new keys (resize may have added chunks).
        writeRamfileScan(scanPath, keys);
        print_header("File Appended");
        print_field("Bytes added", adata.size());
        print_field("Total chunks", keys.size() - 1);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Append Failed (write): "
                  << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_fz->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      auto scanPath = buildRamfileScanFilename(fkey, server_arg);
      auto keys = readRamfileScan(scanPath);
      if (keys.empty()) {
        std::cerr << "Error: scan file not found: " << scanPath << "\n";
        return 1;
      }
      uint8_t rc = ramfileResize(cc, keys, file_newsize_arg, file_days_arg);
      if (rc == CES_OK) {
        writeRamfileScan(scanPath, keys);
        print_header("File Resized");
        print_field("Key", file_key_arg);
        print_field("New size", std::to_string(file_newsize_arg) + " bytes");
        print_field("Chunks", keys.size() - 1);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Resize Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_fh->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      uint8_t rc = ramfileRehash(cc, fkey);
      if (rc == CES_OK) {
        print_header("File Rehashed");
        print_field("Key", file_key_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Rehash Failed: " << errorString(rc) << "\n";
        return 1;
      }

    } else if (cmd_fs->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      std::vector<minx::Hash> keys;
      uint8_t rc = ramfileScan(cc, fkey, keys);
      if (rc != CES_OK) {
        std::cerr << "Scan Failed: " << errorString(rc) << "\n";
        return 1;
      }
      auto scanPath = buildRamfileScanFilename(fkey, server_arg);
      writeRamfileScan(scanPath, keys);
      print_header("File Scanned");
      print_field("Key", file_key_arg);
      print_field("Assets", keys.size());
      print_field("Scan file", scanPath);
      std::cout << "Success.\n";

    } else if (cmd_ff->parsed()) {
      auto fkey = parseAssetKey(file_key_arg);
      auto scanPath = buildRamfileScanFilename(fkey, server_arg);
      auto keys = readRamfileScan(scanPath);
      if (keys.empty()) {
        std::cerr << "Error: scan file not found: " << scanPath << "\n";
        std::cerr << "Run 'cesh ramfile scan " << file_key_arg << "' first.\n";
        return 1;
      }
      uint8_t rc = ramfileFundFromScan(cc, keys, file_days_arg);
      if (rc == CES_OK) {
        print_header("File Funded");
        print_field("Key", file_key_arg);
        print_field("Assets funded", keys.size());
        print_field("Days Added", file_days_arg);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Fund Failed: " << errorString(rc) << "\n";
        return 1;
      }
    }
      return 0;
    };

    // ---- handleDiskFile handler (L2 disk-backed file store) ----
    auto handleDiskFile = [&]() -> int {
      if (rpcPort_arg == 0) {
        std::cerr << "Error: --rpc-port is required for 'file' subcommands.\n";
        return 1;
      }

      // Resolve server host:port → we want the host (the rpcPort is the
      // separate --rpc-port flag). Accept either bare host or host:port
      // — same as elsewhere in cesh. If the user passed --server host:X,
      // we ignore X (that's the main CES port, not the file port).
      std::string host = server_arg;
      auto colon = host.rfind(':');
      if (colon != std::string::npos) host = host.substr(0, colon);
      if (host.empty()) host = "localhost";

      // Fetch server-info once to get serverPublicKey for response sig
      // verification, and feeFileRent for the CREATE upfront estimate.
      // The query is paid from the signer's account.
      std::vector<ServerInfoEntry> entries;
      uint8_t sirc = cc.queryServerInfo(entries);
      if (sirc != CES_OK) {
        std::cerr << "Error: queryServerInfo failed: "
                  << errorString(sirc) << "\n";
        return 1;
      }
      minx::Hash serverPk{};
      bool hasServerPk = false;
      uint64_t feeFileRent = 0;
      uint64_t feeFileWrite = 0;
      for (const auto& e : entries) {
        if (e.key == "serverPublicKey") {
          try {
            minx::stringToHash(serverPk, e.value);
            hasServerPk = true;
          } catch (...) {}
        } else if (e.key == "feeFileRent") {
          try { feeFileRent = std::stoull(e.value); } catch (...) {}
        } else if (e.key == "feeFileWrite") {
          try { feeFileWrite = std::stoull(e.value); } catch (...) {}
        }
      }
      if (!hasServerPk) {
        std::cerr << "Warn: serverPublicKey not found in server-info; "
                  << "response sig verification disabled.\n";
      }

      // Helper: auto-prepend /h/<signer>/ if the path doesn't start with /.
      auto normalizePath = [&](const std::string& raw) -> std::string {
        if (!raw.empty() && raw[0] == '/') return raw;
        return "/h/" + actorKey.getPublicKeyHexStr() + "/" + raw;
      };

      // Helper: compute the 15-min upfront-rent minimum for a new file of
      // `size` bytes at the server's current feeFileRent.
      auto upfrontFor = [&](uint64_t size) -> uint64_t {
        if (feeFileRent == 0 || size == 0) return 0;
        // 15 min = 900 seconds = 9e8 us. A day = 8.64e10 us.
        // owed = size * rate * 9e8 / 8.64e10 (floor). Use __uint128_t.
        __uint128_t owed = static_cast<__uint128_t>(size) *
                           static_cast<__uint128_t>(feeFileRent) *
                           static_cast<__uint128_t>(900'000'000ull);
        owed /= static_cast<__uint128_t>(86'400'000'000ull);
        if (owed > std::numeric_limits<uint64_t>::max())
          return std::numeric_limits<uint64_t>::max();
        return static_cast<uint64_t>(owed);
      };

      CesFileClient cfc;
      uint8_t rc = cfc.connect(host, rpcPort_arg, actorKey);
      if (rc != CES_OK) {
        std::cerr << "Error: file-store connect failed: "
                  << errorString(rc) << "\n";
        return 1;
      }
      if (hasServerPk) cfc.setServerPubkey(serverPk);

      // Sub-MB chunks: the server caps WRITE/READ at 1 MB, and RUDP's
      // per-channel reorder buffer is also 1 MB, so a 1 MB chunk leaves
      // no headroom for retransmits. 512 KB stays within both limits.
      constexpr size_t kChunkSize = 512 * 1024;

      // ---- put ----
      if (cmd_dfp->parsed()) {
        // Load local file fully into memory.
        std::ifstream in(df_local_arg, std::ios::binary);
        if (!in) {
          std::cerr << "Error: cannot open local file: " << df_local_arg
                    << "\n";
          return 1;
        }
        ces::Bytes bytes(
          (std::istreambuf_iterator<char>(in)),
          std::istreambuf_iterator<char>());

        std::string remote = normalizePath(df_remote_arg);

        // STAT first to decide CREATE vs RESIZE path.
        CesFileClient::StatInfo info;
        uint8_t srcRc = cfc.stat(remote, info);
        bool exists = (srcRc == CES_OK);

        // /s/ is unmetered on the server (see file_handler.cpp:
        // isServerZone). The client's per-byte top-up math here would
        // compute nonsense: e.g. 275 MB × 18280 cr/byte ≈ 5 peta-credits.
        // Detect and skip.
        const bool remoteIsServerZone =
          remote.size() >= 3 && remote[0] == '/' &&
          remote[1] == 's' && remote[2] == '/';

        if (exists) {
          if (!remoteIsServerZone) {
            // Auto top-up: make sure the file has enough balance to
            // complete the re-upload. Need = writeCost for the new
            // content + upfront rent on any growth delta. Any user-
            // specified --deposit is added on top as a bonus.
            uint64_t grow = (bytes.size() > info.size)
              ? (bytes.size() - info.size) : 0;
            // feeFileWrite is credits per KB (1024 bytes, ceil).
            uint64_t writeKb = (bytes.size() + 1023) / 1024;
            // Upfront on the growth delta is BURNED on APPEND/RESIZE
            // — we add another 15-min retention float on top so the
            // new bytes actually live past the APPEND.
            uint64_t need = writeKb * feeFileWrite + upfrontFor(grow) * 2;
            uint64_t shortfall = (need > info.fileBalance)
              ? (need - info.fileBalance) : 0;
            uint64_t topUp = shortfall + df_deposit_arg;
            if (topUp > 0) {
              uint64_t newBal = 0;
              uint8_t drc = cfc.deposit(remote, topUp, newBal);
              if (drc != CES_OK) {
                std::cerr << "Error: deposit failed: " << errorString(drc)
                          << "\n";
                return 1;
              }
            }
          }
          // Resize if size changed.
          if (info.size != bytes.size()) {
            uint64_t newSize = 0;
            uint8_t rrc = cfc.resize(remote, bytes.size(),
                                      newSize);
            if (rrc != CES_OK) {
              std::cerr << "Error: resize failed: " << errorString(rrc)
                        << "\n";
              return 1;
            }
          }
        } else if (srcRc == CES_ERROR_FILE_NOT_FOUND) {
          // CREATE path. Decide deposit.
          // Minimum = (15-min upfront rent) + (write cost to fill).
          // The server checks the upfront at CREATE and the write
          // cost at each WRITE; a naive deposit defaults to their
          // sum so a small file "just uploads."
          // /s/ short-circuits — unmetered on the server, the deposit
          // field is forced to 0 by the server regardless.
          uint64_t deposit;
          if (remoteIsServerZone) {
            deposit = 0;
          } else {
            uint64_t upfront = upfrontFor(bytes.size());
            // feeFileWrite is credits per KB (1024 bytes, ceil).
            uint64_t writeKb = (bytes.size() + 1023) / 1024;
            uint64_t writeCost = writeKb * feeFileWrite;
            // Default deposit = upfront_burn + writeCost + 15-min of
            // retention. Upfront is burned at CREATE (not refunded),
            // so we add it twice: once for the burn, once to leave
            // a 15-min rent float in file_balance after the WRITE.
            uint64_t minDeposit = upfront * 2 + writeCost;
            deposit = df_deposit_arg > 0 ? df_deposit_arg : minDeposit;
            if (deposit < upfront) {
              std::cerr << "Error: --deposit " << deposit
                        << " is below the 15-min upfront rent minimum ("
                        << upfront << "). Raise --deposit or reduce "
                        << "the file size.\n";
              return 1;
            }
          }
          uint64_t createdBalance = 0, costDebited = 0;
          uint8_t crc = cfc.create(remote, bytes.size(),
                                    /*price_per_kb=*/0, deposit,
                                    createdBalance, costDebited);
          if (crc != CES_OK) {
            std::cerr << "Error: create failed: " << errorString(crc)
                      << "\n";
            return 1;
          }
        } else {
          std::cerr << "Error: STAT failed: " << errorString(srcRc) << "\n";
          return 1;
        }

        // Stream the bytes in 1-MB chunks.
        size_t written = 0;
        while (written < bytes.size()) {
          size_t chunkLen = std::min(kChunkSize, bytes.size() - written);
          ces::Bytes chunk(bytes.begin() + written,
                                      bytes.begin() + written + chunkLen);
          uint64_t newBal = 0;
          uint8_t wrc = cfc.write(remote, written, chunk,
                                   newBal);
          if (wrc != CES_OK) {
            std::cerr << "Error: write at offset " << written << " failed: "
                      << errorString(wrc) << "\n";
            return 1;
          }
          written += chunkLen;
        }

        // Re-STAT for final info.
        CesFileClient::StatInfo fi;
        if (cfc.stat(remote, fi) == CES_OK) {
          print_header("File Uploaded");
          print_field("Remote", remote);
          print_field("Size", fi.size);
          print_field("Balance", fi.fileBalance);
          print_field("Price/KB", fi.pricePerKb);
          std::cout << std::endl;
        } else {
          std::cout << "File uploaded (" << bytes.size() << " bytes) to "
                    << remote << "\n";
        }
        return 0;
      }

      // ---- get ----
      if (cmd_dfg->parsed()) {
        std::string remote = normalizePath(df_remote_arg);
        CesFileClient::StatInfo info;
        uint8_t srcRc = cfc.stat(remote, info);
        if (srcRc != CES_OK) {
          std::cerr << "Error: STAT failed: " << errorString(srcRc) << "\n";
          return 1;
        }

        ces::Bytes all;
        all.reserve(info.size);
        uint64_t offset = 0;
        while (offset < info.size) {
          uint32_t chunkLen = static_cast<uint32_t>(
            std::min<uint64_t>(kChunkSize, info.size - offset));
          ces::Bytes chunk;
          minx::Hash rh;
          uint8_t rrc = cfc.read(remote, offset, chunkLen,
                                  chunk, rh);
          if (rrc != CES_OK) {
            std::cerr << "Error: read at offset " << offset << " failed: "
                      << errorString(rrc) << "\n";
            return 1;
          }
          all.insert(all.end(), chunk.begin(), chunk.end());
          offset += chunk.size();
        }

        // No local path (or "-") → stream raw bytes to stdout (the data-pipe
        // form). A real path → write the file + human summary.
        if (df_local_arg.empty() || df_local_arg == "-") {
          std::cout.write(reinterpret_cast<const char*>(all.data()),
                          all.size());
          std::cout.flush();
          return 0;
        }

        std::ofstream out(df_local_arg, std::ios::binary | std::ios::trunc);
        if (!out) {
          std::cerr << "Error: cannot open local destination: "
                    << df_local_arg << "\n";
          return 1;
        }
        out.write(reinterpret_cast<const char*>(all.data()), all.size());
        out.close();

        print_header("File Downloaded");
        print_field("Remote", remote);
        print_field("Local", df_local_arg);
        print_field("Size", all.size());
        print_field("Balance", info.fileBalance);
        std::cout << std::endl;
        return 0;
      }

      // ---- stat ----
      if (cmd_dfs->parsed()) {
        std::string remote = normalizePath(df_remote_arg);
        CesFileClient::StatInfo info;
        uint8_t srcRc = cfc.stat(remote, info);
        if (srcRc != CES_OK) {
          std::cerr << "STAT Failed: " << errorString(srcRc) << "\n";
          return 1;
        }
        if (g_quiet) {
          std::cout << "{\"remote\":\"" << jesc(remote)
                    << "\",\"owner\":\"" << minx::hashToString(info.ownerPubkey)
                    << "\",\"size\":" << info.size
                    << ",\"balance\":" << info.fileBalance
                    << ",\"pricePerKb\":" << info.pricePerKb
                    << ",\"createdUs\":" << info.createdUs
                    << ",\"modifiedUs\":" << info.modifiedUs << "}\n";
          return 0;
        }
        print_header("File Info");
        print_field("Remote", remote);
        print_field("Owner", minx::hashToString(info.ownerPubkey));
        print_field("Size", info.size);
        print_field("Balance", info.fileBalance);
        print_field("Price/KB", info.pricePerKb);
        print_field("Created", info.createdUs);
        print_field("Modified", info.modifiedUs);
        std::cout << std::endl;
        return 0;
      }

      // ---- rm ----
      if (cmd_dfrm->parsed()) {
        std::string remote = normalizePath(df_remote_arg);
        uint64_t refunded = 0;
        uint8_t drc = cfc.deleteFile(remote, refunded);
        if (drc != CES_OK) {
          std::cerr << "Error: delete failed: " << errorString(drc) << "\n";
          return 1;
        }
        print_header("File Deleted");
        print_field("Remote", remote);
        print_field("Refunded", refunded);
        std::cout << std::endl;
        return 0;
      }

      // ---- deposit ----
      if (cmd_dfd->parsed()) {
        std::string remote = normalizePath(df_remote_arg);
        uint64_t newBal = 0;
        uint8_t drc = cfc.deposit(remote, df_amount_arg, newBal);
        if (drc != CES_OK) {
          std::cerr << "Error: deposit failed: " << errorString(drc) << "\n";
          return 1;
        }
        print_header("File Deposit");
        print_field("Remote", remote);
        print_field("Balance", newBal);
        std::cout << std::endl;
        return 0;
      }

      // ---- withdraw ----
      if (cmd_dfw->parsed()) {
        std::string remote = normalizePath(df_remote_arg);
        uint64_t newBal = 0;
        uint8_t wrc = cfc.withdraw(remote, df_amount_arg, newBal);
        if (wrc != CES_OK) {
          std::cerr << "Error: withdraw failed: " << errorString(wrc) << "\n";
          return 1;
        }
        print_header("File Withdraw");
        print_field("Remote", remote);
        print_field("Balance", newBal);
        std::cout << std::endl;
        return 0;
      }

      // ---- set-price ----
      if (cmd_dfsp->parsed()) {
        std::string remote = normalizePath(df_remote_arg);
        uint64_t newPrice = 0;
        uint8_t src = cfc.setPrice(remote, df_price_arg, newPrice);
        if (src != CES_OK) {
          std::cerr << "Error: set-price failed: " << errorString(src)
                    << "\n";
          return 1;
        }
        print_header("File Price Updated");
        print_field("Remote", remote);
        print_field("Price/KB", newPrice);
        std::cout << std::endl;
        return 0;
      }

      std::cerr << "Unknown file subcommand.\n";
      return 1;
    };

    // ---- handleCompute handler ----
    auto handleCompute = [&]() -> int {
      if (rpcPort_arg == 0) {
        std::cerr << "Error: compute requires --rpc-port\n";
        return 1;
      }

      // Resolve host (strip :port if caller pasted --server host:X).
      std::string host = server_arg;
      auto colon = host.rfind(':');
      if (colon != std::string::npos) host = host.substr(0, colon);
      if (host.empty()) host = "localhost";

      // Fetch the server's public key for response-sig verification.
      // Same pattern handleDiskFile uses.
      minx::Hash serverPk{};
      bool hasServerPk = false;
      {
        std::vector<ServerInfoEntry> entries;
        uint8_t sirc = cc.queryServerInfo(entries);
        if (sirc == CES_OK) {
          for (const auto& e : entries) {
            if (e.key == "serverPublicKey") {
              try {
                minx::stringToHash(serverPk, e.value);
                hasServerPk = true;
              } catch (...) {}
              break;
            }
          }
        }
      }

      auto normalizePath = [&](const std::string& raw) -> std::string {
        if (!raw.empty() && raw[0] == '/') return raw;
        return "/h/" + actorKey.getPublicKeyHexStr() + "/" + raw;
      };

      CesComputeClient cc2;
      uint8_t rc = cc2.connect(host, rpcPort_arg, actorKey);
      if (rc != CES_OK) {
        std::cerr << "Error: compute connect failed: "
                  << errorString(rc) << "\n";
        return 1;
      }
      if (hasServerPk) cc2.setServerPubkey(serverPk);

      if (cmd_clau->parsed()) {
        std::string remote = normalizePath(compute_path_arg);
        uint64_t id = 0, startedAt = 0;
        uint8_t lrc = cc2.launch(remote, id, startedAt);
        if (lrc != CES_OK) {
          std::cerr << "LAUNCH Failed: " << errorString(lrc) << "\n";
          return 1;
        }
        if (g_quiet) {
          std::cout << "{\"instanceId\":" << id
                    << ",\"startedAtUs\":" << startedAt << "}\n";
          return 0;
        }
        print_header("Compute Launched");
        print_field("Remote", remote);
        print_field("Instance", id);
        print_field("StartedAt", startedAt);
        std::cout << std::endl;
        return 0;
      }

      if (cmd_ckil->parsed()) {
        uint8_t krc = cc2.kill(compute_id_arg);
        if (krc != CES_OK) {
          std::cerr << "KILL Failed: " << errorString(krc) << "\n";
          return 1;
        }
        if (g_quiet) {
          std::cout << "{\"instanceId\":" << compute_id_arg
                    << ",\"killed\":true}\n";
          return 0;
        }
        print_header("Compute Killed");
        print_field("Instance", compute_id_arg);
        std::cout << std::endl;
        return 0;
      }

      if (cmd_cps->parsed()) {
        std::vector<CesComputeClient::InstanceInfo> list;
        uint8_t prc = cc2.list(list);
        if (prc != CES_OK) {
          std::cerr << "LIST Failed: " << errorString(prc) << "\n";
          return 1;
        }
        if (g_quiet) {
          std::cout << "[";
          for (size_t i = 0; i < list.size(); ++i)
            std::cout << (i ? "," : "") << instanceJson(list[i]);
          std::cout << "]\n";
          return 0;
        }
        print_header("Compute Instances");
        if (list.empty()) {
          std::cout << "  (none)\n";
        } else {
          for (auto& e : list) {
            print_field("Instance",    e.instanceId);
            print_field("Remote",      e.sourceName);
            print_field("StartedAt",   e.startedAtUs);
            print_field("FileBalance", e.fileBalance);
            print_field("CpuBp",       e.cpuBasisPoints);
            print_field("RssBytes",    e.rssBytes);
            print_field("ClientPort",  e.clientPort);
            print_field("RpcPort",     e.rpcPort);
            std::cout << "  --\n";
          }
        }
        std::cout << std::endl;
        return 0;
      }

      if (cmd_cst->parsed()) {
        CesComputeClient::InstanceInfo info;
        uint8_t src = cc2.stat(compute_id_arg, info);
        if (src != CES_OK) {
          std::cerr << "STAT Failed: " << errorString(src) << "\n";
          return 1;
        }
        if (g_quiet) {
          std::cout << instanceJson(info) << "\n";
          return 0;
        }
        print_header("Compute Status");
        print_field("Instance",    info.instanceId);
        print_field("Remote",      info.sourceName);
        print_field("StartedAt",   info.startedAtUs);
        print_field("FileBalance", info.fileBalance);
        print_field("CpuBp",       info.cpuBasisPoints);
        print_field("RssBytes",    info.rssBytes);
        print_field("ClientPort",  info.clientPort);
        print_field("RpcPort",     info.rpcPort);
        std::cout << std::endl;
        return 0;
      }

      if (cmd_cinst->parsed()) {
        std::vector<CesComputeClient::InstanceInfo> insts;
        std::string remote = normalizePath(compute_path_arg);
        uint8_t src = cc2.instances(remote, insts);
        if (src != CES_OK) {
          std::cerr << "INSTANCES Failed: " << errorString(src) << "\n";
          return 1;
        }
        if (g_quiet) {
          // JSON array with ports — the form the web gateway consumes.
          std::cout << "[";
          for (size_t i = 0; i < insts.size(); ++i)
            std::cout << (i ? "," : "") << instanceJson(insts[i]);
          std::cout << "]\n";
          return 0;
        }
        // Human mode: one id per line, no header — pipeable into
        // `head -1 | xargs cesh dial`. (Ports are in the -q JSON or stat.)
        for (auto& e : insts) std::cout << e.instanceId << "\n";
        return 0;
      }

      std::cerr << "Unknown compute subcommand.\n";
      return 1;
    };

    // ---- handleAutoexec handler ----
    auto handleAutoexec = [&]() -> int {
    if (cmd_axi->parsed()) {
      auto programId = parseAssetKey(autoexec_program_arg);
      ces::Bytes input;
      if (!autoexec_input_arg.empty())
        input = ces::parseHex(autoexec_input_arg);

      HashPrefix myPrefix = Account::getMapKey(actorKey.getPublicKeyAsHash());
      auto autoKey = buildAutoexecKey(myPrefix);
      auto autoContent = buildAutoexecContent(
        programId, autoexec_budget_arg, input, actorKey, cc.getServerId());
      if (!autoContent) {
        std::cerr << "Install Failed: input too large for autoexec asset "
                     "(max ~40 bytes of --input)\n";
        return 1;
      }

      uint8_t rc = cc.createAsset(autoKey, *autoContent, autoexec_days_arg);
      if (rc == CES_OK) {
        std::string keyHex = minx::hashToString(autoKey);
        print_header("Autoexec Installed");
        print_field("Program", autoexec_program_arg);
        print_field("Budget", autoexec_budget_arg);
        print_field("Autoexec Key", keyHex);
        std::cout << "\nTo disable: cesh asset fast " << keyHex
                  << " --hexcontent 00\n";
        std::cout << "Success.\n";
      } else {
        std::cerr << "Install Failed: " << errorString(rc) << "\n";
        return 1;
      }
    }
      return 0;
    };


    // ---- squery ----

    if (cmd_squery->parsed()) {
      minx::Hash t;
      minx::stringToHash(t, wallet.resolveKey(squery_account_arg));
      std::vector<AccountEntry> vec;
      uint8_t rc = cc.queryAccountSigned(Account::getMapKey(t), 0, vec);
      if (rc == CES_OK && !vec.empty()) {
        print_header("Account (Signed)");
        print_field("Key", minx::hashToString(vec[0].key));
        print_field("Balance", vec[0].balance);
        print_field("Nonce", vec[0].nonce);
        print_field("LastXferDest", hashPrefixToString(vec[0].lastXferDest));
        print_field("LastXferAmount", vec[0].lastXferAmount);
        print_field("LastXferTime", vec[0].lastXferTime);
        std::cout << std::endl;
      } else {
        std::cerr << "Query Failed: " << errorString(rc) << "\n";
        return 1;
      }
    }

    // ---- transfer ----

    else if (cmd_transfer->parsed()) {
      minx::Hash dest;
      minx::stringToHash(dest, wallet.resolveKey(transfer_dest_arg));
      int64_t nb;
      uint8_t rc;
      if (transfer_open)
        rc = cc.openTransfer(dest, transfer_amount_arg, nb);
      else
        rc = cc.transfer(dest, transfer_amount_arg, nb);
      if (rc == CES_OK) {
        print_header("Transfer Sent");
        print_field("To", transfer_dest_arg);
        print_field("Amount", transfer_amount_arg);
        print_field("Rem. Bal", nb);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Transfer Failed: " << errorString(rc) << "\n";
        return 1;
      }
    }

    else if (cmd_payment->parsed()) {
      minx::Hash dest;
      minx::stringToHash(dest, wallet.resolveKey(payment_dest_arg));
      int64_t nb;
      uint8_t rc = cc.createPayment(dest, payment_amount_arg,
                                     static_cast<uint8_t>(payment_days_arg), nb);
      if (rc == CES_OK) {
        print_header("Payment Created");
        print_field("To", payment_dest_arg);
        print_field("Amount", payment_amount_arg);
        print_field("Days", (uint64_t)payment_days_arg);
        print_field("Rem. Bal", nb);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Payment Failed: " << errorString(rc) << "\n";
        return 1;
      }
    }

    else if (cmd_cross->parsed()) {
      minx::Hash dest;
      minx::stringToHash(dest, wallet.resolveKey(cross_dest_arg));
      int64_t nb;
      uint8_t rc = cc.crossTransfer(dest, cross_amount_arg,
                                     cross_server_arg, nb);
      if (rc == CES_OK) {
        print_header("Cross-Transfer Sent");
        print_field("To", cross_dest_arg);
        print_field("Amount", cross_amount_arg);
        print_field("Server", cross_server_arg);
        print_field("Rem. Bal", nb);
        std::cout << "Success.\n";
      } else {
        std::cerr << "Cross-Transfer Failed: " << errorString(rc) << "\n";
        return 1;
      }
    }

    // ---- server-info ----

    else if (cmd_sinfo->parsed()) {
      std::vector<ServerInfoEntry> entries;
      uint8_t rc = cc.queryServerInfo(entries);
      if (rc == CES_OK) {
        if (g_quiet) {
          std::cout << "{";
          for (size_t i = 0; i < entries.size(); ++i)
            std::cout << (i ? "," : "") << "\"" << jesc(entries[i].key)
                      << "\":\"" << jesc(entries[i].value) << "\"";
          std::cout << "}\n";
        } else {
          print_header("Server Info");
          for (const auto& e : entries)
            print_field(e.key, e.value);
          std::cout << std::endl;
        }
      } else {
        std::cerr << "Server Info Failed: " << errorString(rc) << "\n";
        return 1;
      }
    }

    // ---- mine ----

    else if (cmd_mine->parsed()) {
      // Clamp threads to [1, hardware_concurrency]. 0 fallback if the
      // platform can't report concurrency.
      const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
      uint32_t n = mine_threads_arg;
      if (n < 1) n = 1;
      if (n > hw) n = hw;
      std::cout << "Mining... (threads=" << n << ")\n";
      auto result = mineOnce(cc, 1, {}, static_cast<int>(n), [](int r) {
        std::cout << "Status: " << r << "\r" << std::flush;
      });
      if (result.success) {
        std::cout << "\nSuccess! Credit: " << result.credit << "\n";
      } else if (result.status == minx::MINX_SOLUTION_UNTIMELY) {
        std::cout << "\nRejected (Untimely)\n";
      } else if (result.status < 0) {
        std::cerr << "Mining failed to init\n";
        return 1;
      } else {
        std::cerr << "\nSubmission failed (server unresponsive)\n";
        return 1;
      }
    }

    // ---- asset ----

    else if (cmd_asset->parsed()) return handleAsset();

    // ---- file (L1, ramfile) ----

    else if (cmd_file->parsed()) return handleFile();

    // ---- file (L2, disk) ----

    else if (cmd_dfile->parsed()) return handleDiskFile();

    // ---- compute (L2 program instances) ----

    else if (cmd_compute->parsed()) return handleCompute();

    // ---- autoexec ----

    else if (cmd_autoexec->parsed()) return handleAutoexec();

  } catch (std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

  return 0;
}
