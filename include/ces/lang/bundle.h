#pragma once

/**
 * bundle.h — multi-asset packaging for CesVM programs larger than one
 * 210-byte boot block ("the bundler").
 *
 * Runtime layout: the boot asset holds a loader stub; the program body
 * is compiled with codeBase 210 (casmAssemble / ceslCompile) and split
 * into 210-byte chunk assets that SYS_LOAD_CODE reassembles contiguously
 * at 210, 420, ... — so instructions may straddle chunk boundaries and
 * all label targets are link-time constants. Chunk keys live in a chain
 * of key-table assets: each table holds 5 chunk keys plus a next-table
 * key (zeros = end), so one root key in the loader covers the full 8 KB
 * code space. The loader walks the chain (SYS_READ_ASSET per table,
 * SYS_LOAD_CODE per chunk), zeroes the scratch cells it used, and jumps
 * to 210.
 *
 * Keys are deterministic — sha256 over a domain tag, the salt, the
 * index, and the body bytes — so the whole bundle is computed offline
 * with no create-then-patch step. On a key collision with an existing
 * asset, rebundle with a different salt.
 *
 * Deployment: create every chunk and table asset at its listed key
 * (CES_CREATE_ASSET), then the boot asset (any key) last. Every run of
 * the boot program pays feeQuery per table read and per chunk load on
 * top of gas.
 */

#include <ces/asset.h>
#include <ces/buffer.h>

#include <minx/types.h>

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ces {

class CesBundleError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

struct CesBundle {
  AssetData boot{};                    // deploy last, at any key
  std::vector<minx::Hash> chunkKeys;   // create chunks[i] at chunkKeys[i]
  std::vector<AssetData> chunks;
  std::vector<minx::Hash> tableKeys;   // tables[0] is the root (baked into boot)
  std::vector<AssetData> tables;
};

// Package program bytecode into a deployable bundle. A body that fits
// one block (<= 210 bytes, compiled with codeBase 0) becomes a boot-only
// bundle; anything larger must have been compiled with codeBase 210 (the
// compiled length is identical for any base, so the size check is stable
// across the recompile). Throws CesBundleError if the body exceeds the
// 8 KB code space minus the boot block.
CesBundle bundleProgram(const ces::Bytes& body, std::string_view salt = {});

} // namespace ces
