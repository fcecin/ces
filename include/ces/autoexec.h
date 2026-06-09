#pragma once

/**
 * Autoexec — utilities for creating boot-time runAsset assets.
 *
 * An autoexec asset has a recognizable key pattern and contains a
 * signed CesRunAsset packet. The server scans for these on boot
 * and executes them.
 *
 * Key layout: [8 zero bytes][8 AUTOEXEC_KEY_MAGIC BE][8 account prefix][8 random]
 * Content: [2 byte BE packet length][signed CesRunAsset packet bytes]
 */

#include <ces/keys.h>
#include <ces/buffer.h>
#include <ces/protocol.h>
#include <ces/server.h>
#include <ces/types.h>

#include <optional>
#include <random>

namespace ces {

/// Build an autoexec asset key for the given account.
inline minx::Hash buildAutoexecKey(const HashPrefix& accountPrefix) {
  minx::Hash key{};
  // bytes 0-7: zeros (already)
  ces::Buffer::poke<uint64_t>(&key[8], CesConfig::AUTOEXEC_KEY_MAGIC);
  std::memcpy(&key[16], accountPrefix.data(), 8);
  // bytes 24-31: random (LE — read from key purely as opaque bytes)
  std::mt19937_64 rng(std::random_device{}());
  ces::Buffer::pokeLE<uint64_t>(&key[24], rng());
  return key;
}

/// Build autoexec asset content from a program asset key and budget.
/// Signs a nonceless CesRunAsset packet with the given key pair. Returns
/// nullopt when the signed packet does not fit the asset content slot.
inline std::optional<AssetData> buildAutoexecContent(
    const minx::Hash& programAssetId, uint64_t budget, const ces::Bytes& input,
    KeyPair& keyPair, const HashPrefix& serverId) {
  CesRunAsset req;
  req.originId = keyPair.getPublicKeyAsHash();
  req.serverId = serverId;
  req.reqNonce = CES_NONCELESS;
  req.assetId = programAssetId;
  req.budget = budget;
  req.time = getMicrosSinceEpoch();
  req.input = input;
  auto packetBytes = req.toBytes(keyPair);

  AssetData content{};
  if (packetBytes.size() > content.size() - 2)
    return std::nullopt;
  ces::Buffer::poke<uint16_t>(content.data(),
                              static_cast<uint16_t>(packetBytes.size()));
  std::memcpy(&content[2], packetBytes.data(), packetBytes.size());
  return content;
}

} // namespace ces
