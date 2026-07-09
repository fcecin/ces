#include <ces/lang/bundle.h>

#include <ces/cesvm.h>
#include <ces/util/vmprogram.h>

#include <cryptopp/sha.h>

#include <cstring>

namespace ces {

namespace {

constexpr uint64_t kBodyBase = CESVM_CODE_BLOCK;  // loader pads to 210
constexpr size_t kKeysPerTable = 5;
constexpr uint64_t kNextKeyCell = kKeysPerTable * 4;  // cell 20 in the table

minx::Hash bundleKey(const char* tag, std::string_view salt, uint32_t idx,
                     const ces::Bytes& body) {
  CryptoPP::SHA256 h;
  h.Update(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag));
  h.Update(reinterpret_cast<const uint8_t*>(salt.data()), salt.size());
  uint8_t be[4] = {static_cast<uint8_t>(idx >> 24),
                   static_cast<uint8_t>(idx >> 16),
                   static_cast<uint8_t>(idx >> 8),
                   static_cast<uint8_t>(idx)};
  h.Update(be, sizeof(be));
  h.Update(body.data(), body.size());
  minx::Hash out;
  h.Final(out.data());
  return out;
}

// The boot loader: walk the key-table chain, SYS_LOAD_CODE every chunk,
// zero the scratch cells this stub used, jump to the body at 210.
AssetData buildLoader(const minx::Hash& rootTableKey) {
  VmProgram p;
  Region tkey     = p.allocHash();
  Region ckey     = p.allocHash();
  Region zero4    = p.allocHash();
  Region ownerOut = p.allocHashPrefix();
  Region idx      = p.allocCell();
  Region table    = p.allocContent();

  VmLabel tableLoop = p.label();
  VmLabel slotLoop  = p.label();
  VmLabel done      = p.label();

  p.writeBytesToIo(tkey.cell, rootTableKey.data(), rootTableKey.size());
  p.fil(Imm(zero4.cell), Imm(0), Imm(4));

  p.place(tableLoop);
  p.sysReadAsset({.keyPtr = tkey,
                  .ownerOutCell = ownerOut,
                  .contentOutCell = table});
  p.set(Imm(idx.cell), Imm(0));

  p.place(slotLoop);
  p.mul(Ref(idx.cell), Imm(4));
  p.add(Ref(CESVM_CELL_R), Imm(table.cell));
  p.mov(Imm(ckey.cell), Ref(CESVM_CELL_R), Imm(4));
  p.cmp(Imm(ckey.cell), Imm(zero4.cell), Imm(4));
  p.jt(Ref(CESVM_CELL_R), done);  // zero chunk key: no more chunks
  p.sysLoadCode({.keyPtr = ckey});
  p.inc(Imm(idx.cell));
  p.lt(Ref(idx.cell), Imm(kKeysPerTable));
  p.jt(Ref(CESVM_CELL_R), slotLoop);
  p.copy(tkey.cell, table.cell + kNextKeyCell, 4);
  p.cmp(Imm(tkey.cell), Imm(zero4.cell), Imm(4));
  p.jt(Ref(CESVM_CELL_R), done);  // zero next-table key: chain ends
  p.jmp(tableLoop);

  p.place(done);
  // Leave the body a fresh VM: zero every cell the loader or its
  // syscalls touched -- R, S, SYSCALL, the arg registers (READ_ASSET
  // writes balance/price into io[7]/io[8]), and the whole scratch band.
  // Cells 752+ are execute()-preloaded context the loader never writes;
  // PC is set by the jmpr.
  p.fil(Imm(CESVM_CELL_R), Imm(0), Imm(CESVM_IO_INPUT_LEN - CESVM_CELL_R));
  p.jmpr(Imm(kBodyBase));

  return p.buildBootBlock();
}

} // namespace

CesBundle bundleProgram(const ces::Bytes& body, std::string_view salt) {
  if (body.empty()) throw CesBundleError("bundle: empty program body");

  CesBundle b;

  if (body.size() <= AssetData{}.size()) {
    std::memcpy(b.boot.data(), body.data(), body.size());
    return b;
  }
  if (body.size() > CESVM_MAX_CODE - kBodyBase) {
    throw CesBundleError(
      "bundle: body is " + std::to_string(body.size()) +
      " bytes, exceeds the code space behind the boot block (" +
      std::to_string(CESVM_MAX_CODE - kBodyBase) + ")");
  }

  const size_t blockSize = AssetData{}.size();
  const size_t nChunks = (body.size() + blockSize - 1) / blockSize;
  for (size_t i = 0; i < nChunks; ++i) {
    AssetData chunk{};
    const size_t off = i * blockSize;
    const size_t len = std::min(blockSize, body.size() - off);
    std::memcpy(chunk.data(), body.data() + off, len);
    b.chunks.push_back(chunk);
    b.chunkKeys.push_back(
      bundleKey("ces.bundle.chunk", salt, static_cast<uint32_t>(i), body));
  }

  const size_t nTables = (nChunks + kKeysPerTable - 1) / kKeysPerTable;
  for (size_t j = 0; j < nTables; ++j) {
    b.tableKeys.push_back(
      bundleKey("ces.bundle.table", salt, static_cast<uint32_t>(j), body));
  }
  for (size_t j = 0; j < nTables; ++j) {
    AssetData table{};
    for (size_t s = 0; s < kKeysPerTable; ++s) {
      const size_t chunkIdx = j * kKeysPerTable + s;
      if (chunkIdx >= nChunks) break;
      std::memcpy(table.data() + s * 32, b.chunkKeys[chunkIdx].data(), 32);
    }
    if (j + 1 < nTables) {
      std::memcpy(table.data() + kNextKeyCell * 8, b.tableKeys[j + 1].data(),
                  32);
    }
    b.tables.push_back(table);
  }

  b.boot = buildLoader(b.tableKeys[0]);
  return b;
}

} // namespace ces
