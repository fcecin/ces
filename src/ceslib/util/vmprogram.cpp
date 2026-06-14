#include <ces/util/vmprogram.h>
#include <ces/buffer.h>


#include <algorithm>
#include <cstring>
#include <limits>
#include <string>

namespace ces {

// Opcode numbers and control-byte encoding bits come from cesvm.h —
// the single source of truth that cesvm.cpp's parser, this builder,
// and every test file share. Local aliases here keep the encoder
// readable without leaking the "CESVM_" prefix into every line.
static constexpr uint8_t SHORT_VAL_BIT  = CESVM_SHORT_VAL;
static constexpr uint8_t REG_PTR_BIT    = CESVM_REG_PTR;
static constexpr uint64_t MAX_SHORT_VAL = CESVM_MAX_SHORT_VAL;

// ===========================================================================
// Construction
// ===========================================================================

VmProgram::VmProgram() {
  code_.reserve(256);  // typical small program size
}

// ===========================================================================
// Internal emit helpers
// ===========================================================================

void VmProgram::emitByte(uint8_t b) {
  code_.push_back(b);
}

void VmProgram::emitOpcode(uint8_t op) {
  code_.push_back(op);
  lastWasTerminator_ = (op == OP_TERM || op == OP_ABORT);
}

void VmProgram::emitVal(VmVal v) {
  // The CesVM's read() function decodes one operand as follows:
  //   control = next byte
  //   regptr  = (control >> 7) & 1
  //   shortval = (control >> 6) & 1
  //   low6     = control & 0x3F
  //   if shortval: value = low6
  //   else:        value = LE integer read from `low6` bytes following
  //   if regptr:   value = io[value]
  //
  // To encode a VmVal, pick the shortest form that represents `value`
  // and layer the REG_PTR bit on top if deref is requested.

  if (v.value <= MAX_SHORT_VAL) {
    // Short form: value fits in 6 bits, 1 byte total.
    uint8_t ctrl = static_cast<uint8_t>(SHORT_VAL_BIT | (v.value & MAX_SHORT_VAL));
    if (v.deref) ctrl |= REG_PTR_BIT;
    code_.push_back(ctrl);
    return;
  }

  // Wide form: pick minimum number of bytes needed to hold `value`.
  uint8_t bytes = 1;
  for (uint64_t limit = uint64_t{1} << 8;
       bytes < 8 && v.value >= limit;
       limit <<= 8, ++bytes) {
    // keep bumping
  }
  // For values >= 2^56 the loop exits at bytes == 8 without
  // re-checking, which is exactly what we want (8 bytes covers the
  // full uint64_t range).

  uint8_t ctrl = bytes;
  if (v.deref) ctrl |= REG_PTR_BIT;
  code_.push_back(ctrl);
  ces::Buffer::putLE(code_, v.value, bytes);
}

void VmProgram::emitLabelRef(VmLabel l) {
  // Jump/call targets are always 2 bytes little-endian with no control
  // byte — the VM's read(jumpSkipControl=true) path forces control=2
  // and reads 2 bytes directly. Emit a placeholder now and remember to
  // patch it at build time.
  if (l.id >= labels_.size()) {
    throw VmProgramError("vmprogram: label reference out of range");
  }
  relocs_.push_back({code_.size(), l.id});
  code_.push_back(0);
  code_.push_back(0);
}

// ===========================================================================
// Label management
// ===========================================================================

VmLabel VmProgram::label() {
  VmLabel l{labels_.size()};
  labels_.push_back(std::numeric_limits<uint64_t>::max());  // unplaced
  return l;
}

Region VmProgram::alloc(uint64_t count) {
  // Scratch range is io[CESVM_REG_SIZE .. CESVM_IO_INPUT_LEN). Beyond
  // CESVM_IO_INPUT_LEN the cells are protocol-fixed (context, output,
  // input, allowance) and not usable as program-private scratch.
  if (count == 0) {
    throw VmProgramError("vmprogram: alloc(0) is not allowed");
  }
  if (scratchTop_ + count > CESVM_IO_INPUT_LEN) {
    throw VmProgramError(
      "vmprogram: scratch region exhausted — requested " +
      std::to_string(count) + " cells at top=" +
      std::to_string(scratchTop_) + ", limit=" +
      std::to_string(CESVM_IO_INPUT_LEN));
  }
  Region r{scratchTop_, count};
  scratchTop_ += count;
  return r;
}

VmProgram& VmProgram::place(VmLabel l) {
  if (l.id >= labels_.size()) {
    throw VmProgramError("vmprogram: place() called with invalid label");
  }
  if (labels_[l.id] != std::numeric_limits<uint64_t>::max()) {
    throw VmProgramError("vmprogram: label placed twice");
  }
  labels_[l.id] = code_.size();
  return *this;
}

void VmProgram::resolveLabelsOrThrow() {
  for (const auto& r : relocs_) {
    if (r.labelId >= labels_.size()) {
      throw VmProgramError("vmprogram: reloc against unknown label");
    }
    const uint64_t target = labels_[r.labelId];
    if (target == std::numeric_limits<uint64_t>::max()) {
      throw VmProgramError(
        "vmprogram: label referenced but never placed (id=" +
        std::to_string(r.labelId) + ")");
    }
    if (target > 0xFFFFu) {
      throw VmProgramError(
        "vmprogram: label offset exceeds 16-bit range (offset=" +
        std::to_string(target) + ")");
    }
    // VM bytecode operands are little-endian.
    ces::Buffer::pokeLE<uint16_t>(code_.data() + r.offset,
                                  static_cast<uint16_t>(target));
  }
}

// ===========================================================================
// Low-level opcode methods
// ===========================================================================

VmProgram& VmProgram::nop()                  { emitOpcode(OP_NOP);   return *this; }
VmProgram& VmProgram::term()                 { emitOpcode(OP_TERM);  return *this; }
VmProgram& VmProgram::abort()                { emitOpcode(OP_ABORT); return *this; }
VmProgram& VmProgram::host()                 { emitOpcode(OP_HOST);  return *this; }
VmProgram& VmProgram::hostx()                { emitOpcode(OP_HOSTX); return *this; }
VmProgram& VmProgram::rnd()                  { emitOpcode(OP_RND);   return *this; }
VmProgram& VmProgram::time()                 { emitOpcode(OP_TIME);  return *this; }

VmProgram& VmProgram::jmp(VmLabel target) {
  emitOpcode(OP_JMP);
  emitLabelRef(target);
  return *this;
}

VmProgram& VmProgram::jf(VmVal cond, VmLabel target) {
  emitOpcode(OP_JF);
  emitVal(cond);
  emitLabelRef(target);
  return *this;
}

VmProgram& VmProgram::jt(VmVal cond, VmLabel target) {
  emitOpcode(OP_JT);
  emitVal(cond);
  emitLabelRef(target);
  return *this;
}

VmProgram& VmProgram::call(VmLabel target) {
  emitOpcode(OP_CALL);
  emitLabelRef(target);
  return *this;
}

VmProgram& VmProgram::ret(VmVal retVal) {
  emitOpcode(OP_RET);
  emitVal(retVal);
  return *this;
}

VmProgram& VmProgram::jmpr(VmVal target) {
  emitOpcode(OP_JMPR);
  emitVal(target);
  return *this;
}

VmProgram& VmProgram::callr(VmVal target) {
  emitOpcode(OP_CALLR);
  emitVal(target);
  return *this;
}

VmProgram& VmProgram::set(VmVal dst, VmVal src) {
  emitOpcode(OP_SET);
  emitVal(dst);
  emitVal(src);
  return *this;
}

VmProgram& VmProgram::mov(VmVal dst, VmVal src, VmVal count) {
  emitOpcode(OP_MOV);
  emitVal(dst);
  emitVal(src);
  emitVal(count);
  return *this;
}

VmProgram& VmProgram::cmp(VmVal a, VmVal b, VmVal count) {
  emitOpcode(OP_CMP);
  emitVal(a);
  emitVal(b);
  emitVal(count);
  return *this;
}

VmProgram& VmProgram::fil(VmVal dst, VmVal val, VmVal count) {
  emitOpcode(OP_FIL);
  emitVal(dst);
  emitVal(val);
  emitVal(count);
  return *this;
}

VmProgram& VmProgram::ldb(VmVal byteOffset) {
  emitOpcode(OP_LDB);
  emitVal(byteOffset);
  return *this;
}

VmProgram& VmProgram::stb(VmVal byteOffset, VmVal val) {
  emitOpcode(OP_STB);
  emitVal(byteOffset);
  emitVal(val);
  return *this;
}

VmProgram& VmProgram::inc(VmVal cell) {
  emitOpcode(OP_INC);
  emitVal(cell);
  return *this;
}

VmProgram& VmProgram::dec(VmVal cell) {
  emitOpcode(OP_DEC);
  emitVal(cell);
  return *this;
}

// --- Binary arithmetic / logic ---

VmProgram& VmProgram::add(VmVal a, VmVal b)  { emitOpcode(OP_ADD);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::sub(VmVal a, VmVal b)  { emitOpcode(OP_SUB);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::mul(VmVal a, VmVal b)  { emitOpcode(OP_MUL);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::div(VmVal a, VmVal b)  { emitOpcode(OP_DIV);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::mod(VmVal a, VmVal b)  { emitOpcode(OP_MOD);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::or_(VmVal a, VmVal b)  { emitOpcode(OP_OR);   emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::and_(VmVal a, VmVal b) { emitOpcode(OP_AND);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::xor_(VmVal a, VmVal b) { emitOpcode(OP_XOR);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::not_(VmVal a)          { emitOpcode(OP_NOT);  emitVal(a);             return *this; }
VmProgram& VmProgram::lnot(VmVal a)          { emitOpcode(OP_LNOT); emitVal(a);             return *this; }
VmProgram& VmProgram::neg(VmVal a)           { emitOpcode(OP_NEG);  emitVal(a);             return *this; }
VmProgram& VmProgram::shl(VmVal a, VmVal b)  { emitOpcode(OP_SHL);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::shr(VmVal a, VmVal b)  { emitOpcode(OP_SHR);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::sar(VmVal a, VmVal b)  { emitOpcode(OP_SAR);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::andl(VmVal a, VmVal b) { emitOpcode(OP_ANDL); emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::orl(VmVal a, VmVal b)  { emitOpcode(OP_ORL);  emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::eq(VmVal a, VmVal b)   { emitOpcode(OP_EQ);   emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::ne(VmVal a, VmVal b)   { emitOpcode(OP_NE);   emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::gt(VmVal a, VmVal b)   { emitOpcode(OP_GT);   emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::lt(VmVal a, VmVal b)   { emitOpcode(OP_LT);   emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::ge(VmVal a, VmVal b)   { emitOpcode(OP_GE);   emitVal(a); emitVal(b); return *this; }
VmProgram& VmProgram::le(VmVal a, VmVal b)   { emitOpcode(OP_LE);   emitVal(a); emitVal(b); return *this; }

// --- Stack ---

VmProgram& VmProgram::push(VmVal v) {
  emitOpcode(OP_PUSH);
  emitVal(v);
  return *this;
}

VmProgram& VmProgram::pop(VmVal cell) {
  emitOpcode(OP_POP);
  emitVal(cell);
  return *this;
}

// ===========================================================================
// High-level convenience helpers
// ===========================================================================

VmProgram& VmProgram::copy(uint64_t dstCell, uint64_t srcCell,
                            uint64_t count) {
  return mov(Imm(dstCell), Imm(srcCell), Imm(count));
}

VmProgram& VmProgram::copyFromInput(uint64_t dstCell,
                                     uint64_t inputCellOffset,
                                     uint64_t count) {
  return copy(dstCell, CESVM_IO_INPUT + inputCellOffset, count);
}

VmProgram& VmProgram::copyCallerKeyTo(uint64_t dstCell) {
  return copy(dstCell, CESVM_IO_CALLER_KEY, 4);
}

VmProgram& VmProgram::copySelfKeyTo(uint64_t dstCell) {
  return copy(dstCell, CESVM_IO_SELF_KEY, 4);
}

VmProgram& VmProgram::setOutput(VmVal value, uint64_t byteLen) {
  set(Imm(CESVM_IO_OUTPUT_LEN), Imm(byteLen));
  set(Imm(CESVM_IO_OUTPUT), value);
  return *this;
}

VmProgram& VmProgram::setOutputBytes(uint64_t srcCell, uint64_t count,
                                      uint64_t byteLen) {
  copy(CESVM_IO_OUTPUT, srcCell, count);
  set(Imm(CESVM_IO_OUTPUT_LEN), Imm(byteLen));
  return *this;
}

VmProgram& VmProgram::ldbFromCell(uint64_t cellIndex,
                                   uint64_t byteOffsetInCell) {
  return ldb(Imm(byteInCell(cellIndex, byteOffsetInCell)));
}

VmProgram& VmProgram::stbInCell(uint64_t cellIndex,
                                 uint64_t byteOffsetInCell,
                                 VmVal val) {
  return stb(Imm(byteInCell(cellIndex, byteOffsetInCell)), val);
}

VmProgram& VmProgram::loadCodeAndCall(VmVal keyPtr) {
  // Load the library block, then immediately CALL through R (where
  // SYS_LOAD_CODE just wrote the loaded block's offset). Emitting
  // both in this single helper guarantees no builder call in
  // between could clobber R.
  sysLoadCode({.keyPtr = keyPtr});
  return callr(Ref(CESVM_CELL_R));
}

VmProgram& VmProgram::loadCodeAndJmp(VmVal keyPtr) {
  sysLoadCode({.keyPtr = keyPtr});
  return jmpr(Ref(CESVM_CELL_R));
}

VmProgram& VmProgram::writeBytesToIo(uint64_t dstCell, const uint8_t* bytes,
                                      size_t len) {
  // Pack bytes into u64 cells little-endian, eight per cell. A
  // trailing partial cell is padded with zeros. Each cell becomes one
  // OP_SET instruction. The emitVal encoder picks the shortest wide
  // form for each packed value, so small strings (ASCII, likely all
  // bytes < 128) still emit efficient bytecode.
  const size_t cells = (len + 7) / 8;
  for (size_t c = 0; c < cells; ++c) {
    uint64_t val = 0;
    for (size_t b = 0; b < 8; ++b) {
      const size_t idx = c * 8 + b;
      if (idx < len) {
        val |= static_cast<uint64_t>(bytes[idx]) << (b * 8);
      }
    }
    set(Imm(dstCell + c), Imm(val));
  }
  return *this;
}

VmProgram& VmProgram::writeBytesToIo(uint64_t dstCell, std::string_view s) {
  return writeBytesToIo(dstCell,
                        reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// ===========================================================================
// Typed syscall wrappers
// ===========================================================================

// ---------------------------------------------------------------------------
// Ledger / asset / crypto syscall wrappers
// ---------------------------------------------------------------------------
//
// Each of these lowers to one OP_HOSTXV with the syscall number and
// the args in the order the cesvm.cpp dispatcher reads them. The
// syscall ABIs put all input slots contiguously starting at io[4] so
// the wrapper can pass exactly N args with no padding; any output
// slots live past the input range and are written directly by the
// syscall.

VmProgram& VmProgram::sysReadAccount(ReadAccountArgs a) {
  return hostxv(SYS_READ_ACCOUNT, {a.prefixPtr});
}

VmProgram& VmProgram::sysTransfer(TransferArgs a) {
  return hostxv(SYS_TRANSFER, {a.destKeyPtr, a.amount});
}

VmProgram& VmProgram::sysOwnerTransfer(OwnerTransferArgs a) {
  return hostxv(SYS_OWNER_TRANSFER, {a.destKeyPtr, a.amount});
}

VmProgram& VmProgram::sysDeposit(DepositArgs a) {
  return hostxv(SYS_DEPOSIT, {a.amount});
}

VmProgram& VmProgram::sysWithdraw(WithdrawArgs a) {
  return hostxv(SYS_WITHDRAW, {a.amount});
}

VmProgram& VmProgram::sysReadAsset(ReadAssetArgs a) {
  // Three contiguous inputs at io[4..6]: key cell-index, owner-out
  // cell-index, content-out cell-index. Balance and price are written
  // directly by the syscall into io[7] and io[8] respectively.
  return hostxv(SYS_READ_ASSET, {a.keyPtr, a.ownerOutCell, a.contentOutCell});
}

VmProgram& VmProgram::sysCreateAssetRandom(CreateAssetRandomArgs a) {
  return hostxv(SYS_CREATE_ASSET_RANDOM, {a.contentPtr, a.days, a.keyOutPtr});
}

VmProgram& VmProgram::sysCreateAsset(CreateAssetArgs a) {
  return hostxv(SYS_CREATE_ASSET, {a.keyPtr, a.contentPtr, a.days});
}

VmProgram& VmProgram::sysCreateAssetManaged(CreateAssetManagedArgs a) {
  return hostxv(SYS_CREATE_ASSET_MANAGED, {a.keyPtr, a.contentPtr, a.days});
}

VmProgram& VmProgram::sysUpdateAsset(UpdateAssetArgs a) {
  return hostxv(SYS_UPDATE_ASSET, {a.keyPtr, a.contentPtr});
}

VmProgram& VmProgram::sysUpdateAssetMeta(UpdateAssetMetaArgs a) {
  return hostxv(SYS_UPDATE_ASSET_META, {a.keyPtr, a.newOwnerPtr, a.newPrice});
}

VmProgram& VmProgram::sysFundAsset(FundAssetArgs a) {
  return hostxv(SYS_FUND_ASSET, {a.keyPtr, a.days});
}

VmProgram& VmProgram::sysBuyAsset(BuyAssetArgs a) {
  return hostxv(SYS_BUY_ASSET, {a.keyPtr, a.maxPrice});
}

VmProgram& VmProgram::sysGiveAsset(GiveAssetArgs a) {
  return hostxv(SYS_GIVE_ASSET, {a.keyPtr, a.newOwnerPtr});
}

VmProgram& VmProgram::sysHash(HashArgs a) {
  return hostxv(SYS_HASH, {a.dataPtr, a.len, a.outPtr});
}

VmProgram& VmProgram::sysVerifySig(VerifySigArgs a) {
  return hostxv(SYS_VERIFY_SIG, {a.dataPtr, a.dataLen, a.sigPtr, a.pubkeyPtr});
}

VmProgram& VmProgram::sysCrossTransfer(CrossTransferArgs a) {
  return hostxv(SYS_CROSS_TRANSFER, {a.destKeyPtr, a.amount, a.serverPtr});
}

VmProgram& VmProgram::sysLoadCode(LoadCodeArgs a) {
  return hostxv(SYS_LOAD_CODE, {a.keyPtr});
}

VmProgram& VmProgram::sysSendClient(SendClientArgs a) {
  return hostxv(SYS_SEND_CLIENT, {a.clientIdPtr, a.dataPtr, a.dataLen});
}

VmProgram& VmProgram::sysSchedule(ScheduleArgs a) {
  return hostxv(SYS_SCHEDULE, {
    a.assetKeyPtr,
    a.budget,
    a.childAllowance,
    a.inputPtr,
    a.inputLen,
    a.timeUs,
  });
}

VmProgram& VmProgram::sysRpc(RpcArgs a) {
  // io[3] = SYS_RPC, io[4..10] = the seven args in order.
  return hostxv(SYS_RPC, {
    a.hostCell,
    a.hostLen,
    a.port,
    a.fileHead,
    a.followup,
    a.budget,
    a.tag,
  });
}

VmProgram& VmProgram::syscall(
    uint64_t syscallNum,
    std::initializer_list<std::pair<uint64_t, VmVal>> slots) {
  set(Imm(3), Imm(syscallNum));
  for (const auto& [slot, val] : slots) {
    set(Imm(slot), val);
  }
  return hostx();
}

VmProgram& VmProgram::hostv(uint64_t syscallNum,
                             std::initializer_list<VmVal> args) {
  if (args.size() > CESVM_MAX_HOSTV_ARGS) {
    throw VmProgramError(
      "vmprogram: hostv arg count " + std::to_string(args.size()) +
      " exceeds CESVM_MAX_HOSTV_ARGS (" +
      std::to_string(CESVM_MAX_HOSTV_ARGS) + ")");
  }
  emitOpcode(OP_HOSTV);
  emitVal(Imm(syscallNum));
  emitVal(Imm(args.size()));
  for (const auto& a : args) emitVal(a);
  return *this;
}

VmProgram& VmProgram::hostxv(uint64_t syscallNum,
                              std::initializer_list<VmVal> args) {
  if (args.size() > CESVM_MAX_HOSTV_ARGS) {
    throw VmProgramError(
      "vmprogram: hostxv arg count " + std::to_string(args.size()) +
      " exceeds CESVM_MAX_HOSTV_ARGS (" +
      std::to_string(CESVM_MAX_HOSTV_ARGS) + ")");
  }
  emitOpcode(OP_HOSTXV);
  emitVal(Imm(syscallNum));
  emitVal(Imm(args.size()));
  for (const auto& a : args) emitVal(a);
  return *this;
}

// ===========================================================================
// Build-out
// ===========================================================================

AssetData VmProgram::buildBootBlock() {
  resolveLabelsOrThrow();
  AssetData out{};
  if (code_.size() > out.size()) {
    throw VmProgramError(
      "vmprogram: built code is " + std::to_string(code_.size()) +
      " bytes, exceeds AssetData boot-block size (" +
      std::to_string(out.size()) + ") — use buildBytes() + SYS_LOAD_CODE "
      "for programs larger than one asset content block");
  }
  std::memcpy(out.data(), code_.data(), code_.size());
  // Trailing bytes are zero-initialized by the AssetData constructor.
  return out;
}

ces::Bytes VmProgram::buildBytes() {
  resolveLabelsOrThrow();
  if (code_.size() > CESVM_MAX_CODE) {
    throw VmProgramError(
      "vmprogram: built code is " + std::to_string(code_.size()) +
      " bytes, exceeds CESVM_MAX_CODE (" + std::to_string(CESVM_MAX_CODE) +
      ")");
  }
  return code_;
}

} // namespace ces
