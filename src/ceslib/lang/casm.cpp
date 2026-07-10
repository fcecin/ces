#include <ces/lang/casm.h>

#include <ces/cesvm.h>
#include <ces/util/vmprogram.h>

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

namespace ces {

namespace {

struct Insn {
  CesVMOpcode op;
  int nops;
};

// Plain opcode-then-operands mnemonics, emitted via VmProgram::rawOp.
// jmp/call/jf/jt (label targets) and hostv/hostxv (variadic) are
// dispatched separately.
const std::unordered_map<std::string, Insn>& insnTable() {
  static const std::unordered_map<std::string, Insn> t = {
    {"nop",   {OP_NOP,   0}}, {"term",  {OP_TERM,  0}},
    {"abort", {OP_ABORT, 0}}, {"host",  {OP_HOST,  0}},
    {"hostx", {OP_HOSTX, 0}}, {"rnd",   {OP_RND,   0}},
    {"time",  {OP_TIME,  0}}, {"dup",   {OP_DUP,   0}},
    {"not",   {OP_NOT,   1}}, {"lnot",  {OP_LNOT,  1}},
    {"neg",   {OP_NEG,   1}}, {"inc",   {OP_INC,   1}},
    {"dec",   {OP_DEC,   1}}, {"push",  {OP_PUSH,  1}},
    {"pop",   {OP_POP,   1}}, {"ldb",   {OP_LDB,   1}},
    {"jmpr",  {OP_JMPR,  1}}, {"callr", {OP_CALLR, 1}},
    {"ret",   {OP_RET,   1}},
    {"assert",  {OP_ASSERT, 1}}, {"require", {OP_ASSERT, 1}},
    {"set",   {OP_SET,   2}}, {"add",   {OP_ADD,   2}},
    {"sub",   {OP_SUB,   2}}, {"mul",   {OP_MUL,   2}},
    {"div",   {OP_DIV,   2}}, {"mod",   {OP_MOD,   2}},
    {"or",    {OP_OR,    2}}, {"and",   {OP_AND,   2}},
    {"xor",   {OP_XOR,   2}}, {"shl",   {OP_SHL,   2}},
    {"shr",   {OP_SHR,   2}}, {"sar",   {OP_SAR,   2}},
    {"andl",  {OP_ANDL,  2}}, {"orl",   {OP_ORL,   2}},
    {"eq",    {OP_EQ,    2}}, {"ne",    {OP_NE,    2}},
    {"gt",    {OP_GT,    2}}, {"lt",    {OP_LT,    2}},
    {"ge",    {OP_GE,    2}}, {"le",    {OP_LE,    2}},
    {"slt",   {OP_SLT,   2}}, {"sgt",   {OP_SGT,   2}},
    {"sge",   {OP_SGE,   2}}, {"sle",   {OP_SLE,   2}},
    {"addx",  {OP_ADDX,  2}}, {"subx",  {OP_SUBX,  2}},
    {"mulx",  {OP_MULX,  2}}, {"stb",   {OP_STB,   2}},
    {"mov",   {OP_MOV,   3}}, {"cmp",   {OP_CMP,   3}},
    {"fil",   {OP_FIL,   3}},
  };
  return t;
}

const std::unordered_map<std::string, uint64_t>& syscallTable() {
  static const std::unordered_map<std::string, uint64_t> t = {
    {"NOP", SYS_NOP}, {"READ_ACCOUNT", SYS_READ_ACCOUNT},
    {"TRANSFER", SYS_TRANSFER}, {"READ_ASSET", SYS_READ_ASSET},
    {"CREATE_ASSET_RANDOM", SYS_CREATE_ASSET_RANDOM},
    {"CREATE_ASSET_RANGE", SYS_CREATE_ASSET_RANGE},
    {"UPDATE_ASSET", SYS_UPDATE_ASSET}, {"FUND_ASSET", SYS_FUND_ASSET},
    {"BUY_ASSET", SYS_BUY_ASSET}, {"GIVE_ASSET", SYS_GIVE_ASSET},
    {"HASH", SYS_HASH}, {"VERIFY_SIG", SYS_VERIFY_SIG},
    {"CROSS_TRANSFER", SYS_CROSS_TRANSFER}, {"LOAD_CODE", SYS_LOAD_CODE},
    {"CREATE_ASSET", SYS_CREATE_ASSET}, {"SEND_CLIENT", SYS_SEND_CLIENT},
    {"SCHEDULE", SYS_SCHEDULE},
    {"CREATE_ASSET_MANAGED", SYS_CREATE_ASSET_MANAGED},
    {"RPC", SYS_RPC}, {"OWNER_TRANSFER", SYS_OWNER_TRANSFER},
    {"DEPOSIT", SYS_DEPOSIT}, {"WITHDRAW", SYS_WITHDRAW},
    {"UPDATE_ASSET_META", SYS_UPDATE_ASSET_META},
  };
  return t;
}

struct LabelInfo {
  VmLabel label;
  bool placed = false;
  size_t firstLine = 0;
};

class Assembler {
public:
  Assembler(std::string_view source, uint64_t codeBase) : source_(source) {
    pgm_.setBaseOffset(codeBase);
    // Register aliases and protocol cells.
    for (uint64_t i = 0; i < 4; ++i) {
      syms_["a" + std::to_string(i)] = CESVM_CELL_ARG0 + i;
    }
    for (uint64_t i = 0; i < 8; ++i) {
      syms_["g" + std::to_string(i)] = CESVM_CELL_GPR0 + i;
    }
    syms_["pc"] = CESVM_CELL_PC;
    syms_["r"] = CESVM_CELL_R;
    syms_["s"] = CESVM_CELL_S;
    syms_["sys"] = CESVM_CELL_SYSCALL;
    syms_["input_len"] = CESVM_IO_INPUT_LEN;
    syms_["output_len"] = CESVM_IO_OUTPUT_LEN;
    syms_["budget"] = CESVM_IO_BUDGET;
    syms_["start_time"] = CESVM_IO_START_TIME;
    syms_["caller_key"] = CESVM_IO_CALLER_KEY;
    syms_["self_key"] = CESVM_IO_SELF_KEY;
    syms_["output"] = CESVM_IO_OUTPUT;
    syms_["input"] = CESVM_IO_INPUT;
    syms_["allowance"] = CESVM_IO_ALLOWANCE;
    syms_["gas_left"] = CESVM_IO_BUDGET_REMAINING;
  }

  ces::Bytes run() {
    size_t pos = 0;
    while (pos < source_.size()) {
      size_t eol = source_.find('\n', pos);
      if (eol == std::string_view::npos) eol = source_.size();
      line_++;
      assembleLine(std::string(source_.substr(pos, eol - pos)));
      pos = eol + 1;
    }
    for (const auto& [name, info] : labels_) {
      if (!info.placed) {
        fail("label '" + name + "' referenced (line " +
             std::to_string(info.firstLine) + ") but never defined");
      }
    }
    try {
      return pgm_.buildBytes();
    } catch (const VmProgramError& e) {
      throw CasmError(std::string("build: ") + e.what());
    }
  }

private:
  std::string_view source_;
  VmProgram pgm_;
  std::unordered_map<std::string, uint64_t> syms_;
  std::unordered_map<std::string, LabelInfo> labels_;
  size_t line_ = 0;

  [[noreturn]] void fail(const std::string& what) const {
    throw CasmError("line " + std::to_string(line_) + ": " + what);
  }

  // Cut the line at the first ; or # outside a string literal.
  static std::string stripComment(const std::string& raw) {
    bool inStr = false;
    for (size_t i = 0; i < raw.size(); ++i) {
      char c = raw[i];
      if (inStr) {
        if (c == '\\') { ++i; continue; }
        if (c == '"') inStr = false;
        continue;
      }
      if (c == '"') { inStr = true; continue; }
      if (c == ';' || c == '#') return raw.substr(0, i);
    }
    return raw;
  }

  static std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r");
    return s.substr(b, e - b + 1);
  }

  static bool isIdent(const std::string& s) {
    if (s.empty()) return false;
    if (!std::isalpha(static_cast<unsigned char>(s[0])) && s[0] != '_')
      return false;
    for (char c : s) {
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
        return false;
    }
    return true;
  }

  // Numeric literal: decimal or 0x hex, optional leading '-' (wraps).
  bool parseNumber(const std::string& s, uint64_t& out) const {
    if (s.empty()) return false;
    bool negate = (s[0] == '-');
    const std::string body = negate ? s.substr(1) : s;
    if (body.empty()) return false;
    for (char c : body) {
      if (!std::isalnum(static_cast<unsigned char>(c))) return false;
    }
    char* end = nullptr;
    errno = 0;
    uint64_t v = std::strtoull(body.c_str(), &end, 0);
    if (errno != 0 || end == nullptr || *end != '\0') return false;
    out = negate ? (0 - v) : v;
    return true;
  }

  // number | symbol, optionally displaced by +number / -number.
  uint64_t evalValue(const std::string& expr) const {
    std::string s = trim(expr);
    if (s.empty()) fail("empty operand");
    uint64_t num;
    if (parseNumber(s, num)) return num;
    // symbol with optional +N / -N displacement (scan from position 1
    // so a leading '-' sign is not read as a displacement operator)
    size_t op = s.find_first_of("+-", 1);
    if (op != std::string::npos) {
      const std::string base = trim(s.substr(0, op));
      const std::string disp = trim(s.substr(op + 1));
      uint64_t d;
      if (!parseNumber(disp, d)) fail("bad displacement '" + disp + "'");
      return s[op] == '+' ? evalValue(base) + d : evalValue(base) - d;
    }
    auto it = syms_.find(s);
    if (it == syms_.end()) fail("unknown symbol '" + s + "'");
    return it->second;
  }

  VmVal parseOperand(const std::string& raw) const {
    std::string s = trim(raw);
    if (s.size() >= 2 && s.front() == '[' && s.back() == ']') {
      return Ref(evalValue(s.substr(1, s.size() - 2)));
    }
    return Imm(evalValue(s));
  }

  // Split an operand list on top-level commas.
  std::vector<std::string> splitOperands(const std::string& s) const {
    std::vector<std::string> out;
    std::string cur;
    bool inStr = false;
    for (size_t i = 0; i < s.size(); ++i) {
      char c = s[i];
      if (inStr) {
        cur += c;
        if (c == '\\' && i + 1 < s.size()) { cur += s[++i]; continue; }
        if (c == '"') inStr = false;
        continue;
      }
      if (c == '"') { inStr = true; cur += c; continue; }
      if (c == ',') { out.push_back(trim(cur)); cur.clear(); continue; }
      cur += c;
    }
    if (!trim(cur).empty()) out.push_back(trim(cur));
    for (const auto& o : out) {
      if (o.empty()) fail("empty operand in list");
    }
    return out;
  }

  std::string parseStringLiteral(const std::string& raw) const {
    std::string s = trim(raw);
    if (s.size() < 2 || s.front() != '"' || s.back() != '"')
      fail("expected string literal");
    std::string out;
    for (size_t i = 1; i + 1 < s.size(); ++i) {
      char c = s[i];
      if (c != '\\') { out += c; continue; }
      if (i + 2 >= s.size()) fail("dangling escape");
      char e = s[++i];
      switch (e) {
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case '0': out += '\0'; break;
        case '\\': out += '\\'; break;
        case '"': out += '"'; break;
        default: fail(std::string("unknown escape '\\") + e + "'");
      }
    }
    return out;
  }

  VmLabel getLabel(const std::string& name) {
    if (!isIdent(name)) fail("bad label name '" + name + "'");
    auto it = labels_.find(name);
    if (it == labels_.end()) {
      it = labels_.emplace(name, LabelInfo{pgm_.label(), false, line_}).first;
    }
    return it->second.label;
  }

  void defineSymbol(const std::string& name, uint64_t value) {
    if (!isIdent(name)) fail("bad symbol name '" + name + "'");
    if (syms_.count(name)) fail("symbol '" + name + "' already defined");
    syms_[name] = value;
  }

  void assembleLine(const std::string& raw) {
    std::string s = trim(stripComment(raw));
    if (s.empty()) return;

    // Label definition.
    if (s.back() == ':') {
      const std::string name = trim(s.substr(0, s.size() - 1));
      getLabel(name);
      auto& info = labels_[name];
      if (info.placed) fail("label '" + name + "' defined twice");
      pgm_.place(info.label);
      info.placed = true;
      return;
    }

    // Split head (mnemonic or directive) from the operand tail.
    size_t sp = s.find_first_of(" \t");
    std::string head = (sp == std::string::npos) ? s : s.substr(0, sp);
    std::string tail = (sp == std::string::npos) ? "" : trim(s.substr(sp + 1));
    for (auto& c : head) c = std::tolower(static_cast<unsigned char>(c));

    if (head[0] == '.') { directive(head, tail); return; }

    auto ops = tail.empty() ? std::vector<std::string>{}
                            : splitOperands(tail);

    // Stack-mode suffix.
    bool stackMode = false;
    if (head.size() > 2 && head.compare(head.size() - 2, 2, ".s") == 0) {
      stackMode = true;
      head = head.substr(0, head.size() - 2);
    }

    try {
      instruction(head, stackMode, ops);
    } catch (const VmProgramError& e) {
      fail(e.what());
    }
  }

  void directive(const std::string& head, const std::string& tail) {
    // Directives take a name/cell first and one value after it; the
    // separator is whitespace, with an optional comma tolerated.
    size_t sp = tail.find_first_of(" \t,");
    std::string first = (sp == std::string::npos) ? tail : tail.substr(0, sp);
    std::string rest =
      (sp == std::string::npos) ? "" : trim(tail.substr(sp + 1));
    if (!rest.empty() && rest[0] == ',') rest = trim(rest.substr(1));
    first = trim(first);
    if (first.empty() || rest.empty())
      fail(head + " takes: name/cell and a value");

    if (head == ".equ") {
      defineSymbol(first, evalValue(rest));
    } else if (head == ".alloc") {
      uint64_t count = evalValue(rest);
      try {
        defineSymbol(first, pgm_.alloc(count).cell);
      } catch (const VmProgramError& e) {
        fail(e.what());
      }
    } else if (head == ".at") {
      defineSymbol(first, evalValue(rest));
    } else if (head == ".string") {
      pgm_.writeBytesToIo(evalValue(first), parseStringLiteral(rest));
    } else {
      fail("unknown directive '" + head + "'");
    }
  }

  void instruction(const std::string& head, bool stackMode,
                   const std::vector<std::string>& ops) {
    // Label-target family.
    if (head == "jmp" || head == "call") {
      if (stackMode) {
        if (head == "jmp") fail("jmp has no stack variant");
        if (!ops.empty()) fail("call.s pops its target; no operands");
        pgm_.stackOp(OP_CALL);
        return;
      }
      if (ops.size() != 1) fail(head + " takes: label");
      if (head == "jmp") pgm_.jmp(getLabel(ops[0]));
      else pgm_.call(getLabel(ops[0]));
      return;
    }
    if (head == "jf" || head == "jt") {
      if (stackMode) {
        if (ops.size() != 1) fail(head + ".s takes: label");
        if (head == "jf") pgm_.jfStack(getLabel(ops[0]));
        else pgm_.jtStack(getLabel(ops[0]));
        return;
      }
      if (ops.size() != 2) fail(head + " takes: cond, label");
      if (head == "jf") pgm_.jf(parseOperand(ops[0]), getLabel(ops[1]));
      else pgm_.jt(parseOperand(ops[0]), getLabel(ops[1]));
      return;
    }

    // Variadic host dispatch.
    if (head == "hostv" || head == "hostxv") {
      if (stackMode) fail(head + " has no stack variant");
      if (ops.empty()) fail(head + " takes: syscall, args...");
      uint64_t sysNum;
      auto it = syscallTable().find(ops[0]);
      if (it != syscallTable().end()) {
        sysNum = it->second;
      } else if (!parseNumber(ops[0], sysNum)) {
        fail("unknown syscall '" + ops[0] + "'");
      }
      std::vector<VmVal> args;
      for (size_t i = 1; i < ops.size(); ++i)
        args.push_back(parseOperand(ops[i]));
      // hostv/hostxv take an initializer_list; go through the builder's
      // encoding by emitting via the generic path instead.
      if (args.size() > CESVM_MAX_HOSTV_ARGS)
        fail("too many syscall args");
      emitHostV(head == "hostxv", sysNum, args);
      return;
    }

    // Plain table mnemonics.
    auto it = insnTable().find(head);
    if (it == insnTable().end()) fail("unknown mnemonic '" + head + "'");
    const Insn& in = it->second;

    if (stackMode) {
      if (!ops.empty()) fail(head + ".s pops its operands; none allowed");
      pgm_.stackOp(in.op);
      return;
    }
    if (static_cast<int>(ops.size()) != in.nops) {
      fail(head + " takes " + std::to_string(in.nops) + " operand(s), got " +
           std::to_string(ops.size()));
    }
    std::vector<VmVal> vals;
    for (const auto& o : ops) vals.push_back(parseOperand(o));
    switch (vals.size()) {
      case 0: pgm_.rawOp(in.op, {}); break;
      case 1: pgm_.rawOp(in.op, {vals[0]}); break;
      case 2: pgm_.rawOp(in.op, {vals[0], vals[1]}); break;
      case 3: pgm_.rawOp(in.op, {vals[0], vals[1], vals[2]}); break;
      default: fail("internal: bad operand count");
    }
  }

  void emitHostV(bool xv, uint64_t sysNum, const std::vector<VmVal>& args) {
    switch (args.size()) {
      case 0: hv(xv, sysNum, {}); break;
      case 1: hv(xv, sysNum, {args[0]}); break;
      case 2: hv(xv, sysNum, {args[0], args[1]}); break;
      case 3: hv(xv, sysNum, {args[0], args[1], args[2]}); break;
      case 4: hv(xv, sysNum, {args[0], args[1], args[2], args[3]}); break;
      case 5: hv(xv, sysNum, {args[0], args[1], args[2], args[3],
                              args[4]}); break;
      case 6: hv(xv, sysNum, {args[0], args[1], args[2], args[3],
                              args[4], args[5]}); break;
      case 7: hv(xv, sysNum, {args[0], args[1], args[2], args[3],
                              args[4], args[5], args[6]}); break;
      default: fail("too many syscall args (max 7 via casm)");
    }
  }

  void hv(bool xv, uint64_t n, std::initializer_list<VmVal> a) {
    if (xv) pgm_.hostxv(n, a);
    else pgm_.hostv(n, a);
  }
};

} // namespace

ces::Bytes casmAssemble(std::string_view source, uint64_t codeBase) {
  return Assembler(source, codeBase).run();
}

} // namespace ces
