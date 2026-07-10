#include <ces/lang/cesl.h>

#include <ces/cesvm.h>
#include <ces/util/vmprogram.h>

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ces {

namespace {

enum class Tok { End, Ident, Num, Str, Punct };

struct Token {
  Tok t;
  std::string s;
  uint64_t num = 0;
  size_t line = 1;
};

// Thrown by the constant-expression evaluator when it meets a
// non-constant atom; callers backtrack to runtime codegen.
struct NotConst {};

struct SysCall {
  uint64_t num;
  size_t nargs;
};

const std::unordered_map<std::string, SysCall>& sysTable() {
  static const std::unordered_map<std::string, SysCall> t = {
    {"read_account",         {SYS_READ_ACCOUNT, 1}},
    {"transfer",             {SYS_TRANSFER, 2}},
    {"read_asset",           {SYS_READ_ASSET, 3}},
    {"create_asset_random",  {SYS_CREATE_ASSET_RANDOM, 3}},
    {"create_asset_range",   {SYS_CREATE_ASSET_RANGE, 3}},
    {"update_asset",         {SYS_UPDATE_ASSET, 2}},
    {"fund_asset",           {SYS_FUND_ASSET, 2}},
    {"buy_asset",            {SYS_BUY_ASSET, 2}},
    {"give_asset",           {SYS_GIVE_ASSET, 2}},
    {"hash",                 {SYS_HASH, 3}},
    {"verify_sig",           {SYS_VERIFY_SIG, 4}},
    {"cross_transfer",       {SYS_CROSS_TRANSFER, 3}},
    {"load_code",            {SYS_LOAD_CODE, 1}},
    {"create_asset",         {SYS_CREATE_ASSET, 3}},
    {"send_client",          {SYS_SEND_CLIENT, 3}},
    {"schedule",             {SYS_SCHEDULE, 6}},
    {"create_asset_managed", {SYS_CREATE_ASSET_MANAGED, 3}},
    {"rpc",                  {SYS_RPC, 7}},
    {"owner_transfer",       {SYS_OWNER_TRANSFER, 2}},
    {"deposit",              {SYS_DEPOSIT, 1}},
    {"withdraw",             {SYS_WITHDRAW, 1}},
    {"update_asset_meta",    {SYS_UPDATE_ASSET_META, 3}},
    {"refill",               {SYS_REFILL, 1}},
  };
  return t;
}

const std::unordered_set<std::string>& reservedNames() {
  static const std::unordered_set<std::string> r = [] {
    std::unordered_set<std::string> s = {
      "const", "let", "fn", "if", "else", "while", "break", "continue",
      "return", "require", "abort",
      "random", "now", "peek", "getb", "memcmp",
      "slt", "sgt", "sge", "sle", "sar",
      "poke", "setb", "copy", "fill", "emit_string",
    };
    for (const auto& [name, sc] : sysTable()) {
      s.insert(name);
      s.insert("try_" + name);
    }
    return s;
  }();
  return r;
}

struct Sym {
  enum Kind { Const, Var, Region, RoVar, RwVar } kind;
  uint64_t cell = 0;   // Var / Region / RoVar / RwVar
  uint64_t count = 0;  // Region
  uint64_t k = 0;      // Const
};

struct FnInfo {
  VmLabel label{};
  std::vector<std::string> paramNames;
  std::vector<uint64_t> paramCells;
  std::vector<std::string> callees;
  size_t line = 0;
};

// Binary operator levels below && (index 0 binds loosest). && and ||
// are handled separately for short-circuit emission.
struct BinOp {
  const char* tok;
  CesVMOpcode op;
};
const std::vector<std::vector<BinOp>>& binLevels() {
  static const std::vector<std::vector<BinOp>> lv = {
    {{"|", OP_OR}},
    {{"^", OP_XOR}},
    {{"&", OP_AND}},
    {{"==", OP_EQ}, {"!=", OP_NE}},
    {{"<=", OP_LE}, {">=", OP_GE}, {"<", OP_LT}, {">", OP_GT}},
    {{"<<", OP_SHL}, {">>", OP_SHR}},
    {{"+%", OP_ADD}, {"-%", OP_SUB}, {"+", OP_ADDX}, {"-", OP_SUBX}},
    {{"*%", OP_MUL}, {"*", OP_MULX}, {"/", OP_DIV}, {"%", OP_MOD}},
  };
  return lv;
}

class Compiler {
public:
  Compiler(std::string_view source, uint64_t codeBase) : src_(source) {
    pgm_.setBaseOffset(codeBase);
  }

  ces::Bytes run() {
    lex();
    // Temps first so the hottest cells get short-encoded addresses.
    tmpBase_ = pgm_.alloc(kMaxTmp).cell;
    predeclare();
    prepass();

    // Top-level statements become the boot code; fn bodies are skipped
    // here and compiled after the final term.
    pos_ = 0;
    curFn_.clear();
    while (peek().t != Tok::End) {
      if (peek().t == Tok::Ident && peek().s == "fn") { skipFn(); continue; }
      stmt();
    }
    pgm_.term();

    // Second sweep: compile each top-level fn, skipping everything else.
    pos_ = 0;
    int depth = 0;
    while (peek().t != Tok::End) {
      const Token& t = peek();
      if (t.t == Tok::Punct) {
        if (t.s == "(" || t.s == "{" || t.s == "[") depth++;
        else if (t.s == ")" || t.s == "}" || t.s == "]") depth--;
        next();
        continue;
      }
      if (depth == 0 && t.t == Tok::Ident && t.s == "fn") {
        compileFn();
        continue;
      }
      next();
    }

    checkRecursion();
    try {
      return pgm_.buildBytes();
    } catch (const VmProgramError& e) {
      throw CeslError(std::string("build: ") + e.what());
    }
  }

private:
  std::string_view src_;
  std::vector<Token> toks_;
  size_t pos_ = 0;
  VmProgram pgm_;
  std::vector<std::unordered_map<std::string, Sym>> scopes_;
  std::unordered_map<std::string, FnInfo> fns_;
  std::string curFn_;
  struct Loop { VmLabel brk, cont; };
  std::vector<Loop> loops_;

  static constexpr int kMaxTmp = 12;
  uint64_t tmpBase_ = 0;
  int tmpDepth_ = 0;

  // ---- diagnostics ----

  size_t curLine() const {
    return toks_[std::min(pos_, toks_.size() - 1)].line;
  }

  [[noreturn]] void err(const std::string& m) const {
    throw CeslError("line " + std::to_string(curLine()) + ": " + m);
  }

  // ---- lexer ----

  void lex() {
    size_t line = 1;
    size_t i = 0;
    const size_t n = src_.size();
    while (i < n) {
      char c = src_[i];
      if (c == '\n') { line++; i++; continue; }
      if (std::isspace(static_cast<unsigned char>(c))) { i++; continue; }
      if (c == '/' && i + 1 < n && src_[i + 1] == '/') {
        while (i < n && src_[i] != '\n') i++;
        continue;
      }
      if (std::isdigit(static_cast<unsigned char>(c))) {
        size_t j = i;
        while (j < n && std::isalnum(static_cast<unsigned char>(src_[j]))) j++;
        const std::string body(src_.substr(i, j - i));
        char* end = nullptr;
        errno = 0;
        uint64_t v = std::strtoull(body.c_str(), &end, 0);
        if (errno != 0 || end == nullptr || *end != '\0') {
          throw CeslError("line " + std::to_string(line) +
                          ": bad number '" + body + "'");
        }
        toks_.push_back({Tok::Num, body, v, line});
        i = j;
        continue;
      }
      if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
        size_t j = i;
        while (j < n && (std::isalnum(static_cast<unsigned char>(src_[j])) ||
                         src_[j] == '_')) j++;
        toks_.push_back({Tok::Ident, std::string(src_.substr(i, j - i)),
                         0, line});
        i = j;
        continue;
      }
      if (c == '"') {
        std::string out;
        size_t j = i + 1;
        while (j < n && src_[j] != '"') {
          char d = src_[j];
          if (d == '\n') break;
          if (d == '\\' && j + 1 < n) {
            char e = src_[++j];
            switch (e) {
              case 'n': out += '\n'; break;
              case 't': out += '\t'; break;
              case '0': out += '\0'; break;
              case '\\': out += '\\'; break;
              case '"': out += '"'; break;
              default:
                throw CeslError("line " + std::to_string(line) +
                                ": unknown escape");
            }
            j++;
            continue;
          }
          out += d;
          j++;
        }
        if (j >= n || src_[j] != '"') {
          throw CeslError("line " + std::to_string(line) +
                          ": unterminated string");
        }
        toks_.push_back({Tok::Str, out, 0, line});
        i = j + 1;
        continue;
      }
      static const char* two[] = {"+%", "-%", "*%", "<<", ">>", "<=", ">=",
                                  "==", "!=", "&&", "||"};
      bool matched = false;
      if (i + 1 < n) {
        const std::string pair{c, src_[i + 1]};
        for (const char* p : two) {
          if (pair == p) {
            toks_.push_back({Tok::Punct, pair, 0, line});
            i += 2;
            matched = true;
            break;
          }
        }
      }
      if (matched) continue;
      static const std::string singles = "+-*/%<>=!~&|^(){}[],;";
      if (singles.find(c) != std::string::npos) {
        toks_.push_back({Tok::Punct, std::string(1, c), 0, line});
        i++;
        continue;
      }
      throw CeslError("line " + std::to_string(line) +
                      ": unexpected character '" + std::string(1, c) + "'");
    }
    toks_.push_back({Tok::End, "", 0, line});
  }

  // ---- token cursor ----

  const Token& peek(size_t off = 0) const {
    size_t i = pos_ + off;
    return toks_[std::min(i, toks_.size() - 1)];
  }
  const Token& next() {
    const Token& t = toks_[std::min(pos_, toks_.size() - 1)];
    if (pos_ < toks_.size() - 1) pos_++;
    return t;
  }
  bool acceptP(const std::string& p) {
    if (peek().t == Tok::Punct && peek().s == p) { next(); return true; }
    return false;
  }
  void expectP(const std::string& p) {
    if (!acceptP(p)) err("expected '" + p + "'");
  }
  std::string expectIdent() {
    if (peek().t != Tok::Ident) err("expected identifier");
    return next().s;
  }

  // ---- symbols ----

  void predeclare() {
    scopes_.push_back({});
    auto& g = scopes_[0];
    g["input"]      = {Sym::Region, CESVM_IO_INPUT, 128, 0};
    g["output"]     = {Sym::Region, CESVM_IO_OUTPUT, 128, 0};
    g["caller_key"] = {Sym::Region, CESVM_IO_CALLER_KEY, 4, 0};
    g["self_key"]   = {Sym::Region, CESVM_IO_SELF_KEY, 4, 0};
    g["r"]    = {Sym::RoVar, CESVM_CELL_R, 0, 0};
    g["s"]    = {Sym::RoVar, CESVM_CELL_S, 0, 0};
    g["arg0"] = {Sym::RoVar, CESVM_CELL_ARG0, 0, 0};
    g["arg1"] = {Sym::RoVar, CESVM_CELL_ARG1, 0, 0};
    g["arg2"] = {Sym::RoVar, CESVM_CELL_ARG2, 0, 0};
    g["arg3"] = {Sym::RoVar, CESVM_CELL_ARG3, 0, 0};
    g["input_len"]      = {Sym::RoVar, CESVM_IO_INPUT_LEN, 0, 0};
    g["budget_start"]   = {Sym::RoVar, CESVM_IO_BUDGET, 0, 0};
    g["start_time"]     = {Sym::RoVar, CESVM_IO_START_TIME, 0, 0};
    g["allowance_left"] = {Sym::RoVar, CESVM_IO_ALLOWANCE, 0, 0};
    g["gas_left"]       = {Sym::RoVar, CESVM_IO_BUDGET_REMAINING, 0, 0};
    g["output_len"]     = {Sym::RwVar, CESVM_IO_OUTPUT_LEN, 0, 0};
    g["PRICE_UNIT"]     = {Sym::Const, 0, 0, 100000000};
    // Account-hook context: which event invoked this run, and the named event
    // kinds a trigger branches on. For a hook the event descriptor is in the
    // `input` region: input[0..3]=counterparty key, input[4]=amount,
    // input[5]=account balance at fire time.
    g["invoke_kind"]      = {Sym::RoVar, CESVM_IO_INVOKE_KIND, 0, 0};
    g["INVOKE_DIRECT"]     = {Sym::Const, 0, 0, INVOKE_DIRECT};
    g["INVOKE_SCHEDULED"]  = {Sym::Const, 0, 0, INVOKE_SCHEDULED};
    g["INVOKE_XFER_IN"]    = {Sym::Const, 0, 0, INVOKE_HOOK_XFER_IN};
    g["INVOKE_XFER_OUT"]   = {Sym::Const, 0, 0, INVOKE_HOOK_XFER_OUT};
    g["INVOKE_XFER_VM"]    = {Sym::Const, 0, 0, INVOKE_HOOK_XFER_VM};
    g["INVOKE_SETTLE_IN"]  = {Sym::Const, 0, 0, INVOKE_HOOK_SETTLE_IN};
    g["INVOKE_SETTLE_OUT"] = {Sym::Const, 0, 0, INVOKE_HOOK_SETTLE_OUT};
  }

  Sym* find(const std::string& name) {
    for (auto it = scopes_.rbegin(); it != scopes_.rend(); ++it) {
      auto f = it->find(name);
      if (f != it->end()) return &f->second;
    }
    return nullptr;
  }

  void define(const std::string& name, Sym sym) {
    if (reservedNames().count(name)) err("'" + name + "' is reserved");
    if (fns_.count(name)) err("'" + name + "' is a function");
    if (scopes_.back().count(name)) err("'" + name + "' already defined");
    scopes_.back()[name] = sym;
  }

  // ---- temps ----

  uint64_t reserveTmp() {
    if (tmpDepth_ >= kMaxTmp) err("expression too complex");
    return tmpBase_ + tmpDepth_++;
  }
  void releaseTmp(int n) { tmpDepth_ -= n; }

  // ---- pre-pass: register top-level fns, allocate param cells ----

  void prepass() {
    int depth = 0;
    for (size_t i = 0; i < toks_.size(); ++i) {
      const Token& t = toks_[i];
      if (t.t == Tok::Punct) {
        if (t.s == "(" || t.s == "{" || t.s == "[") depth++;
        else if (t.s == ")" || t.s == "}" || t.s == "]") depth--;
        continue;
      }
      if (depth != 0 || t.t != Tok::Ident || t.s != "fn") continue;
      pos_ = i + 1;
      FnInfo fi;
      fi.line = t.line;
      const std::string name = expectIdent();
      if (reservedNames().count(name)) err("'" + name + "' is reserved");
      if (fns_.count(name)) err("function '" + name + "' already defined");
      expectP("(");
      if (!acceptP(")")) {
        for (;;) {
          fi.paramNames.push_back(expectIdent());
          if (!acceptP(",")) break;
        }
        expectP(")");
      }
      for (size_t p = 0; p < fi.paramNames.size(); ++p) {
        for (size_t q = 0; q < p; ++q) {
          if (fi.paramNames[p] == fi.paramNames[q])
            err("duplicate parameter '" + fi.paramNames[p] + "'");
        }
        fi.paramCells.push_back(allocCells(1));
      }
      fi.label = pgm_.label();
      fns_[name] = std::move(fi);
    }
  }

  uint64_t allocCells(uint64_t n) {
    try {
      return pgm_.alloc(n).cell;
    } catch (const VmProgramError& e) {
      err(e.what());
    }
  }

  // ---- statement / fn skipping (pass A) ----

  void skipFn() {
    next();  // fn
    expectIdent();
    expectP("(");
    int d = 1;
    while (d > 0) {
      const Token& t = next();
      if (t.t == Tok::End) err("unterminated parameter list");
      if (t.t == Tok::Punct && t.s == "(") d++;
      if (t.t == Tok::Punct && t.s == ")") d--;
    }
    expectP("{");
    d = 1;
    while (d > 0) {
      const Token& t = next();
      if (t.t == Tok::End) err("unterminated fn body");
      if (t.t == Tok::Punct && t.s == "{") d++;
      if (t.t == Tok::Punct && t.s == "}") d--;
    }
  }

  // ---- pass B: fn bodies ----

  void compileFn() {
    next();  // fn
    const std::string name = expectIdent();
    FnInfo& fi = fns_.at(name);
    expectP("(");
    if (!acceptP(")")) {
      for (;;) {
        expectIdent();
        if (!acceptP(",")) break;
      }
      expectP(")");
    }
    curFn_ = name;
    pgm_.place(fi.label);
    scopes_.push_back({});
    for (size_t i = 0; i < fi.paramNames.size(); ++i) {
      define(fi.paramNames[i], {Sym::Var, fi.paramCells[i], 0, 0});
    }
    expectP("{");
    while (!acceptP("}")) {
      if (peek().t == Tok::End) err("unterminated fn body");
      stmt();
    }
    pgm_.ret(Imm(0));
    scopes_.pop_back();
    curFn_.clear();
  }

  void checkRecursion() {
    // 0 = unvisited, 1 = on the current path, 2 = done.
    std::unordered_map<std::string, int> color;
    for (const auto& [name, fi] : fns_) dfs(name, color);
  }
  void dfs(const std::string& name, std::unordered_map<std::string, int>& c) {
    int& col = c[name];
    if (col == 2) return;
    if (col == 1) {
      throw CeslError("recursion is not supported: call cycle involving '" +
                      name + "' (line " +
                      std::to_string(fns_.at(name).line) + ")");
    }
    col = 1;
    for (const auto& callee : fns_.at(name).callees) dfs(callee, c);
    col = 2;
  }

  // ---- statements ----

  void block() {
    expectP("{");
    scopes_.push_back({});
    while (!acceptP("}")) {
      if (peek().t == Tok::End) err("unterminated block");
      stmt();
    }
    scopes_.pop_back();
  }

  void stmt() {
    const Token& t = peek();
    if (t.t == Tok::Ident) {
      const std::string& k = t.s;
      if (k == "fn") err("fn definitions are top-level only");
      if (k == "let") { letStmt(); return; }
      if (k == "const") { constStmt(); return; }
      if (k == "if") { ifStmt(); return; }
      if (k == "while") { whileStmt(); return; }
      if (k == "break" || k == "continue") {
        next();
        expectP(";");
        if (loops_.empty()) err("'" + k + "' outside a loop");
        pgm_.jmp(k == "break" ? loops_.back().brk : loops_.back().cont);
        return;
      }
      if (k == "return") { returnStmt(); return; }
      if (k == "require") {
        next(); expectP("(");
        expr();
        expectP(")"); expectP(";");
        pgm_.stackOp(OP_ASSERT);
        return;
      }
      if (k == "abort") {
        next(); expectP("("); expectP(")"); expectP(";");
        pgm_.abort();
        return;
      }
      if (k == "poke") {
        // Both operands ride the VM stack until all user code has run;
        // a temp held across the value expression would be clobbered if
        // that expression calls a function (shared temp pool).
        next(); expectP("(");
        expr();
        expectP(",");
        expr();
        expectP(")"); expectP(";");
        uint64_t tV = reserveTmp();
        pgm_.pop(Imm(tV));
        uint64_t tA = reserveTmp();
        pgm_.pop(Imm(tA));
        pgm_.set(Ref(tA), Ref(tV));
        releaseTmp(2);
        return;
      }
      if (k == "setb") {
        // STB stack form pops value then byte offset: push offset, value.
        next(); expectP("(");
        expr();
        expectP(",");
        expr();
        expectP(")"); expectP(";");
        pgm_.stackOp(OP_STB);
        return;
      }
      if (k == "copy" || k == "fill") {
        next(); expectP("(");
        int reserved = 0;
        std::vector<VmVal> args = argOperands(3, reserved);
        expectP(")"); expectP(";");
        if (k == "copy") pgm_.mov(args[0], args[1], args[2]);
        else pgm_.fil(args[0], args[1], args[2]);
        releaseTmp(reserved);
        return;
      }
      if (k == "emit_string") {
        next(); expectP("(");
        const std::string rname = expectIdent();
        Sym* sym = find(rname);
        if (!sym || sym->kind != Sym::Region)
          err("emit_string target must be a region");
        expectP(",");
        if (peek().t != Tok::Str) err("expected string literal");
        const std::string text = next().s;
        expectP(")"); expectP(";");
        if (text.size() > sym->count * 8)
          err("string does not fit the region");
        pgm_.writeBytesToIo(sym->cell, text);
        return;
      }
      if (isAssignment()) { assignStmt(); return; }
    }
    // Expression statement: evaluate and drop the value.
    expr();
    expectP(";");
    uint64_t td = reserveTmp();
    pgm_.pop(Imm(td));
    releaseTmp(1);
  }

  bool isAssignment() const {
    if (peek().t != Tok::Ident) return false;
    const Token& t1 = peek(1);
    if (t1.t != Tok::Punct) return false;
    if (t1.s == "=") return true;
    if (t1.s != "[") return false;
    // scan to the matching ] and check for '='
    int d = 1;
    size_t i = pos_ + 2;
    while (i < toks_.size() && d > 0) {
      const Token& t = toks_[i];
      if (t.t == Tok::Punct) {
        if (t.s == "[") d++;
        else if (t.s == "]") d--;
      }
      i++;
    }
    return i < toks_.size() && toks_[i].t == Tok::Punct && toks_[i].s == "=";
  }

  void letStmt() {
    next();  // let
    const std::string name = expectIdent();
    if (acceptP("[")) {
      uint64_t n = 0;
      try {
        n = constExpr();
      } catch (const NotConst&) {
        err("region size must be a constant expression");
      }
      expectP("]");
      expectP(";");
      if (n == 0) err("region size must be nonzero");
      define(name, {Sym::Region, allocCells(n), n, 0});
      return;
    }
    const uint64_t cell = allocCells(1);
    define(name, {Sym::Var, cell, 0, 0});
    if (acceptP("=")) {
      expr();
      pgm_.pop(Imm(cell));
    }
    expectP(";");
  }

  void constStmt() {
    next();  // const
    const std::string name = expectIdent();
    expectP("=");
    uint64_t v = 0;
    try {
      v = constExpr();
    } catch (const NotConst&) {
      err("const initializer must be a constant expression");
    }
    expectP(";");
    define(name, {Sym::Const, 0, 0, v});
  }

  void ifStmt() {
    next();  // if
    expectP("(");
    expr();
    expectP(")");
    VmLabel elseL = pgm_.label();
    pgm_.jfStack(elseL);
    block();
    if (peek().t == Tok::Ident && peek().s == "else") {
      next();
      VmLabel endL = pgm_.label();
      pgm_.jmp(endL);
      pgm_.place(elseL);
      if (peek().t == Tok::Ident && peek().s == "if") ifStmt();
      else block();
      pgm_.place(endL);
    } else {
      pgm_.place(elseL);
    }
  }

  void whileStmt() {
    next();  // while
    VmLabel top = pgm_.label();
    VmLabel end = pgm_.label();
    pgm_.place(top);
    expectP("(");
    expr();
    expectP(")");
    pgm_.jfStack(end);
    loops_.push_back({end, top});
    block();
    loops_.pop_back();
    pgm_.jmp(top);
    pgm_.place(end);
  }

  void returnStmt() {
    next();  // return
    const bool hasVal = !(peek().t == Tok::Punct && peek().s == ";");
    if (hasVal) expr();
    expectP(";");
    if (!curFn_.empty()) {
      if (hasVal) {
        pgm_.pop(Imm(CESVM_CELL_R));
        pgm_.ret(Ref(CESVM_CELL_R));
      } else {
        pgm_.ret(Imm(0));
      }
      return;
    }
    // Top level: the returned value becomes the 8-byte program output.
    if (hasVal) {
      pgm_.pop(Imm(CESVM_IO_OUTPUT));
      pgm_.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(8));
    }
    pgm_.term();
  }

  void assignStmt() {
    const std::string name = expectIdent();
    Sym* sym = find(name);
    if (!sym) err("unknown identifier '" + name + "'");
    if (acceptP("[")) {
      if (sym->kind != Sym::Region) err("'" + name + "' is not a region");
      const size_t save = pos_;
      const int saveTmp = tmpDepth_;
      try {
        uint64_t idx = constExpr();
        expectP("]");
        expectP("=");
        if (idx >= sym->count) err("index out of range");
        expr();
        expectP(";");
        pgm_.pop(Imm(sym->cell + idx));
        return;
      } catch (const NotConst&) {
        pos_ = save;
        tmpDepth_ = saveTmp;
      }
      expr();  // dynamic index
      pgm_.push(Imm(sym->cell));
      pgm_.stackOp(OP_ADD);
      // The address stays on the VM stack across the right-hand side; a
      // temp held here would be clobbered if the RHS calls a function
      // (shared temp pool across frames).
      expectP("]");
      expectP("=");
      expr();
      expectP(";");
      uint64_t tV = reserveTmp();
      pgm_.pop(Imm(tV));
      uint64_t tA = reserveTmp();
      pgm_.pop(Imm(tA));
      pgm_.set(Ref(tA), Ref(tV));
      releaseTmp(2);
      return;
    }
    expectP("=");
    if (sym->kind != Sym::Var && sym->kind != Sym::RwVar)
      err("cannot assign to '" + name + "'");
    expr();
    expectP(";");
    pgm_.pop(Imm(sym->cell));
  }

  // ---- expressions (leave exactly one value on the VM data stack) ----

  void expr() { orExpr(); }

  void orExpr() {
    andExpr();
    while (acceptP("||")) {
      VmLabel Lt = pgm_.label();
      VmLabel Le = pgm_.label();
      pgm_.jtStack(Lt);
      andExpr();
      pgm_.stackOp(OP_LNOT);
      pgm_.stackOp(OP_LNOT);
      pgm_.jmp(Le);
      pgm_.place(Lt);
      pgm_.push(Imm(1));
      pgm_.place(Le);
    }
  }

  void andExpr() {
    binExpr(0);
    while (acceptP("&&")) {
      VmLabel Lf = pgm_.label();
      VmLabel Le = pgm_.label();
      pgm_.jfStack(Lf);
      binExpr(0);
      pgm_.stackOp(OP_LNOT);
      pgm_.stackOp(OP_LNOT);
      pgm_.jmp(Le);
      pgm_.place(Lf);
      pgm_.push(Imm(0));
      pgm_.place(Le);
    }
  }

  const BinOp* matchLevel(size_t lvl) const {
    if (peek().t != Tok::Punct) return nullptr;
    for (const auto& b : binLevels()[lvl]) {
      if (peek().s == b.tok) return &b;
    }
    return nullptr;
  }

  void binExpr(size_t lvl) {
    if (lvl >= binLevels().size()) { unaryExpr(); return; }
    binExpr(lvl + 1);
    while (const BinOp* b = matchLevel(lvl)) {
      next();
      binExpr(lvl + 1);
      pgm_.stackOp(b->op);
    }
  }

  void unaryExpr() {
    if (peek().t == Tok::Punct) {
      if (acceptP("!")) { unaryExpr(); pgm_.stackOp(OP_LNOT); return; }
      if (acceptP("~")) { unaryExpr(); pgm_.stackOp(OP_NOT); return; }
      if (acceptP("-")) { unaryExpr(); pgm_.stackOp(OP_NEG); return; }
    }
    primary();
  }

  void primary() {
    const Token& t = peek();
    if (t.t == Tok::Num) { next(); pgm_.push(Imm(t.num)); return; }
    if (t.t == Tok::Punct && t.s == "(") {
      next();
      expr();
      expectP(")");
      return;
    }
    if (t.t == Tok::Ident) { identExpr(); return; }
    err("expected expression");
  }

  void identExpr() {
    const std::string name = expectIdent();

    // Value builtins.
    if (name == "random") { callParens0(); pgm_.stackOp(OP_RND); return; }
    if (name == "now") { callParens0(); pgm_.stackOp(OP_TIME); return; }
    if (name == "getb") {
      expectP("(");
      expr();
      expectP(")");
      pgm_.stackOp(OP_LDB);
      return;
    }
    if (name == "peek") {
      expectP("(");
      expr();
      expectP(")");
      uint64_t tA = reserveTmp();
      pgm_.pop(Imm(tA));
      uint64_t tV = reserveTmp();
      pgm_.mov(Imm(tV), Ref(tA), Imm(1));
      pgm_.push(Ref(tV));
      releaseTmp(2);
      return;
    }
    if (name == "memcmp") {
      expectP("(");
      int reserved = 0;
      std::vector<VmVal> args = argOperands(3, reserved);
      expectP(")");
      pgm_.cmp(args[0], args[1], args[2]);
      releaseTmp(reserved);
      pgm_.push(Ref(CESVM_CELL_R));
      return;
    }
    if (name == "slt" || name == "sgt" || name == "sge" || name == "sle" ||
        name == "sar") {
      expectP("(");
      expr();
      expectP(",");
      expr();
      expectP(")");
      pgm_.stackOp(name == "slt" ? OP_SLT
                   : name == "sgt" ? OP_SGT
                   : name == "sge" ? OP_SGE
                   : name == "sle" ? OP_SLE
                                   : OP_SAR);
      return;
    }

    // Syscall builtins: hostxv (abort on error, yield R) or the try_
    // variant: hostv (yield S).
    bool tryVariant = false;
    std::string sysName = name;
    if (name.rfind("try_", 0) == 0) {
      tryVariant = true;
      sysName = name.substr(4);
    }
    auto sc = sysTable().find(sysName);
    if (sc != sysTable().end() && (tryVariant || name == sysName)) {
      expectP("(");
      int reserved = 0;
      std::vector<VmVal> args = argOperands(sc->second.nargs, reserved);
      expectP(")");
      emitHostV(!tryVariant, sc->second.num, args);
      releaseTmp(reserved);
      pgm_.push(Ref(tryVariant ? CESVM_CELL_S : CESVM_CELL_R));
      return;
    }

    // User function call.
    auto fit = fns_.find(name);
    if (fit != fns_.end()) {
      if (peek().t != Tok::Punct || peek().s != "(")
        err("function '" + name + "' used as a value");
      next();
      FnInfo& fi = fit->second;
      const size_t n = fi.paramCells.size();
      for (size_t i = 0; i < n; ++i) {
        if (i) expectP(",");
        expr();
      }
      expectP(")");
      // Args were evaluated left to right onto the stack; land them in
      // the param cells only now, so an argument expression that itself
      // calls into this callee's callees cannot clobber them.
      for (size_t i = n; i > 0; --i) {
        pgm_.pop(Imm(fi.paramCells[i - 1]));
      }
      if (!curFn_.empty()) fns_.at(curFn_).callees.push_back(name);
      pgm_.call(fi.label);
      pgm_.push(Ref(CESVM_CELL_R));
      return;
    }

    // Plain symbol.
    Sym* sym = find(name);
    if (!sym) err("unknown identifier '" + name + "'");
    switch (sym->kind) {
      case Sym::Const:
        pgm_.push(Imm(sym->k));
        return;
      case Sym::Var:
      case Sym::RoVar:
      case Sym::RwVar:
        pgm_.push(Ref(sym->cell));
        return;
      case Sym::Region:
        break;
    }
    if (acceptP("[")) {
      const size_t save = pos_;
      const int saveTmp = tmpDepth_;
      try {
        uint64_t idx = constExpr();
        expectP("]");
        if (idx >= sym->count) err("index out of range");
        pgm_.push(Ref(sym->cell + idx));
        return;
      } catch (const NotConst&) {
        pos_ = save;
        tmpDepth_ = saveTmp;
      }
      expr();  // dynamic index
      expectP("]");
      pgm_.push(Imm(sym->cell));
      pgm_.stackOp(OP_ADD);
      uint64_t tA = reserveTmp();
      pgm_.pop(Imm(tA));
      uint64_t tV = reserveTmp();
      pgm_.mov(Imm(tV), Ref(tA), Imm(1));
      pgm_.push(Ref(tV));
      releaseTmp(2);
      return;
    }
    // Bare region name: its first cell index (a pointer).
    pgm_.push(Imm(sym->cell));
  }

  void callParens0() {
    expectP("(");
    expectP(")");
  }

  // Materialize a comma-separated argument list as VmVal operands for a
  // register-mode emission (syscalls, cmp/mov/fil). Arguments are
  // evaluated left to right onto the VM data stack and landed in temps
  // only after the last argument's code has run: the temp pool is
  // shared across call frames at runtime, so a temp held across an
  // argument expression that calls a function would be clobbered by the
  // callee's own temp use. Only immutable atoms (literals, consts,
  // region base addresses) are captured directly with no code;
  // variables go through the stack so they are read at their textual
  // position, not at dispatch time.
  std::vector<VmVal> argOperands(size_t n, int& reserved) {
    std::vector<VmVal> vals(n);
    std::vector<bool> onStack(n, false);
    for (size_t i = 0; i < n; ++i) {
      if (i) expectP(",");
      const Token& t = peek();
      const Token& t2 = peek(1);
      const bool endsArg =
        t2.t == Tok::Punct && (t2.s == "," || t2.s == ")");
      bool trivial = false;
      if (endsArg) {
        if (t.t == Tok::Num) {
          next();
          vals[i] = Imm(t.num);
          trivial = true;
        } else if (t.t == Tok::Ident) {
          Sym* sym = find(t.s);
          if (sym && sym->kind == Sym::Const) {
            next();
            vals[i] = Imm(sym->k);
            trivial = true;
          } else if (sym && sym->kind == Sym::Region) {
            next();
            vals[i] = Imm(sym->cell);
            trivial = true;
          }
        }
      }
      if (!trivial) {
        expr();
        onStack[i] = true;
      }
    }
    for (size_t i = n; i > 0; --i) {
      if (!onStack[i - 1]) continue;
      uint64_t tc = reserveTmp();
      reserved++;
      pgm_.pop(Imm(tc));
      vals[i - 1] = Ref(tc);
    }
    return vals;
  }

  void emitHostV(bool xv, uint64_t n, const std::vector<VmVal>& a) {
    switch (a.size()) {
      case 1: hv(xv, n, {a[0]}); break;
      case 2: hv(xv, n, {a[0], a[1]}); break;
      case 3: hv(xv, n, {a[0], a[1], a[2]}); break;
      case 4: hv(xv, n, {a[0], a[1], a[2], a[3]}); break;
      case 5: hv(xv, n, {a[0], a[1], a[2], a[3], a[4]}); break;
      case 6: hv(xv, n, {a[0], a[1], a[2], a[3], a[4], a[5]}); break;
      case 7: hv(xv, n, {a[0], a[1], a[2], a[3], a[4], a[5], a[6]}); break;
      default: err("internal: bad syscall arg count");
    }
  }
  void hv(bool xv, uint64_t n, std::initializer_list<VmVal> a) {
    if (xv) pgm_.hostxv(n, a);
    else pgm_.hostv(n, a);
  }

  // ---- constant expressions (pure; consume the same tokens as expr) ----

  uint64_t constExpr() { return cOr(); }

  uint64_t cOr() {
    uint64_t v = cAnd();
    while (acceptP("||")) v = (v || cAnd()) ? 1 : 0;
    return v;
  }
  uint64_t cAnd() {
    uint64_t v = cBin(0);
    while (acceptP("&&")) v = (v && cBin(0)) ? 1 : 0;
    return v;
  }
  uint64_t cBin(size_t lvl) {
    if (lvl >= binLevels().size()) return cUnary();
    uint64_t v = cBin(lvl + 1);
    while (const BinOp* b = matchLevel(lvl)) {
      next();
      v = foldOp(b->op, v, cBin(lvl + 1));
    }
    return v;
  }
  uint64_t cUnary() {
    if (peek().t == Tok::Punct) {
      if (acceptP("!")) return cUnary() == 0 ? 1 : 0;
      if (acceptP("~")) return ~cUnary();
      if (acceptP("-")) return 0 - cUnary();
    }
    return cPrimary();
  }
  uint64_t cPrimary() {
    const Token& t = peek();
    if (t.t == Tok::Num) { next(); return t.num; }
    if (t.t == Tok::Punct && t.s == "(") {
      next();
      uint64_t v = cOr();
      expectP(")");
      return v;
    }
    if (t.t == Tok::Ident) {
      Sym* sym = find(t.s);
      if (sym && sym->kind == Sym::Const) {
        next();
        return sym->k;
      }
    }
    throw NotConst{};
  }

  uint64_t foldOp(CesVMOpcode op, uint64_t a, uint64_t b) {
    const uint64_t kMax = std::numeric_limits<uint64_t>::max();
    switch (op) {
      case OP_ADDX:
        if (a > kMax - b) err("constant expression overflows");
        return a + b;
      case OP_SUBX:
        if (b > a) err("constant expression underflows");
        return a - b;
      case OP_MULX:
        if (b != 0 && a > kMax / b) err("constant expression overflows");
        return a * b;
      case OP_ADD: return a + b;
      case OP_SUB: return a - b;
      case OP_MUL: return a * b;
      case OP_DIV:
        if (b == 0) err("division by zero in constant expression");
        return a / b;
      case OP_MOD:
        if (b == 0) err("division by zero in constant expression");
        return a % b;
      case OP_OR:  return a | b;
      case OP_XOR: return a ^ b;
      case OP_AND: return a & b;
      // The VM faults (CESVM_SEGFAULT) on shift counts >= 64; keep the
      // fold consistent with runtime semantics by rejecting them.
      case OP_SHL:
      case OP_SHR:
        if (b >= 64) err("shift count >= 64 in constant expression");
        return op == OP_SHL ? a << b : a >> b;
      case OP_EQ:  return a == b;
      case OP_NE:  return a != b;
      case OP_LT:  return a < b;
      case OP_GT:  return a > b;
      case OP_LE:  return a <= b;
      case OP_GE:  return a >= b;
      default: err("internal: unexpected fold op");
    }
  }
};

} // namespace

ces::Bytes ceslCompile(std::string_view source, uint64_t codeBase) {
  return Compiler(source, codeBase).run();
}

} // namespace ces
