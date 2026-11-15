#include "chat/tui.h"

#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace ces::chat {

namespace {

bool isCont(char c) { return (static_cast<unsigned char>(c) & 0xC0) == 0x80; }

const char* kOff = "\x1b[0m";
const char* kDim = "\x1b[2m";
const char* kBold = "\x1b[1m";
const char* kAccent = "\x1b[38;5;45m";   // the box and the prompt
const char* kQuestion = "\x1b[38;5;214m";

// The terminal state before raw mode, for the signal handlers.
termios g_saved{};
bool g_raw = false;
volatile std::sig_atomic_t g_resized = 0;

void restoreTerminal() {
  if (!g_raw) return;
  ::tcsetattr(STDIN_FILENO, TCSANOW, &g_saved);
  static const char seq[] = "\x1b[?2004l\x1b[?25h";   // paste mode off, cursor on
  ssize_t w = ::write(STDOUT_FILENO, seq, sizeof seq - 1);
  (void)w;
  g_raw = false;
}

extern "C" void onResize(int) { g_resized = 1; }
extern "C" void onFatal(int sig) {
  restoreTerminal();
  std::signal(sig, SIG_DFL);
  std::raise(sig);
}

// Write to the terminal directly: ceshCapture swaps std::cout while a cesh
// command runs, and the spinner draws during commands.
void out(const std::string& s) {
  size_t off = 0;
  while (off < s.size()) {
    ssize_t n = ::write(STDOUT_FILENO, s.data() + off, s.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return;
    }
    off += static_cast<size_t>(n);
  }
}

// Split `s` into rows of at most `w` code points.
std::vector<std::string> wrap(const std::string& s, size_t w) {
  std::vector<std::string> rows(1);
  size_t n = 0;
  for (size_t i = 0; i < s.size(); ++i) {
    if (!isCont(s[i]) && n == w) {
      rows.emplace_back();
      n = 0;
    }
    rows.back() += s[i];
    if (!isCont(s[i])) ++n;
  }
  return rows;
}

std::string padTo(const std::string& s, size_t w) {
  size_t d = displayWidth(s);
  return d >= w ? s : s + std::string(w - d, ' ');
}

// Cut `s` to `w` columns (ANSI codes kept, an ellipsis at the end).
std::string cut(const std::string& s, size_t w) {
  if (displayWidth(s) <= w) return s;
  std::string o;
  size_t n = 0;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\x1b') {
      while (i < s.size() && s[i] != 'm') o += s[i++];
      if (i < s.size()) o += s[i];
      continue;
    }
    if (!isCont(s[i])) {
      if (n + 1 >= w) break;
      ++n;
    }
    o += s[i];
  }
  return o + "…" + kOff;
}

std::string rule(size_t n) {
  std::string o;
  for (size_t i = 0; i < n; ++i) o += "─";
  return o;
}

}  // namespace

// ---- LineEditor ----

bool LineEditor::apply(Key k, const std::string& t) {
  switch (k) {
    case Key::Char:
    case Key::Paste: {
      std::string in = t;
      if (k == Key::Paste)   // a paste never submits
        for (auto& c : in)
          if (c == '\n' || c == '\r' || c == '\t') c = ' ';
      text_.insert(cursor_, in);
      cursor_ += in.size();
      return false;
    }
    case Key::Enter:
      return true;
    case Key::Backspace:
      if (cursor_ > 0) {
        size_t p = cursor_ - 1;
        while (p > 0 && isCont(text_[p])) --p;
        text_.erase(p, cursor_ - p);
        cursor_ = p;
      }
      return false;
    case Key::Delete:
      if (cursor_ < text_.size()) {
        size_t e = cursor_ + 1;
        while (e < text_.size() && isCont(text_[e])) ++e;
        text_.erase(cursor_, e - cursor_);
      }
      return false;
    case Key::Left:
      if (cursor_ > 0) {
        --cursor_;
        while (cursor_ > 0 && isCont(text_[cursor_])) --cursor_;
      }
      return false;
    case Key::Right:
      if (cursor_ < text_.size()) {
        ++cursor_;
        while (cursor_ < text_.size() && isCont(text_[cursor_])) ++cursor_;
      }
      return false;
    case Key::Home: cursor_ = 0; return false;
    case Key::End: cursor_ = text_.size(); return false;
    case Key::KillStart: text_.erase(0, cursor_); cursor_ = 0; return false;
    case Key::KillEnd: text_.erase(cursor_); return false;
    case Key::WordLeft:
    case Key::KillWord: {
      size_t p = cursor_;
      while (p > 0 && text_[p - 1] == ' ') --p;
      while (p > 0 && text_[p - 1] != ' ') --p;
      if (k == Key::KillWord) text_.erase(p, cursor_ - p);
      cursor_ = p;
      return false;
    }
    case Key::WordRight:
    case Key::KillWordRight: {
      size_t e = cursor_;
      while (e < text_.size() && text_[e] == ' ') ++e;
      while (e < text_.size() && text_[e] != ' ') ++e;
      if (k == Key::KillWordRight) text_.erase(cursor_, e - cursor_);
      else cursor_ = e;
      return false;
    }
    case Key::Clear: text_.clear(); cursor_ = 0; histPos_ = history_.size(); return false;
    case Key::Up:
      if (histPos_ > 0) {
        if (histPos_ == history_.size()) draft_ = text_;
        text_ = history_[--histPos_];
        cursor_ = text_.size();
      }
      return false;
    case Key::Down:
      if (histPos_ < history_.size()) {
        ++histPos_;
        text_ = histPos_ == history_.size() ? draft_ : history_[histPos_];
        cursor_ = text_.size();
      }
      return false;
    default:
      return false;
  }
}

void LineEditor::remember(const std::string& line) {
  if (!line.empty() && (history_.empty() || history_.back() != line)) history_.push_back(line);
  histPos_ = history_.size();
  draft_.clear();
}

size_t displayWidth(const std::string& s) {
  size_t n = 0;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\x1b') {
      while (i < s.size() && s[i] != 'm') ++i;
      continue;
    }
    if (!isCont(s[i])) ++n;
  }
  return n;
}

// ---- The footer ----

Footer renderFooter(const FooterState& st, size_t cols) {
  Footer f;
  if (cols < 20) cols = 20;
  const size_t inner = cols - 1;   // the text rows, one column kept free

  // Between two rules: a question (if any), then the input row(s).
  std::vector<std::string> body;
  size_t caretRow = 0, caretCol = 0;
  if (st.mode == FooterState::Mode::Question || st.mode == FooterState::Mode::Secret) {
    for (auto& r : wrap(st.question, inner)) body.push_back(std::string(kQuestion) + r + kOff);
  }
  if (st.mode == FooterState::Mode::Question) {
    body.push_back(std::string(kBold) + "y" + kOff + kDim + " yes   " + kOff + kBold + "n" + kOff +
                   kDim + " no   esc no" + kOff);
    caretRow = body.size();   // +1 for the top rule, -1 for the last row
    caretCol = 0;
  } else {
    std::string shown = st.text;
    if (st.mode == FooterState::Mode::Secret) {
      shown.clear();
      for (char c : st.text)
        if (!isCont(c)) shown += "•";
    }
    size_t caretCp = 0;
    for (size_t i = 0; i < st.cursor && i < st.text.size(); ++i)
      if (!isCont(st.text[i])) ++caretCp;
    const size_t promptW = displayWidth(st.prompt);
    auto rows = wrap(st.prompt + shown, inner);
    size_t at = promptW + caretCp;
    size_t row = at / inner, col = at % inner;
    if (row >= rows.size()) rows.emplace_back();
    // At most 6 rows of input: keep the caret's row in view.
    size_t first = row >= 6 ? row - 5 : 0;
    size_t start = body.size();
    for (size_t r = first; r < rows.size() && r < first + 6; ++r) {
      std::string text = rows[r];
      if (st.mode == FooterState::Mode::Busy) text = std::string(kDim) + text + kOff;
      else if (r == 0) text = std::string(kAccent) + kBold + st.prompt + kOff + text.substr(st.prompt.size());
      body.push_back(text);
    }
    caretRow = 1 + start + (row - first);
    caretCol = col;
  }

  // One column short of the width: a line that fills the width leaves the
  // terminal in its pending-wrap state, and is the first to reflow when the
  // window gets narrower.
  const std::string ruleLine = std::string(kDim) + rule(cols - 1) + kOff;
  f.lines.push_back(ruleLine);
  for (auto& b : body) f.lines.push_back(cut(b, cols - 1));
  f.lines.push_back(ruleLine);

  // Two status lines below, as the harness state: who and where, then what
  // the chat costs and what it does now.
  const Status& s = st.status;
  std::string facts = "  " + s.server;
  if (!s.signer.empty()) {
    facts += " · " + s.signer;
    if (s.signerKey.size() == 64) facts += " " + s.signerKey.substr(0, 4) + "…" + s.signerKey.substr(60);
  }
  if (!s.balance.empty()) facts += " · " + s.balance + " credits";
  f.lines.push_back(cut(std::string(kDim) + facts + kOff, cols - 1));
  std::string act = "  " + std::string(s.activity.empty() ? "ready" : s.activity);
  if (!s.chatCost.empty()) act += std::string(kDim) + " · this chat " + s.chatCost + " credits" + kOff;
  if (!s.context.empty()) act += std::string(kDim) + " · " + s.context + kOff;
  act += std::string(kDim) + " · esc clears · ctrl+c quits" + kOff;
  f.lines.push_back(cut(act, cols - 1));

  if (st.mode == FooterState::Mode::Question) caretRow = body.size();
  f.caretRow = caretRow;
  f.caretCol = caretCol;
  return f;
}

size_t rowsAboveCaret(const std::vector<size_t>& widths, size_t caretRow, size_t caretCol,
                      size_t cols) {
  if (cols == 0) cols = 1;
  size_t rows = 0;
  for (size_t i = 0; i < caretRow && i < widths.size(); ++i)
    rows += widths[i] == 0 ? 1 : (widths[i] + cols - 1) / cols;
  return rows + caretCol / cols;
}

// ---- Tui ----

Tui::Tui() = default;

Tui::~Tui() { stop(); }

size_t Tui::columns() const {
  winsize ws{};
  if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
  return 80;
}

bool Tui::start() {
  if (!::isatty(STDIN_FILENO) || !::isatty(STDOUT_FILENO)) return false;
  if (::tcgetattr(STDIN_FILENO, &g_saved) != 0) return false;
  termios raw = g_saved;
  raw.c_lflag &= ~static_cast<tcflag_t>(ICANON | ECHO | ISIG | IEXTEN);
  raw.c_iflag &= ~static_cast<tcflag_t>(IXON | ICRNL);
  raw.c_cc[VMIN] = 1;
  raw.c_cc[VTIME] = 0;
  if (::tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return false;
  g_raw = true;
  std::atexit(restoreTerminal);
  struct sigaction sa {};
  sa.sa_handler = onResize;   // no SA_RESTART: a resize wakes the key read
  sigaction(SIGWINCH, &sa, nullptr);
  std::signal(SIGTERM, onFatal);
  std::signal(SIGHUP, onFatal);
  out("\x1b[?2004h");   // bracketed paste on
  started_ = true;
  std::lock_guard<std::mutex> lk(mu_);
  draw();
  return true;
}

void Tui::stop() {
  if (spinner_.joinable()) {
    spinning_ = false;
    spinner_.join();
  }
  if (!started_) return;
  {
    std::lock_guard<std::mutex> lk(mu_);
    erase();
  }
  restoreTerminal();
  started_ = false;
}

void Tui::erase() {
  if (drawnLines_ == 0) return;
  std::string o = "\r";
  size_t up = climb();
  if (up > 0) o += "\x1b[" + std::to_string(up) + "A";
  o += "\x1b[J";
  out(o);
  drawnLines_ = 0;
  drawnCaretRow_ = 0;
  drawnWidths_.clear();
}

// One frame, in one write: go to the top of the footer on the screen, print
// `above` (if any) into the scrollback there, then draw each footer line over
// the old one (erase to the end of the line, not the whole block first), and
// clear what is left below. A terminal that knows synchronized output (DEC
// mode 2026) shows the frame at once; others ignore the mode. Never a blank
// frame, so no flicker. Call with mu_ held.
void Tui::frame(const std::string& above) {
  const size_t cols = columns();
  Footer f = renderFooter(st_, cols);
  std::string o = "\x1b[?2026h\x1b[?25l";
  o += "\r";
  if (drawnLines_ > 0) {
    size_t up = climb();
    if (up > 0) o += "\x1b[" + std::to_string(up) + "A";
  }
  if (!above.empty()) {
    o += "\x1b[J";   // the old footer goes; the text takes its place
    for (char c : above) o += c == '\n' ? std::string("\r\n") : std::string(1, c);
    o += std::string(kOff) + "\r\n";
  }
  for (size_t i = 0; i < f.lines.size(); ++i) {
    o += f.lines[i] + "\x1b[K";
    if (i + 1 < f.lines.size()) o += "\r\n";
  }
  o += "\x1b[J";   // a shorter footer: clear the old lines below it
  // Back to the caret: up from the last line, then to its column.
  size_t up = f.lines.size() - 1 - f.caretRow;
  o += "\r";
  if (up > 0) o += "\x1b[" + std::to_string(up) + "A";
  if (f.caretCol > 0) o += "\x1b[" + std::to_string(f.caretCol) + "C";
  if (st_.mode != FooterState::Mode::Busy) o += "\x1b[?25h";
  o += "\x1b[?2026l";
  out(o);
  drawnLines_ = f.lines.size();
  drawnCaretRow_ = f.caretRow;
  drawnCaretCol_ = f.caretCol;
  drawnCols_ = cols;
  drawnWidths_.clear();
  for (auto& l : f.lines) drawnWidths_.push_back(displayWidth(l));
}

// Rows from the caret up to the top of the footer on the screen now. When the
// window changed width since the footer was drawn, a terminal that reflows
// has wrapped the old lines: count the rows they take at the new width.
size_t Tui::climb() const {
  const size_t cols = columns();
  if (cols == drawnCols_ || drawnWidths_.empty()) return drawnCaretRow_;
  return rowsAboveCaret(drawnWidths_, drawnCaretRow_, drawnCaretCol_, cols);
}

void Tui::draw() { frame(""); }

void Tui::printWords(const std::string& text) {
  const size_t cols = columns();
  print(wrapWords(text, cols > 1 ? cols - 1 : cols));
}

void Tui::print(const std::string& text) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!started_) {
    out(text + "\n");
    return;
  }
  frame(text.empty() ? std::string(" ") : text);
}

void Tui::setStatus(const Status& s) {
  std::lock_guard<std::mutex> lk(mu_);
  std::string activity = st_.status.activity;
  st_.status = s;
  st_.status.activity = activity;
  if (started_) draw();
}

void Tui::spin() {
  static const char* kSpin[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
  while (spinning_) {
    // Nothing reads keys while the chat works, so watch for Ctrl+C here: it
    // ends cesh chat at once, as at the prompt.
    pollfd p{STDIN_FILENO, POLLIN, 0};
    while (::poll(&p, 1, 0) > 0) {
      unsigned char c = 0;
      if (::read(STDIN_FILENO, &c, 1) != 1) break;
      if (c == 3) quitNow();
    }
    {
      std::lock_guard<std::mutex> lk(mu_);
      auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - busySince_).count();
      st_.status.activity = std::string(kQuestion) + kSpin[spinFrame_++ % 10] + kOff + " " + busyLabel_ +
                            " " + std::to_string(secs) + "s";
      if (started_) draw();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
  }
}

void Tui::busy(const std::string& label) {
  if (spinner_.joinable()) {
    spinning_ = false;
    spinner_.join();
  }
  std::lock_guard<std::mutex> lk(mu_);
  if (label.empty()) {
    st_.mode = FooterState::Mode::Input;
    st_.status.activity = "";
    if (started_) draw();
    return;
  }
  busyLabel_ = label;
  busySince_ = std::chrono::steady_clock::now();
  st_.mode = FooterState::Mode::Busy;
  spinning_ = true;
  spinner_ = std::thread([this] { spin(); });
}

namespace {

std::string wrapLine(const std::string& line, size_t width) {
  if (displayWidth(line) <= width) return line;
  // The prefix: the indent and a bullet, with the styles in them.
  size_t i = 0;
  auto skipStyles = [&] {
    while (i < line.size() && line[i] == '\x1b') {
      while (i < line.size() && line[i] != 'm') ++i;
      if (i < line.size()) ++i;
    }
  };
  skipStyles();
  while (i < line.size() && line[i] == ' ') { ++i; skipStyles(); }
  for (const char* b : {"• ", "- ", "* ", "❯ "}) {
    const size_t n = std::strlen(b);
    if (line.compare(i, n, b) == 0) { i += n; break; }
  }
  const std::string prefix = line.substr(0, i);
  // A narrow row has no room for the hanging indent: the rows start at 0.
  const size_t indent = displayWidth(prefix) + 10 > width ? 0 : displayWidth(prefix);

  std::vector<std::string> words;
  size_t start = i;
  for (size_t k = i; k <= line.size(); ++k)
    if (k == line.size() || line[k] == ' ') {
      words.push_back(line.substr(start, k - start));
      start = k + 1;
    }
  std::string out = prefix;
  size_t w = displayWidth(prefix);
  bool rowEmpty = true;
  for (auto& word : words) {
    const size_t dw = displayWidth(word);
    if (!rowEmpty && w + 1 + dw > width) {
      out += "\n" + std::string(indent, ' ');
      w = indent;
      rowEmpty = true;
      if (word.empty()) continue;   // the spaces at a break go
    }
    if (!rowEmpty) { out += ' '; ++w; }
    out += word;
    w += dw;
    rowEmpty = false;
  }
  return out;
}

}  // namespace

std::string wrapWords(const std::string& text, size_t width) {
  std::string out;
  size_t start = 0;
  for (;;) {
    size_t nl = text.find('\n', start);
    out += wrapLine(text.substr(start, nl == std::string::npos ? std::string::npos : nl - start), width);
    if (nl == std::string::npos) break;
    out += '\n';
    start = nl + 1;
  }
  return out;
}

std::string outputBlock(const std::string& text, bool color) {
  std::string t = text;
  while (!t.empty() && t.back() == '\n') t.pop_back();
  const std::string tone = color ? "\x1b[38;5;250m" : "";
  const std::string off = color ? kOff : "";
  const std::string gutter = color ? std::string(kDim) + "  ⎿  " + kOff : "  ⎿  ";
  std::string o;
  size_t start = 0;
  for (bool first = true;; first = false) {
    size_t nl = t.find('\n', start);
    std::string line = t.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
    o += (first ? gutter : std::string("     ")) + tone + line + off;
    if (nl == std::string::npos) break;
    o += "\n";
    start = nl + 1;
  }
  return o;
}

LineEditor::Key keyOfEscape(const std::string& e) {
  using K = LineEditor::Key;
  if (e.empty()) return K::Clear;
  if (e.size() == 1) {   // Alt+key, as readline has them
    switch (e[0]) {
      case 'b': return K::WordLeft;
      case 'f': return K::WordRight;
      case 'd': return K::KillWordRight;
      case 127: case 8: return K::KillWord;   // Alt+Backspace
      default: return K::None;
    }
  }
  const char intro = e[0];
  const char fin = e.back();
  const std::string params = e.substr(1, e.size() - 2);
  if (intro == 'O') {   // SS3: the keys in application mode, and rxvt Ctrl+arrows (Oc, Od)
    switch (fin) {
      case 'A': return K::Up;
      case 'B': return K::Down;
      case 'C': return K::Right;
      case 'D': return K::Left;
      case 'H': return K::Home;
      case 'F': return K::End;
      case 'c': return K::WordRight;
      case 'd': return K::WordLeft;
      default: return K::None;
    }
  }
  if (intro != '[') return K::None;
  // "1;5D": the number after ';' is 1 + a bit set (1 Shift, 2 Alt, 4 Ctrl).
  int mod = 1;
  if (auto semi = params.find(';'); semi != std::string::npos)
    mod = std::atoi(params.c_str() + semi + 1);
  const bool word = mod > 1 && ((mod - 1) & 6) != 0;   // Alt or Ctrl
  const std::string num = params.substr(0, params.find(';'));
  switch (fin) {
    case 'A': return K::Up;
    case 'B': return K::Down;
    case 'C': return word ? K::WordRight : K::Right;
    case 'D': return word ? K::WordLeft : K::Left;
    case 'H': return K::Home;
    case 'F': return K::End;
    case '~':
      if (num == "1" || num == "7") return K::Home;
      if (num == "4" || num == "8") return K::End;
      if (num == "3") return word ? K::KillWordRight : K::Delete;
      return K::None;
    default: return K::None;
  }
}

LineEditor::Key Tui::readKey(std::string& text) {
  using K = LineEditor::Key;
  text.clear();
  auto readByte = [&](unsigned char& c, int waitMs) -> int {
    if (!pushback_.empty()) {
      c = static_cast<unsigned char>(pushback_.front());
      pushback_.erase(0, 1);
      return 1;
    }
    if (waitMs >= 0) {
      pollfd p{STDIN_FILENO, POLLIN, 0};
      int r = ::poll(&p, 1, waitMs);
      if (r <= 0) return r;
    }
    ssize_t n = ::read(STDIN_FILENO, &c, 1);
    return n == 1 ? 1 : (n < 0 && errno == EINTR ? -2 : 0);
  };
  unsigned char c = 0;
  int r = readByte(c, -1);
  if (r == -2) return g_resized ? (g_resized = 0, K::Redraw) : K::None;
  if (r != 1) return K::Closed;
  // A byte that comes within a few ms of the one before is part of a burst
  // (a paste); a person does not type that fast.
  const auto now = std::chrono::steady_clock::now();
  const bool burst = now - lastByte_ < std::chrono::milliseconds(10);
  lastByte_ = now;
  switch (c) {
    case 3: return K::Quit;             // Ctrl+C
    case 4: return K::Eof;              // Ctrl+D
    case 1: return K::Home;             // Ctrl+A
    case 5: return K::End;              // Ctrl+E
    case 2: return K::Left;             // Ctrl+B
    case 6: return K::Right;            // Ctrl+F
    case 16: return K::Up;              // Ctrl+P
    case 14: return K::Down;            // Ctrl+N
    case 21: return K::KillStart;       // Ctrl+U
    case 11: return K::KillEnd;         // Ctrl+K
    case 23: return K::KillWord;        // Ctrl+W
    case 12: return K::Redraw;          // Ctrl+L
    case 127: case 8: return K::Backspace;
    case '\r': case '\n': {
      // An Enter with more input already waiting is a paste (a terminal with
      // no bracketed paste), not a submit. A terminal that sends "\r\n" for
      // one Enter key leaves only that "\n" waiting: that is still an Enter.
      if (!pushback_.empty() || burst) {
        text = " ";
        return K::Paste;
      }
      pollfd p{STDIN_FILENO, POLLIN, 0};
      if (::poll(&p, 1, 0) > 0) {
        unsigned char nx = 0;
        if (c == '\r' && ::read(STDIN_FILENO, &nx, 1) == 1) {
          if (nx == '\n' && ::poll(&p, 1, 0) <= 0) return K::Enter;
          pushback_ += static_cast<char>(nx);   // the paste goes on
        }
        text = " ";
        return K::Paste;
      }
      return K::Enter;
    }
    case 27: {
      unsigned char a = 0;
      if (readByte(a, 30) != 1) return K::Clear;   // a lone Esc
      if (a != '[' && a != 'O') return keyOfEscape(std::string(1, static_cast<char>(a)));   // Alt+key
      std::string seq;
      unsigned char b = 0;
      while (readByte(b, 30) == 1) {
        seq += static_cast<char>(b);
        if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '~') break;
      }
      if (a == '[' && seq == "200~") {   // bracketed paste: read to the end marker
        std::string body;
        const std::string endMark = "\x1b[201~";
        while (readByte(b, 2000) == 1) {
          body += static_cast<char>(b);
          if (body.size() >= endMark.size() &&
              body.compare(body.size() - endMark.size(), endMark.size(), endMark) == 0) {
            body.resize(body.size() - endMark.size());
            break;
          }
        }
        text = body;
        return K::Paste;
      }
      return keyOfEscape(static_cast<char>(a) + seq);
    }
    default:
      break;
  }
  if (c < 32) return K::None;
  text = static_cast<char>(c);
  // The rest of a UTF-8 code point.
  int more = (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : 0;
  for (int i = 0; i < more; ++i) {
    unsigned char d = 0;
    if (readByte(d, 50) != 1) break;
    text += static_cast<char>(d);
  }
  return K::Char;
}

bool Tui::readLine(std::string& line) {
  using K = LineEditor::Key;
  {
    std::lock_guard<std::mutex> lk(mu_);
    st_.mode = FooterState::Mode::Input;
    editor_.clear();
    st_.text.clear();
    st_.cursor = 0;
    draw();
  }
  for (;;) {
    std::string t;
    K k = readKey(t);
    if (k == K::Quit || k == K::Closed || (k == K::Eof && editor_.text().empty())) return false;
    if (k == K::Eof) k = K::Delete;   // Ctrl+D on a line deletes, as in readline
    std::lock_guard<std::mutex> lk(mu_);
    if (k == K::Redraw) {
      draw();
      continue;
    }
    if (editor_.apply(k, t)) {
      line = editor_.text();
      editor_.remember(line);
      st_.text.clear();
      st_.cursor = 0;
      return true;
    }
    st_.text = editor_.text();
    st_.cursor = editor_.cursor();
    draw();
  }
}

void Tui::quitNow() {
  {
    std::lock_guard<std::mutex> lk(mu_);
    erase();
    out(std::string(kDim) + "^C" + kOff + "\r\n");
  }
  restoreTerminal();
  std::_Exit(130);
}

bool Tui::confirm(const std::string& question) {
  using K = LineEditor::Key;
  {
    std::lock_guard<std::mutex> lk(mu_);
    st_.mode = FooterState::Mode::Question;
    st_.question = question;
    draw();
  }
  bool yes = false;
  for (;;) {
    std::string t;
    K k = readKey(t);
    if (k == K::Char && (t == "y" || t == "Y")) { yes = true; break; }
    if (k == K::Char && (t == "n" || t == "N")) break;
    if (k == K::Quit) quitNow();   // Ctrl+C quits, as everywhere
    if (k == K::Enter || k == K::Clear || k == K::Eof || k == K::Closed) break;
    if (k == K::Redraw) {
      std::lock_guard<std::mutex> lk(mu_);
      draw();
    }
  }
  {
    std::lock_guard<std::mutex> lk(mu_);
    st_.mode = FooterState::Mode::Busy;
    st_.question.clear();
  }
  answered(yes, question);
  return yes;
}

void Tui::answered(bool yes, const std::string& question) {
  // The question goes on under itself, after the mark.
  const std::string head =
      std::string("  ") + (yes ? "\x1b[32m✓ yes\x1b[0m" : "\x1b[31m✗ no\x1b[0m") + kDim + "  ";
  const size_t hw = displayWidth(head);
  const size_t cols = columns();
  const size_t width = cols > 1 ? cols - 1 : cols;
  std::string body = wrapWords(question, width > hw + 10 ? width - hw : width);
  std::string o = head;
  for (char c : body) o += c == '\n' ? "\n" + std::string(hw, ' ') : std::string(1, c);
  print(o + kOff);
}

std::string Tui::secret(const std::string& prompt) {
  using K = LineEditor::Key;
  LineEditor ed;
  {
    std::lock_guard<std::mutex> lk(mu_);
    st_.mode = FooterState::Mode::Secret;
    st_.question = prompt;
    st_.text.clear();
    st_.cursor = 0;
    draw();
  }
  for (;;) {
    std::string t;
    K k = readKey(t);
    if (k == K::Quit) quitNow();
    if (k == K::Clear || k == K::Closed) { ed.clear(); break; }
    if (k == K::Up || k == K::Down) continue;   // no history for a secret
    if (k == K::Eof) k = K::Delete;
    if (ed.apply(k, t)) break;
    std::lock_guard<std::mutex> lk(mu_);
    st_.text = ed.text();
    st_.cursor = ed.cursor();
    draw();
  }
  std::string v = ed.text();
  std::lock_guard<std::mutex> lk(mu_);
  st_.mode = FooterState::Mode::Busy;
  st_.text.clear();
  st_.question.clear();
  st_.cursor = 0;
  draw();
  return v;
}

}  // namespace ces::chat
