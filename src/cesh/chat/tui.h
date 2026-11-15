// The terminal UI of cesh chat: the conversation prints into the normal
// scrollback, and a footer at the bottom holds an input box and a status bar.
// Only the footer is drawn again; the scrollback stays the terminal's own.
//
//   ❯ send 5 credits to fabi                 (your line, in the scrollback)
//   I'll send 5 credits from @0 to fabi.
//   → cesh transfer fabi 500000000
//   ──────────────────────────────────────────
//   ❯ █
//   ──────────────────────────────────────────
//     ces.pubcom.org · @0 a1d9…7525 · 1047.5 credits
//     ready · this chat 0.42 credits · esc clears · ctrl+c quits
//
// LineEditor and renderFooter do no I/O, so the tests check them without a
// terminal. Tui owns the terminal: raw mode, keys, and the footer.

#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ces::chat {

// One line of input with a cursor, history, and the usual editing keys.
// The text is UTF-8; the cursor is a byte offset on a code point boundary.
class LineEditor {
public:
  // Eof is Ctrl+D. Closed is the end of the input (the terminal is gone).
  enum class Key {
    Char, Enter, Backspace, Delete, Left, Right, Home, End, Up, Down,
    WordLeft, WordRight, KillStart, KillEnd, KillWord, KillWordRight,
    Paste, Clear, Quit, Eof, Closed, Redraw, None
  };

  // Apply a key. `text` is the character (Key::Char, UTF-8) or the pasted text.
  // A paste never submits: its line breaks become spaces. Key::Clear (Esc)
  // empties the line. A word is a run of characters with no space. Returns
  // true on Enter.
  bool apply(Key k, const std::string& text = "");

  const std::string& text() const { return text_; }
  size_t cursor() const { return cursor_; }   // byte offset
  void clear() { text_.clear(); cursor_ = 0; histPos_ = history_.size(); }
  void remember(const std::string& line);     // add to history

private:
  std::string text_;
  size_t cursor_ = 0;
  std::vector<std::string> history_;
  size_t histPos_ = 0;
  std::string draft_;   // the line being typed, kept while history shows
};

// The key of the bytes that come after an Esc: a CSI or SS3 sequence ("[D",
// "[1;5D", "[3~", "OH", "Oc") or an Alt key ("b", "\x7f"). The keys with Ctrl
// or Alt move or delete by words. An unknown sequence is Key::None.
LineEditor::Key keyOfEscape(const std::string& afterEsc);

// A command's output as a block under its command line, apart from the
// model's words: "  ⎿  " before the first line, an indent before the others,
// and with `color`, a grey tone. A trailing line break is cut.
std::string outputBlock(const std::string& text, bool color);

// Break each line that is wider than `width` at spaces, so no word breaks
// in two. A continuation row starts under the text of its line: after the
// indent, and after a list bullet ("• ", "- ", "* ") or the prompt ("❯ "). A
// word that is wider than the row stays whole, and the terminal breaks it.
// ANSI styles count as no width.
std::string wrapWords(const std::string& text, size_t width);

// Code points in a UTF-8 string, ANSI escape codes skipped.
size_t displayWidth(const std::string& s);

struct Status {
  std::string server;
  std::string signer;        // "@0"
  std::string signerKey;     // 64 hex, or empty
  std::string balance;       // credits, or empty when unknown
  std::string chatCost;      // credits this chat has cost
  std::string context;       // "context 15k of 120k (12%) · cache 80%", or empty
  std::string activity;      // "ready", "⠋ thinking 3s", ...
};

// What the footer shows: the input box (a line being typed, a question, or a
// masked secret) and the status bar.
struct FooterState {
  enum class Mode { Input, Question, Secret, Busy };
  Mode mode = Mode::Input;
  std::string prompt = "❯ ";     // before the text in the input row
  std::string text;              // the text in the box
  size_t cursor = 0;             // byte offset into `text`
  std::string question;          // Mode::Question / Mode::Secret: the line above the text
  Status status;
};

struct Footer {
  std::vector<std::string> lines;   // with ANSI styles, each at most `cols` wide
  size_t caretRow = 0;              // row of the caret in `lines`
  size_t caretCol = 0;              // column of the caret
};

Footer renderFooter(const FooterState& st, size_t cols);

// Rows from the caret up to the top of a footer whose lines have `widths`,
// after a terminal that reflows has wrapped them at `cols` columns.
size_t rowsAboveCaret(const std::vector<size_t>& widths, size_t caretRow, size_t caretCol,
                      size_t cols);

// The terminal. All writes go through it, so output and the footer do not
// tear each other.
class Tui {
public:
  Tui();
  ~Tui();   // puts the terminal back

  bool start();   // raw mode; false when stdin or stdout is not a terminal
  void stop();

  // Print text into the scrollback, above the footer.
  void print(const std::string& styledText);
  // Print words (the model's prose): the lines break at spaces, to fit the
  // window (wrapWords).
  void printWords(const std::string& styledText);

  void setStatus(const Status& s);
  // A spinner and a clock in the status bar while something runs; "" ends it.
  void busy(const std::string& label);

  // Wait for a line; false when the user quits (Ctrl+C, or Ctrl+D on an empty line).
  bool readLine(std::string& line);
  // A yes/no question in the box: y or n. Enter and Esc mean no; Ctrl+C quits.
  bool confirm(const std::string& question);
  // The line for an answered question (also for a yes that --yolo gives).
  void answered(bool yes, const std::string& question);
  // Masked input in the box.
  std::string secret(const std::string& prompt);

private:
  LineEditor::Key readKey(std::string& text);
  void draw();     // draw the footer again (call with mu_ held)
  void frame(const std::string& above);   // one write: text above, then the footer
  void erase();    // erase the footer (call with mu_ held)
  size_t climb() const;   // rows from the caret up to the footer's top
  size_t columns() const;
  void spin();
  [[noreturn]] void quitNow();   // Ctrl+C: footer away, terminal back, exit 130

  std::mutex mu_;
  bool started_ = false;
  FooterState st_;
  size_t drawnLines_ = 0, drawnCaretRow_ = 0, drawnCaretCol_ = 0, drawnCols_ = 0;
  std::vector<size_t> drawnWidths_;   // the width of each footer line as drawn
  LineEditor editor_;
  std::string pushback_;   // bytes read ahead by readKey, read first next time
  std::chrono::steady_clock::time_point lastByte_{};   // when readKey got its last byte
  std::thread spinner_;
  std::atomic<bool> spinning_{false};
  std::string busyLabel_;
  std::chrono::steady_clock::time_point busySince_;
  int spinFrame_ = 0;
};

}  // namespace ces::chat
