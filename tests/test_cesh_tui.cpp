// The terminal UI of cesh chat (src/cesh/chat/tui.h): the line editor and the
// footer layout. Neither needs a terminal.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include "chat/tui.h"

#include <boost/test/unit_test.hpp>

using namespace ces::chat;
using K = LineEditor::Key;

namespace {

bool has(const std::string& s, const std::string& t) { return s.find(t) != std::string::npos; }

std::string plain(const std::string& s) {
  std::string o;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\x1b') {
      while (i < s.size() && s[i] != 'm') ++i;
      continue;
    }
    o += s[i];
  }
  return o;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(CeshTuiTests)

BOOST_AUTO_TEST_CASE(Editor_TypeMoveAndDelete) {
  LineEditor e;
  for (const char* c : {"s", "e", "n", "d"}) e.apply(K::Char, c);
  BOOST_CHECK_EQUAL(e.text(), "send");
  e.apply(K::Left);
  e.apply(K::Left);
  e.apply(K::Char, "X");
  BOOST_CHECK_EQUAL(e.text(), "seXnd");
  e.apply(K::Backspace);
  e.apply(K::Delete);
  BOOST_CHECK_EQUAL(e.text(), "sed");
  e.apply(K::Home);
  BOOST_CHECK_EQUAL(e.cursor(), 0u);
  e.apply(K::End);
  BOOST_CHECK_EQUAL(e.cursor(), 3u);
  BOOST_CHECK(e.apply(K::Enter));
}

BOOST_AUTO_TEST_CASE(Editor_Utf8KeepsCodePointsWhole) {
  LineEditor e;
  e.apply(K::Char, "a");
  e.apply(K::Char, "ç");   // two bytes
  e.apply(K::Char, "€");   // three bytes
  BOOST_CHECK_EQUAL(e.text(), "aç€");
  e.apply(K::Left);
  BOOST_CHECK_EQUAL(e.cursor(), 3u);   // before the euro sign
  e.apply(K::Backspace);
  BOOST_CHECK_EQUAL(e.text(), "a€");
  BOOST_CHECK_EQUAL(displayWidth("a€\x1b[1mç\x1b[0m"), 3u);
}

BOOST_AUTO_TEST_CASE(Editor_KillsAndClear) {
  LineEditor e;
  e.apply(K::Paste, "send five credits");
  e.apply(K::KillWord);
  BOOST_CHECK_EQUAL(e.text(), "send five ");
  e.apply(K::Home);
  e.apply(K::Right);
  e.apply(K::KillEnd);
  BOOST_CHECK_EQUAL(e.text(), "s");
  e.apply(K::End);
  e.apply(K::KillStart);
  BOOST_CHECK_EQUAL(e.text(), "");
  e.apply(K::Paste, "anything");
  e.apply(K::Clear);   // Esc
  BOOST_CHECK_EQUAL(e.text(), "");
  BOOST_CHECK_EQUAL(e.cursor(), 0u);
}

// A paste never submits: its line breaks become spaces.
BOOST_AUTO_TEST_CASE(Editor_PasteHasNoEnter) {
  LineEditor e;
  BOOST_CHECK(!e.apply(K::Paste, "line one\r\nline two\n"));
  BOOST_CHECK_EQUAL(e.text(), "line one  line two ");
}

// Ctrl+arrows (and Alt+b, Alt+f) move by words; Ctrl+Delete and Alt+d
// delete the word to the right.
BOOST_AUTO_TEST_CASE(Editor_WordMoves) {
  LineEditor e;
  e.apply(K::Paste, "compute call  8 0");
  e.apply(K::WordLeft);
  BOOST_CHECK_EQUAL(e.cursor(), 16u);   // before "0"
  e.apply(K::WordLeft);
  e.apply(K::WordLeft);
  BOOST_CHECK_EQUAL(e.cursor(), 8u);    // before "call", over two spaces
  e.apply(K::WordRight);
  BOOST_CHECK_EQUAL(e.cursor(), 12u);   // after "call"
  e.apply(K::KillWordRight);
  BOOST_CHECK_EQUAL(e.text(), "compute call 0");
  e.apply(K::Home);
  e.apply(K::WordLeft);
  BOOST_CHECK_EQUAL(e.cursor(), 0u);
  e.apply(K::End);
  e.apply(K::WordRight);
  BOOST_CHECK_EQUAL(e.cursor(), e.text().size());
  LineEditor u;
  u.apply(K::Paste, "ç€ ab");
  u.apply(K::WordLeft);
  u.apply(K::WordLeft);
  BOOST_CHECK_EQUAL(u.cursor(), 0u);
  u.apply(K::WordRight);
  BOOST_CHECK_EQUAL(u.cursor(), 5u);    // after the two code points
}

// The sequences that terminals send for the editing keys.
BOOST_AUTO_TEST_CASE(Keys_EscapeSequences) {
  struct Case { const char* seq; K key; };
  const Case cases[] = {
    {"[A", K::Up}, {"[B", K::Down}, {"[C", K::Right}, {"[D", K::Left},
    {"[1;5C", K::WordRight}, {"[1;5D", K::WordLeft},   // Ctrl (xterm, VTE, kitty)
    {"[1;3C", K::WordRight}, {"[1;3D", K::WordLeft},   // Alt
    {"[1;2C", K::Right}, {"[1;2D", K::Left},           // Shift: a plain move
    {"Oc", K::WordRight}, {"Od", K::WordLeft},         // rxvt Ctrl
    {"OC", K::Right}, {"OD", K::Left}, {"OA", K::Up}, {"OB", K::Down},
    {"[H", K::Home}, {"[F", K::End}, {"OH", K::Home}, {"OF", K::End},
    {"[1~", K::Home}, {"[7~", K::Home}, {"[4~", K::End}, {"[8~", K::End},
    {"[1;5H", K::Home}, {"[1;5F", K::End},
    {"[3~", K::Delete}, {"[3;5~", K::KillWordRight}, {"[3;3~", K::KillWordRight},
    {"b", K::WordLeft}, {"f", K::WordRight}, {"d", K::KillWordRight},
    {"\x7f", K::KillWord},                             // Alt+Backspace
    {"[2~", K::None}, {"x", K::None}, {"[Z", K::None},
  };
  for (auto& c : cases)
    BOOST_CHECK_MESSAGE(keyOfEscape(c.seq) == c.key, "ESC " << c.seq);
}

BOOST_AUTO_TEST_CASE(Editor_HistoryKeepsTheDraft) {
  LineEditor e;
  e.remember("first");
  e.remember("second");
  e.remember("second");   // no repeat
  e.apply(K::Paste, "draft");
  e.apply(K::Up);
  BOOST_CHECK_EQUAL(e.text(), "second");
  e.apply(K::Up);
  BOOST_CHECK_EQUAL(e.text(), "first");
  e.apply(K::Up);
  BOOST_CHECK_EQUAL(e.text(), "first");
  e.apply(K::Down);
  e.apply(K::Down);
  BOOST_CHECK_EQUAL(e.text(), "draft");
}

BOOST_AUTO_TEST_CASE(Footer_RulesInputAndTwoStatusLines) {
  FooterState st;
  st.text = "hi";
  st.cursor = 2;
  st.status.server = "ces.pubcom.org:53830";
  st.status.signer = "@0";
  st.status.signerKey = std::string(60, 'a') + "7525";
  st.status.balance = "1047.5";
  st.status.chatCost = "0.42";
  Footer f = renderFooter(st, 60);
  BOOST_REQUIRE_EQUAL(f.lines.size(), 5u);   // rule, input, rule, two status lines
  BOOST_CHECK(has(plain(f.lines[0]), "────"));
  BOOST_CHECK_EQUAL(plain(f.lines[1]), "❯ hi");
  BOOST_CHECK(has(plain(f.lines[3]), "ces.pubcom.org:53830 · @0 aaaa…7525 · 1047.5 credits"));
  BOOST_CHECK(has(plain(f.lines[4]), "ready · this chat 0.42 credits"));
  BOOST_CHECK_EQUAL(f.caretRow, 1u);
  BOOST_CHECK_EQUAL(f.caretCol, 4u);   // after "❯ hi"
  for (auto& l : f.lines) BOOST_CHECK_LE(displayWidth(l), 60u);
}

BOOST_AUTO_TEST_CASE(Footer_LongInputWraps) {
  FooterState st;
  st.text = std::string(70, 'x');
  st.cursor = st.text.size();
  Footer f = renderFooter(st, 40);
  BOOST_REQUIRE_GE(f.lines.size(), 6u);   // the input takes two rows
  BOOST_CHECK_EQUAL(f.caretRow, 2u);
  BOOST_CHECK_EQUAL(f.caretCol, (2 + 70) % 39);
}

BOOST_AUTO_TEST_CASE(Footer_QuestionSecretAndBusy) {
  FooterState q;
  q.mode = FooterState::Mode::Question;
  q.question = "Send 2 credits from @0 to fabi. Run it?";
  Footer f = renderFooter(q, 80);
  BOOST_CHECK(has(plain(f.lines[1]), "Send 2 credits from @0 to fabi. Run it?"));
  BOOST_CHECK(has(plain(f.lines[2]), "y yes"));

  FooterState s;
  s.mode = FooterState::Mode::Secret;
  s.question = "Paste the private key";
  s.text = "00abcd";
  s.cursor = 6;
  f = renderFooter(s, 80);
  BOOST_CHECK(has(plain(f.lines[2]), "❯ ••••••"));
  for (auto& l : f.lines) BOOST_CHECK(!has(l, "00abcd"));

  FooterState b;
  b.mode = FooterState::Mode::Busy;
  b.status.activity = "⠋ thinking 3s";
  f = renderFooter(b, 80);
  BOOST_CHECK(has(plain(f.lines.back()), "⠋ thinking 3s"));
}

// A narrower window wraps the old footer: a 99-wide rule takes two rows at
// 60 columns and three at 40, and the climb to the top must count them.
BOOST_AUTO_TEST_CASE(Resize_ClimbCountsTheWrappedRows) {
  std::vector<size_t> widths = {99, 2, 99, 50, 60};   // rule, input, rule, two status lines
  BOOST_CHECK_EQUAL(rowsAboveCaret(widths, 1, 2, 100), 1u);   // no wrap: one row up
  BOOST_CHECK_EQUAL(rowsAboveCaret(widths, 1, 2, 60), 2u);    // the top rule takes 2 rows
  BOOST_CHECK_EQUAL(rowsAboveCaret(widths, 1, 2, 40), 3u);
  BOOST_CHECK_EQUAL(rowsAboveCaret(widths, 1, 70, 60), 3u);   // the caret's line wrapped too
}

// No footer line fills the width: the rules are one column short.
BOOST_AUTO_TEST_CASE(Footer_NoLineFillsTheWidth) {
  FooterState st;
  st.status.server = std::string(80, 's');   // longer than the window
  st.status.chatCost = std::string(80, '9');
  st.text = std::string(120, 'x');
  st.cursor = st.text.size();
  Footer f = renderFooter(st, 50);
  for (auto& l : f.lines) BOOST_CHECK_LT(displayWidth(l), 50u);
}

// A command's output sits under its command line, apart from the model's
// words.
BOOST_AUTO_TEST_CASE(Output_IsABlockUnderTheCommand) {
  BOOST_CHECK_EQUAL(outputBlock("one\ntwo\n", false), "  ⎿  one\n     two");
  BOOST_CHECK_EQUAL(outputBlock("x", false), "  ⎿  x");
  std::string c = outputBlock("one\ntwo", true);
  BOOST_CHECK_EQUAL(plain(c), "  ⎿  one\n     two");
  BOOST_CHECK(has(c, "\x1b[38;5;250m"));
}

// The model's words break at spaces, never inside a word, and a list item
// goes on under its text.
BOOST_AUTO_TEST_CASE(Wrap_BreaksAtSpaces) {
  BOOST_CHECK_EQUAL(wrapWords("a pid is the number of a program", 16),
                    "a pid is the\nnumber of a\nprogram");
  BOOST_CHECK_EQUAL(wrapWords("short", 16), "short");
  BOOST_CHECK_EQUAL(wrapWords("  • one two three four five", 16),
                    "  • one two\n    three four\n    five");
  // Styles have no width, and stay in place.
  std::string styled = "\x1b[1mbold\x1b[0m words that go on and on";
  std::string w = wrapWords(styled, 16);
  BOOST_CHECK_EQUAL(plain(w), "bold words that\ngo on and on");
  for (size_t a = 0, b; a <= w.size(); a = b + 1) {
    b = w.find('\n', a);
    if (b == std::string::npos) b = w.size();
    BOOST_CHECK_LE(displayWidth(w.substr(a, b - a)), 16u);
  }
  // A word wider than the row stays whole; two lines wrap on their own.
  BOOST_CHECK_EQUAL(wrapWords("go 0123456789abcdefghij x", 12), "go\n0123456789abcdefghij\nx");
  BOOST_CHECK_EQUAL(wrapWords("one two three\nfour five six", 9), "one two\nthree\nfour five\nsix");
  // The user's line goes on under its text, after the prompt.
  BOOST_CHECK_EQUAL(plain(wrapWords("\x1b[1m❯ \x1b[0mwrite a lua program hello.lua", 20)),
                    "❯ write a lua\n  program hello.lua");
}

BOOST_AUTO_TEST_SUITE_END()
