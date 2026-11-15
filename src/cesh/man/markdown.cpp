#include "man/markdown.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <vector>

namespace ces::man {

namespace {

std::string trim(std::string_view s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return std::string(s.substr(a, b - a));
}

// Inline markup of one run of text: `code`, **bold**, *italic*, [text](url).
std::string inlineHtml(std::string_view s, const LinkMap& link) {
  std::string o;
  size_t i = 0;
  while (i < s.size()) {
    char c = s[i];
    if (c == '`') {
      size_t e = s.find('`', i + 1);
      if (e != std::string_view::npos) {
        o += "<code>" + escapeHtml(s.substr(i + 1, e - i - 1)) + "</code>";
        i = e + 1;
        continue;
      }
    }
    if (c == '*' && i + 1 < s.size() && s[i + 1] == '*') {
      size_t e = s.find("**", i + 2);
      if (e != std::string_view::npos) {
        o += "<strong>" + inlineHtml(s.substr(i + 2, e - i - 2), link) + "</strong>";
        i = e + 2;
        continue;
      }
    }
    if (c == '*' && i + 1 < s.size() && s[i + 1] != ' ') {
      size_t e = s.find('*', i + 1);
      if (e != std::string_view::npos && e > i + 1) {
        o += "<em>" + inlineHtml(s.substr(i + 1, e - i - 1), link) + "</em>";
        i = e + 1;
        continue;
      }
    }
    if (c == '[') {
      size_t close = s.find("](", i);
      size_t end = close == std::string_view::npos ? close : s.find(')', close + 2);
      size_t inner = s.find('[', i + 1);
      if (end != std::string_view::npos && (inner == std::string_view::npos || inner > close)) {
        std::string href = link ? link(s.substr(close + 2, end - close - 2))
                                : std::string(s.substr(close + 2, end - close - 2));
        o += "<a href=\"" + escapeHtml(href) + "\">" +
             inlineHtml(s.substr(i + 1, close - i - 1), link) + "</a>";
        i = end + 1;
        continue;
      }
    }
    o += escapeHtml(s.substr(i, 1));
    ++i;
  }
  return o;
}

bool isTableRow(std::string_view l) {
  std::string t = trim(l);
  return t.size() >= 2 && t.front() == '|';
}

bool isTableRule(std::string_view l) {
  std::string t = trim(l);
  if (!isTableRow(t)) return false;
  for (char c : t)
    if (c != '|' && c != '-' && c != ':' && c != ' ') return false;
  return true;
}

std::vector<std::string> cells(std::string_view l) {
  std::string t = trim(l);
  if (!t.empty() && t.front() == '|') t.erase(0, 1);
  if (!t.empty() && t.back() == '|') t.pop_back();
  std::vector<std::string> out;
  std::string cur;
  bool code = false;
  for (char c : t) {
    if (c == '`') code = !code;
    if (c == '|' && !code) { out.push_back(trim(cur)); cur.clear(); continue; }
    cur += c;
  }
  out.push_back(trim(cur));
  return out;
}

// The list marker of a line: 'u' for "- " or "* ", 'o' for "1. ", 0 for none.
// `rest` gets the text after the marker.
char listItem(std::string_view l, std::string& rest) {
  if (l.size() >= 2 && (l[0] == '-' || l[0] == '*') && l[1] == ' ') {
    rest = trim(l.substr(2));
    return 'u';
  }
  size_t d = 0;
  while (d < l.size() && std::isdigit(static_cast<unsigned char>(l[d]))) ++d;
  if (d > 0 && d + 1 < l.size() && l[d] == '.' && l[d + 1] == ' ') {
    rest = trim(l.substr(d + 2));
    return 'o';
  }
  return 0;
}

}  // namespace

std::string escapeHtml(std::string_view s) {
  std::string o;
  o.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '&': o += "&amp;"; break;
      case '<': o += "&lt;"; break;
      case '>': o += "&gt;"; break;
      case '"': o += "&quot;"; break;
      case '\'': o += "&#39;"; break;
      default: o += c;
    }
  }
  return o;
}

std::string markdownToHtml(std::string_view md, const LinkMap& link) {
  std::vector<std::string> lines;
  {
    std::istringstream in{std::string(md)};
    std::string l;
    while (std::getline(in, l)) {
      if (!l.empty() && l.back() == '\r') l.pop_back();
      lines.push_back(l);
    }
  }

  std::string o;
  std::string para;
  auto flushPara = [&] {
    if (!trim(para).empty()) o += "<p>" + inlineHtml(trim(para), link) + "</p>\n";
    para.clear();
  };

  size_t i = 0;
  while (i < lines.size()) {
    const std::string& l = lines[i];
    std::string t = trim(l);

    if (t.rfind("```", 0) == 0) {
      flushPara();
      std::string code;
      ++i;
      while (i < lines.size() && trim(lines[i]).rfind("```", 0) != 0) {
        code += lines[i] + "\n";
        ++i;
      }
      ++i;  // the closing fence
      o += "<pre><code>" + escapeHtml(code) + "</code></pre>\n";
      continue;
    }
    if (t.empty()) { flushPara(); ++i; continue; }
    if (t == "---" || t == "***") { flushPara(); o += "<hr>\n"; ++i; continue; }
    if (t.front() == '#') {
      flushPara();
      size_t n = t.find_first_not_of('#');
      if (n != std::string::npos && n <= 6 && t[n] == ' ') {
        std::string lvl = std::to_string(n);
        o += "<h" + lvl + ">" + inlineHtml(trim(t.substr(n)), link) + "</h" + lvl + ">\n";
        ++i;
        continue;
      }
    }
    if (isTableRow(t) && i + 1 < lines.size() && isTableRule(lines[i + 1])) {
      flushPara();
      o += "<table>\n<thead><tr>";
      for (auto& c : cells(t)) o += "<th>" + inlineHtml(c, link) + "</th>";
      o += "</tr></thead>\n<tbody>\n";
      i += 2;
      while (i < lines.size() && isTableRow(lines[i])) {
        o += "<tr>";
        for (auto& c : cells(lines[i])) o += "<td>" + inlineHtml(c, link) + "</td>";
        o += "</tr>\n";
        ++i;
      }
      o += "</tbody>\n</table>\n";
      continue;
    }
    if (t.rfind("> ", 0) == 0 || t == ">") {
      flushPara();
      std::string q;
      while (i < lines.size()) {
        std::string u = trim(lines[i]);
        if (u.rfind(">", 0) != 0) break;
        q += trim(u.substr(1)) + " ";
        ++i;
      }
      o += "<blockquote><p>" + inlineHtml(trim(q), link) + "</p></blockquote>\n";
      continue;
    }
    std::string rest;
    char kind = listItem(t, rest);
    if (kind) {
      flushPara();
      const char* tag = kind == 'u' ? "ul" : "ol";
      o += std::string("<") + tag + ">\n";
      while (i < lines.size()) {
        std::string u = trim(lines[i]);
        std::string r;
        char k = listItem(u, r);
        if (k != kind) break;
        std::string item = r;
        ++i;
        // Indented lines continue the item.
        while (i < lines.size() && !lines[i].empty() &&
               std::isspace(static_cast<unsigned char>(lines[i][0])) &&
               !listItem(trim(lines[i]), r)) {
          item += " " + trim(lines[i]);
          ++i;
        }
        o += "<li>" + inlineHtml(item, link) + "</li>\n";
      }
      o += std::string("</") + tag + ">\n";
      continue;
    }
    para += l + " ";
    ++i;
  }
  flushPara();
  return o;
}

namespace {

const char* kBold = "\x1b[1m";
const char* kDim = "\x1b[2m";
const char* kItalic = "\x1b[3m";
const char* kCode = "\x1b[36m";
const char* kOff = "\x1b[0m";

std::string inlineTerminal(std::string_view s) {
  std::string o;
  size_t i = 0;
  while (i < s.size()) {
    char c = s[i];
    if (c == '`') {
      size_t e = s.find('`', i + 1);
      if (e != std::string_view::npos) {
        o += kCode + std::string(s.substr(i + 1, e - i - 1)) + kOff;
        i = e + 1;
        continue;
      }
    }
    if (c == '*' && i + 1 < s.size() && s[i + 1] == '*') {
      size_t e = s.find("**", i + 2);
      if (e != std::string_view::npos) {
        o += kBold + inlineTerminal(s.substr(i + 2, e - i - 2)) + kOff;
        i = e + 2;
        continue;
      }
    }
    if (c == '*' && i + 1 < s.size() && s[i + 1] != ' ') {
      size_t e = s.find('*', i + 1);
      if (e != std::string_view::npos && e > i + 1) {
        o += kItalic + inlineTerminal(s.substr(i + 1, e - i - 1)) + kOff;
        i = e + 1;
        continue;
      }
    }
    if (c == '[') {
      size_t close = s.find("](", i);
      size_t end = close == std::string_view::npos ? close : s.find(')', close + 2);
      size_t inner = s.find('[', i + 1);
      if (end != std::string_view::npos && (inner == std::string_view::npos || inner > close)) {
        o += inlineTerminal(s.substr(i + 1, close - i - 1)) + " (" +
             std::string(s.substr(close + 2, end - close - 2)) + ")";
        i = end + 1;
        continue;
      }
    }
    o += c;
    ++i;
  }
  return o;
}

// Columns a string takes on a terminal: UTF-8 code points, ANSI codes skipped.
size_t columns(const std::string& s) {
  size_t n = 0;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\x1b') {
      while (i < s.size() && s[i] != 'm') ++i;
      continue;
    }
    if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80) ++n;
  }
  return n;
}

}  // namespace

std::string markdownToTerminal(std::string_view md) {
  std::vector<std::string> lines;
  {
    std::istringstream in{std::string(md)};
    std::string l;
    while (std::getline(in, l)) {
      if (!l.empty() && l.back() == '\r') l.pop_back();
      lines.push_back(l);
    }
  }
  std::string o;
  size_t i = 0;
  while (i < lines.size()) {
    std::string t = trim(lines[i]);
    if (t.rfind("```", 0) == 0) {
      ++i;
      while (i < lines.size() && trim(lines[i]).rfind("```", 0) != 0) {
        o += std::string("    ") + kDim + lines[i] + kOff + "\n";
        ++i;
      }
      ++i;
      continue;
    }
    if (isTableRow(t) && i + 1 < lines.size() && isTableRule(lines[i + 1])) {
      std::vector<std::vector<std::string>> rows;
      rows.push_back(cells(t));
      i += 2;
      while (i < lines.size() && isTableRow(lines[i])) rows.push_back(cells(lines[i++]));
      std::vector<size_t> width;
      for (auto& r : rows)
        for (size_t c = 0; c < r.size(); ++c) {
          r[c] = inlineTerminal(r[c]);
          if (width.size() <= c) width.push_back(0);
          width[c] = std::max(width[c], columns(r[c]));
        }
      for (size_t r = 0; r < rows.size(); ++r) {
        std::string row = "  ";
        for (size_t c = 0; c < rows[r].size(); ++c) {
          std::string cell = rows[r][c];
          if (c + 1 < rows[r].size()) cell += std::string(width[c] - columns(cell) + 2, ' ');
          row += r == 0 ? kBold + cell + kOff : cell;
        }
        o += row + "\n";
      }
      continue;
    }
    if (!t.empty() && t[0] == '#') {
      size_t n = t.find_first_not_of('#');
      if (n != std::string::npos && t[n] == ' ') {
        o += kBold + inlineTerminal(trim(t.substr(n))) + kOff + "\n";
        ++i;
        continue;
      }
    }
    std::string rest;
    if (char k = listItem(t, rest)) {
      size_t indent = lines[i].find_first_not_of(' ');
      o += std::string(indent == std::string::npos ? 0 : indent, ' ') +
           (k == 'u' ? "• " : t.substr(0, t.find('.') + 2)) + inlineTerminal(rest) + "\n";
      ++i;
      continue;
    }
    o += inlineTerminal(lines[i]) + "\n";
    ++i;
  }
  while (!o.empty() && o.back() == '\n') o.pop_back();
  return o;
}

}  // namespace ces::man
