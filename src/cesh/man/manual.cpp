#include "man/manual.h"

#include "man/embedded.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <map>
#include <sstream>

namespace ces::man {

namespace {

std::string trim(std::string_view s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return std::string(s.substr(a, b - a));
}

std::string lower(std::string_view s) {
  std::string o(s);
  for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return o;
}

bool endsWith(std::string_view s, std::string_view t) {
  return s.size() >= t.size() && s.substr(s.size() - t.size()) == t;
}

// "files/rent" -> "files"; "files" -> ""; "" -> "".
std::string dirOf(std::string_view path) {
  auto slash = path.rfind('/');
  return slash == std::string_view::npos ? std::string() : std::string(path.substr(0, slash));
}

std::string lastPart(std::string_view path) {
  auto slash = path.rfind('/');
  return std::string(slash == std::string_view::npos ? path : path.substr(slash + 1));
}

// "files/rent.md" -> "files/rent"; "files/index.md" -> "files"; "index.md" -> "".
std::string pagePathOf(std::string_view file) {
  std::string p(file);
  if (endsWith(p, ".md")) p.resize(p.size() - 3);
  if (p == "index") return "";
  if (endsWith(p, "/index")) p.resize(p.size() - 6);
  return p;
}

// Collapse "." and ".." in a '/'-separated path. Returns false when ".."
// goes above the root.
bool normalizePath(std::string_view in, std::string& out) {
  std::vector<std::string> parts;
  size_t i = 0;
  while (i <= in.size()) {
    size_t j = in.find('/', i);
    if (j == std::string_view::npos) j = in.size();
    std::string part(in.substr(i, j - i));
    if (part == "..") {
      if (parts.empty()) return false;
      parts.pop_back();
    } else if (!part.empty() && part != ".") {
      parts.push_back(part);
    }
    i = j + 1;
  }
  out.clear();
  for (size_t k = 0; k < parts.size(); ++k) {
    if (k) out += '/';
    out += parts[k];
  }
  return true;
}

// Read the front matter into `p`. Returns false with `err` set when the
// block is missing or bad.
bool parseFrontMatter(const std::string& content, Page& p, std::string& err) {
  if (content.rfind("---\n", 0) != 0) {
    err = "no front matter (the file must start with ---)";
    return false;
  }
  size_t end = content.find("\n---", 3);
  if (end == std::string::npos) {
    err = "the front matter has no closing ---";
    return false;
  }
  std::istringstream in(content.substr(4, end - 3));
  std::string line;
  while (std::getline(in, line)) {
    if (trim(line).empty()) continue;
    auto colon = line.find(':');
    if (colon == std::string::npos) {
      err = "bad front matter line: " + line;
      return false;
    }
    std::string key = trim(std::string_view(line).substr(0, colon));
    std::string val = trim(std::string_view(line).substr(colon + 1));
    if (val.size() >= 2 && (val.front() == '"' || val.front() == '\'') &&
        val.back() == val.front())
      val = val.substr(1, val.size() - 2);
    if (key == "title") p.title = val;
    else if (key == "summary") p.summary = val;
    else if (key == "order") {
      try { p.order = std::stoi(val); } catch (...) {
        err = "order is not a number: " + val;
        return false;
      }
    }
  }
  size_t bodyStart = content.find('\n', end + 1);
  p.body = bodyStart == std::string::npos ? "" : content.substr(bodyStart + 1);
  while (!p.body.empty() && p.body.front() == '\n') p.body.erase(0, 1);
  return true;
}

// Call fn(textBegin, textEnd, target, linkBegin, linkEnd) for each markdown
// link [text](target) in `line`. Positions are in `line`.
template <class F>
void forEachLink(std::string_view line, F&& fn) {
  size_t i = 0;
  while ((i = line.find('[', i)) != std::string_view::npos) {
    size_t close = line.find("](", i);
    if (close == std::string_view::npos) return;
    size_t end = line.find(')', close + 2);
    if (end == std::string_view::npos) return;
    // A '[' inside the text means this is not one link; start again there.
    size_t inner = line.find('[', i + 1);
    if (inner != std::string_view::npos && inner < close) { i = inner; continue; }
    fn(i + 1, close, line.substr(close + 2, end - close - 2), i, end + 1);
    i = end + 1;
  }
}

bool isFence(std::string_view line) {
  return trim(line).rfind("```", 0) == 0;
}

}  // namespace

Manual::Manual(std::vector<Source> sources) {
  std::vector<Page> raw;
  for (auto& s : sources) {
    std::string content = s.content;
    content.erase(std::remove(content.begin(), content.end(), '\r'), content.end());
    Page p;
    p.file = s.file;
    p.path = pagePathOf(s.file);
    p.isIndex = s.file == "index.md" || endsWith(s.file, "/index.md");
    std::string err;
    if (!parseFrontMatter(content, p, err)) {
      problems_.push_back(s.file + ": " + err);
      p.body = content;
    }
    if (p.title.empty()) problems_.push_back(s.file + ": no title");
    if (p.summary.empty()) problems_.push_back(s.file + ": no summary");
    raw.push_back(std::move(p));
  }

  // A folder with pages but no index.md still gets a section, named after
  // the folder, so its pages have a place in the tree.
  std::map<std::string, bool> folders;
  for (auto& p : raw) {
    for (std::string up = dirOf(p.path); !up.empty(); up = dirOf(up))
      folders.emplace(up, false);
  }
  for (auto& p : raw)
    if (p.isIndex && !p.path.empty()) folders[p.path] = true;
  for (auto& [dir, has] : folders) {
    if (has) continue;
    problems_.push_back(dir + "/: no index.md");
    Page s;
    s.path = dir;
    s.file = dir + "/index.md";
    s.title = lastPart(dir);
    s.isIndex = true;
    s.order = 1000;
    raw.push_back(std::move(s));
  }

  // Sidebar order: the home page, then each folder's children by
  // (order, title), depth first.
  auto parentOf = [](const Page& p) { return dirOf(p.path); };
  std::function<void(const std::string&, int)> emit =
    [&](const std::string& folder, int depth) {
      std::vector<const Page*> kids;
      for (auto& p : raw)
        if (!p.path.empty() && parentOf(p) == folder) kids.push_back(&p);
      std::sort(kids.begin(), kids.end(), [](const Page* a, const Page* b) {
        if (a->order != b->order) return a->order < b->order;
        return a->title < b->title;
      });
      for (const Page* k : kids) {
        Page copy = *k;
        copy.depth = depth;
        pages_.push_back(std::move(copy));
        if (k->isIndex) emit(k->path, depth + 1);
      }
    };
  for (auto& p : raw)
    if (p.path.empty()) { pages_.push_back(p); break; }
  emit("", 0);

  // Every internal link must reach a page.
  for (auto& p : pages_) {
    std::istringstream in(p.body);
    std::string line;
    bool fence = false;
    while (std::getline(in, line)) {
      if (isFence(line)) { fence = !fence; continue; }
      if (fence) continue;
      forEachLink(line, [&](size_t, size_t, std::string_view target, size_t, size_t) {
        Link l = resolve(p, target);
        if (l.internal && !l.found)
          problems_.push_back(p.file + ": broken link " + std::string(target));
      });
    }
  }
}

const Manual& Manual::builtin() {
  static const Manual m = [] {
    std::vector<Source> s;
    for (size_t i = 0; i < kManualPageCount; ++i)
      s.push_back({kManualPages[i].file,
                   std::string(kManualPages[i].data, kManualPages[i].size)});
    return Manual(std::move(s));
  }();
  return m;
}

const Page* Manual::find(std::string_view name) const {
  auto c = candidates(name);
  return c.size() == 1 ? c.front() : nullptr;
}

std::vector<const Page*> Manual::candidates(std::string_view name) const {
  std::string n = trim(name);
  while (!n.empty() && n.front() == '/') n.erase(0, 1);
  while (!n.empty() && n.back() == '/') n.pop_back();
  if (endsWith(n, ".md")) n.resize(n.size() - 3);
  if (n == "index") n.clear();
  std::vector<const Page*> out;
  for (auto& p : pages_)
    if (p.path == n) return {&p};
  if (n.empty() || n.find('/') != std::string::npos) return out;
  for (auto& p : pages_)
    if (!p.path.empty() && lastPart(p.path) == n) out.push_back(&p);
  return out;
}

Link Manual::resolve(const Page& from, std::string_view target) const {
  Link l;
  std::string t = trim(target);
  if (t.empty() || t.front() == '#' || t.find("://") != std::string::npos ||
      t.rfind("mailto:", 0) == 0)
    return l;
  auto hash = t.find('#');
  if (hash != std::string::npos) t.resize(hash);
  l.internal = true;
  std::string base = dirOf(from.file);
  std::string joined = t.front() == '/' ? t.substr(1) : (base.empty() ? t : base + "/" + t);
  std::string norm;
  if (!normalizePath(joined, norm)) return l;
  // A link may name a file ("rent.md") or a page path ("files/rent").
  if (endsWith(norm, ".md")) norm.resize(norm.size() - 3);
  if (norm == "index") norm.clear();
  if (endsWith(norm, "/index")) norm.resize(norm.size() - 6);
  for (auto& p : pages_)
    if (p.path == norm) { l.found = true; l.path = norm; break; }
  return l;
}

std::vector<SearchHit> Manual::search(std::string_view word) const {
  std::vector<SearchHit> hits;
  std::string w = lower(trim(word));
  if (w.empty()) return hits;
  for (auto& p : pages_) {
    if (lower(p.title).find(w) != std::string::npos ||
        lower(p.summary).find(w) != std::string::npos)
      hits.push_back({&p, 0, p.title + ": " + p.summary});
    std::istringstream in(p.body);
    std::string line;
    int n = 0;
    while (std::getline(in, line)) {
      ++n;
      if (lower(line).find(w) != std::string::npos) hits.push_back({&p, n, trim(line)});
    }
  }
  return hits;
}

std::string Manual::index() const {
  std::string o;
  for (auto& p : pages_) {
    o.append(static_cast<size_t>(p.depth) * 2, ' ');
    o += p.path.empty() ? "index" : p.path;
    o += "  ";
    o += p.summary.empty() ? p.title : p.summary;
    o += '\n';
  }
  return o;
}

std::string renderText(const Manual& m, const Page& p, bool styled) {
  const char* bold = styled ? "\x1b[1m" : "";
  const char* dim = styled ? "\x1b[2m" : "";
  const char* off = styled ? "\x1b[0m" : "";
  std::string o;
  if (styled) {
    o += bold + p.title + off + "\n" + p.summary + "\n\n";
  } else {
    o += "# " + p.title + "\n\n> " + p.summary + "\n\n";
  }

  std::istringstream in(p.body);
  std::string line;
  bool fence = false;
  while (std::getline(in, line)) {
    if (isFence(line)) {
      fence = !fence;
      if (!styled) o += line + "\n";
      continue;
    }
    if (fence) {
      o += styled ? std::string("    ") + dim + line + off + "\n" : line + "\n";
      continue;
    }
    // Rewrite the links of the line.
    std::string out;
    size_t pos = 0;
    forEachLink(line, [&](size_t tb, size_t te, std::string_view target, size_t lb, size_t le) {
      out += line.substr(pos, lb - pos);
      std::string text = line.substr(tb, te - tb);
      Link l = m.resolve(p, target);
      std::string where = l.found ? (l.path.empty() ? "index" : l.path) : std::string(target);
      if (styled)
        out += text + " (" + (l.found ? "cesh man " : "") + where + ")";
      else
        out += "[" + text + "](" + where + ")";
      pos = le;
    });
    out += line.substr(pos);
    if (styled && out.rfind('#', 0) == 0) {
      size_t h = out.find_first_not_of('#');
      out = std::string(bold) + trim(std::string_view(out).substr(h == std::string::npos ? out.size() : h)) + off;
    }
    o += out + "\n";
  }
  return o;
}

}  // namespace ces::man
