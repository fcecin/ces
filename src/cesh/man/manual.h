// The cesh manual: a tree of markdown pages with front matter.
//
// Each page is one file. It starts with a front matter block:
//
//   ---
//   title: Rent and the file balance
//   summary: How a file pays rent from its own balance, ...
//   order: 2
//   ---
//
// The body follows, with no H1: the title is the H1. A folder is a section,
// and its index.md is the page of the section. The page path is the file path
// with no ".md": "files/rent.md" is "files/rent", "files/index.md" is "files",
// and the root "index.md" is "" (the home page).
//
// The same tree serves `cesh man` (terminal), `cesh man --serve` (HTML) and
// the index that `cesh chat` gives the model.

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ces::man {

struct Page {
  std::string path;      // "files/rent"; "files" for a folder index; "" = home
  std::string file;      // "files/rent.md"
  std::string title;
  std::string summary;
  int order = 0;
  int depth = 0;         // 0 for the home page and top-level pages and sections
  bool isIndex = false;  // the index.md of a folder (or the home page)
  std::string body;      // markdown after the front matter
};

// A link in a page body. `internal` is true for a link to a page of the
// manual (a relative path, with or without ".md"). Then `found` says if the
// page exists and `path` is its page path.
struct Link {
  bool internal = false;
  bool found = false;
  std::string path;
};

struct SearchHit {
  const Page* page = nullptr;
  int line = 0;          // 1-based line of the body; 0 = the title or summary
  std::string text;
};

class Manual {
public:
  struct Source {
    std::string file;      // relative path, "files/rent.md"
    std::string content;
  };

  explicit Manual(std::vector<Source> sources);

  // The manual that the build compiled into the binary.
  static const Manual& builtin();

  // All pages in sidebar order: the home page, then each section, depth
  // first, by (order, title).
  const std::vector<Page>& pages() const { return pages_; }

  // A page by its path ("files/rent", "/files/rent", "files/rent.md"), or by
  // its last part ("rent") when only one page has that last part. Null when
  // there is no page, or more than one page has that last part.
  const Page* find(std::string_view name) const;

  // The pages whose path or last part matches `name` (for an error that
  // lists the choices).
  std::vector<const Page*> candidates(std::string_view name) const;

  // Resolve a link target of a page body.
  Link resolve(const Page& from, std::string_view target) const;

  // Case-insensitive search of the titles, summaries and bodies.
  std::vector<SearchHit> search(std::string_view word) const;

  // One line for each page: indent by depth, path, summary.
  std::string index() const;

  // Faults of the tree: a page with no title or no summary, a broken
  // internal link, a bad front matter. Empty when the manual is sound.
  std::vector<std::string> problems() const { return problems_; }

private:
  std::vector<Page> pages_;
  std::vector<std::string> problems_;
};

// The page as text for a terminal. With `styled`, headings are bold and
// internal links show as "text (cesh man <path>)". Without it, the output is
// markdown: "# Title", the summary as a quote, and the body with internal
// links changed to page paths.
std::string renderText(const Manual& m, const Page& p, bool styled);

}  // namespace ces::man
