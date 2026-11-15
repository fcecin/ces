// The cesh manual (src/cesh/man/, src/cesh/docs/): the page tree, lookup,
// links, search, text and HTML rendering, the HTTP server, and the `cesh man`
// command. `ManualBuiltinTests` checks that every page that ships in cesh is
// sound: each has a title and a summary, and each internal link reaches a page.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include "man/http.h"
#include "man/manual.h"
#include "man/markdown.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <thread>

using namespace ces::man;
namespace asio = boost::asio;

namespace {

std::string page(const std::string& title, const std::string& summary, int order,
                 const std::string& body) {
  return "---\ntitle: " + title + "\nsummary: " + summary + "\norder: " +
         std::to_string(order) + "\n---\n\n" + body;
}

Manual sample() {
  return Manual({
    {"index.md", page("Home", "The start", 0, "See [rent](files/rent.md).\n")},
    {"files/index.md", page("Files", "The file store", 2, "- [Rent](rent.md)\n")},
    {"files/rent.md", page("Rent", "How files pay", 2,
                           "Back to [files](index.md) and [keys](../keys.md).\n"
                           "## Rules\n\nThe Balance pays.\n")},
    {"files/zones.md", page("Zones", "Path zones", 1, "Text.\n")},
    {"keys.md", page("Keys", "The wallet", 1, "Visit [site](https://example.com).\n")},
  });
}

bool contains(const std::string& s, const std::string& t) {
  return s.find(t) != std::string::npos;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(ManualTests)

BOOST_AUTO_TEST_CASE(Parse_PathsTitlesAndSidebarOrder) {
  Manual m = sample();
  BOOST_CHECK(m.problems().empty());
  std::vector<std::string> paths;
  for (auto& p : m.pages()) paths.push_back(p.path);
  // Home first; then by order: keys (1), files (2) with zones (1), rent (2).
  std::vector<std::string> want = {"", "keys", "files", "files/zones", "files/rent"};
  BOOST_CHECK_EQUAL_COLLECTIONS(paths.begin(), paths.end(), want.begin(), want.end());
  const Page* rent = m.find("files/rent");
  BOOST_REQUIRE(rent);
  BOOST_CHECK_EQUAL(rent->title, "Rent");
  BOOST_CHECK_EQUAL(rent->summary, "How files pay");
  BOOST_CHECK_EQUAL(rent->depth, 1);
  BOOST_CHECK(rent->body.rfind("Back to", 0) == 0);
  BOOST_CHECK(m.find("files")->isIndex);
}

BOOST_AUTO_TEST_CASE(Find_ByPathLastPartAndForms) {
  Manual m = sample();
  BOOST_CHECK_EQUAL(m.find("rent")->path, "files/rent");
  BOOST_CHECK_EQUAL(m.find("/files/rent")->path, "files/rent");
  BOOST_CHECK_EQUAL(m.find("files/rent.md")->path, "files/rent");
  BOOST_CHECK_EQUAL(m.find("index")->path, "");
  BOOST_CHECK(m.find("nope") == nullptr);
  BOOST_CHECK(m.find("rent/x") == nullptr);
}

BOOST_AUTO_TEST_CASE(Find_AmbiguousLastPart_GivesCandidates) {
  Manual m({
    {"a/index.md", page("A", "a", 1, "")},
    {"a/x.md", page("AX", "a x", 1, "")},
    {"b/index.md", page("B", "b", 2, "")},
    {"b/x.md", page("BX", "b x", 1, "")},
  });
  BOOST_CHECK(m.find("x") == nullptr);
  BOOST_CHECK_EQUAL(m.candidates("x").size(), 2u);
  BOOST_CHECK_EQUAL(m.find("b/x")->title, "BX");
}

BOOST_AUTO_TEST_CASE(Resolve_RelativeExternalAndBroken) {
  Manual m = sample();
  const Page& rent = *m.find("files/rent");
  Link l = m.resolve(rent, "../keys.md");
  BOOST_CHECK(l.internal && l.found);
  BOOST_CHECK_EQUAL(l.path, "keys");
  l = m.resolve(rent, "index.md");
  BOOST_CHECK(l.found);
  BOOST_CHECK_EQUAL(l.path, "files");
  l = m.resolve(rent, "zones");
  BOOST_CHECK(l.found);
  BOOST_CHECK_EQUAL(l.path, "files/zones");
  l = m.resolve(rent, "https://example.com");
  BOOST_CHECK(!l.internal);
  l = m.resolve(rent, "../../x.md");
  BOOST_CHECK(l.internal && !l.found);
}

BOOST_AUTO_TEST_CASE(Problems_ListBadPages) {
  Manual m({
    {"index.md", "no front matter\n"},
    {"x.md", "---\ntitle: X\n---\nA [gone](gone.md) link.\n"},
    {"sub/y.md", page("Y", "y", 1, "")},
  });
  auto p = m.problems();
  auto has = [&](const std::string& t) {
    for (auto& s : p) if (contains(s, t)) return true;
    return false;
  };
  BOOST_CHECK(has("index.md: no front matter"));
  BOOST_CHECK(has("x.md: no summary"));
  BOOST_CHECK(has("x.md: broken link gone.md"));
  BOOST_CHECK(has("sub/: no index.md"));
  // The folder with no index still gets a section, so its page has a place.
  BOOST_REQUIRE(m.find("sub/y"));
  BOOST_CHECK_EQUAL(m.find("sub/y")->depth, 1);
}

BOOST_AUTO_TEST_CASE(Search_IsCaseInsensitive) {
  Manual m = sample();
  auto hits = m.search("BALANCE");
  BOOST_REQUIRE_EQUAL(hits.size(), 1u);
  BOOST_CHECK_EQUAL(hits[0].page->path, "files/rent");
  BOOST_CHECK_EQUAL(hits[0].line, 4);
  hits = m.search("wallet");
  BOOST_REQUIRE_EQUAL(hits.size(), 1u);
  BOOST_CHECK_EQUAL(hits[0].line, 0);   // the summary
  BOOST_CHECK(m.search("").empty());
}

BOOST_AUTO_TEST_CASE(Index_HasOneLinePerPage) {
  std::string idx = sample().index();
  BOOST_CHECK(contains(idx, "index  The start\n"));
  BOOST_CHECK(contains(idx, "  files/rent  How files pay\n"));
  BOOST_CHECK_EQUAL(std::count(idx.begin(), idx.end(), '\n'), 5);
}

BOOST_AUTO_TEST_CASE(RenderText_PlainAndStyled) {
  Manual m = sample();
  const Page& rent = *m.find("files/rent");
  std::string plain = renderText(m, rent, false);
  BOOST_CHECK(plain.rfind("# Rent\n\n> How files pay\n\n", 0) == 0);
  BOOST_CHECK(contains(plain, "[keys](keys)"));
  BOOST_CHECK(contains(plain, "[files](files)"));
  BOOST_CHECK(contains(plain, "## Rules"));
  std::string styled = renderText(m, rent, true);
  BOOST_CHECK(contains(styled, "keys (cesh man keys)"));
  BOOST_CHECK(contains(styled, "\x1b[1mRules\x1b[0m"));
  const Page& keys = *m.find("keys");
  BOOST_CHECK(contains(renderText(m, keys, true), "site (https://example.com)"));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MarkdownTests)

BOOST_AUTO_TEST_CASE(Blocks) {
  std::string h = markdownToHtml(
    "## Head\n\nOne line\nand two.\n\n- a\n- b\n  more\n\n1. x\n2. y\n\n"
    "```\nif (a < b) {}\n```\n\n| A | B |\n| --- | --- |\n| `x|y` | 2 |\n\n> quote\n\n---\n",
    nullptr);
  BOOST_CHECK(contains(h, "<h2>Head</h2>"));
  BOOST_CHECK(contains(h, "<p>One line and two.</p>"));
  BOOST_CHECK(contains(h, "<ul>\n<li>a</li>\n<li>b more</li>\n</ul>"));
  BOOST_CHECK(contains(h, "<ol>\n<li>x</li>\n<li>y</li>\n</ol>"));
  BOOST_CHECK(contains(h, "<pre><code>if (a &lt; b) {}\n</code></pre>"));
  BOOST_CHECK(contains(h, "<th>A</th><th>B</th>"));
  BOOST_CHECK(contains(h, "<td><code>x|y</code></td><td>2</td>"));
  BOOST_CHECK(contains(h, "<blockquote><p>quote</p></blockquote>"));
  BOOST_CHECK(contains(h, "<hr>"));
}

BOOST_AUTO_TEST_CASE(InlineAndEscaping) {
  LinkMap map = [](std::string_view t) { return "/x/" + std::string(t); };
  std::string h = markdownToHtml(
    "A `<b>` and **bold** and *it* and [go](p.md) <script>\"'&\n", map);
  BOOST_CHECK(contains(h, "<code>&lt;b&gt;</code>"));
  BOOST_CHECK(contains(h, "<strong>bold</strong>"));
  BOOST_CHECK(contains(h, "<em>it</em>"));
  BOOST_CHECK(contains(h, "<a href=\"/x/p.md\">go</a>"));
  BOOST_CHECK(contains(h, "&lt;script&gt;&quot;&#39;&amp;"));
  BOOST_CHECK(!contains(h, "<script>"));
}

BOOST_AUTO_TEST_CASE(Terminal_StylesAndAlignsTables) {
  std::string t = markdownToTerminal(
    "## Balances\n\nYou have **5** credits in `@1`, see [rent](files/rent).\n\n"
    "| Key | Credits |\n|---|---|\n| @0 | 1048.18 |\n| @1 | 5 |\n\n- one\n\n```\ncesh query @0\n```\n");
  BOOST_CHECK(contains(t, "\x1b[1mBalances\x1b[0m"));
  BOOST_CHECK(contains(t, "\x1b[1m5\x1b[0m credits in \x1b[36m@1\x1b[0m, see rent (files/rent)."));
  // The table: the header bold, the cells padded to one column width.
  BOOST_CHECK(contains(t, "  \x1b[1mKey  \x1b[0m\x1b[1mCredits\x1b[0m\n"));
  BOOST_CHECK(contains(t, "  @0   1048.18\n  @1   5\n"));
  BOOST_CHECK(contains(t, "• one"));
  BOOST_CHECK(contains(t, "    \x1b[2mcesh query @0\x1b[0m"));
  BOOST_CHECK(!contains(t, "|"));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ManualHttpTests)

BOOST_AUTO_TEST_CASE(Respond_Routes) {
  Manual m = sample();
  auto r = respond(m, "GET", "/");
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(contains(r.body, "<h1>Home</h1>"));
  r = respond(m, "GET", "/files/rent");
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(contains(r.body, "<h1>Rent</h1>"));
  BOOST_CHECK(contains(r.body, "<a href=\"/keys\">keys</a>"));
  BOOST_CHECK(contains(r.body, "<li class=\"here\""));
  BOOST_CHECK(!contains(r.body, "<script"));
  r = respond(m, "GET", "/nope");
  BOOST_CHECK_EQUAL(r.status, 404);
  r = respond(m, "POST", "/");
  BOOST_CHECK_EQUAL(r.status, 405);
  r = respond(m, "GET", "/search?q=balance");
  BOOST_CHECK_EQUAL(r.status, 200);
  BOOST_CHECK(contains(r.body, "href=\"/files/rent\""));
  BOOST_CHECK(contains(r.body, "files/rent:4"));
}

BOOST_AUTO_TEST_CASE(Respond_EscapesTheQuery) {
  auto r = respond(sample(), "GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
  BOOST_CHECK(!contains(r.body, "<script>alert"));
  BOOST_CHECK(contains(r.body, "&lt;script&gt;alert(1)"));
}

BOOST_AUTO_TEST_CASE(Server_AnswersGetAndClosesAnOversizedRequest) {
  Manual m = sample();
  asio::io_context io;
  HttpServer server(io, m, asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0));
  const uint16_t port = server.port();
  BOOST_REQUIRE(port != 0);
  std::thread t([&] { io.run(); });

  auto exchange = [&](const std::string& req) {
    asio::io_context cio;
    asio::ip::tcp::socket s(cio);
    s.connect(asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), port));
    // The server may close an oversized request while the client still
    // writes, so the write takes an error code instead of a throw.
    boost::system::error_code ec;
    asio::write(s, asio::buffer(req), ec);
    std::string out;
    std::array<char, 4096> buf;
    for (;;) {
      size_t n = s.read_some(asio::buffer(buf), ec);
      out.append(buf.data(), n);
      if (ec) break;
    }
    return out;
  };

  std::string got = exchange("GET /files/rent HTTP/1.1\r\nHost: x\r\n\r\n");
  BOOST_CHECK(got.rfind("HTTP/1.1 200 OK\r\n", 0) == 0);
  BOOST_CHECK(contains(got, "Content-Security-Policy: default-src 'none'"));
  BOOST_CHECK(contains(got, "<h1>Rent</h1>"));

  got = exchange("HEAD / HTTP/1.1\r\n\r\n");
  BOOST_CHECK(got.rfind("HTTP/1.1 200 OK\r\n", 0) == 0);
  BOOST_CHECK(!contains(got, "<html"));

  // 17 KB with no end of headers: the server closes with no reply.
  got = exchange("GET /" + std::string(17 * 1024, 'a'));
  BOOST_CHECK(got.empty());

  server.close();
  io.stop();
  t.join();
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ManualBuiltinTests)

BOOST_AUTO_TEST_CASE(EveryShippedPageIsSound) {
  const Manual& m = Manual::builtin();
  for (auto& p : m.problems()) BOOST_ERROR("manual: " << p);
  BOOST_REQUIRE(!m.pages().empty());
  BOOST_CHECK(m.pages().front().path.empty());   // the home page comes first
  for (auto& p : m.pages()) {
    BOOST_CHECK_MESSAGE(!p.title.empty(), p.file << " has no title");
    BOOST_CHECK_MESSAGE(!p.summary.empty(), p.file << " has no summary");
    BOOST_CHECK_MESSAGE(p.body.rfind("# ", 0) != 0,
                        p.file << " repeats the title as an H1");
  }
}

BOOST_AUTO_TEST_CASE(Cesh_ManCommand) {
  const std::string cesh = ces::e2e::findCeshBinary();
  auto r = ces::e2e::runShell(cesh + " man", 30);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK(contains(r.out, "files/rent  "));

  r = ces::e2e::runShell(cesh + " man rent", 30);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK(r.out.rfind("# Rent and the file balance\n", 0) == 0);   // piped: markdown

  // A command gives its help and then the page of the same name.
  r = ces::e2e::runShell(cesh + " man transfer", 30);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK(contains(r.out, "--open"));
  BOOST_CHECK(contains(r.out, "# Send credits"));

  r = ces::e2e::runShell(cesh + " man file put", 30);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK(contains(r.out, "--deposit"));

  r = ces::e2e::runShell(cesh + " man --search hold", 30);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK(contains(r.out, "think:"));

  r = ces::e2e::runShell(cesh + " man no-such-thing", 30);
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  BOOST_CHECK(contains(r.out, "No page or command"));
}

BOOST_AUTO_TEST_SUITE_END()
