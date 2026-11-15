#include "man/command.h"

#include "man/http.h"
#include "man/manual.h"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/signal_set.hpp>

#include <unistd.h>

#include <iostream>

using ces::man::Manual;
using ces::man::Page;

namespace {

std::string joined(const std::vector<std::string>& w, const char* sep) {
  std::string o;
  for (size_t i = 0; i < w.size(); ++i) {
    if (i) o += sep;
    o += w[i];
  }
  return o;
}

// The cesh subcommand named by `words` ("file", "put"), or null.
CLI::App* commandOf(CLI::App& app, const std::vector<std::string>& words) {
  CLI::App* c = &app;
  for (auto& w : words) {
    CLI::App* next = nullptr;
    for (auto* s : c->get_subcommands([](CLI::App*) { return true; }))
      if (s->get_name() == w) { next = s; break; }
    if (!next) return nullptr;
    c = next;
  }
  return c == &app ? nullptr : c;
}

}  // namespace

CLI::App* addManCommand(CLI::App& app, ManArgs& args) {
  auto* cmd = app.add_subcommand(
    "man", "The cesh manual");
  cmd->footer("Shows a page, the help of a command, the result of a search, or serves the "
              "manual to a web browser.");
  cmd->add_option("page", args.words,
                  "A page (files/rent, or rent) or a command (transfer, file put). "
                  "With nothing, list all pages.");
  cmd->add_option("-s,--search", args.search, "List the pages and lines that contain WORD");
  cmd->add_option("--serve", args.servePort,
                  "Serve the manual to a browser on this port (0 = any free port)")
    ->each([&](const std::string&) { args.serve = true; });
  cmd->add_option("--bind", args.bind, "Address for --serve (default 127.0.0.1)");
  return cmd;
}

int runMan(CLI::App& app, const ManArgs& args) {
  const Manual& m = Manual::builtin();
  const bool styled = ::isatty(STDOUT_FILENO) != 0;

  if (args.serve) {
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(args.bind, ec);
    if (ec) {
      std::cerr << "Error: bad --bind address " << args.bind << "\n";
      return 1;
    }
    boost::asio::io_context io;
    std::unique_ptr<ces::man::HttpServer> server;
    try {
      server = std::make_unique<ces::man::HttpServer>(
        io, m, boost::asio::ip::tcp::endpoint(addr, args.servePort));
    } catch (const std::exception& e) {
      std::cerr << "Error: cannot listen on " << args.bind << ":" << args.servePort
                << ": " << e.what() << "\n";
      return 1;
    }
    std::string host = addr.is_v6() ? "[" + args.bind + "]" : args.bind;
    std::cout << "Serving the cesh manual on http://" << host << ":" << server->port()
              << "/ (Ctrl-C to stop)" << std::endl;
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code&, int) {
      server->close();
      io.stop();
    });
    io.run();
    return 0;
  }

  if (!args.search.empty()) {
    auto hits = m.search(args.search);
    if (hits.empty()) {
      std::cerr << "No page has \"" << args.search << "\".\n";
      return 1;
    }
    for (auto& h : hits) {
      std::cout << (h.page->path.empty() ? "index" : h.page->path);
      if (h.line) std::cout << ":" << h.line;
      std::cout << ": " << h.text << "\n";
    }
    return 0;
  }

  if (args.words.empty()) {
    std::cout << m.index();
    return 0;
  }

  // A command prints its help, then the page of the same name, if any.
  CLI::App* cmd = commandOf(app, args.words);
  const Page* page = m.find(joined(args.words, "/"));
  if (cmd) {
    std::cout << cmd->help();
    if (page) std::cout << "\n" << ces::man::renderText(m, *page, styled);
    return 0;
  }
  if (page) {
    std::cout << ces::man::renderText(m, *page, styled);
    return 0;
  }
  auto choices = m.candidates(joined(args.words, "/"));
  if (choices.size() > 1) {
    std::cerr << "More than one page matches \"" << joined(args.words, " ") << "\":\n";
    for (auto* p : choices) std::cerr << "  " << p->path << "  " << p->summary << "\n";
    return 1;
  }
  std::cerr << "No page or command \"" << joined(args.words, " ")
            << "\". Try: cesh man --search " << args.words.back() << "\n";
  return 1;
}
