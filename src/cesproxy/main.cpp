/**
 * cesproxy — CES-aware TCP-to-UDP MINX proxy executable.
 */

#include <ces/cesproxy.h>
#include <ces/util/ctrlc.h>
#include <ces/util/resolver.h>

#include <CLI/CLI.hpp>

#include <iostream>
#include <string>

int main(int argc, char** argv) {
  CLI::App app{"cesproxy — CES-aware TCP-to-UDP MINX proxy"};

  std::string listenAddr = "0.0.0.0";
  uint16_t listenPort = 443;
  std::string upstreamAddr;
  uint16_t upstreamPort = 0;
  size_t channels = 8;
  size_t maxClients = 1000;
  size_t maxQueue = 0;

  app.add_option("upstream", upstreamAddr, "Upstream MINX/CES server address")
    ->required();
  app.add_option("port", upstreamPort, "Upstream server UDP port")->required();
  app.add_option("--listen,-l", listenAddr,
                 "TCP listen address (default: 0.0.0.0)");
  app.add_option("--listen-port,-p", listenPort,
                 "TCP listen port (default: 443)");
  app.add_option("--channels,-c", channels,
                 "Number of upstream ticket channels (default: 8)");
  app.add_option("--max-clients,-m", maxClients,
                 "Max simultaneous TCP connections (default: 1000)");
  app.add_option("--max-queue,-q", maxQueue,
                 "Max queued requests, 0=unlimited (default: 0)");

  CLI11_PARSE(app, argc, argv);

  auto listenEp = ces::Resolver::resolveTcp(listenAddr, listenPort);
  auto upstreamEp = ces::Resolver::resolveUdp(upstreamAddr, upstreamPort);

  minx::MinxProxyConfig config;
  config.numChannels = channels;
  config.maxClients = maxClients;
  config.maxQueueSize = maxQueue;

  CesProxy proxy(listenEp, upstreamEp, config);

  std::cout << "cesproxy listening on " << listenEp << " -> upstream "
            << upstreamEp << " (" << channels << " channels, max " << maxClients
            << " clients)\n";

  // Block until Ctrl+C
  while (ces::notInterrupted())
    ces::sleep(100);

  std::cout << "cesproxy stopping...\n";
  proxy.stop();

  return 0;
}
