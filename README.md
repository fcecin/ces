# ces

__NOTE: This is experimental software.__

A public token system for public computing systems, written in C++.

## Server

There should be a public CES server running at `ces.pubcom.org:53830`:

```
$ ./cesh --server ces.pubcom.org:53830 ping
status=ok
```

If the server isn't working, please file an issue in this repository.

## Rationale

CES implements the simplest resource accounting system that could possibly work in the open internet. It is a public computing service that supplies other public computing services with the basic means to bootstrap their resource accounting.

CES is a client-server system, and each CES server is responsible for maintaining its own token ledger. Anybody can run a CES server, and all CES clients can choose which CES servers to use.

Servers can peer with each other for inter-server token transfers via bilateral settlement.

On top of the token economy, the CES system implements fully-featured compute, storage, and networking services for users and applications. Detailed documentation on all features is pending at the moment.

A definition of public computing, and more on the rationale behind the design of CES can be found at the https://pubcom.org website.

## Components

* `ces` is the server.
* `cesh` is the command-line client.
* `cesqt` is a graphical client (Qt6, cross-platform).
* `cesproxy` is a TCP-to-UDP proxy for firewalled clients.
* `cesbench` is a benchmark tool.
* `cesnet` / `cesnetbot` are network simulation and testing tools.
* `cesweb` is an HTTP gateway that serves a server's files to ordinary browsers (plus a `/dev` terminal to interact with L2 programs).

## Numbers

### Transactions per second (TPS)

The TPS numbers are obtained with `cesbench`, an end-to-end benchmarking tool that does simple token transfers between the full client and server stack on the same machine.

ThinkPad P16v Gen2 laptop: ~90,000 TPS.

### Memory use

Each account entry consumes 64 bytes of RAM. Each asset entry consumes 256 bytes of RAM. The core data structures use Boost unordered flat map with the default load factor.

## Building

Requires: C++20 compiler, CMake 3.28+, Boost 1.83+ (system, log, log_setup, stacktrace_addr2line). Qt6 is optional (for `cesqt`). All other dependencies are pulled in by CMake.

```bash
./build.sh debug            # Debug build
./build.sh release          # Optimized build
./build.sh debug --test     # Build and run tests
```

## Running a server

```bash
./run ces --genkeypair
# Copy the private key into your config file

./run ces --config production.toml
```

See `production.toml` for recommended settings, or `ces --config` (no argument) to dump the default config with all options.

## Using the shell client

```bash
./run cesh --server myserver:53830 query <pubkey>
./run cesh --server myserver:53830 -a @0 mine
./run cesh --server myserver:53830 -a @0 transfer <dest> 1000 --open
```

## Network simulator

```bash
./cesnet init 3         # Create 3 peered servers in ./mynet
./cesnet up             # Launch them
./cesnet cesh --server 127.0.0.1:54000 query @0
./cesnetbot run --users 10 --rounds 5
./cesnet destroy        # Clean up
```

Run `./cesnet` or `./cesnetbot` with no arguments for full usage.

## Portability

The `ces` stack is written primarily on and tested on Linux.

The graphical client (`cesqt`) is written using Qt and should work on Windows, Mac and Linux.

All portability-related contributions are welcome.

## Versioning

There is no release process. Each commit to the main branch has its own implicit version which is the git commit hash.

## Contributing

This project is fork-friendly. Anyone can fork and do whatever they want with it, e.g. create proper versioning, distros, etc.

All contributions welcome, especially bug fixes, documentation, and other clear improvements. I don't know when I will have the time to evaluate them, but I'll do my best.

## Documentation

There's an AI-generated `CLAUDE.md` dump with a good amount of technical details, but accuracy is not guaranteed. Proper documentation is pending.

## AI status note

A *lot* of the code at the tail end of the project was generated with assistance from Claude Opus 4.6/4.7 Extended/1M. I haven't caught up with all reviews yet. Once I can afford to actually review everything, I'll update this note.

## License

[Unlicense](https://unlicense.org/) (public domain)
