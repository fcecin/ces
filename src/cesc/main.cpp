/**
 * cesc — CesVM toolchain CLI.
 *
 * Compiles cesl source (.cesl) or assembles casm text (.casm) into
 * CesVM bytecode. Language picked by input extension unless forced
 * with --lang. --boot enforces the 210-byte boot-block limit and pads
 * the output to exactly 210 bytes (the deployment shape for a single
 * asset content cell).
 */

#include <ces/alias.h>
#include <ces/asset.h>
#include <ces/lang/bundle.h>
#include <ces/lang/casm.h>
#include <ces/lang/cesl.h>
#include <ces/util/hex.h>

#include <CLI/CLI.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

int main(int argc, char** argv) {
  CLI::App app{"cesc - casm assembler / cesl compiler for CesVM"};

  std::string inPath;
  std::string outPath;
  std::string lang;
  std::string bundleDir;
  std::string salt;
  bool boot = false;
  bool alias = false;
  bool hex = false;

  app.add_option("input", inPath, "source file (.cesl or .casm)")
    ->required();
  app.add_option("-o,--output", outPath,
                 "output file (default: input with .bin extension)");
  app.add_option("--lang", lang, "force input language: cesl or casm")
    ->check(CLI::IsMember({"cesl", "casm"}));
  app.add_flag("--boot", boot,
               "enforce the 210-byte boot-block limit and pad to 210");
  auto* aliasFlag =
    app.add_flag("--alias", alias,
                 "enforce the alias inline-code limit and pad to the inline "
                 "code area (deploy with `cesh alias write` at the content "
                 "offset)");
  aliasFlag->excludes("--boot");
  app.add_flag("--hex", hex, "print hex to stdout instead of writing a file");
  app.add_option("--bundle", bundleDir,
                 "write a multi-asset bundle (boot + chunks + key tables + "
                 "manifest) to this directory")
    ->excludes("--boot")
    ->excludes("--alias")
    ->excludes("--hex")
    ->excludes("-o");
  app.add_option("--salt", salt,
                 "salt mixed into the bundle's deterministic asset keys");

  try {
    if (argc <= 1) throw CLI::CallForHelp();
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  }

  std::ifstream in(inPath, std::ios::binary);
  if (!in) {
    std::cerr << "cesc: cannot open " << inPath << "\n";
    return 1;
  }
  std::stringstream ss;
  ss << in.rdbuf();
  const std::string source = ss.str();

  if (lang.empty()) {
    const size_t dot = inPath.rfind('.');
    const std::string ext =
      dot == std::string::npos ? "" : inPath.substr(dot + 1);
    if (ext == "cesl") lang = "cesl";
    else if (ext == "casm") lang = "casm";
    else {
      std::cerr << "cesc: cannot infer language from '" << inPath
                << "'; pass --lang cesl|casm\n";
      return 1;
    }
  }

  auto compile = [&](uint64_t codeBase) {
    return (lang == "cesl") ? ces::ceslCompile(source, codeBase)
                            : ces::casmAssemble(source, codeBase);
  };

  ces::Bytes code;
  try {
    code = compile(0);
  } catch (const std::exception& e) {
    std::cerr << "cesc: " << inPath << ": " << e.what() << "\n";
    return 1;
  }

  if (!bundleDir.empty()) {
    namespace fs = std::filesystem;
    try {
      // The compiled length is base-independent, so the fits-one-block
      // decision made on the base-0 build is stable.
      if (code.size() > ces::AssetData{}.size()) {
        code = compile(210);
      }
      ces::CesBundle b = ces::bundleProgram(code, salt);
      fs::create_directories(bundleDir);
      auto writeBlock = [&](const std::string& name,
                            const ces::AssetData& block) {
        std::ofstream f(fs::path(bundleDir) / name,
                        std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("cannot write " + name);
        f.write(reinterpret_cast<const char*>(block.data()),
                static_cast<std::streamsize>(block.size()));
      };
      std::string manifest;
      manifest += "# cesc bundle for " + inPath + " (" +
                  std::to_string(code.size()) + " bytes, " +
                  std::to_string(b.chunks.size()) + " chunks, " +
                  std::to_string(b.tables.size()) + " tables)\n";
      manifest += "# create every chunk and table asset at its key "
                  "(CES_CREATE_ASSET), then the boot asset (any key) last\n";
      manifest += "# one-command deploy: "
                  "cesh asset deploy-bundle <name> <this dir> --days N\n";
      char name[32];
      for (size_t i = 0; i < b.chunks.size(); ++i) {
        std::snprintf(name, sizeof(name), "chunk_%02zu.bin", i);
        writeBlock(name, b.chunks[i]);
        manifest += "chunk " +
                    ces::bytesToHex({b.chunkKeys[i].data(), 32}) + " " +
                    name + "\n";
      }
      for (size_t i = 0; i < b.tables.size(); ++i) {
        std::snprintf(name, sizeof(name), "table_%02zu.bin", i);
        writeBlock(name, b.tables[i]);
        manifest += "table " +
                    ces::bytesToHex({b.tableKeys[i].data(), 32}) + " " +
                    name + (i == 0 ? " root\n" : "\n");
      }
      writeBlock("boot.bin", b.boot);
      manifest += "boot - boot.bin\n";
      std::ofstream mf(fs::path(bundleDir) / "manifest.txt",
                       std::ios::trunc);
      if (!mf) throw std::runtime_error("cannot write manifest.txt");
      mf << manifest;
      std::cout << "wrote bundle to " << bundleDir << " ("
                << code.size() << " bytes";
      if (b.chunks.empty()) {
        std::cout << ", boot block only)\n";
      } else {
        std::cout << ", " << b.chunks.size() << " chunks, "
                  << b.tables.size() << " tables)\n";
      }
      return 0;
    } catch (const std::exception& e) {
      std::cerr << "cesc: " << inPath << ": " << e.what() << "\n";
      return 1;
    }
  }

  const size_t rawSize = code.size();
  if (boot) {
    if (rawSize > ces::AssetData{}.size()) {
      std::cerr << "cesc: " << rawSize << " bytes exceeds the "
                << ces::AssetData{}.size() << "-byte boot block\n";
      return 1;
    }
    code.resize(ces::AssetData{}.size(), 0);
  }
  if (alias) {
    if (rawSize > ces::ALIAS_INLINE_CODE_BYTES) {
      std::cerr << "cesc: " << rawSize << " bytes exceeds the "
                << ces::ALIAS_INLINE_CODE_BYTES
                << "-byte alias inline code area\n";
      return 1;
    }
    code.resize(ces::ALIAS_INLINE_CODE_BYTES, 0);
  }

  if (hex) {
    std::cout << ces::bytesToHex({code.data(), code.size()}) << "\n";
    return 0;
  }

  if (outPath.empty()) {
    const size_t dot = inPath.rfind('.');
    outPath = (dot == std::string::npos ? inPath : inPath.substr(0, dot)) +
              ".bin";
  }
  std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
  if (!out) {
    std::cerr << "cesc: cannot write " << outPath << "\n";
    return 1;
  }
  out.write(reinterpret_cast<const char*>(code.data()),
            static_cast<std::streamsize>(code.size()));
  out.close();
  std::cout << "wrote " << outPath << " (" << rawSize << " bytes"
            << (boot ? ", padded to 210-byte boot block"
                : alias ? ", padded to the alias inline code area" : "")
            << ")\n";
  return 0;
}
