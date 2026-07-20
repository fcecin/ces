cmake_minimum_required(VERSION 3.28)

project(ces)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# -----------------------------------------------------------------------------
# 1. EXPLICIT COMPILER CONFIGURATION
# -----------------------------------------------------------------------------

# Apply hardware optimizations globally to all C and C++ targets
set(CES_MARCH "x86-64-v3" CACHE STRING "Target -march; 'native' = local-only")
add_compile_options(-march=${CES_MARCH})

# Force -O3 for pure Release builds (Overrides secp256k1's -O2 fallback)
add_compile_options("$<$<CONFIG:Release>:-O3>")
add_compile_options("$<$<CONFIG:Release>:-DNDEBUG>")

# For profiling builds, cleanly enforce -O3 and keep the frame pointer
add_compile_options("$<$<CONFIG:RelWithDebInfo>:-O3>")
add_compile_options("$<$<CONFIG:RelWithDebInfo>:-DNDEBUG>")
add_compile_options("$<$<CONFIG:RelWithDebInfo>:-g>")
add_compile_options("$<$<CONFIG:RelWithDebInfo>:-fno-omit-frame-pointer>")

include(FetchContent)

# If no network connection, just use cached FetchContent deps
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

# -----------------------------------------------------------------------------
# 2. SYSTEM DEPENDENCIES
# -----------------------------------------------------------------------------

find_package(Threads)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.83.0 REQUIRED COMPONENTS system log log_setup stacktrace_addr2line)

# -----------------------------------------------------------------------------
# 3. FETCH CONTENT DEPENDENCIES
# -----------------------------------------------------------------------------

FetchContent_Declare(
  cryptopp-cmake
  GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
  GIT_TAG        master
)
set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "Disable building Crypto++ tests" FORCE)
FetchContent_MakeAvailable(cryptopp-cmake)

FetchContent_Declare(
    secp256k1
    GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
    GIT_TAG        v0.4.1 # Stable release with solid CMake support
)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "Disable secp256k1 tests" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "Disable secp256k1 exhaustive tests" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "Disable secp256k1 benchmarks" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "Disable secp256k1 examples" FORCE)
set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "Only build static library" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "Enable recovery module" FORCE)

FetchContent_MakeAvailable(secp256k1)

FetchContent_Declare(
    cli11_proj
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG        v2.6.1
)
FetchContent_MakeAvailable(cli11_proj)

FetchContent_Declare(
    minx
    GIT_REPOSITORY https://github.com/fcecin/minx.git
    GIT_TAG        main
)
set(MINX_BUILD_EXAMPLES OFF CACHE BOOL "Disable building MINX examples" FORCE)
FetchContent_MakeAvailable(minx)

FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG        v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

# mene: the admin-panel UI library. Its build exports mene::assets, a
# dependency-free static lib carrying the embedded Lua library and browser
# renderer (see <mene/assets.h>), so the Lua encoder and the JS renderer in
# one server binary cannot skew. Bump GIT_TAG to take a new mene. Local mene
# checkout for development: cmake -DFETCHCONTENT_SOURCE_DIR_MENE=/path/to/mene
FetchContent_Declare(
    mene
    GIT_REPOSITORY https://github.com/fcecin/mene.git
    GIT_TAG        1ad758ddd51587602fe145653a45c9d76d36b11a
    SOURCE_SUBDIR  cpp
)
FetchContent_MakeAvailable(mene)

# -----------------------------------------------------------------------------
# 4. EXTERNAL PROJECT DEPENDENCIES
# -----------------------------------------------------------------------------

include(ExternalProject)

set(LIBBACKTRACE_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libbacktrace_install)
set(LIBBACKTRACE_INCLUDE_DIR ${LIBBACKTRACE_PREFIX}/include)
set(LIBBACKTRACE_LIB ${LIBBACKTRACE_PREFIX}/lib/libbacktrace.a)

ExternalProject_Add(libbacktrace_ext
    GIT_REPOSITORY    https://github.com/ianlancetaylor/libbacktrace.git
    GIT_TAG           master
    PREFIX            ${LIBBACKTRACE_PREFIX}
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=${LIBBACKTRACE_PREFIX} --enable-shared=OFF --enable-static=ON --with-pic
    BUILD_COMMAND     make
    INSTALL_COMMAND   make install
    UPDATE_COMMAND    ""
    LOG_DOWNLOAD ON LOG_CONFIGURE ON LOG_BUILD ON
)

file(MAKE_DIRECTORY ${LIBBACKTRACE_INCLUDE_DIR})

add_library(libbacktrace STATIC IMPORTED GLOBAL)
add_dependencies(libbacktrace libbacktrace_ext)
set_target_properties(libbacktrace PROPERTIES
    IMPORTED_LOCATION "${LIBBACKTRACE_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBBACKTRACE_INCLUDE_DIR}"
)

# -----------------------------------------------------------------------------
# 5. TARGETS
# -----------------------------------------------------------------------------

# Recursive so ceslib's source tree mirrors the include tree: every
# include/ces/<group>/<name>.h has its src/ceslib/<group>/<name>.cpp.
file(GLOB_RECURSE CESLIB_SOURCES "src/ceslib/*.cpp")
add_library(ceslib STATIC ${CESLIB_SOURCES})

target_compile_definitions(ceslib PUBLIC BOOST_ASIO_HEADER_ONLY BOOST_STACKTRACE_USE_BACKTRACE)

target_compile_options(ceslib PRIVATE -Wall -Wextra -Wpedantic)

target_include_directories(ceslib
PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${Boost_INCLUDE_DIRS}
  ${logkv_SOURCE_DIR}/include
)

target_link_libraries(ceslib
PUBLIC
  ${Boost_LIBRARIES}
  Boost::stacktrace_addr2line
  cryptopp::cryptopp
  secp256k1
  minxlib
  mene::assets
  Threads::Threads
  libbacktrace
  ${CMAKE_DL_LIBS}
  tomlplusplus::tomlplusplus
)

execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)
execute_process(
  COMMAND bash -c "date -u -d \"$(git log -1 --format=%ci)\" '+%Y-%m-%d %H:%M:%S UTC'"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_DATE
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)
if(NOT GIT_COMMIT_HASH)
  set(GIT_COMMIT_HASH "unknown")
endif()
if(NOT GIT_COMMIT_DATE)
  set(GIT_COMMIT_DATE "unknown")
endif()

file(GLOB CES_CPP "src/ces/*.cpp")
add_executable(ces ${CES_CPP})
target_link_libraries(ces PRIVATE ceslib CLI11::CLI11)
target_link_options(ces PRIVATE "-Wl,-z,noexecstack")
target_compile_definitions(ces PRIVATE CES_GIT_HASH="${GIT_COMMIT_HASH}")
set_target_properties(ces PROPERTIES OUTPUT_NAME "ces")

file(GLOB CESH_CPP "src/cesh/*.cpp")
add_executable(cesh ${CESH_CPP})
target_link_libraries(cesh PRIVATE ceslib CLI11::CLI11)
target_link_options(cesh PRIVATE "-Wl,-z,noexecstack")
target_compile_definitions(cesh PRIVATE CES_GIT_HASH="${GIT_COMMIT_HASH}")
set_target_properties(cesh PROPERTIES OUTPUT_NAME "cesh")

file(GLOB CESBENCH_CPP "src/cesbench/*.cpp")
add_executable(cesbench ${CESBENCH_CPP})
target_link_libraries(cesbench PRIVATE ceslib CLI11::CLI11)
target_link_options(cesbench PRIVATE "-Wl,-z,noexecstack")
set_target_properties(cesbench PROPERTIES OUTPUT_NAME "cesbench")

file(GLOB CESVMBENCH_CPP "src/cesvmbench/*.cpp")
add_executable(cesvmbench ${CESVMBENCH_CPP})
target_link_libraries(cesvmbench PRIVATE ceslib)
target_link_options(cesvmbench PRIVATE "-Wl,-z,noexecstack")
set_target_properties(cesvmbench PROPERTIES OUTPUT_NAME "cesvmbench")

add_executable(cesproxy src/cesproxy/main.cpp)
target_link_libraries(cesproxy PRIVATE ceslib CLI11::CLI11)
target_link_options(cesproxy PRIVATE "-Wl,-z,noexecstack")
set_target_properties(cesproxy PROPERTIES OUTPUT_NAME "cesproxy")

add_executable(cesc src/cesc/main.cpp)
target_link_libraries(cesc PRIVATE ceslib CLI11::CLI11)
target_link_options(cesc PRIVATE "-Wl,-z,noexecstack")
set_target_properties(cesc PROPERTIES OUTPUT_NAME "cesc")

add_executable(cescompmockd src/cescompmockd/main.cpp)
target_link_options(cescompmockd PRIVATE "-Wl,-z,noexecstack")
set_target_properties(cescompmockd PROPERTIES OUTPUT_NAME "cescompmockd")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LUAJIT REQUIRED luajit)
add_executable(cesluajitd
  src/cesluajitd/main.cpp
  src/cesluajitd/sha256.cpp
)
target_include_directories(cesluajitd PRIVATE ${LUAJIT_INCLUDE_DIRS})
target_link_libraries(cesluajitd PRIVATE ${LUAJIT_LIBRARIES} ceslib)
target_link_directories(cesluajitd PRIVATE ${LUAJIT_LIBRARY_DIRS})
target_link_options(cesluajitd PRIVATE "-Wl,-z,noexecstack")
set_target_properties(cesluajitd PROPERTIES OUTPUT_NAME "cesluajitd")

# -----------------------------------------------------------------------------
# 6. OPTIONAL: the hyle consensus engine (core + services) for cesluajitd
# -----------------------------------------------------------------------------
# Enabled by build.sh --hyle (-DCES_HYLE=ON). Fetches hyle from GitHub like every
# other dep (no local paths). hyle transitively pulls malachite-cpp (its Rust core,
# via corrosion) and builds hyle (core) + hyle_services (the node facilities: kv +
# the a/e economy + mempool + the consensus-drive runtime; embedded, it builds the
# libs only, not morphe's CLI or tests). cesluajitd links hyle_services (which
# PUBLIC-links core), so the C++ side can drive a blockchain node over its own
# transport. Wired now; unused (no #include) until cesluajitd starts using it.
option(CES_HYLE "Fetch + link the hyle consensus engine (core + services) into cesluajitd" OFF)
if(CES_HYLE)
  FetchContent_Declare(
    hyle
    GIT_REPOSITORY https://github.com/fcecin/hyle.git
    GIT_TAG        f3092352f17f9702a7a56f12b90d3ebf0de34e92
  )
  FetchContent_MakeAvailable(hyle)
  target_link_libraries(cesluajitd PRIVATE hyle_services)
  target_compile_definitions(cesluajitd PRIVATE CES_HYLE=1)
  # cesh links it too, for the client-side hyle verbs (build + sign ops, speak a
  # chain's line protocol). Linked to the cesh target only, never ceslib: the CES
  # client engine stays hyle-free; all hyle knowledge rides in the shell.
  target_link_libraries(cesh PRIVATE hyle_services)
  target_compile_definitions(cesh PRIVATE CES_HYLE=1)
  message(STATUS "CES_HYLE ON: cesluajitd + cesh link hyle_services (+ core) from github.com/fcecin/hyle")
endif()

# Outbound mail: builtin:mail + the SMTP/TLS client. Off by default; build.sh
# --mail. Needs system OpenSSL.
option(CES_MAIL "Enable outbound mail (builtin:mail + SMTP with TLS)" OFF)
if(CES_MAIL)
  find_package(OpenSSL REQUIRED)
  target_link_libraries(ceslib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(ceslib PUBLIC CES_MAIL=1)
  target_compile_definitions(cesluajitd PRIVATE CES_MAIL=1)
  message(STATUS "CES_MAIL ON: builtin:mail + SMTP/TLS (OpenSSL)")
endif()

include(${CMAKE_CURRENT_LIST_DIR}/cmake/QtDiscovery.cmake)
find_package(Qt6 QUIET COMPONENTS Widgets Network)
if(Qt6_FOUND)
  set(CMAKE_AUTOMOC ON)
  add_executable(cesqt
    src/cesqt/main.cpp
    src/cesqt/rpcserver.cpp
    src/cesqt/rpcserver.h
    src/cesqt/console.h
    src/cesqt/about.h
    src/cesqt/appmodel.h)
  target_link_libraries(cesqt PRIVATE ceslib Qt6::Widgets Qt6::Network)
  target_compile_definitions(cesqt PRIVATE
    CES_GIT_HASH="${GIT_COMMIT_HASH}"
    CES_GIT_DATE="${GIT_COMMIT_DATE}"
    CES_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
    CES_COMPILER="${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
  set_target_properties(cesqt PROPERTIES OUTPUT_NAME "cesqt")
  message(STATUS "Qt6 found — cesqt will be built")
else()
  message(STATUS "Qt6 not found — cesqt will not be built")
endif()

option(CES_BUILD_TESTS "Build unit tests" ON)
if(CES_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()