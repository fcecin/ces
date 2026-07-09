find_package(Boost 1.83.0 REQUIRED COMPONENTS unit_test_framework filesystem)

# All tests in one binary
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "*.cpp")

add_executable(cestests ${TEST_SOURCES})

target_link_libraries(cestests
  PRIVATE
    ceslib
    Boost::unit_test_framework
    Boost::filesystem
)

# Repo root, so tests can read in-tree source assets (e.g. the shipped
# /s/dice.lua under extensions/) instead of hardcoding a path
# relative to the build dir.
target_compile_definitions(cestests PRIVATE CES_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

# E2E tests need the binaries they shell out to, plus the compute
# child stub (the handler fork+execs cescompmockd).
add_dependencies(cestests cesh cesc cesproxy cescompmockd cesluajitd)
if(Qt6_FOUND)
  add_dependencies(cestests cesqt)
endif()

add_test(NAME CesTests COMMAND cestests)
