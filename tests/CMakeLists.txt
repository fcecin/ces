find_package(Boost 1.83.0 REQUIRED COMPONENTS unit_test_framework filesystem)

# All tests in one binary (glob everything except benchmarks)
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "*.cpp")
list(FILTER TEST_SOURCES EXCLUDE REGEX "bench_.*\\.cpp$")

add_executable(cestests ${TEST_SOURCES})

target_link_libraries(cestests
  PRIVATE
    ceslib
    Boost::unit_test_framework
    Boost::filesystem
)

# E2E tests need the binaries they shell out to, plus the compute
# child stub (the handler fork+execs cescompmockd).
add_dependencies(cestests cesh cesproxy cescompmockd)
if(Qt6_FOUND)
  add_dependencies(cestests cesqt)
endif()

add_test(NAME CesTests COMMAND cestests)

# CesVM benchmark (standalone, not part of any test suite)
add_executable(cesvmbench bench_cesvm.cpp)
target_link_libraries(cesvmbench PRIVATE ceslib)
