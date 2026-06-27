#!/bin/bash

# Stop the script if any command fails
set -e

print_help() {
    echo "Builds the project, runs tests, or cleans build files."
    echo ""
    echo "Usage: $0 [target] [options] | [command]"
    echo ""
    echo "Targets (defaults to 'debug' if unspecified but flags are present):"
    echo "  debug           Builds with debug information, no optimizations."
    echo "  release         Builds for production (optimized, no debug info)."
    echo "  relwithdebinfo  Builds an optimized build with debug info."
    echo "  minsizerel      Builds the smallest possible release."
    echo ""
    echo "Options:"
    echo "  --native        Build for the build host's exact CPU (-march=native)."
    echo "                  Faster but NOT portable -- local dev/bench only."
    echo "                  Default is -march=x86-64-v3 (portable, shippable)."
    echo "  --asan          Enables AddressSanitizer."
    echo "  --test [FILTER] Runs tests after building. Optional Boost.Test filter."
    echo "                  Examples:"
    echo "                    --test                Run all tests"
    echo "                    --test CesVMTests     Run one suite"
    echo "                    --test FileStore*     Run by wildcard"
    echo "                    --test */PutGetSmall  Run one test case"
    echo "  --clean         Cleans the target before building."
    echo "  --rm            Deletes 'build/' dir before building."
    echo "  --help, -h      Print help and exit."
    echo ""
    echo "Commands:"
    echo "  clean           Cleans ALL targets."
    echo "  rm              Deletes 'build/' dir."
    echo ""
    echo "Examples:"
    echo "  $0 --test --asan       Build debug with ASan and run all tests"
    echo "  $0 --test CesVMTests   Build debug and run only CesVM tests"
    echo "  $0 release --clean     Rebuild (Clean + Build) release"
    echo "  $0 rm                  Wipe all builds"
}

deep_clean_project() {
    echo "Deleting all builds..."
    rm -rf build
    echo "Done."
}

soft_clean_project() {
    echo "Cleaning all targets..."
    for dir in build/*/; do
        if [ -d "$dir" ]; then
            echo "  cmake --build $dir --target clean"
            cmake --build "$dir" --target clean 2>/dev/null || true
        fi
    done
}

clean_one_target() {
    local BUILD_TYPE_LOWER="$1"
    local BUILD_DIR="build/${BUILD_TYPE_LOWER}"
    if [ -d "$BUILD_DIR" ]; then
        echo "Cleaning ${BUILD_TYPE_LOWER}..."
        cmake --build "$BUILD_DIR" --target clean 2>/dev/null || true
    fi
}

build_one_config() {
    local BUILD_TYPE_LOWER="$1"
    local BUILD_TYPE_CAMEL="$2"
    local BUILD_DIR="build/${BUILD_TYPE_LOWER}"
    local EXTRA_ARGS=""

    if [ "$ENABLE_ASAN" = true ]; then
        EXTRA_ARGS="-DCMAKE_CXX_FLAGS=-fsanitize=address -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address"
    fi

    # Portable -march by default; --native pins to the build host.
    local MARCH="x86-64-v3"
    [ "$ENABLE_NATIVE" = true ] && MARCH="native"

    # Always reconfigure: the git hash baked into the version stamp is
    # captured at configure time (CMakeLists.txt, git rev-parse HEAD), so
    # skipping configure on an existing build dir leaves the stamp stale.
    echo "Configuring ${BUILD_TYPE_CAMEL} build (-march=${MARCH})..."
    cmake -S . -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE_CAMEL}" \
        -DCES_MARCH="${MARCH}" \
        $EXTRA_ARGS

    echo "Building ${BUILD_TYPE_CAMEL}..."
    cmake --build "$BUILD_DIR" --parallel "$(nproc)"
    echo "✅ ${BUILD_TYPE_CAMEL} build complete."
}

TARGET="debug"
CAMEL_TARGET="Debug"
ACTION="build"
RUN_TESTS=false
TEST_FILTER=""
DO_CLEAN=false
ENABLE_ASAN=false
ENABLE_NATIVE=false
DO_DEEP_CLEAN=false

# Parse arguments — --test may optionally consume the next arg as a filter
ARGS=("$@")
i=0
while [ $i -lt ${#ARGS[@]} ]; do
    arg="${ARGS[$i]}"
    LOWER_ARG=$(echo "$arg" | tr '[:upper:]' '[:lower:]')

    case "$LOWER_ARG" in
        --help|-h)
            print_help
            exit 0
            ;;
        --test)
            RUN_TESTS=true
            # Check if next arg is a filter (not another flag, not a target)
            next_i=$((i + 1))
            if [ $next_i -lt ${#ARGS[@]} ]; then
                next="${ARGS[$next_i]}"
                case "$next" in
                    --*|debug|release|relwithdebinfo|minsizerel|clean|rm)
                        ;; # not a filter
                    *)
                        TEST_FILTER="$next"
                        i=$next_i
                        ;;
                esac
            fi
            ;;
        --clean)
            DO_CLEAN=true
            ;;
        --native)
            ENABLE_NATIVE=true
            ;;
        --asan)
            ENABLE_ASAN=true
            ;;
        --rm)
            DO_DEEP_CLEAN=true
            ;;
        clean)
            ACTION="soft_clean_all"
            ;;
        rm)
            ACTION="deep_clean"
            ;;
        release)
            TARGET="release"
            CAMEL_TARGET="Release"
            ;;
        relwithdebinfo)
            TARGET="relwithdebinfo"
            CAMEL_TARGET="RelWithDebInfo"
            ;;
        minsizerel)
            TARGET="minsizerel"
            CAMEL_TARGET="MinSizeRel"
            ;;
        debug)
            TARGET="debug"
            CAMEL_TARGET="Debug"
            ;;
        *)
            echo "❌ Error: Invalid argument '$arg'." >&2
            exit 1
            ;;
    esac
    i=$((i + 1))
done

case "$ACTION" in
    deep_clean)
        deep_clean_project
        exit 0
        ;;
    soft_clean_all)
        soft_clean_project
        exit 0
        ;;
    build)
        if [ "$DO_DEEP_CLEAN" = true ]; then
            deep_clean_project
        fi

        if [ "$DO_CLEAN" = true ]; then
            clean_one_target "$TARGET"
        fi

        build_one_config "$TARGET" "$CAMEL_TARGET"

        if [ "$RUN_TESTS" = true ]; then
            BIN="build/${TARGET}/tests/cestests"
            if [ -f "$BIN" ] && [ -x "$BIN" ]; then
                # -l test_suite: per-suite progress during the run.
                # --report_level=short: a count summary (cases/assertions) at the end.
                BOOST_ARGS="-l test_suite --report_level=short"
                LABEL="All Tests"
                if [ -n "$TEST_FILTER" ]; then
                    BOOST_ARGS="$BOOST_ARGS --run_test=$TEST_FILTER"
                    LABEL="Tests ($TEST_FILTER)"
                fi
                echo "--- Running $LABEL ---"
                # Per-run log file so concurrent build.sh --test invocations
                # don't clobber each other's output/tally.
                logf=$(mktemp "${TMPDIR:-/tmp}/cestests.XXXXXX.log")
                set +e
                "$BIN" $BOOST_ARGS 2>&1 | tee "$logf"
                rc=${PIPESTATUS[0]}
                set -e
                # Build a one-line tally from the Boost short report. Never drive
                # by the exit code alone (a wrapping command can mask it).
                cases=$(grep -aoE '[0-9]+ test cases? out of [0-9]+ (passed|failed)' "$logf" | tail -1)
                skipped=$(grep -aoE '[0-9]+ test cases? out of [0-9]+ skipped' "$logf" | tail -1)
                asserts=$(grep -aoE '[0-9]+ assertions? out of [0-9]+ (passed|failed)' "$logf" | tail -1)
                summary="$cases"
                [ -n "$skipped" ] && summary="$summary, $skipped"
                [ -n "$asserts" ] && summary="$summary; $asserts"
                failed=$(grep -aoE '\*\*\* [0-9]+ failures? (are|is) detected|has failed with' "$logf" | tail -1)
                if [ $rc -ne 0 ] || [ -n "$failed" ]; then
                    # Keep the log for inspection on failure; print its path.
                    echo "❌ $LABEL FAILED (exit code $rc) — ${summary:-see output above}"
                    echo "   log: $logf"
                    exit 1
                else
                    rm -f "$logf"
                    echo "✅ $LABEL passed — ${summary:-no tally}"
                fi
            else
                echo "⚠️  cestests not found: $BIN"
                exit 1
            fi
        fi
        ;;
esac

echo ""
echo "Done."
