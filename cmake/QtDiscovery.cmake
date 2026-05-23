# QtDiscovery.cmake — do everything we reasonably can to locate a Qt6
# install before the main CMakeLists.txt calls `find_package(Qt6 ...)`.
#
# Precedence (highest wins, each step is a no-op if the previous found a hit):
#
#   1. User override via -DQt6_DIR=... or -DCMAKE_PREFIX_PATH=...
#      (respected implicitly — we check Qt6_DIR first and bail out if set).
#   2. $ENV{Qt6_DIR} — honored by CMake natively, listed for completeness.
#   3. $ENV{QTDIR} / $ENV{QT_DIR} — common user convention (Qt4/5 legacy
#      but still widely respected in the wild).
#   4. `qmake6` / `qmake-qt6` / `qmake` on $PATH. Queried via
#      `qmake -query QT_INSTALL_PREFIX`, same technique KDE uses. Catches
#      system packages and locally-built Qt that the user has on $PATH.
#   5. Glob well-known Qt online-installer roots (`~/Qt/<ver>/<platform>/`,
#      `/opt/Qt/<ver>/<platform>/`). For each match we run the bundled
#      qmake and trust its reported prefix. We pick the highest-versioned
#      match so upgrades are picked up automatically.
#
# Only the final `find_package(Qt6 ...)` call in the main CMakeLists.txt
# decides whether we actually succeeded. This file is purely about stuffing
# good candidates into CMAKE_PREFIX_PATH so that call has a chance.
#
# All internal variables are namespaced `_qt_disc_*` and unset on exit so
# this file is safe to `include()` from the top-level scope.

if(DEFINED Qt6_DIR AND NOT Qt6_DIR STREQUAL "Qt6_DIR-NOTFOUND")
  message(STATUS "QtDiscovery: Qt6_DIR already set (${Qt6_DIR}); skipping")
  return()
endif()

# --- helper: given a qmake binary path, prepend its QT_INSTALL_PREFIX -------
function(_qt_disc_try_qmake qmake_path label)
  if(NOT EXISTS "${qmake_path}")
    return()
  endif()
  execute_process(
    COMMAND "${qmake_path}" -query QT_INSTALL_PREFIX
    OUTPUT_VARIABLE _prefix
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _rc
    ERROR_QUIET)
  if(_rc EQUAL 0 AND _prefix AND EXISTS "${_prefix}")
    message(STATUS "QtDiscovery: ${label} -> ${_prefix}")
    list(PREPEND CMAKE_PREFIX_PATH "${_prefix}")
    set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH}" PARENT_SCOPE)
  endif()
endfunction()

# --- 2 & 3: environment variables -------------------------------------------
foreach(_var Qt6_DIR QTDIR QT_DIR)
  if(DEFINED ENV{${_var}} AND NOT "$ENV{${_var}}" STREQUAL "")
    set(_path "$ENV{${_var}}")
    message(STATUS "QtDiscovery: env ${_var}=${_path}")
    list(PREPEND CMAKE_PREFIX_PATH "${_path}")
  endif()
endforeach()

# --- 4: qmake on $PATH ------------------------------------------------------
find_program(_qt_disc_qmake_path
  NAMES qmake6 qmake-qt6 qmake
  DOC "qmake binary used to locate Qt install prefix")
if(_qt_disc_qmake_path)
  _qt_disc_try_qmake("${_qt_disc_qmake_path}" "qmake on PATH")
endif()

# --- 5: glob well-known online-installer roots ------------------------------
# `~/Qt/<version>/<platform>/bin/qmake6` and friends. Version dirs sort
# lexically as MAJOR.MINOR.PATCH, which is monotonic enough for our purposes
# (6.10.2 > 6.9.5 > 6.6.0). Reverse the sort to prefer the newest.
set(_qt_disc_roots
  "$ENV{HOME}/Qt"
  "/opt/Qt"
)
set(_qt_disc_candidates)
foreach(_root IN LISTS _qt_disc_roots)
  if(EXISTS "${_root}")
    # Two-level glob: <root>/<version>/<platform>/bin/qmake*
    # Platform examples: gcc_64, macos, msvc2022_64, mingw_64.
    file(GLOB _matches
      "${_root}/*/*/bin/qmake6"
      "${_root}/*/*/bin/qmake")
    list(APPEND _qt_disc_candidates ${_matches})
  endif()
endforeach()
if(_qt_disc_candidates)
  list(REMOVE_DUPLICATES _qt_disc_candidates)
  # Sort lexically; reverse so the highest-versioned path comes first.
  list(SORT _qt_disc_candidates)
  list(REVERSE _qt_disc_candidates)
  list(GET _qt_disc_candidates 0 _qt_disc_best)
  _qt_disc_try_qmake("${_qt_disc_best}" "Qt online installer")
endif()

# --- cleanup ----------------------------------------------------------------
unset(_qt_disc_qmake_path CACHE)
unset(_qt_disc_roots)
unset(_qt_disc_candidates)
unset(_qt_disc_best)
unset(_path)
unset(_matches)
