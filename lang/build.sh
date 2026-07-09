#!/usr/bin/env bash
# Compile every example into lang/build/ (gitignored).
set -euo pipefail
. "$(dirname "$0")/common.sh"

if [ ! -x "${CESC_BIN}" ]; then
  echo "error: cesc not built. run \`./build.sh debug\` from ${CES_ROOT}" >&2
  exit 1
fi

mkdir -p "${BUILD_DIR}"
for src in "${LANG_DIR}"/examples/*.casm "${LANG_DIR}"/examples/*.cesl; do
  base="$(basename "${src}")"
  out="${BUILD_DIR}/${base%.*}.bin"
  "${CESC_BIN}" "${src}" -o "${out}"
done
