#!/usr/bin/env bash
# build.sh - one-shot local build for macOS / Linux.
# Usage: ./scripts/build.sh [--opencl] [--clean]
set -euo pipefail
cd "$(dirname "$0")/.."

EXTRA=""
CLEAN=0
for a in "$@"; do
  case "$a" in
    --opencl) EXTRA="$EXTRA -DRAR3_WITH_OPENCL=ON" ;;
    --clean)  CLEAN=1 ;;
  esac
done

[ "$CLEAN" = "1" ] && rm -rf build

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release $EXTRA
cmake --build build -j

echo "== running core self-test =="
./build/selftest
echo "== done. binary: build/rar3crack =="
