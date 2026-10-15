#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."
if command -v caffeinate >/dev/null 2>&1; then
    exec caffeinate -disu ./build.sh --test "$@"
else
    exec ./build.sh --test "$@"
fi
