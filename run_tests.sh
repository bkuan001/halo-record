#!/usr/bin/env bash
# Run the halo-record test suite against the working tree (no install needed).
# Pure stdlib unittest — matches the package's zero-dependency stance.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 -m unittest discover -s tests -t . -v "$@"
