#!/usr/bin/env bash
# Build and install symmetry, then (on macOS) code-sign it with a stable
# local identity so keychain "Always Allow" grants survive rebuilds.
#
# Ad-hoc-signed cargo binaries get a new code identity on every build, which
# resets the keychain ACL and re-triggers the "enter your login password /
# Always Allow" dialog. The signing itself lives in install.sh (--sign-only)
# so both installers share one implementation.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HOME/.cargo/bin/symmetry"

cargo install --path "$REPO_DIR"

if [[ "$(uname)" == "Darwin" ]]; then
    sh "$REPO_DIR/scripts/install.sh" --sign-only "$BIN"
fi
