#!/bin/sh
# Symmetry installer — downloads a prebuilt release binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/OWNER/symmetry-cli/main/scripts/install.sh | sh
#
# Configuration (environment variables):
#   SYMMETRY_REPO         GitHub repo to install from (default: jackh-sh/symmetry-cli)
#   SYMMETRY_VERSION      Release tag, e.g. v0.1.0 (default: latest)
#   SYMMETRY_INSTALL_DIR  Where to put the binary (default: ~/.local/bin)
#   SYMMETRY_NO_SIGN=1    Skip stable macOS code signing
#
# Contributors building from a checkout should use scripts/dev-install.sh instead.
#
# `install.sh --sign-only <binary>` skips the download and just applies the
# stable macOS code signature to an existing binary (used by dev-install.sh).
set -eu

REPO="${SYMMETRY_REPO:-jackh-sh/symmetry-cli}"
VERSION="${SYMMETRY_VERSION:-latest}"
INSTALL_DIR="${SYMMETRY_INSTALL_DIR:-$HOME/.local/bin}"
CERT_NAME="symmetry-dev"

say() { printf '%s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }

# On macOS, re-sign with a stable self-signed identity. Release binaries are
# ad-hoc signed, so every upgrade would get a new code identity and reset the
# keychain "Always Allow" ACL; signing each install with the same local
# certificate keeps macOS trusting it across upgrades.
create_cert() {
    say "Creating self-signed code-signing certificate '$CERT_NAME' (one-time)..."
    cat > "$tmp/openssl.cnf" << EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $CERT_NAME
[ext]
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
basicConstraints = critical,CA:FALSE
EOF
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
        -config "$tmp/openssl.cnf" \
        -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null

    keychain="$HOME/Library/Keychains/login.keychain-db"
    # -T pre-authorizes codesign to use the key without prompting each time.
    security import "$tmp/key.pem" -k "$keychain" -T /usr/bin/codesign
    security import "$tmp/cert.pem" -k "$keychain"
    # Trust it for code signing (user domain). macOS asks for your password.
    say "macOS will now ask for your login password to trust the certificate."
    security add-trusted-cert -p codeSign -k "$keychain" "$tmp/cert.pem"
}

sign_binary() {
    if ! security find-identity -p codesigning -v 2>/dev/null | grep -q "\"$CERT_NAME\""; then
        create_cert
    fi
    codesign --force --sign "$CERT_NAME" "$1"
}

if [ "${1:-}" = "--sign-only" ]; then
    [ "$#" -ge 2 ] || err "usage: install.sh --sign-only <binary>"
    [ "$(uname -s)" = "Darwin" ] || err "--sign-only only applies on macOS"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT INT TERM
    sign_binary "$2"
    say "Signed $2 as '$CERT_NAME' (keychain grants survive rebuilds)."
    exit 0
fi

command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar >/dev/null 2>&1 || err "tar is required"

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
    Darwin)
        case "$arch" in
            arm64) target="aarch64-apple-darwin" ;;
            x86_64) target="x86_64-apple-darwin" ;;
            *) err "unsupported macOS architecture: $arch" ;;
        esac ;;
    Linux)
        case "$arch" in
            x86_64 | amd64) target="x86_64-unknown-linux-gnu" ;;
            aarch64 | arm64) target="aarch64-unknown-linux-gnu" ;;
            *) err "unsupported Linux architecture: $arch" ;;
        esac ;;
    *) err "unsupported OS: $os (on Windows, install with 'cargo install' from source)" ;;
esac

asset="symmetry-$target.tar.gz"
if [ "$VERSION" = "latest" ]; then
    base="https://github.com/$REPO/releases/latest/download"
else
    base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading symmetry ($VERSION, $target) from $REPO..."
curl -fsSL --proto '=https' -o "$tmp/$asset" "$base/$asset" ||
    err "download failed: $base/$asset (is there a release with an asset for $target?)"

if curl -fsSL --proto '=https' -o "$tmp/$asset.sha256" "$base/$asset.sha256" 2>/dev/null; then
    (
        cd "$tmp"
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum -c "$asset.sha256" >/dev/null
        else
            shasum -a 256 -c "$asset.sha256" >/dev/null
        fi
    ) || err "checksum verification failed for $asset"
    say "Checksum verified."
else
    say "warning: release has no checksum file; skipping verification"
fi

tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/symmetry" ] || err "archive did not contain a 'symmetry' binary"

mkdir -p "$INSTALL_DIR"
install -m 755 "$tmp/symmetry" "$INSTALL_DIR/symmetry"
say "Installed $INSTALL_DIR/symmetry"

if [ "$os" = "Darwin" ] && [ "${SYMMETRY_NO_SIGN:-0}" != "1" ]; then
    if sign_binary "$INSTALL_DIR/symmetry"; then
        say "Signed as '$CERT_NAME' (keychain grants survive upgrades)."
    else
        say "warning: could not apply a stable code signature; macOS may ask for"
        say "keychain access again after upgrades. Set SYMMETRY_NO_SIGN=1 to skip."
    fi
fi

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        say ""
        say "note: $INSTALL_DIR is not on your PATH. Add it with:"
        say "  bash/zsh: export PATH=\"$INSTALL_DIR:\$PATH\""
        say "  fish:     fish_add_path $INSTALL_DIR"
        ;;
esac

say ""
say "Done. Run 'symmetry --help' to get started."
