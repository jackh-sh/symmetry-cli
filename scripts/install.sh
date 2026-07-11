#!/usr/bin/env bash
# Build and install symmetry, then (on macOS) code-sign it with a stable
# local identity so keychain "Always Allow" grants survive rebuilds.
#
# Ad-hoc-signed cargo binaries get a new code identity on every build, which
# resets the keychain ACL and re-triggers the "enter your login password /
# Always Allow" dialog. Signing every build with the same self-signed
# certificate keeps the identity stable, so macOS keeps trusting it.
set -euo pipefail

CERT_NAME="symmetry-dev"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HOME/.cargo/bin/symmetry"

create_cert() {
    echo "Creating self-signed code-signing certificate '$CERT_NAME' (one-time)..."
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    cat > "$tmp/openssl.cnf" <<EOF
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

    local keychain="$HOME/Library/Keychains/login.keychain-db"
    # -T pre-authorizes codesign to use the key without prompting each build.
    security import "$tmp/key.pem" -k "$keychain" -T /usr/bin/codesign
    security import "$tmp/cert.pem" -k "$keychain"
    # Trust it for code signing (user domain). macOS asks for your password.
    echo "macOS will now ask for your login password to trust the certificate."
    security add-trusted-cert -p codeSign -k "$keychain" "$tmp/cert.pem"
}

cargo install --path "$REPO_DIR"

if [[ "$(uname)" == "Darwin" ]]; then
    if ! security find-identity -p codesigning -v 2>/dev/null | grep -q "\"$CERT_NAME\""; then
        create_cert
    fi
    codesign --force --sign "$CERT_NAME" "$BIN"
    echo "Signed $BIN as '$CERT_NAME'"
fi
