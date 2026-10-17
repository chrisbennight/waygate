#!/usr/bin/env bash
# CI provisioner: put the pinned cargo-about on PATH for the license check.
#
# scripts/generate-rust-licenses.sh accepts exactly one cargo-about version.
# This script provides that version without compiling it from source.
#
# Binary resolution:
#   1. `cargo-about` on PATH (incl. ~/.cargo/bin) at the pinned version —
#      the local-dev path:
#      cargo install cargo-about --version <V> --locked --features cli
#   2. Otherwise, on x86_64 Linux (the CI runners): download the release's
#      musl tarball, verify it against the pinned sha256, and install the
#      binary to ~/.cargo/bin so the license check resolves it.
#
# Bump CARGO_ABOUT_VERSION, CARGO_ABOUT_SHA256 and the required_version in
# generate-rust-licenses.sh together. Take the checksum from the .sha256 file
# published beside the release asset and confirm it against the downloaded
# tarball.
#
# Exit codes: 0 ready; 2 environment error (version mismatch, failed
# download, bad checksum) — never a vacuous OK.
set -euo pipefail

CARGO_ABOUT_VERSION=0.9.1
# sha256 of cargo-about-${CARGO_ABOUT_VERSION}-x86_64-unknown-linux-musl.tar.gz
CARGO_ABOUT_SHA256=c0e7dc6f5d74b0beec5c0053d39ab24514c717d19acd91886907a22457ea9e98

export PATH="$HOME/.cargo/bin:$PATH"

fail_env() {
    echo "ensure-cargo-about: FAIL — $1" >&2
    echo "Install the pinned tool: cargo install cargo-about --version $CARGO_ABOUT_VERSION --locked --features cli" >&2
    exit 2
}

version_of() {
    # `cargo-about --version` prints "cargo-about <semver>".
    "$1" --version 2>/dev/null | awk 'NR==1 {print $2}'
}

if command -v cargo-about >/dev/null 2>&1; then
    found=$(version_of cargo-about)
    if [ "$found" != "$CARGO_ABOUT_VERSION" ]; then
        fail_env "cargo-about on PATH is version '$found', pinned to $CARGO_ABOUT_VERSION"
    fi
    echo "ensure-cargo-about: OK (cargo-about $CARGO_ABOUT_VERSION already on PATH)"
    exit 0
fi

if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    asset="cargo-about-${CARGO_ABOUT_VERSION}-x86_64-unknown-linux-musl"
    url="https://github.com/EmbarkStudios/cargo-about/releases/download/${CARGO_ABOUT_VERSION}/${asset}.tar.gz"
    curl -sSfL --retry 3 -o "$tmp/cargo-about.tar.gz" "$url" \
        || fail_env "download failed: $url"
    echo "$CARGO_ABOUT_SHA256  $tmp/cargo-about.tar.gz" | sha256sum -c --quiet - \
        || fail_env "sha256 mismatch on downloaded tarball (expected $CARGO_ABOUT_SHA256)"
    tar -xzf "$tmp/cargo-about.tar.gz" -C "$tmp"
    [ -x "$tmp/$asset/cargo-about" ] || fail_env "extracted tarball is missing the cargo-about binary"
    mkdir -p "$HOME/.cargo/bin"
    install -m 0755 "$tmp/$asset/cargo-about" "$HOME/.cargo/bin/cargo-about"
else
    fail_env "cargo-about not on PATH and no prebuilt binary for $(uname -s)/$(uname -m)"
fi

# Positive control: the installed binary must identify as the pinned version
# before the license check trusts it.
resolved=$(version_of "$HOME/.cargo/bin/cargo-about")
if [ "$resolved" != "$CARGO_ABOUT_VERSION" ]; then
    fail_env "installed binary reports version '$resolved', expected $CARGO_ABOUT_VERSION"
fi
echo "ensure-cargo-about: OK (installed cargo-about $CARGO_ABOUT_VERSION to ~/.cargo/bin)"
