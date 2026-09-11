#!/usr/bin/env bash
# CI provisioner: put the pinned cargo-nextest on PATH.
#
# The workflows run the workspace test suite through cargo-nextest (it
# executes tests from all binaries in parallel; `cargo test` runs one test
# binary at a time). This script makes the runner ready for a subsequent
# `cargo nextest run` step without compiling anything.
#
# The tool version is PINNED: nextest's execution model and config schema
# evolve between releases, and the suite must behave the same locally and
# in CI. The pin lives only here (Renovate does not manage it); bump
# VERSION + SHA256 together when upgrading, verifying the new tarball's
# sha256 against the checksum file nextest publishes alongside each
# release asset.
#
# Binary resolution:
#   1. `cargo-nextest` on PATH (incl. ~/.cargo/bin) at the pinned version —
#      the local-dev path: cargo install cargo-nextest --locked --version <V>,
#      or the prebuilt archives at https://nexte.st for your platform.
#   2. Otherwise, on x86_64 Linux (the CI runners): download the
#      sha256-pinned musl release tarball and install the binary to
#      ~/.cargo/bin so the later `cargo nextest run` step resolves it.
#
# Exit codes: 0 ready; 2 environment error (version mismatch, failed
# download, bad checksum) — never a vacuous OK.
set -euo pipefail

NEXTEST_VERSION=0.9.140
# sha256 of cargo-nextest-${NEXTEST_VERSION}-x86_64-unknown-linux-musl.tar.gz
NEXTEST_SHA256=bc2a998567816eef7b087b920036f49fb89aa2a8a603f6a3d84098be160b62c5

export PATH="$HOME/.cargo/bin:$PATH"

fail_env() {
    echo "ensure-nextest: FAIL — $1" >&2
    echo "Install the pinned tool: cargo install cargo-nextest --locked --version $NEXTEST_VERSION" >&2
    exit 2
}

version_of() {
    # `cargo-nextest --version` prints "cargo-nextest <semver> (<hash> <date>)".
    "$1" --version 2>/dev/null | awk 'NR==1 {print $2}'
}

if command -v cargo-nextest >/dev/null 2>&1; then
    found=$(version_of cargo-nextest)
    if [ "$found" != "$NEXTEST_VERSION" ]; then
        fail_env "cargo-nextest on PATH is version '$found', pinned to $NEXTEST_VERSION (runner behaviour must be deterministic across local and CI runs)"
    fi
    echo "ensure-nextest: OK (cargo-nextest $NEXTEST_VERSION already on PATH)"
    exit 0
fi

if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    url="https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-${NEXTEST_VERSION}/cargo-nextest-${NEXTEST_VERSION}-x86_64-unknown-linux-musl.tar.gz"
    curl -sSfL --retry 3 -o "$tmp/nextest.tar.gz" "$url" \
        || fail_env "download failed: $url"
    echo "$NEXTEST_SHA256  $tmp/nextest.tar.gz" | sha256sum -c --quiet - \
        || fail_env "sha256 mismatch on downloaded tarball (expected $NEXTEST_SHA256)"
    tar -xzf "$tmp/nextest.tar.gz" -C "$tmp"
    [ -x "$tmp/cargo-nextest" ] || fail_env "extracted tarball is missing the cargo-nextest binary"
    mkdir -p "$HOME/.cargo/bin"
    install -m 0755 "$tmp/cargo-nextest" "$HOME/.cargo/bin/cargo-nextest"
else
    fail_env "cargo-nextest not on PATH and no prebuilt binary for $(uname -s)/$(uname -m)"
fi

# Positive control: the installed binary must identify as the pinned version
# before the runner is trusted.
resolved=$(version_of "$HOME/.cargo/bin/cargo-nextest")
if [ "$resolved" != "$NEXTEST_VERSION" ]; then
    fail_env "installed binary reports version '$resolved', expected $NEXTEST_VERSION"
fi
echo "ensure-nextest: OK (installed cargo-nextest $NEXTEST_VERSION to ~/.cargo/bin)"
