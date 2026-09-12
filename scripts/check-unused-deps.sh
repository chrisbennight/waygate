#!/usr/bin/env bash
# CI gate: no unused dependencies in any crate manifest.
#
# Runs cargo-machete (source-scan mode, no cargo/toolchain needed) across the
# workspace. Remove dependencies that the crate does not use.
#
# The tool version is PINNED: machete's detection heuristics change between
# releases, and a gate must give the same answer locally and in CI. The pin
# lives only here (Renovate does not manage it); bump VERSION + SHA256
# together when upgrading, and re-run the negative probe (add a scratch
# unused dep, confirm the gate fails) in the same PR.
#
# Binary resolution:
#   1. `cargo-machete` on PATH (incl. ~/.cargo/bin) at the pinned version —
#      the local-dev path: cargo install cargo-machete --locked --version <V>
#   2. Otherwise, on x86_64 Linux (the CI runners): download the sha256-pinned
#      release tarball and run it from a temp dir. Compile-free, so this check
#      can run in the workflows' fast-fail block before the toolchain install.
#
# Known limitation: machete 0.9.2 does not flag unused
# [dev-dependencies] — this gate covers [dependencies] only.
#
# Exit codes: 0 clean; 1 unused deps found (the finding); 2 environment /
# self-check error (wrong version, failed download, bad checksum) — never a
# vacuous OK.
set -euo pipefail
cd "$(dirname "$0")/.."

MACHETE_VERSION=0.9.2
# sha256 of cargo-machete-v${MACHETE_VERSION}-x86_64-unknown-linux-musl.tar.gz
MACHETE_SHA256=48200087f54c55aabcd4db4af1e25742b49846c02a1b1bfa134711945b35b2e9

export PATH="$HOME/.cargo/bin:$PATH"

fail_env() {
    echo "check-unused-deps: FAIL — $1" >&2
    echo "Install the pinned tool: cargo install cargo-machete --locked --version $MACHETE_VERSION" >&2
    exit 2
}

BIN=""
if command -v cargo-machete >/dev/null 2>&1; then
    found=$(cargo-machete --version 2>/dev/null || true)
    if [ "$found" != "$MACHETE_VERSION" ]; then
        fail_env "cargo-machete on PATH is version '$found', gate is pinned to $MACHETE_VERSION (detection heuristics differ across versions; the gate must be deterministic)"
    fi
    BIN=cargo-machete
elif [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    url="https://github.com/bnjbvr/cargo-machete/releases/download/v${MACHETE_VERSION}/cargo-machete-v${MACHETE_VERSION}-x86_64-unknown-linux-musl.tar.gz"
    curl -sSfL --retry 3 -o "$tmp/machete.tar.gz" "$url" \
        || fail_env "download failed: $url"
    echo "$MACHETE_SHA256  $tmp/machete.tar.gz" | sha256sum -c --quiet - \
        || fail_env "sha256 mismatch on downloaded tarball (expected $MACHETE_SHA256)"
    tar -xzf "$tmp/machete.tar.gz" -C "$tmp"
    BIN="$tmp/cargo-machete-v${MACHETE_VERSION}-x86_64-unknown-linux-musl/cargo-machete"
    [ -x "$BIN" ] || fail_env "extracted tarball is missing the cargo-machete binary"
else
    fail_env "cargo-machete not on PATH and no prebuilt binary for $(uname -s)/$(uname -m)"
fi

# Positive control: the resolved binary must identify as the pinned version
# before a clean run is trusted.
resolved=$("$BIN" --version 2>/dev/null || true)
if [ "$resolved" != "$MACHETE_VERSION" ]; then
    fail_env "resolved binary reports version '$resolved', expected $MACHETE_VERSION"
fi

# --skip-target-dir: local trees have build output under target/ whose
# vendored manifests must not be scanned (CI checkouts don't have one yet,
# but the gate must behave identically everywhere).
status=0
out=$("$BIN" --skip-target-dir 2>&1) || status=$?
if [ "$status" -eq 0 ]; then
    echo "check-unused-deps: OK (no unused dependencies; cargo-machete $MACHETE_VERSION)"
    exit 0
fi
if [ "$status" -eq 1 ]; then
    echo "$out" >&2
    echo "check-unused-deps: FAIL — the crate manifests above declare dependencies their code never uses." >&2
    echo "Remove each unused dependency (and its [workspace.dependencies] pin if no other crate uses it)." >&2
    echo "If a dependency is real but only reached via a macro machete cannot see, keep it and add:" >&2
    echo '  [package.metadata.cargo-machete]' >&2
    echo '  ignored = ["<dep>"]  # used via <macro>, invisible to the source scan' >&2
    exit 1
fi
echo "$out" >&2
fail_env "cargo-machete exited $status (expected 0 clean / 1 findings)"
