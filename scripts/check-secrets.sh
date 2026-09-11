#!/usr/bin/env bash
# Scan the current source snapshot with a checksum-pinned conventional scanner.
set -euo pipefail
cd "$(dirname "$0")/.."

GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

version_of() {
    "$1" version 2>/dev/null | awk 'NR == 1 { print $1 }'
}

# These fixtures intentionally contain public, noncredential test keys. Their
# scanner exception remains valid only while the reviewed bytes are unchanged.
if ! printf '%s\n' \
    '9785143373b559a7fa53f2aff45774390fd14ec645986320fa10f063ddd79432  crates/waygate-oidc/tests/fixtures/private.pem' \
    '236fa3819c990d2b710d051be5ee7768cbe7229f88128a629d1457959ac9d7ef  crates/waygate-oidc/tests/fixtures/ec_p256_private.pem' \
    | sha256sum --check --quiet -; then
    echo "check-secrets: FAIL — public OIDC test-key fixture content changed" >&2
    exit 1
fi

scanner=""
cached_scanner="${CARGO_TARGET_DIR:-target}/ci-tools/gitleaks-${GITLEAKS_VERSION}/gitleaks"
if command -v gitleaks >/dev/null 2>&1 \
    && [ "$(version_of gitleaks)" = "$GITLEAKS_VERSION" ]; then
    scanner=$(command -v gitleaks)
elif [ -x "$cached_scanner" ] \
    && [ "$(version_of "$cached_scanner")" = "$GITLEAKS_VERSION" ]; then
    scanner="$cached_scanner"
elif [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; then
    download_dir=$(mktemp -d)
    trap 'rm -rf "$download_dir"' EXIT
    archive="$download_dir/gitleaks.tar.gz"
    url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    curl -sSfL --retry 3 -o "$archive" "$url"
    echo "$GITLEAKS_SHA256  $archive" | sha256sum -c --quiet -

    tool_dir=$(dirname "$cached_scanner")
    mkdir -p "$tool_dir"
    tar --no-same-owner -xzf "$archive" -C "$tool_dir" gitleaks
    chmod 0755 "$tool_dir/gitleaks"
    scanner="$tool_dir/gitleaks"
else
    echo "check-secrets: FAIL — install gitleaks $GITLEAKS_VERSION or run on x86_64 Linux" >&2
    exit 2
fi

if [ "$(version_of "$scanner")" != "$GITLEAKS_VERSION" ]; then
    echo "check-secrets: FAIL — resolved scanner is not gitleaks $GITLEAKS_VERSION" >&2
    exit 2
fi

"$scanner" dir . \
    --config .gitleaks.toml \
    --redact \
    --no-banner \
    --no-color \
    --exit-code 1

echo "check-secrets: OK (gitleaks $GITLEAKS_VERSION)"
