#!/usr/bin/env bash
# Public-release guard for project license grants and bundled asset notices.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() {
    echo "check-licenses: FAIL — $*" >&2
    exit 1
}

for path in \
    LICENSE-APACHE \
    THIRD_PARTY_LICENSES.md \
    scripts/licenses/about.toml \
    scripts/licenses/about.hbs; do
    test -s "$path" || fail "$path is missing or empty"
done

printf '%s  %s\n' \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 LICENSE-APACHE \
    | sha256sum --check --status - \
    || fail 'root license text differs from the reviewed canonical copy'

grep -Fqx 'license = "Apache-2.0"' Cargo.toml \
    || fail 'workspace.package must declare Apache-2.0'

for manifest in crates/*/Cargo.toml; do
    grep -Fqx 'license.workspace = true' "$manifest" \
        || fail "$manifest does not inherit the workspace license"
done

for path in \
    crates/waygate-admin/static/js/htmx.min.js \
    crates/waygate-admin/static/js/codemirror.bundle.js \
    crates/waygate-admin/static/lucide.svg; do
    test -s "$path" || fail "bundled asset or notice $path is missing"
    grep -Fq "$path" THIRD_PARTY_LICENSES.md \
        || fail "THIRD_PARTY_LICENSES.md does not identify $path"
done

grep -Fq 'version:"2.0.4"' crates/waygate-admin/static/js/htmx.min.js \
    || fail 'vendored htmx version no longer matches its notice'
grep -Fq 'Zero-Clause BSD' THIRD_PARTY_LICENSES.md \
    || fail 'htmx Zero-Clause BSD terms are missing'
grep -Fq 'Copyright (C) 2018-2021 by Marijn Haverbeke' THIRD_PARTY_LICENSES.md \
    || fail 'CodeMirror MIT notice is missing'
grep -Fq 'Copyright (c) 2026 Lucide Icons and Contributors' THIRD_PARTY_LICENSES.md \
    || fail 'Lucide ISC notice is missing'
grep -Fq 'Copyright (c) 2013-present Cole Bemis' THIRD_PARTY_LICENSES.md \
    || fail 'Feather MIT notice is missing'

grep -Fq '## Rust dependencies' THIRD_PARTY_LICENSES.md \
    || fail 'Rust dependency notices are missing'
for font in 'Outfit' 'Adobe Source Sans 3' 'Adobe Source Code Pro'; do
    grep -Fq "## $font" THIRD_PARTY_LICENSES.md \
        || fail "font attribution is missing: $font"
done
grep -Fq 'SIL OPEN FONT LICENSE Version 1.1' THIRD_PARTY_LICENSES.md \
    || fail 'font license terms are missing'

grep -Fq 'aws-lc-sys 0.40.0' THIRD_PARTY_LICENSES.md \
    || fail 'generated Rust dependency notice omits linked native TLS code'
grep -Fq 'Mozilla Public License 2.0' THIRD_PARTY_LICENSES.md \
    || fail 'generated Rust dependency notice omits accepted license text'
grep -Fq 'CDLA-Permissive-2.0' scripts/licenses/about.toml \
    || fail 'cargo-about accepted-license policy is incomplete'
grep -Fq 'ignore-dev-dependencies = true' scripts/licenses/about.toml \
    || fail 'cargo-about must exclude dependencies absent from release binaries'
grep -Fq 'ignore-build-dependencies = true' scripts/licenses/about.toml \
    || fail 'cargo-about must exclude build-only dependencies'

grep -Fq \
    'THIRD_PARTY_LICENSES.md /etc/mcp-gateway/static/THIRD_PARTY_LICENSES.md' \
    Dockerfile \
    || fail 'published image does not place notices beside browser assets'
grep -Fq '/admin/static/THIRD_PARTY_LICENSES.md' \
    crates/waygate-admin/static/lucide.svg \
    || fail 'Lucide sprite does not point to its published notices'
grep -Fq '/usr/share/licenses/mcp-gateway/' Dockerfile \
    || fail 'published image omits its conventional license directory'

test "$(grep -Fc \
    'cp LICENSE-APACHE THIRD_PARTY_LICENSES.md dist/' \
    .github/workflows/release-mcp-files.yml)" -eq 1 \
    || fail 'mcp-files shared licenses must be staged once for the release'
awk '
    /^  macos:/ { in_macos = 1 }
    in_macos && /needs: linux-windows/ { found = 1 }
    END { exit !found }
' .github/workflows/release-mcp-files.yml \
    || fail 'macOS build must wait for shared licenses and other platforms'
grep -Fq '          bash scripts/check-licenses.sh' \
    .github/workflows/image.yml \
    || fail 'image-publishing workflow does not run the license gate'
# Image CI runs for every main push, including license-only changes.
grep -Fq '    branches: [main]' .github/workflows/image.yml \
    || fail 'image-publishing workflow must run on main pushes'
if grep -Eq '^[[:space:]]+paths(-ignore)?:' .github/workflows/image.yml; then
    fail 'image-publishing workflow must not filter out license-only changes'
fi

python3 - crates/waygate-admin/codemirror/package-lock.json <<'PY' \
    || fail 'CodeMirror lockfile runtime-license validation failed'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    lock = json.load(handle)

packages = lock.get("packages")
if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
    raise SystemExit("package-lock.json has no packages root")

root = packages[""]
dependencies = root.get("dependencies", {})
dev_dependencies = root.get("devDependencies", {})
if "esbuild" in dependencies or "esbuild" not in dev_dependencies:
    raise SystemExit("esbuild must remain build-only")

runtime_packages = []
for path, package in packages.items():
    if not path or package.get("dev") is True:
        continue
    runtime_packages.append(path)
    if package.get("license") != "MIT":
        raise SystemExit(f"non-MIT runtime package: {path}")

if not runtime_packages:
    raise SystemExit("package-lock.json has no runtime packages")
PY

echo 'check-licenses: OK'
