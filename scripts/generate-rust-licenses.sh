#!/usr/bin/env bash
# Regenerate the checked-in third-party license notice deterministically
# from the locked release dependency graph.
set -euo pipefail
cd "$(dirname "$0")/.."

required_version='0.9.1'
if ! command -v cargo-about >/dev/null; then
    echo "cargo-about $required_version is required" >&2
    exit 1
fi

actual_version="$(cargo-about --version)"
if [ "$actual_version" != "cargo-about $required_version" ]; then
    echo "expected cargo-about $required_version, found $actual_version" >&2
    exit 1
fi

output_file="$(mktemp)"
trap 'rm -f "$output_file"' EXIT

cargo-about generate \
    --workspace \
    --frozen \
    --fail \
    --output-file "$output_file" \
    about.hbs

# Upstream license files can use CRLF or contain trailing spaces. Normalize
# only whitespace so the checked-in generated artifact passes repository
# hygiene checks without changing the license wording.
sed -i -e 's/\r$//' -e 's/[[:blank:]]*$//' "$output_file"
awk 'NF { while (blank_lines > 0) { print ""; blank_lines-- }; print; next }
     { blank_lines++ }' "$output_file" > THIRD_PARTY_LICENSES.md

mapfile -t workspace_manifests < <(
    find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -type f -print \
        | LC_ALL=C sort
)
sha256sum \
    Cargo.toml \
    Cargo.lock \
    "${workspace_manifests[@]}" \
    about.toml \
    about.hbs \
    scripts/generate-rust-licenses.sh \
    THIRD_PARTY_LICENSES.md \
    > THIRD_PARTY_LICENSES.lock
