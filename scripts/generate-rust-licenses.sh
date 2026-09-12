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

case "${1:-}" in
    '') check=0 ;;
    --check) check=1 ;;
    *) echo 'Usage: generate-rust-licenses.sh [--check]' >&2; exit 2 ;;
esac
test "$#" -le 1 || exit 2
output_dir="$(mktemp -d)"
trap 'rm -rf "$output_dir"' EXIT
output_file="$output_dir/raw.md"

cargo-about generate \
    --workspace \
    --frozen \
    --fail \
    --output-file "$output_file" \
    --config scripts/licenses/about.toml \
    scripts/licenses/about.hbs

# Upstream license files can use CRLF or contain trailing spaces. Normalize
# only whitespace so the checked-in generated artifact passes repository
# hygiene checks without changing the license wording.
sed -i -e 's/\r$//' -e 's/[[:blank:]]*$//' "$output_file"
awk 'NF { while (blank_lines > 0) { print ""; blank_lines-- }; print; next }
     { blank_lines++ }' "$output_file" > "$output_dir/THIRD_PARTY_LICENSES.md"

if [ "$check" -eq 1 ]; then
    if ! cmp -s "$output_dir/THIRD_PARTY_LICENSES.md" THIRD_PARTY_LICENSES.md; then
        echo 'Third-party notices are stale; run scripts/generate-rust-licenses.sh' >&2
        exit 1
    fi
else
    cp "$output_dir/THIRD_PARTY_LICENSES.md" THIRD_PARTY_LICENSES.md
fi
