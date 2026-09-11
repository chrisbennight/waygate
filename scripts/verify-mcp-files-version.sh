#!/usr/bin/env bash
# Check the compiled binary agrees with the workspace and release metadata
# already validated by helper_release.py before any artifacts are published.
set -euo pipefail

bin="${1:?usage: verify-mcp-files-version.sh <binary>}"
version="${VERSION:?VERSION is required}"

reported="$("$bin" --version)"
# clap prints "<name> <version>"; take the last field so a rename does not
# silently turn this into a no-op.
reported_version="${reported##* }"

if [ "$reported_version" != "$version" ]; then
  echo "refusing $version: $bin reports '$reported_version'" >&2
  echo "bump the crate version to match, or build the version the crate already has" >&2
  exit 1
fi

echo "binary reports $reported_version, matching the requested version"
