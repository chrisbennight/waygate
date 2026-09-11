#!/usr/bin/env bash
# Install the checksum-pinned Grype version selected by the workflow.
# Both the version and checksum must be updated together after verification.

set -euo pipefail

: "${GRYPE_VERSION:?GRYPE_VERSION must be set}"
: "${GRYPE_CHECKSUM:?GRYPE_CHECKSUM must be set}"

tarball="grype_${GRYPE_VERSION}_linux_amd64.tar.gz"
url="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${tarball}"

curl -sSfL \
  --retry 5 --retry-all-errors --retry-delay 2 \
  --connect-timeout 10 --max-time 120 \
  -o "${tarball}" "${url}"

echo "${GRYPE_CHECKSUM}  ${tarball}" | sha256sum --check --strict
sudo tar -xzf "${tarball}" -C /usr/local/bin grype
rm -f "${tarball}"

grype version
