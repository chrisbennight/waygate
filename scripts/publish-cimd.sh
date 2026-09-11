#!/usr/bin/env bash
# Publish a rendered CIMD identity to an explicitly selected Git repository.
#
# Requirements:
#   - authenticated Git access to CIMD_WELL_KNOWN_REPO
#   - CIMD_CLIENT_ID_URL: the public HTTPS URL where the document will be served
#   - git and Python 3 available on PATH
#
# Usage: ./scripts/publish-cimd.sh [--dry-run]
set -euo pipefail

REPO_URL="${CIMD_WELL_KNOWN_REPO:?set CIMD_WELL_KNOWN_REPO to the destination Git repository}"
CLIENT_ID_URL="${CIMD_CLIENT_ID_URL:?set CIMD_CLIENT_ID_URL to the public document URL}"
SOURCE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/cimd/mcp-test-client.json"
DEST_NAME="mcp-test-client.json"

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  shift || true
fi

if [[ "$#" -ne 0 ]]; then
  echo 'Usage: publish-cimd.sh [--dry-run]' >&2
  exit 2
fi

if [[ ! -f "${SOURCE_PATH}" ]]; then
  echo "source not found: ${SOURCE_PATH}" >&2
  exit 1
fi

WORKDIR="$(mktemp -d -t cimd-publish-XXXXXX)"
trap 'rm -rf "${WORKDIR}"' EXIT

# Validate and render locally before contacting the destination. Arguments are
# data to the Python program; neither a path nor a URL becomes Python source.
python3 - "${SOURCE_PATH}" "${CLIENT_ID_URL}" "${WORKDIR}/rendered.json" <<'PY'
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

source, client_id, output = sys.argv[1:]
try:
    url = urlsplit(client_id)
    # Accessing port validates syntax and the TCP port range; urlsplit alone
    # leaves malformed ports in the authority without rejecting them.
    port = url.port
except ValueError:
    raise SystemExit('CIMD_CLIENT_ID_URL must have a valid URL authority and port')
if (url.scheme != 'https' or not url.hostname or url.username or url.password
        or url.fragment or url.query or not url.path or url.path == '/'):
    raise SystemExit('CIMD_CLIENT_ID_URL must be an HTTPS document URL without userinfo, query, or fragment')
if url.hostname in {'example.com', 'clients.example.com'}:
    raise SystemExit('replace the example client identity with your real hosted document URL')
document = json.loads(Path(source).read_text())
document['client_id'] = client_id
Path(output).write_text(json.dumps(document, indent=2) + '\n')
PY

if [[ "${DRY_RUN}" -eq 1 ]]; then
  cat "${WORKDIR}/rendered.json"
  exit 0
fi

git clone --depth 1 -- "${REPO_URL}" "${WORKDIR}/repo"
cp "${WORKDIR}/rendered.json" "${WORKDIR}/repo/${DEST_NAME}"
cd "${WORKDIR}/repo"
# `git diff --quiet` ignores untracked files, so we'd falsely short-circuit
# the first publish into an empty repo. Use `git status --porcelain` instead.
if [[ -z "$(git status --porcelain -- "${DEST_NAME}")" ]]; then
  echo "No changes to ${DEST_NAME}; nothing to publish."
  exit 0
fi

STAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
MSG="publish mcp-test-client CIMD (${STAMP})"

git add "${DEST_NAME}"
git commit -m "${MSG}"
git push
echo "Published ${DEST_NAME}; verify it is served at the configured client identity URL"
