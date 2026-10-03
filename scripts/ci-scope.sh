#!/usr/bin/env bash
set -euo pipefail

rust_scope=none
guards=false
docs=false
licenses=false
browser=false
tooling=false
image=false
quickstart=false
helper=false
scanner_tests=false
architecture=false
tool_context=false
admin_assets=false
synthetic_fixtures=false
client_metadata=false
case "${GITHUB_EVENT_NAME:?event is required}" in
  workflow_dispatch) full=true ;;
  push|pull_request)
    full=false
    if [[ "$GITHUB_EVENT_NAME" == push && "${GITHUB_REF:-}" == refs/tags/* ]]; then full=true; fi
    ;;
  *) echo 'Unsupported event' >&2; exit 1 ;;
esac
if [[ "$full" == true ]]; then
  rust_scope=workspace; guards=true; docs=true; licenses=true; browser=true
  tooling=true; image=true; quickstart=true; helper=true; scanner_tests=true; architecture=true; tool_context=true; admin_assets=true; synthetic_fixtures=true; client_metadata=true
else
  [[ "${BASE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || { echo 'A full base commit is required' >&2; exit 1; }
  changed_files="$(mktemp)"
  trap 'rm -f "$changed_files"' EXIT
  if [[ "$GITHUB_EVENT_NAME" == pull_request ]]; then
    git diff --name-only --no-renames -z "$BASE_SHA...HEAD" >"$changed_files"
  else
    git diff --name-only --no-renames -z "$BASE_SHA" HEAD >"$changed_files"
  fi
  while IFS= read -r -d '' path; do
    case "$path" in
      scripts/ci-scope.sh|scripts/ci-cargo.sh)
        rust_scope=workspace; guards=true; docs=true; licenses=true; browser=true; tooling=true; image=true; quickstart=true; helper=true; scanner_tests=true; architecture=true; tool_context=true; admin_assets=true; synthetic_fixtures=true; client_metadata=true ;;
      .github/workflows/image.yml)
        rust_scope=workspace; guards=true; docs=true; licenses=true; browser=true; tooling=true; image=true; architecture=true; tool_context=true; admin_assets=true; synthetic_fixtures=true; client_metadata=true ;;
      Cargo.toml|Cargo.lock|rust-toolchain.toml|.cargo/*)
        rust_scope=workspace; guards=true; licenses=true; image=true; quickstart=true; helper=true ;;
      *.md) docs=true ;;
      crates/waygate-files-helper/*)
        if [[ "$rust_scope" == none ]]; then rust_scope=helper; fi
        helper=true; docs=true ;;
      crates/waygate-test-client/*|crates/waygate-test-support/*)
        rust_scope=workspace; guards=true; docs=true ;;
      crates/waygate-admin/codemirror/*|crates/waygate-admin/static/js/codemirror.bundle.js) browser=true; docs=true; image=true; quickstart=true ;;
      crates/waygate-admin/static/*) docs=true; image=true; quickstart=true ;;
      crates/*|migrations/*) rust_scope=workspace; guards=true; docs=true; image=true; quickstart=true ;;
    esac
    case "$path" in
      crates/*/Cargo.toml) licenses=true; guards=true ;;
      docs/architecture.md) architecture=true ;;
      examples/email-policy/*) rust_scope=workspace; guards=true ;;
      scripts/report-tool-context.mjs|scripts/fixtures/tool-context/standard-budget.json) tooling=true; tool_context=true ;;
      *.md|scripts/check-doc-anchors.sh|scripts/check-licenses.sh|scripts/check-no-plan-citations.sh) docs=true ;;
      scripts/licenses/*|scripts/generate-rust-licenses.sh|THIRD_PARTY_LICENSES.md|LICENSE-APACHE)
        docs=true; licenses=true; image=true; quickstart=true; helper=true ;;
      scripts/helper_release.py|scripts/verify-mcp-files-version.sh|.github/workflows/release-mcp-files.yml)
        helper=true; tooling=true ;;
      scripts/release_policy.py) tooling=true; image=true; quickstart=true; helper=true ;;
      scripts/publish-gateway-image.py) tooling=true; image=true; quickstart=true ;;
      scripts/test_release_*.py) tooling=true ;;
      scripts/report-tool-context*|scripts/dashboard-badge*|scripts/fixtures/tool-context/*|crates/waygate-admin/static/js/badge.js)
        tooling=true ;;
      scripts/check-*.sh|scripts/ensure-nextest.sh|.config/nextest.toml)
        rust_scope=workspace; guards=true ;;
      scripts/boot-smoke/*) image=true ;;
      Dockerfile|.dockerignore|build-docker.sh|scripts/smoke-gateway-image.sh|scripts/boot-smoke-2026/*|scripts/release_policy.py|scripts/publish-gateway-image.py)
        image=true; quickstart=true ;;
      docker-compose.yml|examples/quickstart/*|.github/workflows/quickstart.yml) quickstart=true ;;
      scripts/threat-gate/*|.github/workflows/threat-gate.yml) scanner_tests=true ;;
    esac
    case "$path" in
      crates/waygate-admin/static/css/*|crates/waygate-admin/static/fonts/*|crates/waygate-admin/static/lucide.svg) admin_assets=true ;;
      scripts/fixtures/tool-context/standard-tools-list.json) synthetic_fixtures=true ;;
      cimd/mcp-test-client.json) client_metadata=true ;;
    esac
    case "$path" in
      THIRD_PARTY_LICENSES.md|LICENSE-APACHE) docs=true; licenses=true; image=true; quickstart=true; helper=true ;;
      Dockerfile|.github/workflows/release-mcp-files.yml) docs=true ;;
    esac
    if [[ ! -e "$path" ]]; then docs=true; fi
  done <"$changed_files"
fi
printf 'rust_scope=%s\nguards=%s\ndocs=%s\nlicenses=%s\nbrowser=%s\ntooling=%s\nimage=%s\nquickstart=%s\nhelper=%s\nscanner_tests=%s\narchitecture=%s\ntool_context=%s\nadmin_assets=%s\nsynthetic_fixtures=%s\nclient_metadata=%s\n' \
  "$rust_scope" "$guards" "$docs" "$licenses" "$browser" "$tooling" "$image" "$quickstart" "$helper" "$scanner_tests" "$architecture" "$tool_context" "$admin_assets" "$synthetic_fixtures" "$client_metadata" >>"${GITHUB_OUTPUT:?output file is required}"
