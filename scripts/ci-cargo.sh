#!/usr/bin/env bash
set -euo pipefail

case "${CARGO_CHECK_SCOPE:?Rust scope is required}" in
  workspace) packages=(--workspace) ;;
  helper) packages=(-p waygate-files-helper) ;;
  *) echo 'Rust checks require a selected package scope' >&2; exit 1 ;;
esac
command="${1:?Cargo command is required}"
shift
if [[ "$command" == nextest ]]; then
  [[ "${1:-}" == run ]] || { echo 'Expected nextest run' >&2; exit 1; }
  shift
  exec cargo nextest run "${packages[@]}" "$@"
fi
exec cargo "$command" "${packages[@]}" "$@"
