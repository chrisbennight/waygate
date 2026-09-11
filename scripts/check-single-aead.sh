#!/usr/bin/env bash
# Fail if any code outside waygate-oidc's aead module touches aes-gcm
# directly. Fast, compile-free CI tripwire (image.yml).
#
# Why it exists: before consolidation, two independent AES-256-GCM envelope
# implementations existed — the session-cookie codec in waygate-oidc and the
# upstream-token keyring in waygate-as — with the same `nonce || ct || tag`
# framing but divergent nonce RNG sources. Security-relevant framing must have exactly one
# implementation: `waygate_oidc::aead::{seal, open, cipher}`. Callers name
# the cipher type via the module's re-export and never depend on the
# aes-gcm crate themselves, so a new hand-rolled envelope can't slip in.
#
# What to do instead of adding a direct dependency:
# `use waygate_oidc::aead::{self, Aes256Gcm};` and call seal/open/cipher.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allowed_rs="crates/waygate-oidc/src/aead.rs"
allowed_toml="crates/waygate-oidc/Cargo.toml"

fail=0

# 1. No `aes_gcm` use/path references outside the shared module.
rs_hits="$(
  grep -rnE 'aes_gcm(::|\b)' "$repo_root/crates" --include='*.rs' \
    | grep -v "$allowed_rs" || true
)"
if [ -n "$rs_hits" ]; then
  {
    echo "ERROR: direct aes_gcm reference(s) outside $allowed_rs —"
    echo "use waygate_oidc::aead::{seal, open, cipher, Aes256Gcm} instead:"
    echo "$rs_hits" | sed 's/^/  /'
  } >&2
  fail=1
fi

# 2. No crate other than waygate-oidc declares the aes-gcm dependency —
#    including under a renamed key (`gcm = { package = "aes-gcm", ... }`),
#    which would defeat the source-level aes_gcm grep above because the
#    use sites would say `gcm::` instead of `aes_gcm::`.
toml_hits="$(
  grep -rnE '(^[[:space:]]*aes-gcm[[:space:]]*[=.])|package[[:space:]]*=[[:space:]]*"aes-gcm"' \
    "$repo_root/crates"/*/Cargo.toml \
    | grep -v "$allowed_toml" || true
)"
if [ -n "$toml_hits" ]; then
  {
    echo "ERROR: aes-gcm dependency declared outside $allowed_toml —"
    echo "depend on waygate-oidc and use its aead module instead:"
    echo "$toml_hits" | sed 's/^/  /'
  } >&2
  fail=1
fi

[ "$fail" -eq 0 ] || exit 1
echo "check-single-aead: OK (aes-gcm confined to waygate-oidc/src/aead.rs)"
