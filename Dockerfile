# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# Multi-stage build: cargo-chef for dependency caching, distroless final.
#
# CARGO_PROFILE / BINARY_SUBDIR control the cargo build profile:
#   * release / release  — default. What CI publishes; what production runs.
#                          The release binary rejects GATEWAY_AUTH_MODE=disabled
#                          at config parse (Config::from_env in
#                          crates/waygate-server/src/config.rs bails when
#                          auth_mode == Disabled and !cfg(debug_assertions)).
#                          The synthetic-admin code in waygate-oidc is itself
#                          compiled into every binary; the security boundary
#                          is "release binary refuses the mode at config
#                          parse," not "the synthetic-principal code does
#                          not exist in release."
#   * dev     / debug    — used by docker-compose.yml for local development
#                          so the documented `docker compose up --build`
#                          workflow keeps working with AUTH_MODE=disabled.
#
# BINARY_SUBDIR selects the compiled profile directory without overriding
# Cargo's CARGO_TARGET_DIR environment variable. Build and COPY paths must agree.
# See docs/deployment.md for supported build profiles.

# RUST_VERSION pins the rust base image. Keep this aligned with the
# stable channel `rust-toolchain.toml` resolves to at build time — if
# the base lags, rustup downloads the newer compiler inside the
# container on every build (~15s wasted) AND introduces a subtle
# fingerprint-skew source between the cook and build steps. Bump in
# lockstep when stable advances.
ARG RUST_VERSION=1.95
ARG DEBIAN_CODENAME=bookworm

FROM rust:${RUST_VERSION}-${DEBIAN_CODENAME} AS chef
# Nested build containers cannot reliably detect the enclosing runner's quota.
# All derived build stages inherit the explicit job limit when one is supplied.
ARG CARGO_BUILD_JOBS
# Pin recipe generation and use --bin so dependency cooking does not create a
# dummy gateway binary whose fingerprint could suppress the final link step.
RUN cargo install cargo-chef --locked --version 0.1.77
WORKDIR /app

FROM chef AS planner
COPY . .
# `--bin gateway-server` slims the generated recipe to gateway-server's
# dependency closure. REQUIRED — it's the half of the fix that takes
# the dummy-bin path out of cook entirely (see chef install comment).
RUN cargo chef prepare --recipe-path recipe.json --bin gateway-server

FROM chef AS builder
ARG CARGO_PROFILE=release
# BINARY_SUBDIR is a PATH SUFFIX only (release vs debug, matching
# cargo's profile-to-output-dir mapping); it is NOT cargo's
# CARGO_TARGET_DIR env var. See top-of-file comment for why the
# rename matters.
ARG BINARY_SUBDIR=release
# Cook and build must see the same rustc; copying the toolchain file before
# cook avoids a rustup switch after `COPY . .` that would invalidate all deps.
COPY rust-toolchain.toml ./
COPY --from=planner /app/recipe.json recipe.json
# `--bin gateway-server` matches the planner above. cargo-chef cooks
# only gateway-server's dep closure as rlibs — NO dummy binary at
# `target/release/gateway-server`. The real `cargo build` below
# therefore has no cached link step to falsely-resume from, so it
# always fresh-links the bin. The release/dev split stays because
# cargo-chef still uses `--release` as its profile selector flag.
RUN if [ "${CARGO_PROFILE}" = "release" ]; then \
        cargo chef cook --release --recipe-path recipe.json --bin gateway-server; \
    else \
        cargo chef cook --recipe-path recipe.json --bin gateway-server; \
    fi
COPY . .
RUN cargo build --profile ${CARGO_PROFILE} --bin gateway-server
# `strip` is best-effort — the release profile's `strip = "symbols"` already
# handles symbol removal, and dev binaries deliberately keep them. Keep
# this as its own RUN so the `|| true` can't mask a `cargo build` failure
# (shell parses `cmd1 && cmd2 || true` as `(cmd1 && cmd2) || true`).
RUN strip /app/target/${BINARY_SUBDIR}/gateway-server || true

# Staged file-transfer bytes land here when an operator points
# GATEWAY_FILE_STORAGE_DIR at the conventional path. The directory is built
# here because the distroless runtime has no shell to mkdir with; it is
# copied into the runtime stage owned by nonroot below.
RUN mkdir -p /image-owned/var/lib/mcp-gateway/files

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e AS runtime
# ARG must be re-declared per stage; the value is inherited from the build
# command, not from the builder stage above.
ARG BINARY_SUBDIR=release
WORKDIR /app
COPY --from=builder /app/target/${BINARY_SUBDIR}/gateway-server /usr/local/bin/gateway-server

# Upstream server manifests are deliberately NOT baked. Like the Cedar policies below,
# the served set is operator-managed and supplied at runtime via the NFS volume
# mounted at GATEWAY_SERVERS_DIR, so the published image ships NONE: a different
# deployment carries its own upstreams instead of this repo's (the portability
# goal). A missing/unreadable servers dir fails loud rather than silently serving
# "zero upstreams"; the tool-facts catalog persists in Postgres across restarts
# and the ~20s poll reconciles it from the NFS set. The build-mcp-gateway boot
# smoke's hardened-boot attempts run with an empty servers mount (zero upstreams
# = hermetic); its reachability phase bakes ONE fixture manifest into a derived
# smoke-only image, the same way it bakes policies, so the gate can prove the
# image actually dials an upstream rather than merely starting. The published
# image ships neither. Representative manifests for the loader/schema test live
# in crates/waygate-upstream/tests/fixtures/servers/.
# Cedar policies are likewise deliberately NOT baked. They are the live
# authorization set, supplied at runtime by a persistent runtime volume mounted at
# GATEWAY_POLICIES_DIR so dashboard/REST edits survive a restart (see
# docs/server-config-source-of-truth.md).
# Policies have NO image-baked fallback ON PURPOSE: an empty or absent policy set
# must fail closed (recover from the policy_bundles ledger, or refuse to boot)
# rather than silently serve a stale baked authorization set.
# The in-repo policy set is a synthetic CI/test and local-evaluation example
# (at crates/waygate-authz/tests/fixtures/policies/), NOT the live source or a
# deployment seed. The build-mcp-gateway boot smoke bakes it into a SMOKE-ONLY
# derived image
# (FROM this image + COPY policies/) — a DinD bind mount can't reach the job's
# files — so the published image stays de-baked while the smoke still boots a
# valid example policy set. Prod supplies policies via the runtime volume at
# GATEWAY_POLICIES_DIR.
# Admin dashboard static assets (css, js, Lucide sprite, fonts). The
# dashboard router serves these via tower-http ServeDir at runtime; the
# distroless image has no source tree, so resolving through CARGO_MANIFEST_DIR
# at build time would 404 in prod. GATEWAY_STATIC_DIR points the router here.
COPY --chown=nonroot:nonroot crates/waygate-admin/static/ /etc/mcp-gateway/static/
COPY --chown=nonroot:nonroot THIRD_PARTY_LICENSES.md /etc/mcp-gateway/static/THIRD_PARTY_LICENSES.md

# Keep the project's grants and every bundled notice in the conventional image
# license directory as well. This path remains available when an operator
# extracts the distroless image without running the HTTP service.
COPY --chown=nonroot:nonroot LICENSE-APACHE THIRD_PARTY_LICENSES.md /usr/share/licenses/mcp-gateway/

# The conventional GATEWAY_FILE_STORAGE_DIR, shipped empty and owned by the
# user this image runs as.
#
# It exists for its ownership, not its contents. Docker initializes a fresh
# named volume from the image's directory at the mount point, ownership
# included; with no directory here it creates the mount point root-owned
# instead, and the gateway cannot stage a byte into a volume it may not write.
# Nothing in the file plane recovers from that — the transfer authorizes, the
# client streams, and staging fails at the last step with a permission error.
#
# This covers the conventional path only. An operator pointing
# GATEWAY_FILE_STORAGE_DIR somewhere else owns that path's permissions, and a
# volume already created root-owned stays that way: the image seeds a fresh
# volume, it does not repair an existing one.
COPY --from=builder --chown=nonroot:nonroot /image-owned/var/lib/mcp-gateway/files /var/lib/mcp-gateway/files

USER nonroot:nonroot
EXPOSE 8080

ENV GATEWAY_LISTEN_ADDR=0.0.0.0:8080 \
    GATEWAY_LOG_LEVEL=info \
    GATEWAY_SERVERS_DIR=/etc/mcp-gateway/servers \
    GATEWAY_POLICIES_DIR=/etc/mcp-gateway/policies \
    GATEWAY_STATIC_DIR=/etc/mcp-gateway/static

ENTRYPOINT ["/usr/local/bin/gateway-server"]
