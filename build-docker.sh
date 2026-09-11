#!/usr/bin/env bash
# Build a source-tagged image without publishing. CI smokes this exact local
# image before assigning any registry channels or release versions.
set -euo pipefail

image="${GATEWAY_IMAGE_REPOSITORY:?GATEWAY_IMAGE_REPOSITORY is required}"
platform="${GATEWAY_IMAGE_PLATFORM:-linux/amd64}"
source_sha="$(git rev-parse HEAD)"
tag_pinned="${image}:sha-${source_sha}"

# Export the exact tags so later workflow steps (boot-smoke, push) act on this
# build without recomputing a fresh timestamp.
if [ -n "${GITHUB_ENV:-}" ]; then
  {
    echo "GATEWAY_IMAGE_PINNED=${tag_pinned}"
  } >> "$GITHUB_ENV"
fi

build_args=()
if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
  build_args+=(--build-arg "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS")
fi

sudo docker build "${build_args[@]}" --platform "$platform" . \
  --file ./Dockerfile \
  --label "org.opencontainers.image.revision=$source_sha" \
  --label "io.waygate.release.version=${GATEWAY_RELEASE_VERSION:-}" \
  -t "$tag_pinned"

echo "Built (not published): $tag_pinned"
echo "Publishing happens in repository CI, after the smoke gates."
