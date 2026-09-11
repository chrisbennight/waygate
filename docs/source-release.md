# Build and publish from the source repository

The source repository owns the gateway image and helper releases. Deployment
repositories select an immutable published image and own their rollout,
configuration, secrets, and recovery. Source workflows have no deployment hook.

## GitHub publication

The [image workflow](../.github/workflows/image.yml) runs source tests with
PostgreSQL, builds the hardened image, and smoke-tests the exact local image
before publication. The trigger determines which registry tags it publishes:

| Trigger | Publication |
| --- | --- |
| Pull request or manual dispatch | None; build and smoke only |
| Push to `main` | `sha-<full-commit>` and `edge` |
| Push `v<version>` with a prerelease, such as `v0.2.0-rc.1` | Full version only, such as `0.2.0-rc.1` |
| Push a stable tag, such as `v0.2.0` | Full version; also `latest` if newer than the current stable image |

Release tags must match `workspace.package.version` in `Cargo.toml`, and their
commit must be reachable from `main`. Versions use semantic versioning without
build metadata (`+...`), which container tags cannot represent. Helper tags use
a separate `mcp-files-v` namespace and never trigger gateway image publication.

Use `edge` to follow main and `latest` for the newest stable release.
Deployments should use the published digest rather than either channel.
A SHA tag is a source locator, not a promise of byte-for-byte reproducible builds.

The publication job is serialized across main and release runs, including the
registry checks and writes. CI must be the sole writer of these package tags:
GHCR does not enforce conditional tag updates. Do not write tags manually alongside this workflow. GitHub can replace an older pending
job in a concurrency group; rerun a canceled release after the active publisher
finishes. Running publication jobs are not canceled by newer runs.

A version image that already exists stops publication instead of being replaced.
On interrupted publication, inspect the version image, its source/release labels,
the run's smoke results, and any GitHub draft before recovery. Preserve the
published digest and finish missing release notes or channel updates through a
reviewed recovery change; rebuilding and rerunning is not an overwrite mechanism.
A failure to authenticate or read registry metadata also stops publication.
Successful releases record the source commit and image digest in GitHub notes.

The job uses the repository's short-lived identity with `packages: write` and
`contents: write`; build-only jobs retain read-only repository permissions. No
home secret provider is required. Protect `main` and release tags, restrict
package writers, and configure private package read access separately. These
hosting settings are not enabled by committing a workflow file.

The [helper release workflow](../.github/workflows/release-mcp-files.yml)
builds Linux amd64/arm64, Windows amd64, and macOS arm64 artifacts on PRs,
manual dispatches, and `mcp-files-v<version>` tag pushes. Only tag pushes publish.
The tag, `release/mcp-files.version`, and workspace version must agree. Native runners verify
their executable, and the publication job collects checked artifacts, verifies SHA-256 checksums, and
attaches binaries and license notices to a `mcp-files-v<version>` release.
Build jobs have read-only repository permissions; only publication receives
`contents: write`. The workflow consumes the pushed tag and never creates or
moves it. Prerelease helper versions are marked as GitHub prereleases; helper
releases never change the repository's latest release. Enable immutable releases
and protect `v*` and `mcp-files-v*` tags from updates/deletion before production
release publication.
These controls prevent another writer from changing a tag during a build.

The release command refuses an existing release instead of overwriting assets.
If publication is interrupted, inspect any draft and tag before retrying;
reconcile the partial release against the run's exact commit and checksums.
Do not silently replace an already published version. GitHub's
[release command documentation](https://cli.github.com/manual/gh_release_create)
explains draft creation, asset upload, and immutability.

## Prepare and trigger a release

1. Open a release PR that updates `workspace.package.version` in `Cargo.toml`
   and `release/mcp-files.version` together, plus release notes describing the
   user-visible changes. Keep workspace crates on the shared version.
2. Refresh `Cargo.lock` with Cargo and regenerate the consolidated third-party
   notice with [`scripts/generate-rust-licenses.sh`](../scripts/generate-rust-licenses.sh)
   when the license guard reports it stale. Include the resulting metadata in the PR.
3. Run the release tests, normal source checks, and helper platform builds.
   Obtain AERB review of the current head and merge after GitHub CI passes.
4. Push `v<version>` pointing to that merged commit for the gateway image, and
   `mcp-files-v<version>` pointing to the same commit when publishing the helper.
   Tag creation is the deliberate release action; merging the version PR does
   not publish either versioned release. Do not move or reuse release tags.
5. Wait for the release workflows, check the image digest and helper checksums,
   and verify authenticated access from a private consumer before rollout.

An authenticated Git push triggers the workflows. If automating
release creation in Actions, tags pushed with the default `GITHUB_TOKEN` do not
start another push workflow. Use an appropriately scoped GitHub App identity or
an explicit workflow dependency instead of relying on that event chain.

The Actions page's **Run workflow** option runs image verification without
publication. Helper manual dispatch likewise only verifies builds, and an
optional version input must agree with the checked-out workspace. These are
useful checks before deliberately pushing a release tag.

## Container update checks

GitHub CI runs the repository's [threat scanner](../scripts/threat-gate/).
For Renovate container updates it resolves Dockerfile defaults and Compose
image defaults, compares current and candidate Grype findings, and applies the
configured severity and CISA Known Exploited Vulnerabilities policy. Required
KEV retrieval fails closed. Unresolvable build-time image values are reported
as skipped; this is not a general scan of every runtime image or Rust advisory.

The scanner and its tests are maintained with this repository. To run the
isolated tests, install the hashed requirements into a virtual environment and
run pytest, or use the included public-index uv lock. The scanner uses the
[Grype project](https://github.com/anchore/grype) and
[CISA KEV feed](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
Infrastructure-specific mirrors, cache addresses, and runner labels belong in
the consuming deployment's configuration.
