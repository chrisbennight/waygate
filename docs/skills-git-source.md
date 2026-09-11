# Agent Skills from Git

The gateway can expose Agent Skills directly from an external Git repository.
The authoring repository remains the source of truth: it is not copied into
this repository, mirrored into another package system, cloned into the
container, or downloaded in full.

This design follows the Agent Skills progressive-disclosure model. A refresh
resolves one Git revision, reads its tree, and fetches only each discovered
`SKILL.md` so the gateway can validate skill metadata and offer it for distribution review. Scripts,
references, examples, and assets are fetched individually from that same
revision only when a caller requests the corresponding resource or an operator
selects it for privileged review. The
gateway keeps an in-memory metadata index; it does not maintain a working tree
or persistent content cache.

## Configuration

Set these values to enable the source:

- `GATEWAY_SKILLS_GIT_API_URL`: the HTTPS base URL of a Gitea-compatible API,
  such as `https://gitea.example/api/v1`;
- `GATEWAY_SKILLS_GIT_REPOSITORY`: the `owner/repository` containing the
  skills;
- `GATEWAY_SKILLS_GIT_ROOTS`: comma-separated repository paths under which
  `SKILL.md` files may be discovered;
- `GATEWAY_SKILLS_GIT_REF`: branch, tag, or commit to resolve, defaulting to
  `main`;
- `GATEWAY_SKILLS_SOURCE_ID`: the lower-case namespace used in `skill://`
  URIs; required explicitly so the deployment chooses its own stable identity;
- `GATEWAY_SKILLS_GIT_EXPECTED_COMMIT`: optional full lower-case Git commit ID
  that the resolved ref must equal;
- `GATEWAY_SKILLS_GIT_EXPECTED_TREE`: optional full lower-case Git root-tree
  object ID that the resolved ref's content must equal; and
- `GATEWAY_SKILLS_REFRESH_INTERVAL_SECONDS`: refresh cadence, defaulting to
  300 seconds, or `0` to index once for the process lifetime.

When upgrading a deployment that relied on the former `homelab` default, set
`GATEWAY_SKILLS_SOURCE_ID=homelab` explicitly to preserve existing URIs and
policy identities. Choose a different namespace for a new deployment. Changing
an existing namespace requires updating consumers and policies that reference
the old `skill://` URIs. See [integration configuration](integration-configuration.md).

Public repositories need no credential. For a private repository,
`GATEWAY_SKILLS_GIT_TOKEN_ENV` names the environment variable containing a
read-only Git service token. It is an environment-variable reference, not the
token value. The client adds that token only to same-origin API calls, refuses
redirects, never puts it in a URL, and redacts request failures.

The two assertions cover different operator decisions. An expected commit
requires a branch or tag to resolve to the selected revision and preserves that
revision in policy and audit evidence. The gateway loads the tree named by that
commit and rejects root bytes that do not recompute to the named tree object ID.
An expected tree independently binds the repository content to
`git rev-parse '<ref>^{tree}'`; content changes then fail refresh while the last
accepted snapshot continues to serve. A deployment may use either assertion or
both. The tree assertion is the stronger rug-pull control for bytes because it
does not rely on commit metadata projected by the API.

The gateway explicitly asks Gitea for `<commit>^{tree}`. Gitea can accept a
bare commit at the tree endpoint while echoing the commit ID in the response
metadata, even though the returned entries belong to the root tree. Explicit
dereferencing makes the response name the tree object, which the gateway then
recomputes and verifies locally.

## Acquisition and integrity

The source uses the service's read-only Git API:

1. resolve the configured ref, load the tree named by its commit, and recompute
   that root-tree object ID from the non-recursive API response;
2. resolve each configured root to its tree object without recursively reading
   unrelated repository paths;
3. recursively read only those configured-root trees, recompute every tree
   object ID, and locate `SKILL.md` files beneath them;
4. fetch and validate those root files; and
5. publish the resulting metadata snapshot atomically.

The index records each regular file's Git object ID, byte length, media type,
repository path, and `skill://` URI. Symlinks, submodules, path traversal,
ambiguous nested skill roots, overlapping configured roots, malformed object
IDs, and files outside a skill root are refused. All API responses are bounded
before parsing. Tree expansion admits path segments, full paths, nesting depth,
entry count, and cumulative stored path bytes before allocating joined paths.
Resource reads request the recorded blob by object ID and locally recompute the
Git blob ID from the decoded bytes. An echoed ID or a same-length response is
not accepted as integrity evidence.

The resolved commit and locally verified root tree are both carried through
catalog identity, Cedar policy facts, audit targets, skill revision and
approval bindings, and Code Mode evidence. The tree binds configured
descendants to their tree and blob object IDs, so the optional tree pin covers
content without relying on commit metadata returned by the API. Resource
evidence additionally carries the repository path and Git blob identity. When
bytes are actually read, the gateway computes their SHA-256 content digest
before the access decision and reuses those same verified bytes for the
response. The gateway does not fetch every supporting file merely to compute
SHA-256 values for discovery.
Instead it advertises the SEP-2640 `resources: "dynamic"` form. This is the
standards-compatible way to preserve progressive disclosure when the backing
source does not already provide the extension's SHA-256 resource manifest.

Configured commit and tree pins constrain new catalog observations. Recovery of
an approved historical revision instead verifies the exact commit and tree in
its persisted review record. Advancing the current pins therefore preserves the
previously approved contents while replacement contents await review.

Gateway-owned skill URIs remain isolated from upstream MCP resources. A
manifest-declared upstream prefix that overlaps a skill resource prevents the
skill catalog from being listed. For legacy resource providers without URI
claims, the gateway's published `skill://` URI remains authoritative and a
skill read does not enumerate those providers. An unrelated legacy catalog, an
undeclared matching URI, or a legacy provider outage therefore cannot disable
the gateway-owned skill namespace.

The existing Agent Skills limits from SEP-2640 remain validation boundaries.
They come from the draft specification rather than locally invented success
criteria. Before fetching any root document, the Git adapter also rejects a
catalog whose declared skill count or aggregate `SKILL.md` bytes exceed its
in-memory metadata budget. The same byte budget is checked again as root blobs
are decoded. Limits on Git tree and HTTP response processing separately
protect the gateway from an unexpectedly large or hostile source.
Blob acquisition also has a process-wide admission boundary. A request that
cannot obtain a slot fails before outbound I/O or response allocation, so
concurrent permitted reads cannot multiply source requests and maximum-sized
decode buffers without bound. Base64 whitespace is removed in place rather
than copied into another full-size string before decoding.

## Availability

Skill acquisition is optional and is never a gateway startup dependency. The
listener starts after local configuration is validated, then the source is
indexed in a supervised task. A cold-start source failure leaves the Skills
extension absent and reports `source_unavailable` in readiness detail while
the gateway remains ready for its other work.

A later successful refresh atomically publishes the new metadata snapshot. A
network failure, unavailable credential, mismatched pin, malformed response,
invalid skill, or timeout keeps the last accepted snapshot. Client discovery
selects approved contents. After restart or cache eviction it may restore an
approved metadata revision from Git; metadata already in the bounded cache
requires no Git request. A standard `resources/read` for a supporting file
performs a bounded blob read from the exact selected revision; a failure returns an error for that resource without affecting
gateway readiness. Readiness reports `degraded` while the last accepted
snapshot is serving after a failed refresh, and returns to `ok` after the next
successful refresh.

Standard MCP tools and prompt shortcuts also expose this catalog to clients
without the Skills extension. See [client delivery](skills-client-delivery.md).

## MCP and execution boundaries

New and changed skill contents require a tenant-scoped distribution decision.
The dashboard's Skills page provides exact candidate review, approval, rejection,
and quarantine. Until an update is approved, clients retain the previously
approved contents when those files remain available. See
[distribution review](skill-distribution-review.md) for recovery and revocation.


The gateway advertises the experimental
`io.modelcontextprotocol/skills` extension only while a snapshot exists.
`skills/list` and `skills/get` expose validated frontmatter and the dynamic
resource declaration. Individual files use ordinary MCP `resources/read` and
retain their media type. Explicit upstream URI reservations cannot overlap the
gateway skill catalog; undeclared legacy catalogs do not override a published
gateway skill URI. Skill reads apply the existing Cedar authorization,
inspection, and audit path.

A resource read has two authorization decisions because its SHA-256 does not
exist until the one requested blob has been fetched. First, API-key profile
admission and the Cedar `FetchSkillResource` action evaluate the immutable
repository revision, skill revision, path, and Git object ID. A refusal at
this stage performs no supporting-blob request and its audit target does not
claim a content digest. Approved metadata recovery may already have consulted
the configured Git source. Only after the fetch permit does the gateway fetch and verify the
blob. The Cedar `ReadSkill` action then evaluates the same provenance plus the
SHA-256 of the exact bytes that would be returned. Policies that allow dynamic
supporting resources therefore permit both actions at their respective trust
boundaries; the representative policy fixture shows the source-wide form.

Serving a skill supplies untrusted content to a model. It does not activate the
skill, trust its instructions, grant any tool, or make a script executable.
The `allowed-tools` field remains producer metadata. Code Mode can load a
UTF-8 JavaScript file directly by its `skill://` URI using the caller's ordinary
execution authority, without a separate script grant. Optional compatibility
metadata reports publisher testing and never controls execution. Calls made by
the script return to the ordinary governed invocation pipeline. See
[compatibility hints](codemode.md#optional-compatibility-hint).

## Why this design

Git already supplies review history, object-addressed trees and files, and the
repository structure used by Agent Skills. Adding a second
release package and registry authentication path duplicated the content,
created a new credential and availability dependency, and defeated the
format's progressive-disclosure purpose. Direct read-only Git access keeps one
source of truth. Optional commit and tree assertions add independent deployment
control without forcing that extra machinery on every installation.

## Research references

- [Agent Skills specification and progressive disclosure](https://agentskills.io/specification)
- [SEP-2640 Skills extension pull request and discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2640)
- [Pinned SEP-2640 draft text](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/753b9f2be43e07fdd070e535d75f190cff14beea/seps/2640-skills-extension.md)
- [Skills Over MCP working-group repository](https://github.com/modelcontextprotocol/experimental-ext-skills)
- [MCP Skills capability proposal](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2167)
- [MCP first-class Skills proposal](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2405)
- [MCP executable-resource proposal](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1632)
- [MCP executable-resource discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/1636)
- [MCP Resources specification](https://modelcontextprotocol.io/specification/2025-06-18/server/resources)
- [Gitea API documentation](https://docs.gitea.com/api/1.24/)
- [Git object model](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)
- [Git data model and object-name integrity](https://git-scm.com/docs/gitdatamodel)
- [OpenAI MCP skill import guidance](https://developers.openai.com/plugins/build/mcp-server#import-skills-from-the-mcp-server)
- [OpenAI skill bundle guidance](https://developers.openai.com/plugins/build/skills)
- [Agent Skills prompt-injection research](https://arxiv.org/abs/2510.26328)
- [Agent Skills in the Wild](https://arxiv.org/abs/2601.10338)
