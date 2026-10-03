# Use gateway workflows without local skill bundles

The gateway exposes its Git-backed Agent Skills through ordinary MCP tools and
prompts. A client does not need the draft Skills extension to discover and read
them. The authoring repository remains the source of truth; these interfaces
use its existing verified catalog and individual resource reader.

## Discover and use a workflow

1. Call `gateway-skills.search` with a short task description, such as
   `{"query":"review pull request","limit":3}`. Exact skill names and returned
   URIs select only those available matches. Descriptions are previews bounded
   to 480 characters; ranking still uses complete discovery metadata.
   Select a fitting candidate without opening several workflows. Follow
   `next_cursor` with the same query and revision only when more candidates are
   needed. Omit `query` to list all workflows and follow every page for a complete
   inventory. `limit` is a positive page size and defaults to 20.
2. Call `gateway-skills.load` with the returned `uri` and `revision`.
   Read `instructions` and consult `files` for references, templates and helpers.
3. Call `gateway-skills.read_file` with a file's exact `uri` and the loaded
   `revision`. Resolve relative references against the inventory rather than
   assuming a locally installed skill directory exists.
4. If the workflow invokes another skill, find it with search using the same `revision`, then load it using
   the calling workflow's revision. A newer search result does not authorize
   substituting a newer revision during an active task.

## Retain complete instructions

Keep the complete load response together: instructions, file inventory, URI,
revision, and `document_hash`. Reuse those instructions during later task steps.
Read only the supporting references required by the selected workflow, using
their exact inventory URIs and the same revision.

When a freshness check is needed, call `gateway-skills.load` with that URI,
revision, and `known_document_hash`. An authorized, inspected unchanged response
contains `unchanged: true`, `uri`, `revision`, and `document_hash`; it omits
instructions and the file inventory. Check that its identity matches the
retained response before reusing the complete instructions. A complete response
replaces the retained content. Current access checks still apply on every call.

Hand-offs and compaction must distinguish retained metadata from available
instructions. Preserve the complete response in client memory or a governed
artifact when reliable, and keep the exact file inventory with it. If only the
hash or a summary survives, omit `known_document_hash` and request a full load
before continuing. A hash cannot recover instructions. Never accept an
`unchanged` response when the corresponding complete response is unavailable.
An unavailable revision requires explicit rediscovery and reassessment.

The executable [client retention example](../crates/waygate-mcp/examples/support/skill_client.rs)
demonstrates both states, exact supporting-file selection, and revision checks.
It is an in-memory example, not an automatic integration with a client's
compaction system. The [offline comparison](../crates/waygate-mcp/examples/skill_discovery_evaluation.rs)
runs it through the production handlers:

```sh
cargo run --locked -p waygate-mcp --example skill_discovery_evaluation
cargo test --locked -p waygate-mcp --example skill_discovery_evaluation
```

The fixture adapts published discovery descriptions with synthetic instructions
and files. It covers task descriptions, overlapping workflows, exact names and
URIs, and no-match queries. The legacy search projection is rebuilt from a
currently authorized list; both paths use the same initial load handler.
The report measures candidates, search calls before selection, response bytes,
redundant full loads, and local time to usable fixture instructions. Subsequent
reuse and necessary recovery after losing content are reported separately.
Elapsed times exclude network and model decisions and do not prove agent speed.

The tool and prompt methods require `mcp:read` or `mcp:admin`, in addition to
the applicable catalog/resource policy and profile checks. Search, skill lists,
and prompt lists include only approved skills whose root instructions the caller
may fetch and read. Filtering happens before ranking and pagination. A caller
with the read scope but no matching skill grants receives an empty list.

Load reads the selected root instructions and includes only supporting files
the caller may fetch and read. To evaluate content-bound read policies, it
verifies supporting file digests after fetch authorization, within the catalog's
file/byte limits and a 30-second inventory deadline. File reads return only
the requested resource. Text is returned in `text`, binary
content in `base64`. Programmatic clients can capture `structuredContent` and
write those bytes to their local workspace without copying them into model
context. A client must supply filesystem and execution tools for workflows
that edit local checkouts or run local helpers. Retrieval never executes code.

Pass a JavaScript file URI directly as `skill_script` to `codemode.execute`
and pass the loaded catalog revision as `skill_revision` to keep execution on
the same workflow version. Omitting `skill_revision` selects the currently
approved serving version. A requested unavailable revision fails instead of
substituting newer source. Use the same fields with `codemode.start`;
the gateway fetches the bytes without a download/re-upload
step or source text in model context. Optional `files[].code_mode_tested` reports
publisher compatibility testing, never permission. Missing, false, malformed, or
legacy metadata does not block execution. The ordinary Code Mode sandbox and
tool permissions apply. See [compatibility hints](codemode.md#optional-compatibility-hint).
The skill's instructions cannot expand the user's task authorization.

## Revisions and updates

Skill tools, prompt capabilities, the Skills extension, and workflow guidance
are advertised only when the caller can access at least one approved skill.
During initial loading they are absent; direct calls report unavailable content.
Successful changed publications use
the shared catalog-change signal to notify connected clients to refetch tools
and prompts; unrelated tool catalog changes may also prompt a harmless refetch.
Legacy clients that negotiated no prompt capability need a new session to learn
that capability after skills become available. Stateless clients can rediscover
current capabilities. Cached names do not preserve access after revocation:
reads and discovery recheck policy and approval before releasing a response.

Load returns an identity that binds the source, commit, verified tree and skill
inventory. The gateway retains the current and four previous distinct metadata
snapshots in process memory. Repeated refreshes of an unchanged catalog do not
consume retention slots. Supporting file bytes are still fetched individually.

The latest approved serving revision can be restored from Git after restart or
cache eviction. Older retained references may become unavailable when their
metadata leaves the bounded cache. Source withdrawal, quarantine, or unavailable
Git objects can also refuse a read. The gateway never substitutes pending
contents. Explicitly reload and reassess the workflow before continuing. Current
distribution approval, policy, and profile checks apply to every access,
including retained revisions. See [skill review](skill-distribution-review.md).

## Command shortcuts

`prompts/list` advertises names such as
`gateway-skills:tutorial:summarize-items`. `prompts/get` accepts an optional `task`
argument and returns the selected current workflow, its revision and file
inventory. Opening a prompt supplies instructions; it does not perform the
workflow or grant permission for its actions.

Claude Code documents MCP prompts in its slash-command menu. Cursor documents
MCP prompt support. Codex's native skill picker is distinct from MCP tool
search; the presence of gateway skill tools does not promise native `$skill`
entries. Client-specific UI presentation must be checked on the installed
client version. A local shim, when desired for a native picker, should contain
only discovery metadata and loading instructions, never a maintained copy of
the workflow itself.

Protocol contract tests cover delivery, authorization and inspection refusals,
and revision retention. They do not establish model selection behavior or
command UI support in any particular client release. Keep local bundles until
fresh-session verification with those bundles disabled establishes the desired
replacement behavior. See the [recorded client checks and optional native-menu shims](skills-client-verification.md).

## Sources

- [Codex skill discovery](https://learn.chatgpt.com/docs/build-skills)
- [Claude Code MCP commands](https://code.claude.com/docs/en/mcp#use-mcp-prompts-as-commands)
- [Cursor MCP capabilities](https://cursor.com/docs/mcp)
- [Git source and integrity](skills-git-source.md)
