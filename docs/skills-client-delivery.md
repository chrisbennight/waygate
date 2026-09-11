# Use gateway workflows without local skill bundles

The gateway exposes its Git-backed Agent Skills through ordinary MCP tools and
prompts. A client does not need the draft Skills extension to discover and read
them. The authoring repository remains the source of truth; these interfaces
use its existing verified catalog and individual resource reader.

## Discover and use a workflow

1. Call `gateway-skills.search` with a short task description, such as
   `{"query":"review pull request"}`. Omit `query` to list all workflows.
   Follow `next_cursor` with the same query until it is absent.
2. Call `gateway-skills.load` with the returned `uri` and `revision`.
   Read `instructions` and consult `files` for references, templates and helpers.
3. Call `gateway-skills.read_file` with a file's exact `uri` and the loaded
   `revision`. Resolve relative references against the inventory rather than
   assuming a locally installed skill directory exists.
4. If the workflow invokes another skill, find it with search using the same `revision`, then load it using
   the calling workflow's revision. A newer search result does not authorize
   substituting a newer revision during an active task.

The tool and prompt methods require `mcp:read` or `mcp:admin`, in addition to
the applicable catalog/resource policy and profile checks. Search advertises
metadata; load reads the selected root instructions; file reads acquire only
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

When a Git skill source is configured, fixed tools and the prompt capability
remain advertised during initial loading or an outage. Calls report unavailable
content until a verified snapshot exists. Successful changed publications use
the shared catalog-change signal to notify connected clients to refetch tools
and prompts; unrelated tool catalog changes may also prompt a harmless refetch.

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
