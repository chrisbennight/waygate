# Discover and use verified workflows

Skills package task instructions with references, templates, and optional
helpers. The gateway serves a reviewed Git-backed catalog so a client can load
one workflow and only the supporting files it needs. Local workflow copies are
not required for MCP delivery.

## Follow one revision

1. Search `gateway-skills.search` with a task description. Follow `next_cursor`
   when more results are available.
2. Pass a selected result's exact `uri` and `revision` to `gateway-skills.load`.
3. Read its instructions and file inventory. Load supporting files with
   `gateway-skills.read_file`, using the same revision and returned file URI.
4. When a workflow references another skill, discover and load it at that
   revision. If the revision is no longer available, reload and reassess rather
   than silently substituting newer instructions.

A compatible JavaScript helper can be submitted directly to `codemode.execute`
using `skill_script` and `skill_revision`, plus separate `input`. The gateway
loads its verified source without a download/re-upload round trip or putting
the helper text in model context. See [Code Mode](code-mode.md).

## Work through a synthetic source

The [summarize-items skill](../../examples/skills/summarize-items/SKILL.md)
includes a supporting format reference and a JavaScript helper. Publish the
`examples/skills` directory into a disposable Gitea-compatible repository you
control, preserving that path. This repository is test content, not a live
workflow collection. Configure an isolated authenticated gateway with review
storage and the following metadata, replacing the example host and repository:

```text
GATEWAY_SKILLS_GIT_API_URL=https://git.example.com/api/v1
GATEWAY_SKILLS_GIT_REPOSITORY=example/tutorial-workflows
GATEWAY_SKILLS_GIT_ROOTS=examples/skills
GATEWAY_SKILLS_GIT_REF=main
GATEWAY_SKILLS_SOURCE_ID=tutorial
GATEWAY_SKILLS_REFRESH_INTERVAL_SECONDS=300
```

For this update exercise, omit expected-commit/tree pins; those deliberately
prevent a moving reference from accepting different source. A private source
also needs the read-only token reference described below. Restart to load
environment settings, wait for indexing, and review **summarize-items** in the
dashboard's **Skills** page. Its first candidate is pending. Approve its exact
inventory and record a reason before expecting client delivery.

Search with `{"query":"summarize synthetic work items"}`. Save the returned
revision as **A**. Load its returned URI at A, then read the inventory's
`references/output.md` URI at A. It says "revision A". Execute the inventory's
[summarize.js helper](../../examples/skills/summarize-items/scripts/summarize.js)
URI using `skill_script`, `skill_revision: A`, and:

```json
{"items":[{"status":"open"},{"status":"closed"},{"status":"open"}]}
```

The helper returns `{"total":3,"by_status":{"open":2,"closed":1}}` with
zero connector calls. The namespace is chosen by this tutorial; copy actual
URIs and revision values from responses rather than constructing them.

Now change "revision A" to "revision B" in the supporting reference, commit,
and push to the disposable source. After refresh, the dashboard shows a new
pending candidate while the approved A content continues to serve. Rejecting B
also preserves A. To proceed, approve the reviewed B candidate, search/load
again, and read the reference at the returned revision **B**; it now says B.

For an unavailable-revision check, call `read_file` with that same URI and
`revision` set to `sha256:` followed by 64 zeroes. It must refuse with
"Skill or revision unavailable", rather than return B under that identity.
Real old revisions are subject to cache retention, source availability, and
current distribution eligibility; A is not promised to remain readable after
an update. Quarantine the skill and confirm that current and retained reads
are refused. Re-approve only the exact content intended for further use.

## Review content separately from execution authority

The source adapter verifies Git object identities and file inventory, and
fetches supporting bytes on demand. Distribution review decides which exact
contents a tenant may retrieve. New candidates are pending; an update awaiting
review preserves the previously approved version. Quarantine prevents further
retrieval even when an old approval exists. Review decisions are version-bound
and recorded with their actor and reason.

Those checks establish source identity and distribution approval. They do not
prove that instructions are harmless, expand the user's task authorization,
or grant the script more tool permissions. Code Mode rechecks the caller's
ordinary authority for every nested call. The optional `code_mode_tested`
flag reports publisher testing only; it is neither approval nor a guarantee.

## Configure a catalog

Supply an explicit stable `GATEWAY_SKILLS_SOURCE_ID`, source API, repository,
reference, and roots as described in [Git source configuration](../skills-git-source.md).
The current adapter uses a Gitea-compatible API. Configure durable review
storage and approve candidate contents through **Skills** in the dashboard.
Unavailable review storage refuses distribution instead of auto-approving it.
Git credentials remain deployment secrets; public sources can be anonymous.

Ordinary skill tools and MCP prompts provide the portable client path. The
optional Skills extension is an additional projection. A client's native skill
picker or slash-command UI depends on that client; fetching an MCP prompt does
not execute its instructions. See [client delivery](../skills-client-delivery.md).

The gateway retains a bounded set of recent metadata revisions. The approved
serving revision can be restored after restart, but deleted Git objects,
quarantine, or eviction can make older references unavailable. Revision pinning
means refusing substitution, not promising indefinite archival access.

See the [Agent Skills specification](https://agentskills.io/specification),
[source integrity contract](../skills-git-source.md#acquisition-and-integrity),
and [distribution-review contract](../skill-distribution-review.md) for the
format, verification, and decision boundaries.
