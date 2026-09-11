# Coding-client verification of central workflows

## What was tested

The installed clients were tested on 2026-09-05 and 2026-09-06 against the production
`GatewayServer` and `SkillTools` handlers, served by the loopback-only
[synthetic fixture](../crates/waygate-mcp/examples/skill_client_fixture.rs).
This establishes client behavior against the candidate implementation, not a
production rollout or compatibility with every workflow's local dependencies.

The fixture supplies a release-check workflow, a checklist reference, a small
Python helper, and a called signoff workflow with its own reference. A successful
execution reports the checklist and signoff markers and actually runs the
retrieved helper. The markers are absent from the initial task and discovery
metadata, so a successful response requires loading supporting files. Tool
transcripts were checked for the reads, helper exit status, and shared catalog
revision; a model's final summary alone was not treated as proof.

| Client | Verified behavior | Limits |
| --- | --- | --- |
| Codex CLI 0.153.2 | Natural-language discovery, root instructions, references, downloaded helper execution, and called skill at the same revision. | Used an isolated configuration and temporary workspace. This does not establish a native MCP-prompt menu. |
| Claude Code 2.1.233 | With `claude-sonnet-5`, completed discovery, instructions, references, downloaded helper execution, and the called skill at one revision. Listed generated MCP slash commands with local skills disabled. | The initial default `claude-fable-5` run hit its usage-credit limit. The successful run used the supported `--model sonnet` session override; account settings were unchanged. |
| Cursor Agent 2026.08.25-3e8eec8 | Natural-language discovery, instructions, references, downloaded helper execution, and called skill at the same revision. Read-only Ask mode also completed the reference flow. | Used configured execution controls and automatic tool approval review. Explicit execution-sandbox mode could not start in this environment. Native prompt-menu presentation was not tested. |

A separate Codex run invoked `$orchard-release-check` from generated project
`.agents/skills/` shims and completed the same workflow through gateway reads.
This verifies explicit native skill invocation; interactive menu rendering was
not exercised.

Existing locally installed bundles were not uninstalled. Codex used
`--ignore-user-config`; Claude used `--disable-slash-commands`,
`--setting-sources ""`, and `--strict-mcp-config`. Cursor's personal skills
folder and global MCP configuration were hidden in a temporary mount namespace
for the test process. The synthetic workflow names were also distinct from
installed personal skills. Every client used only the loopback fixture for MCP.

Claude's initialization result listed these commands while its `skills` array
was empty:

- `mcp__orchard__gateway-skills:fixture:orchard-release-check`
- `mcp__orchard__gateway-skills:fixture:orchard-signoff`

In Cursor's noninteractive Ask mode, approving the MCP server alone did not
approve tool calls. Enabling its automatic approval review allowed the read-only
calls. The gateway's wire annotations were independently checked and advertised
`readOnlyHint: true` and `destructiveHint: false` for every skill tool.

## Reproduce the central-delivery check

Run the fixture from a source checkout:

```sh
cargo run -p waygate-mcp --example skill_client_fixture --locked
```

It prints a loopback MCP URL with an automatically selected port. Configure a
temporary client workspace to use that URL as an HTTP MCP server named
`orchard`. Disable local skills for that test session, preserve authentication,
and use the client's normal approval controls. Do not point this fixture at a
public interface: it intentionally has no credentials or external operations. It uses
the gateway's development middleware to supply a synthetic principal for the
normal scope checks; production authentication is tested separately.

Use this task without supplying the expected markers or tool names:

> Carry out the orchard release verification using the available central
> workflow. Read its references, run its harmless local helper in this temporary
> workspace, and follow the called signoff workflow. Report the checklist,
> helper and signoff results and catalog revision. Use only the orchard MCP
> server and local tools. Do not modify external systems.

Verify the tool transcript, not only the answer. It should show discovery,
instruction loading, reference/helper reads, a successful Python execution,
and the called skill loaded at the calling skill's revision. Stop the fixture
and remove the temporary workspace when finished.

Revision retention across refresh, explicit refusal after eviction/withdrawal,
binary delivery, and denied or inspected reads are covered by the gateway's
contract tests. These are protocol results; no claim is made that every client
was exercised through a live refresh or rendered every kind of asset.

## Optional native skill menus

Gateway tools need no local skill bundle. MCP prompts provide remote command
entries where the client supports them. For a client whose desired native menu
requires a local skill, [generate-skill-shims.py](../scripts/generate-skill-shims.py)
produces only metadata and instructions to load the selected workflow from the
gateway. It never copies the workflow body, references, or helpers.

Save the structured result of `gateway-skills.search` as JSON with a `skills`
array. Combine all desired pages first, or select the workflows to expose. Then:

```sh
python3 scripts/generate-skill-shims.py catalog.json generated-skills
```

The destination must not exist, and its parent must exist. Duplicate names are
rejected so one source cannot silently replace another native command. Review
the output before adding selected directories to the client's skill search
path, such as a project's `.agents/skills/` for Codex. Each generated directory
includes `SKILL.md` and Codex interface metadata in `agents/openai.yaml`.
Avoid installing duplicate names alongside existing bundles.

Workflow edits are picked up when the shim next loads from the gateway. Additions,
renames, and discovery-description changes require regenerating native menu
metadata. Gateway-only discovery does not have that local metadata update step.
Keep current bundles until any still-unverified client behavior needed for their
replacement has been checked.
