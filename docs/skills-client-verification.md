# Verify central workflows with an MCP client

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
