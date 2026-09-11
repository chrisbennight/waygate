# Skill distribution review

The distribution-review store records which verified skill contents an operator
has approved for delivery within a tenant. Once a JavaScript file is available,
clients can submit its URI directly to Code Mode under their ordinary execution
and tool permissions. There is no separate script-execution grant. Compatibility
metadata is an optional publisher-reported test result, never an access decision.

The Skills page in the dashboard shows the configured catalog, candidate
status, approved serving version, exact file inventory and content comparisons.
Pending candidates also appear in Decisions and the overview. Only approved
contents are available through skill tools, prompts, the Skills extension,
resource reads, or Code Mode skill-script selection. Missing or unavailable
review storage denies skill distribution while the rest of the gateway remains
available.

Existing skills start pending when this control is first enabled. There is no
automatic approval of previously indexed content. An administrator reviews the
candidate and records a reason to approve, reject, or quarantine it.

The inventory distinguishes approval from whether the approved metadata can be
restored. Supporting-file access still performs its own source and authorization
checks; metadata availability does not promise every later file fetch will succeed.

Tenant onboarding creates pending reviews from an already-loaded catalog, even
when periodic source refresh is disabled. It does not copy another tenant's
approvals. Deleting a tenant removes its skill reviews and decision history in
the same database cascade, so reusing its identifier starts without approvals.
The gateway's separate audit retention policy still applies to audit events.

## Content and source identity

A review candidate comes from a verified skill catalog snapshot. It records the
source repository and configured reference, the resolved commit and tree, the
skill metadata, and the complete supporting-file inventory. File identities,
paths, media types, sizes, additions, and removals participate in the approval
identity. Supporting files remain fetched on demand; observation does not
download their bytes merely to populate review state.

Distribution approval excludes unrelated repository revisions from its content
identity. If another skill changes while this skill's inventory and metadata
remain identical, this skill does not need a new distribution decision. Source
origin and configured reference remain part of the identity, so approval never
moves silently to another repository or tracking reference. The original
approved commit and tree remain recorded as provenance.

## Decisions and concurrency

New observations start pending, with no approved serving candidate. An approved
candidate becomes the serving candidate. Observing a different candidate or
rejecting it preserves that serving candidate. Repeated observations of the
same content preserve its rejection and do not create another review.
Returning to the exact serving content restores its existing approved status;
it does not create a rejectable candidate for that same approved version.

Explicit quarantine overrides all prior distribution approvals for that skill
in the tenant. A subsequent explicit approval can allow the reviewed content
again; it does not restore older approvals revoked by the quarantine. A read
must consult authoritative eligibility before requested file acquisition and again
before releasing content after slow work. Stored approval alone is never a
substitute for the client's authorization or content inspection.

Observations take a generation witness captured before source acquisition.
Control-plane decisions take the generation and exact candidate that the
operator reviewed. The store refuses stale witnesses. Decisions and their
actor, issuer, reason, and content record commit in one transaction, so a
concurrent approval or quarantine cannot silently overwrite a completed
decision. Handlers remain responsible for binding the tenant to authenticated
authority and applying the existing authorization and CSRF protections.

The metadata of both the serving and candidate revisions survives process
restart. Restoring the corresponding source snapshot must verify its immutable
identities before serving bytes, and must never substitute a newer revision.
Missing records grant no permission; database failures remain errors.
The gateway reserves the `skill://` URI scheme. Withdrawn and stale skill
references fail instead of falling through to ordinary upstream resource routing.

Discovery reads review records in bounded pages and checks the selected contents
in a batch against current approval state. Metadata recovery and approval checks
have separate bounded deadlines. Exhausting the historical recovery budget marks
unrestored revisions unavailable while retaining approved metadata available in
the current catalog or cache. Recovery uses bounded concurrency so one stalled
revision does not prevent independent historical revisions from making progress.
A final revocation check still runs after inspection and
audit submission. If that check refuses release, an additional denial event
explains that the earlier authorization did not result in content release;
authorization audit records are not client delivery receipts.

Discovery at an explicit catalog revision filters out unapproved skill contents
without hiding independent approved skills in that same revision.

## Operator workflow

Open **Skills** from the MCP Gateway navigation or the command palette. Search
by name or description, then open the skill review. The candidate includes every
supporting file, including scripts and binary assets. Select a file to compare
its approved and candidate contents; source text is escaped and displayed as
inert text. The inventory identifies binary contents by immutable object, size,
and media type.

**Approve this candidate** allows its contents to be distributed in the current
tenant. **Reject this candidate** leaves the serving version available.
**Quarantine all versions** blocks subsequent delivery, including retained
references. Quarantine cannot remove bytes a client has already received.
Decisions require an administrator session, CSRF protection, the displayed
content digest and review generation, and an attributed reason. Concurrent or
stale decisions return a conflict and require a fresh review.

The same mutation core backs the registered `skill.approve`, `skill.reject`, and
`skill.quarantine` control-plane actions. Distribution decisions do not replace
the existing maker/checker change-request workflow.
Administrators can read the `skill_review` resource through the existing observe
tools to obtain current decision identifiers and links to the review page.

## Source recovery

Approved metadata persists in PostgreSQL. On a cache miss the gateway can
restore that source revision from the configured Git API and verify it against
the recorded candidate, for either supported Git object hash format. This is
metadata acquisition under the configured source authority; requested supporting
files still pass their ordinary fetch and read authorization. Restored metadata uses the existing bounded catalog
cache. A withdrawn source cannot be restored for client delivery.

Configured commit and tree pins select newly observed contents. Historical
recovery verifies the exact commit and tree retained in the review record, so
advancing the current pins does not revoke the previously approved contents.
Changing the configured source identity or quarantining the skill still blocks it.

If an approved revision cannot be retrieved, its reads fail explicitly; pending
contents are never substituted. Other approved skills can remain discoverable.
Database approval is checked again after slow work before content is released.

## Evidence

The [distribution review regression suite](../crates/waygate-skills/tests/review_pg.rs)
exercises the public store against an isolated PostgreSQL database through the
shared test preamble. Its database cases are not run when
`AUDIT_DATABASE_URL` is unset. The ordinary workspace CI provisions PostgreSQL.

See [Git-backed skills](skills-git-source.md) for source acquisition and existing
MCP delivery, and [the architecture contract](architecture.md) for ownership.
