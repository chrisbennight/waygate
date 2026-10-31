# Bulk administrator decisions

Tool changes, Skills, and pending invocation requests support selected decisions.
Decisions links to the owning review queues. This guide describes the shared
experience, including selected approval of supported administrative changes.

## Purpose

An administrator should be able to review several pending items and confirm
one decision for the explicit selection. Reducing repetitive interaction must
preserve understandable effects, existing approval conditions, and reliable
results for each item.

Tool-definition acceptance, permission for a particular tool invocation, skill
distribution approval, and approval of an administrative change have different
effects. They share an interaction pattern, but retain their own authority and
decision rules.

## Eligible decisions

| Queue | Bulk actions | Required review |
| --- | --- | --- |
| Tool changes | Approve replacements; Keep blocked | Exact observed definitions, changed fields, flags, and any required initial classification. |
| Skills | Approve; Reject | Exact candidate content, supporting files, and an operator reason. |
| Pending invocation requests | Approve; Deny | Request effects, requester identity, reviewed tool behavior, and the particular request being authorized. |
| Administrative changes | Approve independent rate-limit policy creations | Captured intent, required effect previews, and every individual approval condition. |

The Decisions inbox groups selection by decision type. A selected tool review
cannot select an administrative change or an active break-glass control.
Already-issued grants are lifecycle records rather than pending approvals.
Privileged blanket approval remains unavailable. Changes with dependent effects
require individual review unless a supported action explicitly governs their
combined effect.

Eligibility must be enforced by the decision service as well as explained in
the interface. Individual review remains available.

## Selection and review

Selection starts empty. Each eligible row has a labelled native checkbox. The
header control says **Select eligible items on this page** and shows a mixed
state when only some eligible rows are selected. A contextual action bar shows
the selected count, applicable actions, and **Clear selection**.

Changing the page, filter, or tenant clears the selection. Newly arriving items
are never selected automatically. Updates preserve selection only for the same
reviewed identities; changed or removed items require another review. While a
submission is in progress, conflicting mutation controls are unavailable.

The initial tool-review ceiling is fifty items, matching the existing listing
size. The complete selection also has a two-MiB review budget, measured as the
combined UTF-8 bytes of the compact JSON serialization of the stored approved
and observed contract definitions
before escaping or diff rendering. A selection exceeding either limit is
refused with guidance to select fewer items; significant decision details are
never truncated to fit. Other queues retain their existing aggregate review
bounds and may need a smaller item ceiling.

Skill selections are limited to ten pending candidates and two MiB of combined
candidate metadata and declared file sizes. The review displays every candidate's
metadata, source revision, supporting-file inventory, and complete text files.
Binary files retain their immutable object identity, media type, and size.
Unavailable candidate source or files prevent approval from that review.
An operator reason is required and retained for every selected decision.
Rejecting candidates preserves any previously serving version; quarantine
remains an individual operation.

Invocation selections are limited to fifty requests and two MiB of complete
serialized review context. Current Code Mode calls use the ordinary direct
channel and the same per-call request queue as direct tool calls. Review includes
value-free context, full requester identity, and exact behavior and argument
identities; review argument values with the requester through a trusted channel.
Approval permits only that matching call. It does not execute a tool, restart a
program, or authorize replay of prior effects. The caller retries only the
reviewed call through the ordinary invocation boundary.

Historical `approval_bound_mutation` executions cannot continue on the current
runtime. Their separate selection group offers reviewed denial only. The queue
loads identifying metadata rather than complete request payloads. Individual
and selected review load the full captured context within the review budget;
oversized context is refused without truncation. Denial binds the exact durable
request and execution at the owning store mutation, ends the waiting execution,
and preserves completed prior effects. Issued grants remain separate lifecycle
records.

Administrative selections currently support `rate_limit.create` only. Select
new policies with the same scope and action, and distinct scope targets. The
review presents complete captured parameters, requester, justification, binding
code, freshness witness, expiry, and frozen approval requirements. Each item
retains its own eligible role, distinct-administrator quorum, fresh session
factors, and proposal-age cooldown. Required approvals can remain pending toward
a quorum; approval completion and execution success or failure are distinct
outcomes. A single confirmation never counts as multiple administrators.

The existing change service owns approval and executes the captured intent;
the policy store's uniqueness constraint rejects a target created concurrently.
Updates and deletions, policy/manifest publication, identity and secret changes,
break-glass controls, mixed scope/action selections, and dependent operations
remain on individual review. Their effects or freshness requirements need their
own supported design before bulk approval can be offered. An unsupported or
incompatible selection is refused before any selected effect.

For example, selecting several tool replacements shows their server and tool
names, changed-field summaries, flags, and complete stored comparisons. A
missing baseline is identified explicitly. An unavailable observed definition
cannot be accepted. Initial approval requires an explicit risk choice for each
tool that needs classification; no blanket classification is preselected.

Confirmation says **Approve these selected tool replacements** and identifies
the selection and its effect. Accepting a definition restores its eligibility
under existing configuration and policy. Approving an invocation instead
authorizes that particular request; it does not create standing permission.

## Decision boundaries

The authenticated administrator and authoritative tenant context govern every
item. Request protection, role eligibility, freshness, expiry, cooldowns,
authentication factors, distinct-administrator quorum, and required effect
review retain their existing meaning.

Approval binds to the exact selection and versions reviewed. A changed candidate
cannot inherit approval, including when its content returns to an earlier value
under a newer review generation. Shared configuration changes must be
coordinated; the service cannot silently adopt a newer configuration baseline
to make the remaining selection succeed.

## Outcomes and recovery

Every selected item receives an outcome. The result view distinguishes:

- Approved, or kept blocked/rejected as requested.
- Already decided.
- Changed since review; review again.
- Unavailable; no confirmed decision.
- Applied, with evidence recording requiring attention.
- Outcome uncertain; reconciliation required.
- Not started.

A result such as **Some replacements approved; others changed and need review**
keeps unresolved items visible and links to the exact remaining review. The
queue and badge reflect observed state. Approval recorded toward a quorum,
execution completed, and execution failed are distinct outcomes.

An interrupted submission has a durable, administrator-scoped receipt. Repeating
the same submission returns recorded progress without repeating completed
decisions; changing the submitted selection requires a new confirmation.
Uncertain effects are reconciled against authoritative state before any retry.
There is no implied all-or-nothing transaction across configuration files,
database state, runtime activation, and evidence delivery.

**Recent bulk decisions and interrupted submissions**, available from both
entry pages even when no tools remain pending, lists this administrator's
receipts in the current tenant. Receipts expire after seven days, and each
administrator can retain at most one hundred. An interrupted item with no
confirmed result requires checking its current review and Activity. Refreshing
or resubmitting its confirmation never repeats the claimed submission.

Bulk tool reviews require the same administrator authority in the upstream
configuration tenant as individual tool reviews, plus a configured database
for receipts. Other tenants and individual decisions retain their existing
boundaries. A compact selection has its own receipt size limit; full tool
contracts are read from the review store rather than copied into the receipt.

Existing per-item attribution and evidence remain available, with correlation
to the bulk submission. General summaries and logs do not copy credentials,
raw invocation arguments, or complete upstream content.

## Accessibility and responsive behavior

Checkbox labels identify their item. Keyboard users can select with Space,
reach review and confirmation controls, and return to a predictable focus
position after an update. Selection and result changes are announced to
assistive technology. Status is expressed in words as well as color.

At narrow widths, each item keeps its identity and selection control together;
the action bar remains readable without covering the review. Full comparisons
remain available. Verify both themes, zoom, visible focus, and reduced-motion
preferences using the existing dashboard design language.

## Design basis

These references informed the interaction and safety constraints. The supported
queues and resource limits are Waygate design choices, not MCP requirements.

- [MCP tools and human control](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).
- [Carbon data-table selection and batch actions](https://carbondesignsystem.com/components/data-table/usage/).
- [OWASP transaction authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html).
- [W3C mixed-state checkbox pattern](https://www.w3.org/WAI/ARIA/apg/patterns/checkbox/).
- [Per-item batch outcomes](https://learn.microsoft.com/en-us/graph/json-batching).
- [Dashboard implementation guidance](agents/dashboard-ui.md).
- [Existing approval conditions](agents/hitl-control-plane.md#captured-approval-requirement).
