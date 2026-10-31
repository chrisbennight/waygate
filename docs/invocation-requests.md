# Pending invocation requests

Open **Decisions → Invocation requests** to review direct tool calls that were
refused because they require human approval. With the PostgreSQL catalog
configured, these requests survive a missed notification or gateway restart.
Notifications include a link to the same retained request when capture succeeds.
Code Mode retains its requests in its separate execution journal.

A retained request is a reference for a human decision. It does not queue tool
execution, grant permission, or automatically retry a call. Approval issues a
single-use grant; the requester must retry through the ordinary invocation path,
which still checks access policy, current tool behavior, arguments, and expiry.
Rejecting a request issues no grant. Issued grants have their own lifecycle on
the **Approvals** page.

## Review and decide

The review identifies the requester by tenant, issuer, and subject, names the
tool, and shows the admitted description, submitted schema field names, and exact
behavior and argument identities. Argument values are not copied into this queue.
Review the exact requested values and effects with the requester through a
trusted channel before confirming approval. Oversized review context is marked
unavailable rather than truncated and cannot be approved from this surface.

An administrator supplies a reason and explicitly confirms that they reviewed
the request. The requester cannot approve their own invocation; identity includes
the issuer as well as the subject. A changed tool, expired request, or completed
decision requires another review. Concurrent decisions cannot issue multiple
grants for the same request.

The decision and its administrator attribution commit with grant issuance.
Required Activity evidence is recorded afterward; an evidence failure is shown
as requiring attention and does not imply the grant was undone. Inspect the
retained request and issued grant before taking further action.

## Lifetime, limits, and recovery

- Pending requests expire after fifteen minutes. Repeated identical refusals
  within that window reuse the pending request without extending its deadline.
- An approved grant lasts at most five minutes and never beyond the request's
  original expiry. It is consumed once by a matching retry.
- Retained request records are available for seven days. A later refusal after
  a completed decision is a new request requiring a new administrator decision.
- The queue permits at most one hundred pending requests per requester, one
  thousand per tenant, and ten thousand retained records per tenant. The listing
  shows the oldest pending requests first, in a bounded page. Resolve those
  requests to reveal later work.

Expiry and retention cleanup occur when another request is captured. Reads also
enforce deadlines, so an expired record cannot confer permission before cleanup.
If persistence or capacity prevents capture, the tool call remains refused and
the notification has no durable request reference. Existing individual grant
issuance remains available for an independently reviewed request.

See [invocation approval bindings](agents/authz.md#invocation-approval-bindings)
for the permission boundary and [bulk decisions](bulk-decisions.md) for selected
decision availability.
