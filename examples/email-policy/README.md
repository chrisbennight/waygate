# Send internally; approve external email

An assistant can send email to colleagues at `example.com`. Sending to anyone
outside that domain requires approval for the exact message. Changing To, Cc,
Bcc, the subject, or the body cannot reuse that approval, and a successful
dispatch consumes it.

[email.cedar](email.cedar) demonstrates the policy for
`example-messages.send` and the `mail-assistants` group. Load it through the
policy bundle editor and adapt the tool identity, group, and internal domain
to your deployment. Other policies still apply; this example does not override
an existing forbid. Use `approval_mode: policy_only` on the upstream if Cedar
should decide which calls need approval instead of a blanket tool requirement.

## Try the decisions

In **Policies → Simulator**, use the `mail-assistants` group, `call_tool`,
the `tool` resource type, server `example-messages`, and tool `send` in both
tool fields. Mark side effects. Enter these tool arguments:

```json
{
  "to": ["alice@example.com"],
  "cc": [],
  "bcc": [],
  "subject": "Quarterly update",
  "body": "The report is ready."
}
```

The decision is **ALLOW**. Add `partner@outside.example` to Bcc and the
decision becomes **APPROVAL_REQUIRED**, identifying `approve-external-email`.
The simulator does not send a message or mint an approval. A real call uses
the existing [invocation approval API](../../docs/agents/authz.md#invocation-approval-bindings)
and requires a catalog-admitted tool version so approval can bind to its
reviewed behavior and the complete arguments.

## Supported email contract

Apply this policy only to a tool whose complete delivery recipients are the
top-level `to`, `cc`, and `bcc` arguments. Each accepts a bare ASCII email
address or an array of addresses. Omitted fields are empty; at least one
recipient is required. Nulls, nested recipient objects, display names, comma
separated strings, domain literals, internationalized addresses, and more than
1,000 recipients are refused by the example policy. A tool with another envelope
format needs an adapter to this contract. Its input schema should reject
unknown fields and must not offer alternative recipient or forwarding inputs.

Waygate computes `context.email_recipients.valid` and the normalized domain set
`context.email_recipients.domains` from the arguments before authorization.
Domain comparison is exact and case insensitive: subdomains and lookalike
domains do not inherit access. If any recipient is invalid, the complete
projection is invalid; a valid subset cannot authorize the call.

The gateway sets `context.discovery` only for tool metadata visibility checks.
The recipient rules defer until invocation, when arguments exist. It is false
for real calls and simulator requests, and callers cannot set it through tool
arguments. The group permit still controls who can discover and invoke the tool.

These facts describe addressed delivery, not message content, mailing-list
membership, or subsequent forwarding. The mail service remains responsible
for honoring the declared envelope. Recipient addresses and message bodies
are not added to audit events. Recorded decisions without recipient facts
cannot reproduce these policies in impact replay; the strict evaluator reports
the missing inputs rather than inventing a result.
