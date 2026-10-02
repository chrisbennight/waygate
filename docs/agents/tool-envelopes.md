# Upstream operation envelopes

Publish one canonical operation selector, `operation_id`, and one canonical
argument object, `arguments`, for a tool that dispatches operations. Derive the
input schema from the same request type that the handler validates. Per-operation
classification must use that selector, so policy evaluates the operation that
will execute. Describe tools should also publish `operation_id` for their exact
operation lookup. A qualified tool identity is a separate selector and retains
its own meaning.

At the gateway admission boundary, an admitted envelope can accept `operation`,
`name`, or `tool` for its operation selector and `args` for its argument object.
These spellings are accepted only when they are not declared business fields.
The gateway normalizes the root before validation, policy facts, approval hashes,
and dispatch. It never rewrites nested operation arguments. Supplying more than
one spelling of the same envelope field is an error, including equal values;
that error occurs before policy or upstream effects. Ordinary tools with a
business `name` field do not become operation envelopes.

Schemas, examples, and discovery responses advertise only the canonical fields.
An upstream server that also serves direct clients should apply the same
normalization before its own validation and dispatch. This keeps direct and
gateway-mediated calls consistent without teaching agents multiple spellings.

Keep compact defaults and reject non-positive result counts. Honor an explicit
positive count for a finite local collection without an arbitrary count ceiling.
Retain byte limits, timeouts, retention rules, and authorization. When the real
upstream API imposes a page limit, send its supported count and report the
requested, effective, and returned counts. Compute continuation from the page
actually requested upstream; a clamped page is not evidence that the collection
ended.

For read-only FastMCP tools with a simple wrapped text result, a positive integer
`limit` and a declared native maximum, the gateway admits larger requested
counts and clamps them immediately before dispatch. The published limit schema
retains its minimum and default and identifies the native maximum under
`x-mcp-result-count`. Schemas with references, additional count constraints, and
connections with native Tasks support retain their native contract. A different
stored input or output contract also retains its authority over validation;
count projection requires agreement with the published source contract.

An adjusted response includes `_gateway_counts.limit` with `requested`,
`effective`, `upstreamMaximum`, `returned`, and `clamped`. `returned` is null
because free text does not provide a reliable row count. The original text is
preserved. The count report follows the complete result through response
inspection and file delivery. Acquisition budgets, such as extraction counts,
retain their limits. A changed native ceiling invalidates a cached invocation
contract before dispatch.
