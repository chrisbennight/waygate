# Move files outside model context

The gateway can receive, retain, forward, and download files while the model
handles only references and metadata. A file-aware client can use the native
draft protocol. An ordinary MCP client can use `gateway-files.*` and the
`mcp-files` helper, which moves bytes directly over HTTPS.

## Upload, use, and download

Install the helper from a gateway checkout using its pinned Rust toolchain:

```sh
cargo install --path crates/waygate-files-helper --locked
mcp-files init --gateway https://gateway.example.com
mcp-files thumbprint
```

Replace the example gateway with your authenticated deployment. Initialization
records its origin and creates a local signing key. The thumbprint identifies
that key; a prepare grant alone cannot be redeemed without its proof.

1. Call `gateway-files.prepare_upload` with the returned `helper_jkt` and any
   known file metadata. Discover the live schema for supported fields.
2. Run `mcp-files upload --uri <file.uri> --file ./document.pdf` with the
   `file.uri` from that result. The helper redeems the grant prepared for its
   key and that URI, and prints the URI once the upload succeeds.
3. Pass that URI in a tool's advertised file input. The gateway authorizes the
   call, delivers bytes to the selected upstream, and substitutes its private
   file URI before dispatch. A connector must support the corresponding file
   workflow; an arbitrary string parameter is not automatically a file input.
4. For a returned gateway file, call `gateway-files.prepare_download` with its
   URI and helper thumbprint, then run
   `mcp-files download --uri <uri> --dest ./result.pdf`.

Only the file URI and a local path reach the helper. Clients that can feed a
tool result to a command's standard input may instead omit `--uri` and pipe the
prepare result's `structuredContent` to the helper.

Keep file bytes out of tool arguments, pasted base64, and model-visible output.
The [bundled transfer skill](../../skills/mcp-file-transfer/SKILL.md) gives exact
helper commands and recovery instructions. A denied helper network call should
be resolved in the execution host's network permissions.

## Recover delivery into an upstream

A successful helper upload means the gateway has the source file. The consuming
tool must still ingest it. Keep the original gateway URI for retry; do not split
large files, rename fragments, or wrap them in archives to work around a
capacity error. Keep the intended destination and the source's expected size
and digest before calling the consuming tool. Declared tool file constraints
are checked before forwarding.

Call `gateway-files.delivery_status` with `{}` to inspect the gateway's file
size and global/per-owner active-transfer limits. Those limits differ from an
upstream's staged-file capacity. Pass `{"uri":"mcp-file://gateway/<file-id>"}`
to inspect recent deliveries owned by the caller. Each record has an opaque
`delivery_id`, its receiving server/tool, the last gateway-observed stage, and
an upstream-confirmed state when the upstream supports lifecycle inspection.
`receiving`, `publishing` and `cancelling` describe unfinished work; do not
start another consuming mutation while that work is pending. An upstream may
retire a finished upload instead of retaining its result. Its missing entry
then appears as `unknown`, not as proof of failure or non-publication.
The response is bounded; when `next_cursor` is present, pass it as `cursor`
with the same URI to continue. New deliveries do not shift continuation pages.

To abandon a delivery, call `gateway-files.cancel_delivery` with its
`delivery_id`. Only its owner may cancel it. Recovery rechecks the original tool's current
policy, credential profile, reviewed contract and upstream configuration;
changed authority or routing must be restored before the private upload can be
accessed. Cancellation preserves the source
file in gateway storage and refuses to delete committed files or uncertain
publication. `cancelling` means resource release is pending; only
`cancelled: true` confirms the upstream released staging. A finished entry may
be retired before a status poll observes it, so do not wait indefinitely for a
retained `cancelled` result. `unknown` or `commit_uncertain` requires inspecting
the known destination through the receiving service and comparing the expected
size and digest before deciding what to do next. A matching destination proves
its current contents, not the historical outcome of a particular request.
An absent or different destination does not prove that an in-flight operation
failed or that overwriting it is safe. Do not replay the mutation blindly.

Direct MCP ingestion failures after staging may include `delivery_ids` in error
data; successful tool results carry them under
`_meta["io.cacahuate.mcp-gateway/file-deliveries"]`. Status lookup by original
file URI also works when the tool response was lost. A definitely rejected
request triggers automatic cancellation when supported. An `upload_not_found`
cleanup reply does not replace explicit publication facts or imply a capacity
refusal or expiry-based retry delay. Terminal native task
results settle the original delivery when polled. A timeout or lost mutation
response remains unknown and does not trigger replay or cancellation.

Through Code Mode, catch the connector error and inspect its optional
`error.fileRecovery` detail. It distinguishes `file_too_large`,
`unsupported_type` and `upload_capacity_exhausted`, including refusals before
any delivery record exists. Older upstreams may also return `receipt_capacity`;
the gateway retains that error vocabulary for compatibility. Known limits, retry hints,
publication facts and caller-owned delivery IDs are included; unknown facts
are omitted. A missing publication fact never means publication was prevented.
Retain the original URI and use status lookup for staging recovery. Arbitrary
MCP error data and success metadata are not the Code Mode recovery interface;
see [Code Mode error handling](../codemode.md#execution-model).

A recovery-store failure after allocation stops before the consuming tool is
dispatched. Keep `source_uri`; `cleanup_pending: true` and `cleanup_state`
`cancelling` or `unconfirmed` mean staging release is not confirmed. Do not retry
automatically. If the allocation could not be recorded, an operator may need to
wait for upstream staging expiry or clean it up at the upstream.

Upstream lifecycle support is optional: the gateway interoperability extension
uses `files/transferStatus` and `files/cancelUpload`, advertised through the
upload authorization's `lifecycle` descriptor. These methods are separate from
the SEP-2631 draft. Older upstreams remain usable but report cancellation as
unsupported. Lifecycle records contain routing and ownership metadata, never
transfer credentials, and expire independently of the original source bytes.

## Receiving tool and task reports

An upstream may return a file from an ordinary tool call or from a completed
native task. Waygate advertises its own download support upstream when file
output storage is configured and the invocation is authenticated. Helper
clients do not need to advertise native file capabilities to receive these
references. Disabled storage cannot be enabled by a client's capability claim.

Native clients must include
`_meta["io.modelcontextprotocol/clientCapabilities"].files` with
`{"download": true, "transports": ["https"]}` on each
`files/authorizeDownload` request. A declaration on the earlier tool call or
task poll is insufficient. Helper clients instead use the prepare/download
steps above; neither path places the bytes in model context.

A completed task can still encounter a delivery failure. Retry `tasks/get` to
retrieve its result while the task ID and upstream file remain valid,
without submitting the work again. A task's lifetime does not extend file
retention. See the [upstream and client interoperability contract](../file-transfer.md#file-output-negotiation-for-tools-and-tasks)
for examples, transport constraints, and supported draft limitations.

## What makes the workflow governed

File ownership, credential-profile restrictions, authorization, expiry,
storage budgets, and integrity checks apply across the native and helper
surfaces. The helper rejects a transfer URL that belongs to a different origin
from its configured gateway. Downloads verify declared size and digest.
Storage must be enabled and visible to the replicas serving the transfer.
See [deployment settings](../file-transfer.md#gateway-settings).

An upload with an unknown outcome is reconciled with
`gateway-files.upload_status` before preparing another upload. Similarly, a
connector mutation may succeed even if its retained attachment cannot be
delivered. A result reporting `retry_operation: false` must not cause the
mutation to be repeated merely to retrieve its attachment.

Retained connector responses can also become owner-scoped files when they are
too large or unsuitable to return as ordinary JSON. Code Mode can process a
supported bounded body internally and return a summary; larger or binary
responses follow the file route. The retained-resource adapter has a separate
16 MiB decoded-body admission bound. It is not a multi-gigabyte streaming adapter.

When gateway file storage is enabled, an ordinary successful structured tool
result larger than 16 KiB in serialized MCP JSON is delivered as a compact file
reference to authenticated direct clients. Anonymous responses remain inline
because owner-scoped downloads require an authenticated caller. The JSON file
contains the complete MCP result, including its original text, structured
content, and metadata. Download it with
the helper above when the complete content is needed. Smaller results remain
inline; trusted Code Mode materialization keeps its existing response budget.
Existing upstream file attachments and retained-response envelopes keep their
own delivery rules.

The original response passes inspection and output validation before storage.
The saved result is owned by the caller and remains restricted to its producing
tool under credential profiles. Sensitive results use the configured short
retention period; download authorization enforces expiry. Audit records contain
file and invocation identifiers, never the saved content. A storage failure
after a successful mutation reports that the operation succeeded and must not
be retried.

## Interoperability and inspection

### Exercise refusal and recovery

Use synthetic files and disposable identities in an isolated deployment:

| Exercise | Expected outcome and next action |
| --- | --- |
| Download a file as its owning identity | The helper writes verified bytes; compare them with the original synthetic file. |
| Change the expected digest in a local copy of the download metadata | The helper refuses the mismatch. Investigate the metadata or transfer; do not accept the corrupted result. |
| Request the same URI as a different identity | Ownership checks refuse access; knowing a URI does not grant access. |
| Request a file after its advertised expiry | Retrieval is refused. Obtain a new authorized file through the appropriate workflow. |
| Lose an upload response | Reconcile with `upload_status` before preparing another upload. |
| Receive an attachment-delivery failure with `retry_operation: false` | Preserve the operation outcome and follow its delivery recovery information; do not dispatch the underlying mutation again. |

The last case matters for operations such as creating a document: inability
to download its attachment does not mean that document creation failed.

Native `files/authorizeUpload`, `files/authorizeDownload`, and `x-mcp-file`
follow the [SEP-2631 proposal](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2631).
The helper surface is a gateway enhancement available through ordinary tools.
The [wire-profile matrix](../file-transfer.md#version-negotiation-matrix)
explains legacy initialization and per-request capability behavior.

Integrity verification does not mean malware scanning. No file scanner is
currently connected. File-tool responses contain transfer and integrity
metadata without a scanner status field. Response inspection can
replace a retained response before publication, but does not establish file
scanner coverage.
