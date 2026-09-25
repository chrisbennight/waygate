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
2. Feed the result's `structuredContent` to
   `mcp-files upload --file ./document.pdf` through standard input. Capture the
   resulting `mcp-file://gateway/...` URI.
3. Pass that URI in a tool's advertised file input. The gateway authorizes the
   call, delivers bytes to the selected upstream, and substitutes its private
   file URI before dispatch. A connector must support the corresponding file
   workflow; an arbitrary string parameter is not automatically a file input.
4. For a returned gateway file, call `gateway-files.prepare_download` with its
   URI and helper thumbprint. Feed the prepare result to
   `mcp-files download --dest ./result.pdf` through standard input.

Keep file bytes out of tool arguments, pasted base64, and model-visible output.
The [bundled transfer skill](../../skills/mcp-file-transfer/SKILL.md) gives exact
helper framing and recovery instructions. A denied helper network call should
be resolved in the execution host's network permissions.

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

Integrity verification does not mean malware scanning. Files currently report
`uninspectable` because no file scanner is connected. Response inspection can
replace a retained response before publication, but does not establish file
scanner coverage. These states remain visible so an operator can apply policy
appropriate to the actual inspection performed.
