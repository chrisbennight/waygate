---
name: mcp-file-transfer
description: Move a file to or from an MCP gateway without its bytes entering model context, using the `mcp-files` helper. Use when a tool needs a file you have on disk, when a tool returned an `mcp-file://gateway/...` address you need to fetch, or when you are about to paste file contents into a tool argument. Trigger on "upload this file to the gateway", "attach this file to that tool call", "download the file the tool returned", "mcp-file:// URI", "gateway-files.prepare_upload", "gateway-files.prepare_download", "gateway-files.upload_status", or noticing that a file's contents are about to become a tool argument.
license: Apache-2.0
metadata:
  source: waygate
  version: 0.2.0
---

# Moving a file through the gateway

The gateway can hold a file for you so it never travels through a tool
argument or a tool result. You make one tool call; a local command does the
signing and moves the bytes. What comes back is an address you pass along.

## Why there is a command at all

The prepare call creates a grant bound to a key on this machine. Redeeming it
requires signing with that key, which needs a JOSE library — so it is done by
`mcp-files` rather than by you. The command finds the grant from its own key
and the file's `mcp-file://` address, so the only things you pass it are that
address and a local path. The address is not an access credential.

Pasting file contents into a tool argument is not the fallback when the command
is missing. It defeats the whole arrangement. Install the command instead.

## Upload

```
mcp-files thumbprint
```

Prints a short fingerprint. It is stable, so you can reuse it; run it again
rather than remembering it across sessions.

Then call `gateway-files.prepare_upload` with:

- `helper_jkt` — the fingerprint from above
- `name`, `mime_type`, `size` — whatever you know; all optional

Take `file.uri` from the result and run:

```
mcp-files upload --uri <file.uri> --file <path>
```

It prints the same `mcp-file://gateway/...` address once the upload succeeds.
That address, and metadata like the file name, are the only things to carry
forward. Not the bytes, not the local path, not anything else from the result.

Use the address wherever the next tool wants the file.

If the helper reports that the upload outcome is unknown, retain the URI named
in the error and call `gateway-files.upload_status` before preparing another
upload. `ready` means the file was published. `prepared` or `in_progress` means
do not duplicate it yet. A new upload can be prepared after `failed` or
`expired`.

## Download

`mcp-files thumbprint`, then `gateway-files.prepare_download` with the
`mcp-file://` address and that fingerprint, then:

```
mcp-files download --uri <mcp-file address> --dest <path>
```

It writes the file and checks it against the size and digest the gateway
reports when the grant is redeemed, so a truncated or altered transfer fails
instead of landing.

## Each prepare call is good for one transfer

The helper redeems the newest unused grant prepared for its key and that
address. A grant works once and expires after a few minutes. If the helper
says the grant is unavailable, call the prepare tool again and rerun the
command; do not retry the command alone.

## Older gateways and piped results

A gateway that predates address-based redemption refuses `--uri` at the
credential exchange. Against such a gateway, omit `--uri` and give the helper
the prepare call's `structuredContent` on standard input instead, for example:

```
mcp-files download --dest <path> <<'JSON'
<the prepare_download structuredContent>
JSON
```

The helper reads the first complete JSON value without waiting for EOF and
also accepts a whole tool result. `--input-framing eof` and
`--input-framing jsonl` exist for launchers that need fixed framing.

## First run on a machine

```
mcp-files init --gateway https://<your-gateway>
```

Records the gateway's base address and creates the signing key. Without it the
other commands refuse and say so. The helper sends grants and bytes only to
that recorded gateway.

The helper connects directly to that recorded gateway over HTTPS. In a
sandboxed execution host, grant network access for the `mcp-files upload` or
`mcp-files download` command, scoped to the configured gateway when the host can
express that restriction. A network denial is not a reason to move file bytes
through a tool argument.

## When the command is missing

From a checkout of the gateway repository, use its pinned Rust toolchain:

```sh
cargo install --path crates/waygate-files-helper --locked
```

This installs `mcp-files` into Cargo's binary directory; ensure that directory
is on `PATH`. It does not require access to a private artifact server.

If your operator provides prebuilt releases, use the destination they configure.
The release artifact names are `mcp-files-linux-amd64`, `mcp-files-linux-arm64`,
`mcp-files-windows-amd64.exe`, and `mcp-files-macos-arm64`. Verify the matching
`.sha256` from the trusted release, retain its license notices, and install the
binary as `mcp-files` (`mcp-files.exe` on Windows). Do not invent a download URL
or assume that this checkout has been published to a registry.

If neither is possible, say so and stop. Do not work around it by moving the
file's contents through a tool call — that is the failure this exists to
prevent, and it is worth being blocked on.

## What not to do

- Do not put file bytes, base64, or a local path into a tool argument.
- Do not try to perform the credential exchange yourself. The tool result
  describes it for people writing their own client; from an agent loop it needs
  a signer you do not have.
- Do not carry the grant handle or the transfer credential anywhere after the
  command has run. They are short-lived and single-use, and nothing later
  wants them.
