---
name: mcp-file-transfer
description: Move a file to or from an MCP gateway without its bytes entering model context, using the `mcp-files` helper. Use when a tool needs a file you have on disk, when a tool returned an `mcp-file://gateway/...` address you need to fetch, or when you are about to paste file contents into a tool argument. Trigger on "upload this file to the gateway", "attach this file to that tool call", "download the file the tool returned", "mcp-file:// URI", "gateway-files.prepare_upload", "gateway-files.prepare_download", "gateway-files.upload_status", or noticing that a file's contents are about to become a tool argument.
license: Apache-2.0
metadata:
  source: waygate
  version: 0.1.3
---

# Moving a file through the gateway

The gateway can hold a file for you so it never travels through a tool
argument or a tool result. You make one tool call; a local command does the
signing and moves the bytes. What comes back is an address you pass along.

## Why there is a command at all

The tool call returns a grant that is bound to a key on this machine. That
binding is the point: the grant is safe to sit in your context precisely
because reading it is not enough to use it. Redeeming it requires signing with
that key, which needs a JOSE library — so it is done by `mcp-files` rather than
by you.

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

Then pipe that tool result straight into the command:

```
mcp-files upload --file <path> <<'JSON'
<the prepare_upload structuredContent>
JSON
```

The default input mode starts the transfer as soon as it receives one complete
JSON value. It accepts compact or formatted JSON and does not wait for EOF. If
the execution host can write only through a PTY, start the PTY with terminal
echo disabled and send the JSON followed by a newline once; do not send Ctrl-D.
The explicit `--input-framing eof` and `--input-framing jsonl` modes remain
available for launchers that require fixed framing.

Use the tool call's `structuredContent` object when it is available. The helper
also accepts a complete tool result carrying `structuredContent`. For clients
that drop that field, it accepts exactly one text content block only when that
block is entirely a JSON prepare result; it does not scrape JSON from prose.

It prints one line: an `mcp-file://gateway/...` address. That address, and
metadata like the file name, are the only things to carry forward. Not the
bytes, not the local path, not anything else from the result.

Use the address wherever the next tool wants the file.

If the helper reports that the upload outcome is unknown, retain the URI named
in the error and call `gateway-files.upload_status` before preparing another
upload. `ready` means the file was published. `prepared` or `in_progress` means
do not duplicate it yet. A new upload can be prepared after `failed` or
`expired`.

## Download

Same shape. `mcp-files thumbprint`, then `gateway-files.prepare_download` with
the `mcp-file://` address and that fingerprint, then:

```
mcp-files download --dest <path> <<'JSON'
<the prepare_download structuredContent>
JSON
```

The download command uses the same automatic framing and supports the same
explicit overrides.

It writes the file and checks it against whatever size and digest the gateway
declared, so a truncated or altered transfer fails instead of landing.

## First run on a machine

```
mcp-files init --gateway https://<your-gateway>
```

Records which gateway the transfer addresses must belong to, and creates the
signing key. Without it the other commands refuse and say so.

That check matters: the tool result reaches the command by way of your context,
so the addresses inside it are not trusted. An address pointing anywhere other
than the recorded gateway is refused before any bytes move.

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
