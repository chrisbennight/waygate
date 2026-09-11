# Runtime configuration source of truth

> **Status:** Accepted and implemented. This record describes the current
> configuration model for upstream manifests and Cedar policies.

## Decision

The files on the shared runtime volume are authoritative:

- `servers/*.yaml` defines the upstream set and its tool classifications.
- `policies/*.cedar` defines the default tenant's authorization policy.

The dashboard and governed change paths edit those files directly. Git and the
published container image are not configuration sources, mirrors, or recovery
layers. The repository contains representative test fixtures, but the runtime
image contains no manifest or policy set.

Postgres supports the file source of truth in three roles:

1. **Ledger:** version history, rollback, audit attribution, and last-resort
   recovery when the live files are unreadable.
2. **Turnstile:** compare-and-swap serialization for concurrent writers.
3. **Doorbell:** `LISTEN`/`NOTIFY` signals that prompt every replica to reload;
   periodic polling remains the missed-notification and out-of-band-edit
   backstop.

Postgres is never preferred over a readable live file set.

## Boot and recovery

### Upstream manifests

Boot resolves manifests in this order:

1. A readable `GATEWAY_SERVERS_DIR` is authoritative. An existing, cleanly
   empty directory deliberately means zero upstreams.
2. If the directory is missing, unreadable, mid-write, or contains an invalid
   manifest, recover the newest usable `server_manifests` ledger snapshot and
   mark configuration health degraded.
3. If neither source is usable, refuse to start.

There is no image-baked fallback. A missing mount must not be mistaken for an
intentional empty set.

### Cedar policies

The default tenant follows the same file-first model through
`GATEWAY_POLICIES_DIR`. If the live policy set is unreadable, the gateway may
recover the newest usable policy ledger snapshot. If neither is usable, the
gateway refuses to start rather than serving with stale or absent
authorization.

Non-default tenants do not have filesystem namespaces. Their latest published
policy bundles are compiled into the tenant policy registry. A failed refresh
keeps the previous compiled generation; a tenant without a bundle falls back to
the default tenant's file-backed engine.

## Writes and concurrency

A coordinated publish or rollback:

1. validates the complete candidate before mutation;
2. claims the turnstile against the current file generation;
3. writes the file set using the coordinated write marker and atomic rename;
4. records the ledger version and audit evidence; and
5. rings the doorbell after the committed state is visible.

Writers compare content generations, not mtimes. A lost turnstile claim is a
conflict, not permission to overwrite a newer file set. Reload readers refuse a
directory carrying an active write marker, so they never activate a partial
multi-file publication.

Disk remains authoritative when a file write succeeds but a later ledger write
fails. The reconciliation path records that file generation into the ledger on
a later clean pass rather than restoring older bytes over a potentially newer
writer.

## Reload and catalog convergence

Boot, SIGHUP, doorbell handling, and periodic polling all read the same live
files. A malformed or unavailable live set never clears the active in-memory
configuration. A usable ledger snapshot is applied as degraded recovery; when
reload has no usable recovery, it keeps the previous generation and reports
degraded configuration health. Boot refuses to start when neither source is
usable.

After a manifest generation is accepted, the gateway atomically reconciles its
tool-facts catalog from that generation. Servers absent from the authoritative
set are quarantined rather than deleted, preventing absence from becoming a
permissive catalog miss. Per-tool catalog retirement is tracked separately.

Connection-shape changes re-dial the affected upstream. Other replicas converge
through the shared files plus doorbell/poll path; the database is coordination,
not a second configuration authority.

## Operational requirements

- The manifest and policy directories must be persistent, writable by the
  gateway uid, and shared by every replica.
- A genuinely missing or unreadable mount is an operational fault. Do not create
  a local shadow directory that hides a failed NFS mount.
- A fresh server directory may intentionally start empty. A fresh policy
  directory must be seeded through a governed publish or supported import before
  the gateway can authorize traffic unless a usable ledger snapshot exists.
- Use dashboard/REST/HITL publication for normal changes. Explicit import
  commands remain available for controlled bootstrap and recovery.
- Roll back through the ledger-backed dashboard path or restore the desired
  files on the shared volume, then reload. Never rely on an image downgrade to
  restore configuration.

## Accepted tradeoffs

- File authority makes the active state directly inspectable and gives every
  deployment its own configuration, but the shared volume and its durability
  are load-bearing.
- Dashboard publication replaces pull-request review for live configuration.
  Validation, impact preview, HITL approval, audit evidence, and versioned
  rollback provide the review boundary in the control plane.
- Ledger recovery favors availability during a damaged file generation, but it
  is visibly degraded because the recovered snapshot may be stale.
- Failing boot after both live files and ledger recovery are unavailable is
  intentional. Serving an unknown or image-stale configuration would conceal
  the storage failure and diverge from operator intent.
