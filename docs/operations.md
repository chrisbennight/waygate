# Install, upgrade, and recover the gateway

Start with the [local tutorial](../examples/quickstart/README.md) to see a real
authenticated call and policy refusal without an external account. For an
actual deployment, use [the authenticated Compose starting point](../examples/deployment/README.md)
or translate its settings into your orchestrator. Keep that configuration in
your own deployment repository.

## Prerequisites and first acceptance

Choose a reviewed gateway image digest, a supported PostgreSQL build, a TLS
endpoint, an identity provider, and at least one reachable MCP upstream.
Prepare the [required environment groups](configuration.md), signing and
encryption keys, persistent configuration, and backup storage. The image is
distroless and runs as uid 65532; it has no shell or package manager.

Configure the gateway's public URL and exact OAuth callback URLs before login.
The dashboard client and optional built-in authorization-server client are
separate registrations. External resource-server mode still needs an
interactive dashboard login configuration in the production profile. Do not
turn off authentication to work around an issuer or audience mismatch.

Before opening access to users, verify:

- The container's `gateway-server --healthcheck` succeeds and `/readyz` reports
  readiness. Inspect bounded, redacted logs for startup failures.
- A real user completes dashboard login, and the intended MCP client obtains
  an audience-correct token through your configured identity path.
- Discovery exposes an expected harmless tool, that call succeeds, and a
  forbidden tool is refused when called directly as well as hidden when applicable.
- The default tenant's manifest and policy configuration health is current;
  the dashboard is not quietly serving an unexpected recovery snapshot.
- A durable audit query finds the synthetic acceptance call. Configure and
  verify trace/metric collection separately; a database alone does not install
  those backends.
- An isolated backup restore succeeds before the deployment holds important
  credentials, policies, or evidence.

Record the source commit/image digest, PostgreSQL version, enabled features,
configuration generation, and acceptance results. Record secret identifiers
and key versions separately from secret values.

## What persists

| State | Recovery requirement |
| --- | --- |
| PostgreSQL | Back up the full database, including schema migration checksums, tenants, authorization state, encrypted credentials, configuration history, audit, and opted-in execution content. |
| PostgreSQL cluster roles and ownership | Preserve required roles and grants separately from a single-database dump. Audit retention uses a dedicated `audit_log_sweep_role` and security-definer function owners. |
| Default-tenant manifests and policies | Back up the authoritative served directories as well as the database ledger. Restore them as a coordinated configuration generation. |
| Other tenants' policies | Their published bundles are database-backed; do not reconstruct them from the default tenant's files. |
| Signing, encryption, and session keys | Preserve the secret provider's required key versions and recovery procedure. Restoring encrypted rows without the matching key material does not recover usable credentials. |
| Retained file bytes | Preserve configured storage with its database metadata if files must remain available. Expiry and ownership still apply after restore. |
| Optional runtime integrations | Preserve operator-owned source coordinates and secret references; verify reachability and authorization after recovery. |

The default tenant's readable file set wins over the ledger, including an
intentionally empty manifest directory. Missing or unreadable files may cause
ledger recovery and degraded configuration health. If neither source is usable,
startup fails. A readable old directory can therefore overwrite your intended
recovery choice: restore the files you mean to serve, not merely the database.
See [runtime configuration authority](server-config-source-of-truth.md).

Multiple replicas need shared writable manifest and default-policy volumes,
and shared retained-file storage when that feature is enabled. Database
notifications tell replicas to reload; they do not distribute local files.
Do not substitute ephemeral replica storage when a shared mount fails.

## Upgrade deliberately

1. Read the candidate's configuration, protocol, and migration changes. Record
   the previous digest and configuration generation. Run your harmless permit
   and refusal checks against the current deployment first.
2. Take a coordinated backup. Stop or fence all gateway writers during a simple
   logical backup; for online backup, use a PostgreSQL-consistent backup method
   and coordinate the served file generation. Protect backup files as sensitive.
3. Restore into an isolated environment with disposable identity/upstream
   endpoints. Keep production traffic, outbound mutations, and webhook notifiers
   disconnected. Test the candidate against the restored data and configuration.
4. Let the candidate apply its shipped migrations to that isolated database.
   Check login, policy decisions, configuration health, encrypted-credential
   readability through the authorized runtime, and any enabled file/Code Mode
   workflows. Do not expose the restored credential values in diagnostics.
5. Select the candidate's immutable image digest through your deployment review
   path. Start the intended replicas, inspect migration/readiness outcomes, and
   repeat the acceptance checks before completing rollout.

Shipped SQL migrations are immutable. Never edit a migration to bypass a
checksum failure or delete migration bookkeeping to force startup. Preserve
the failed state for diagnosis and compare the deployed image with the intended
release. A fresh empty-database test cannot prove upgrade compatibility.

The overview category-feed index migration builds an index over the audit log.
The transactional migration runner holds a write-blocking table lock during
that build; on a large audit history, do not assume startup will be brief or
that other replicas can continue recording audit events. Measure the build on
the isolated restore, allow enough disk space and startup time, and schedule a
maintenance window that accounts for audit writers. After rollout, verify the
overview feed plan uses both tenant and category as index conditions and no
longer scans unrelated history. This index does not eliminate the separate
traffic-histogram query or guarantee a particular total page-load time.
The feed also prepares its query afresh for each request under PostgreSQL's
default automatic plan selection, so a reusable generic plan cannot replace
the category-specific plan. Other queries retain their existing caching.

The notable-events timestamp index has the same transactional build constraint.
The overview selects non-success events by event timestamp descending, using ID
only to break ties, and excludes pre-call records before applying the limit.
After rollout, verify its plan uses the tenant and timestamp as index conditions
without sorting the matching history. This does not change the activity
browser's ID-based pagination.

## Roll back the appropriate state

Image, configuration, and database rollback are separate decisions:

- Use the governed configuration rollback path for a policy or manifest change.
  It restores an approved generation to the served files and records history.
- Re-selecting the previous image is safe only after verifying it can read the
  current schema and state. Additive migration wording alone is not proof that
  an older binary can run against the upgraded database.
- If the prior binary is incompatible, stop writers and restore the matched
  database, configuration files, retained storage, and key versions from the
  pre-upgrade backup. Keep the failed database for diagnosis; do not overwrite
  the only recoverable copy.

Database restore cannot undo external MCP mutations. It may also rewind
revocations or approval/execution state. Reconcile the authoritative external
system and security changes made since the backup before restoring access.
Do not automatically replay uncertain Code Mode work or a tool call whose
attachment delivery failed. Cancellation cannot undo an external effect.

## Practice recovery on disposable data

After building the tutorial image, run the automated exercise:

```sh
python3 examples/quickstart/verify-recovery.py --image mcp-gateway:local
```

It creates a unique Compose project with loopback ports, copies the synthetic
configuration, restores a dump into a separate database container, compares
migration checksums and security-definer ownership, and repeats the tool/refusal check. It removes its own
containers and volumes. Supply `--baseline-image <prior-image>` to additionally
test the prior image before the backup and against the candidate's resulting
database state. The script uses only disposable data; a failure demonstrates
that the selected combination needs investigation, not permission to bypass
the migration or policy checks.

The tutorial provides a safe database exercise. Run it in its own Compose
project, complete the checker, then stop the gateway while leaving Postgres
running. Export a custom-format dump with `pg_dump -U gateway -d gateway -Fc`
inside the Postgres container; capture stdout into a protected local file.
Save the demo manifests and policies from that same checkout.

Export cluster roles separately with `pg_dumpall --roles-only --no-role-passwords`.
PostgreSQL's [cluster dump reference](https://www.postgresql.org/docs/17/app-pg-dumpall.html)
explains why those global objects are separate from a single-database dump.
Restore those role definitions into the isolated cluster before database objects;
use a separate restore administrator so the source login role can be created.
Re-establish login credentials through your secret provider. The automated
exercise uses only the fixed, public tutorial password for this step.

Restore the dump using `pg_restore --exit-on-error` into a new empty database
owned by the intended role, in a separate disposable PostgreSQL container of
the same build. Preserve object ownership and grants: blanket `--no-owner` or
`--no-acl` options can break audit retention's security boundary. Compare
security-definer function owners as well as migration version/checksum rows
with the source database. Point
an isolated gateway at the restored database and copied configuration, start
the demo upstream and issuer, and repeat the checker. Restart the gateway when
the disposable issuer's signing key changes.

Next repeat with the candidate image and the previous image, using separate
copies of the restored database. Record which combinations actually start and
pass the tool/refusal check. A same-version restore validates the backup path;
it does not prove every future upgrade or rollback. Delete only the disposable
containers, volumes, and synthetic backups you created for this exercise.
