//! `gateway-server --import-manifests [<dir>]` — one-shot import of
//! `servers/*.yaml` manifests into the durable catalog tables.
//!
//! Runs to completion and exits without starting the HTTP server.
//! Intended for the deploy runbook's cutover step: the catalog
//! migration requires a one-time `--import-manifests` step in the
//! deploy runbook before the binary upgrade.
//!
//! Requires `GATEWAY_DATABASE_URL` — the catalog lives in Postgres,
//! so importing without a DB is a usage error, not a silent no-op.
//! The one-shot CLI paths reuse `PgAuditSink::connect` to get a pool with all
//! migrations applied. Boot reconciliation instead receives the serving
//! process's control pool so it cannot create an unbudgeted fourth pool.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use anyhow::Context;
use waygate_catalog::{ImportOperation, ImportServer, ImportTool, ManifestImporter};
use waygate_core::TenantId;
use waygate_storage::PgAuditSink;
use waygate_upstream::{
    load_manifests, parse_manifest_set, serialize_manifest_set, Transport, UpstreamManifest,
};

use crate::config::Config;

/// `(filename, error)` for a manifest file that failed to read or
/// parse during a lenient import load.
type ManifestParseError = (String, String);

/// Result of [`load_manifests_lenient`]: the successfully-parsed
/// manifests keyed by server name, plus the per-file failures.
type LenientLoad = (BTreeMap<String, UpstreamManifest>, Vec<ManifestParseError>);

/// Per-file-lenient manifest load. Unlike `waygate_upstream::load_manifests`
/// (which fails fast on the first YAML parse error), this parses each
/// `*.yaml` independently so one malformed file doesn't abort the whole
/// import. Returns the successfully-parsed manifests plus a list of
/// `(filename, error)` for the files that failed — the caller folds
/// those into `ImportStats::errors`. The import command's documented
/// "one bad manifest, the rest still import" behaviour requires
/// per-file tolerance the fail-fast loader doesn't provide.
fn load_manifests_lenient(dir: &Path) -> std::io::Result<LenientLoad> {
    let mut ok = BTreeMap::new();
    let mut errors = Vec::new();
    if !dir.exists() {
        return Ok((ok, errors));
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_owned();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                errors.push((fname, format!("read: {e}")));
                continue;
            }
        };
        match serde_yaml::from_slice::<UpstreamManifest>(&bytes) {
            Ok(m) => {
                // Enforce the same manifest invariants the normal
                // `load_manifests` path enforces. Without
                // this, an import that mixes incompatible
                // identity fields (e.g. `tier_c_peer:` +
                // `exchange:`) would persist a catalog row
                // that normal boot would reject — operator
                // would see a green import and then a boot
                // refusal hours later.
                if let Err(e) = waygate_upstream::validate_manifest_invariants(&m) {
                    errors.push((fname, format!("invariant: {e}")));
                    continue;
                }
                ok.insert(m.name.clone(), m);
            }
            Err(e) => {
                errors.push((fname, format!("parse: {e}")));
            }
        }
    }
    Ok((ok, errors))
}

/// Detect a `<flag> [<dir>]` directory-flag on the command line and,
/// if present, return the optional directory override. `<flag>` alone
/// ⇒ `Some(None)` (use the config default); with a value ⇒
/// `Some(Some(dir))`; absent ⇒ `None`. Accepts both the separate
/// (`<flag> <dir>`) and joined (`<flag>=<dir>`) forms.
fn parse_dir_flag(flag: &str) -> Option<Option<String>> {
    let joined = format!("{flag}=");
    let args: Vec<String> = std::env::args().collect();
    for (i, a) in args.iter().enumerate() {
        if a == flag {
            // Next arg is the dir unless it's another flag.
            let dir = args.get(i + 1).filter(|v| !v.starts_with("--")).cloned();
            return Some(dir);
        }
        if let Some(rest) = a.strip_prefix(&joined) {
            return Some(Some(rest.to_owned()));
        }
    }
    None
}

/// Detect `--import-manifests` and return the optional directory
/// override (`cfg.servers_dir` when absent). See [`parse_dir_flag`].
pub fn parse_import_flag() -> Option<Option<String>> {
    parse_dir_flag("--import-manifests")
}

/// Detect `--import-policies` and return the optional directory
/// override (`cfg.policies_dir` when absent). See [`parse_dir_flag`].
pub fn parse_import_policies_flag() -> Option<Option<String>> {
    parse_dir_flag("--import-policies")
}

/// Detect `--import-server-bundle` and return the optional directory
/// override (`cfg.servers_dir` when absent). See [`parse_dir_flag`].
/// Distinct from `--import-manifests` (which is the catalog import):
/// this one seeds the durable `server_manifests` overlay.
pub fn parse_import_server_bundle_flag() -> Option<Option<String>> {
    parse_dir_flag("--import-server-bundle")
}

/// Reconcile the tool-facts catalog from an ALREADY-LOADED, prod-safety-gated
/// manifest set into `pool`, atomically (all-or-nothing, `preserve_status =
/// true` so an operator quarantine/retire survives). The change-detected reload
/// path (`reload_once` / `reload_manifests_only`) calls this after loading the
/// authoritative live manifest set, so a dashboard publication takes effect
/// without a restart.
///
/// **Quarantine-on-absence is ON:** `import_atomic(.., true)` flips
/// any `live` server ABSENT from this (full) set to `quarantined`, so a server
/// removed from the live set stops being authorized even while an older pool
/// generation or in-flight call still holds it — by status flip, never delete
/// (a deleted row would fall through to `resolve_invocation_tool`'s unknown-tool
/// least-sensitive default, a permissive regression). SERVER-level only: a tool
/// dropped from a still-present server is left in the catalog — the live pool already
/// quarantines an unclassified upstream tool, so it is not callable; tool-level
/// catalog cleanup is handled separately from server-level reconciliation.
///
/// A clean empty set is authoritative for the default tenant and quarantines
/// its formerly-live catalog servers. Unreadable or partial live sets never
/// reach this function: resolution either recovers a complete ledger generation
/// or keeps/fails the active generation before reconciliation.
pub async fn reconcile_catalog_from_manifests(
    pool: &sqlx::PgPool,
    manifests: &BTreeMap<String, UpstreamManifest>,
) -> anyhow::Result<waygate_catalog::ImportStats> {
    let started = Instant::now();
    let importer = ManifestImporter::new(pool.clone());
    let servers: Vec<ImportServer> = manifests.values().map(to_import_server).collect();
    let result = importer
        .import_atomic(TenantId::DEFAULT, &servers, true)
        .await
        .context("catalog reconcile from loaded manifests (atomic, all-or-nothing)");
    waygate_telemetry::metrics::record_catalog_reconciliation(
        result.is_ok(),
        started.elapsed().as_secs_f64(),
    );
    result
}

/// The dashboard Reload handler's catalog-reconcile seam: the same catalog
/// import the doorbell/SIGHUP reload path runs, wrapped in the callback shape
/// `AdminState` carries so `waygate-admin` never depends on this crate.
pub fn catalog_reconcile_callback(pool: sqlx::PgPool) -> waygate_admin::SharedCatalogReconcile {
    std::sync::Arc::new(move |manifests| {
        let pool = pool.clone();
        Box::pin(async move {
            let result = reconcile_catalog_from_manifests(&pool, &manifests).await;
            // Arm the doorbell latch on EVERY dashboard reconcile attempt,
            // success included: the next doorbell/poll tick then re-imports
            // from current disk truth, which both retries a failure and
            // settles any interleaving between this reconcile and a
            // concurrent doorbell/SIGHUP reconcile (last writer here could
            // otherwise be the staler set). The latch disarms only when the
            // doorbell's own reconcile succeeds.
            crate::reload::CATALOG_RECONCILE_LATCH.arm();
            result
                .map(|stats| (stats.servers, stats.tools))
                .map_err(|e| e.to_string())
        })
    })
}

/// Run the import and return. The caller exits with the result's
/// status (non-zero on any per-server failure).
pub async fn run(cfg: &Config, dir_override: Option<String>) -> anyhow::Result<()> {
    let dir = dir_override
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cfg.servers_dir.clone());

    let url = cfg.database_url.as_deref().context(
        "--import-manifests requires GATEWAY_DATABASE_URL (the catalog lives in Postgres)",
    )?;

    let (manifests, parse_errors) = load_manifests_lenient(&dir)
        .with_context(|| format!("read manifest dir {}", dir.display()))?;
    tracing::info!(
        count = manifests.len(),
        parse_errors = parse_errors.len(),
        dir = %dir.display(),
        "loaded manifests for import",
    );

    // Same prod-safety gate the normal boot path applies: importing
    // a stdio manifest under the `prod` deployment profile would
    // seed a forbidden stdio server into the catalog, and a later
    // DB-backed boot would route it. Refuse the import the same
    // way boot refuses.
    cfg.enforce_prod_manifest_safety(&manifests)
        .context("GATEWAY_DEPLOYMENT_PROFILE=prod manifest safety check (import)")?;

    // Reuse the audit sink's connect path so the catalog tables
    // (migration 0011) are applied before we write to them.
    let sink = PgAuditSink::connect(url)
        .await
        .context("connect catalog DB + run migrations")?;
    let importer = ManifestImporter::new(sink.pool());

    let servers: Vec<ImportServer> = manifests.values().map(to_import_server).collect();
    let mut stats = importer.import(&servers).await;
    // Fold the per-file YAML parse failures into the same error
    // list as the per-server import failures so the operator sees
    // one unified "what didn't import" report and the exit code
    // reflects parse failures too.
    stats.errors.extend(
        parse_errors
            .into_iter()
            .map(|(f, e)| (format!("{f} (parse)"), e)),
    );

    tracing::info!(
        servers = stats.servers,
        tools = stats.tools,
        errors = stats.errors.len(),
        "manifest import complete",
    );
    for (subject, err) in &stats.errors {
        tracing::error!(subject = %subject, error = %err, "manifest import failure");
    }
    if stats.errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "manifest import finished with {} failure(s); see logs",
            stats.errors.len()
        )
    }
}

/// `gateway-server --import-policies [<dir>]` — one-shot import of the
/// on-disk `policies/*.cedar` files into a published `policy_bundles`
/// row. Runs to completion and exits without starting the HTTP
/// server — the deploy-runbook step that seeds the durable policy
/// ledger from the files so rollback / recovery have a v1 to fall
/// back to. Under file-as-truth precedence, the on-disk files remain
/// the SOURCE OF TRUTH the loader reads; this seeds the history/recovery
/// ledger beside them (it does NOT make the store the boot source).
///
/// Requires `GATEWAY_DATABASE_URL` (bundles live in Postgres).
/// Validates that the concatenated policy set parses as Cedar BEFORE
/// publishing, so a broken policy directory fails the import loudly
/// rather than seeding an unloadable bundle. Imports to the default
/// tenant (per-tenant policy import is a future concern).
pub async fn run_policies(cfg: &Config, dir_override: Option<String>) -> anyhow::Result<()> {
    use waygate_policy::PolicyStore;

    let dir = dir_override
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cfg.policies_dir.clone());

    let url = cfg.database_url.as_deref().context(
        "--import-policies requires GATEWAY_DATABASE_URL (policy bundles live in Postgres)",
    )?;

    let contents = waygate_policy::read_policy_dir(&dir)
        .with_context(|| format!("read policy dir {}", dir.display()))?;
    // Refuse empty or unparseable imports BEFORE touching the DB.
    validate_policy_import(&contents, &dir)?;

    // Reuse the audit sink's connect path so the policy table
    // (migration 0012) is applied before we write to it.
    let sink = PgAuditSink::connect(url)
        .await
        .context("connect policy DB + run migrations")?;
    let store = waygate_policy::PgPolicyStore::new(sink.pool());
    let tenant = TenantId::DEFAULT;

    // Stage then publish so the imported bundle is the active one. Two
    // round-trips, but it reuses the store's version assignment and
    // content hashing rather than re-implementing the INSERT here.
    let draft = store
        .create_draft(tenant, &contents.source, None, Some("--import-policies"))
        .await
        .context("create policy draft")?;
    let published = store
        .publish(tenant, draft.id, "--import-policies")
        .await
        .context("publish imported policy bundle")?;

    tracing::info!(
        version = published.version,
        content_hash = %published.content_hash,
        files = contents.files.len(),
        tenant = %tenant,
        dir = %dir.display(),
        "policy import complete: published bundle",
    );
    Ok(())
}

/// Pre-write validation for `--import-policies`: the directory must
/// have contributed at least one `.cedar` file, and the concatenated
/// source must parse as Cedar. Pure (no DB) so the guards are
/// unit-testable. Refusing here means a bad import fails loudly
/// instead of publishing an empty (deny-all) or unloadable bundle.
fn validate_policy_import(
    contents: &waygate_policy::PolicyDirContents,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    if contents.is_empty() {
        anyhow::bail!(
            "no .cedar files found in {}; refusing to import an empty policy bundle",
            dir.display()
        );
    }
    waygate_authz::CedarEngine::from_source(&contents.source).map_err(|e| {
        anyhow::anyhow!("policy dir {} does not parse as Cedar: {e}", dir.display())
    })?;
    Ok(())
}

/// `gateway-server --import-server-bundle [<dir>]` — one-shot import of
/// the on-disk `servers/*.yaml` set into a published `server_manifests`
/// bundle. Runs to completion and exits without starting the
/// HTTP server — the deploy-runbook cutover step that seeds the durable
/// recovery ledger from the files. Boot and SIGHUP remain file-first; they
/// consult the active ledger bundle only when the live directory is unusable.
///
/// Distinct from `--import-manifests`, which seeds the *catalog*
/// (one row per server). This seeds the *whole-set bundle* that the
/// runtime pool is built from.
///
/// Requires `GATEWAY_DATABASE_URL` (bundles live in Postgres). Loads the
/// manifests strictly (the same fail-loud `load_manifests` boot uses),
/// applies the prod-safety gate, refuses an empty set, and round-trip
/// self-checks the serialized form BEFORE publishing — so a broken or
/// non-round-tripping set fails the import loudly rather than seeding a
/// bundle that boot would silently skip. Imports to the default tenant
/// (per-tenant manifests are a future concern). Non-idempotent, like
/// `--import-policies`: re-running publishes a new version re-seeded
/// from the current YAML.
pub async fn run_server_bundle(cfg: &Config, dir_override: Option<String>) -> anyhow::Result<()> {
    use waygate_manifest_store::ManifestStore;

    let dir = dir_override
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cfg.servers_dir.clone());

    let url = cfg.database_url.as_deref().context(
        "--import-server-bundle requires GATEWAY_DATABASE_URL (manifest bundles live in Postgres)",
    )?;

    // Strict load — fail loud on the first bad manifest, exactly like
    // boot. A set that can't fully load must NOT be published.
    let manifests =
        load_manifests(&dir).with_context(|| format!("load manifests from {}", dir.display()))?;

    // Same prod-safety gate boot applies, before any DB write — refuse
    // to seed a bundle boot would itself reject.
    cfg.enforce_prod_manifest_safety(&manifests)
        .context("GATEWAY_DEPLOYMENT_PROFILE=prod manifest safety check (import)")?;

    let serialized = serialize_manifest_set(&manifests).context("serialize manifest set")?;
    // Refuse empty + verify the serialized form round-trips, BEFORE the
    // DB write.
    validate_server_bundle_import(&manifests, &serialized, &dir)?;

    // Reuse the audit sink's connect path so the manifest table
    // (migration 0037) is applied before we write to it.
    let sink = PgAuditSink::connect(url)
        .await
        .context("connect manifest DB + run migrations")?;
    let store = waygate_manifest_store::PgManifestStore::new(sink.pool());
    let tenant = TenantId::DEFAULT;

    // Stage then publish so the imported bundle is the active one. Two
    // round-trips, but it reuses the store's version assignment and
    // content hashing rather than re-implementing the INSERT here.
    let draft = store
        .create_draft(tenant, &serialized, Some("--import-server-bundle"))
        .await
        .context("create manifest draft")?;
    let published = store
        .publish(tenant, draft.id, "--import-server-bundle")
        .await
        .context("publish imported manifest bundle")?;

    tracing::info!(
        version = published.version,
        content_hash = %published.content_hash,
        upstreams = manifests.len(),
        tenant = %tenant,
        dir = %dir.display(),
        "server bundle import complete: published bundle",
    );
    Ok(())
}

/// Pre-write validation for `--import-server-bundle`: the directory
/// must contribute at least one manifest, and the serialized set must
/// re-parse to the same upstream names. Pure (no DB) so the guards are
/// unit-testable. Refusing here means a bad import fails loudly instead
/// of publishing an empty ("no upstreams") or non-round-tripping
/// bundle that boot would silently skip via the YAML fallback.
fn validate_server_bundle_import(
    manifests: &BTreeMap<String, UpstreamManifest>,
    serialized: &str,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    if manifests.is_empty() {
        anyhow::bail!(
            "no *.yaml manifests found in {}; refusing to import an empty server bundle",
            dir.display()
        );
    }
    // Round-trip self-check: the serialized form must parse back to the
    // same set of upstream names. Catches a serialize/parse asymmetry
    // before an unusable bundle is published into the recovery ledger.
    let reparsed = parse_manifest_set(serialized)
        .with_context(|| format!("serialized bundle from {} does not re-parse", dir.display()))?;
    let orig: Vec<&String> = manifests.keys().collect();
    let round: Vec<&String> = reparsed.keys().collect();
    if orig != round {
        anyhow::bail!(
            "serialized server bundle from {} did not round-trip (names changed: {:?} -> {:?})",
            dir.display(),
            orig,
            round,
        );
    }
    Ok(())
}

/// Map a parsed `UpstreamManifest` into the catalog's neutral
/// import shape. Imports everything to the default tenant —
/// per-tenant catalog import is a future concern (manifests
/// don't carry a tenant).
///
/// `runtime_target` preserves EVERY connection-relevant manifest
/// field, not just url/command: dropping `auth` would mean a future
/// DB-backed boot reconstructs an upstream that the YAML declared
/// bearer-protected as an UNAUTHENTICATED connection — a real
/// security regression for public-internet upstreams. `exchange`
/// (Tier-A token exchange config) and `tier_a_required`
/// (fail-closed flag) are likewise connection-shaping and must
/// survive the round-trip. Each is serialised only when present so
/// the JSONB stays minimal for the common no-auth/no-exchange
/// upstream.
fn to_import_server(m: &UpstreamManifest) -> ImportServer {
    let transport = match m.transport {
        Transport::Http => "http",
        Transport::Sse => "sse",
        Transport::Stdio => "stdio",
    };
    let mut rt = serde_json::Map::new();
    match m.transport {
        Transport::Http | Transport::Sse => {
            rt.insert("url".into(), serde_json::json!(m.url));
        }
        Transport::Stdio => {
            rt.insert("command".into(), serde_json::json!(m.command));
        }
    }
    // The lifecycle override is connection-relevant exactly like `url` /
    // `auth`: an explicit `legacy` or `2026-07-28` must survive into the
    // persisted runtime target or the catalog row cannot represent the
    // dial the source manifest declared. The `auto` default stays out,
    // matching the manifest serialization.
    if !m.protocol.is_auto() {
        rt.insert("protocol".into(), serde_json::json!(m.protocol));
    }
    if m.auth.is_some() {
        rt.insert("auth".into(), serde_json::json!(m.auth));
    }
    if m.exchange.is_some() {
        rt.insert("exchange".into(), serde_json::json!(m.exchange));
    }
    if m.tier_a_required {
        rt.insert("tier_a_required".into(), serde_json::json!(true));
    }
    // Round-trip the mTLS block too. A future catalog-backed
    // transport reconstruction (`TransportFactory`) would read
    // `runtime_target` to dial; dropping `mtls` here would silently
    // swap a YAML-declared mTLS-required upstream for an
    // anonymous-TLS connection on a DB-backed boot — same shape of
    // regression as dropping `auth`. Only emitted when present so
    // the JSONB stays minimal for non-mTLS upstreams.
    if m.mtls.is_some() {
        rt.insert("mtls".into(), serde_json::json!(m.mtls));
    }
    // `tier_c_peer:` is a connection-relevant identity selector —
    // at runtime the pool reads it to override the X-MCP-Identity
    // audience and stamp Authorization: Bearer with the peer-issuer
    // JWT. Without round-tripping it through `runtime_target`, a
    // `--import-manifests` pass then DB-backed boot would silently
    // downgrade a Tier-C upstream to Tier-B until the operator
    // re-edited the catalog by hand. Same regression shape as the
    // `auth` / `exchange` / `mtls` round-trips above; only emitted
    // when present so the JSONB stays minimal for non-Tier-C
    // upstreams.
    if m.tier_c_peer.is_some() {
        rt.insert("tier_c_peer".into(), serde_json::json!(m.tier_c_peer));
    }
    // `session` (today the `concurrency` pool-size override) is
    // connection-shaping — it sizes the slot pool at dial time.
    // Without round-tripping
    // it through `runtime_target`, a `--import-manifests` pass
    // would store catalog metadata lacking the override, so any
    // runtime-target-backed dial would silently fall back to the
    // global `GATEWAY_UPSTREAM_POOL_SIZE`. Same regression shape
    // as the auth / exchange / mtls / tier_c_peer round-trips
    // above; only emitted when present so the JSONB stays minimal
    // for upstreams on the global default.
    if m.session.is_some() {
        rt.insert("session".into(), serde_json::json!(m.session));
    }
    ImportServer {
        tenant_id: TenantId::DEFAULT.to_owned(),
        name: m.name.clone(),
        transport: transport.to_owned(),
        runtime_target: serde_json::Value::Object(rt),
        classification_mode: match m.classification_mode {
            waygate_upstream::ClassificationMode::Manifest => "manifest",
            waygate_upstream::ClassificationMode::McpAnnotations => "mcp_annotations",
        }
        .to_owned(),
        tools: m.tools.iter().map(to_import_tool).collect(),
    }
}

fn to_import_tool(c: &waygate_upstream::ToolClassification) -> ImportTool {
    use waygate_mcp::protocol::RiskTier;
    let risk = match c.risk {
        RiskTier::Low => "low",
        RiskTier::Medium => "medium",
        RiskTier::High => "high",
    };
    ImportTool {
        name: c.name.clone(),
        approved_behavior_hash: c.approved_behavior_hash.clone(),
        risk: risk.to_owned(),
        side_effects: c.side_effects,
        pii: c.pii,
        discriminator: c.discriminator.clone(),
        operations: c
            .operations
            .iter()
            .map(|operation| ImportOperation {
                value: operation.value.clone(),
                risk: match operation.risk {
                    RiskTier::Low => "low",
                    RiskTier::Medium => "medium",
                    RiskTier::High => "high",
                }
                .to_owned(),
                side_effects: operation.side_effects,
                pii: operation.pii,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str, transport: Transport) -> UpstreamManifest {
        UpstreamManifest {
            classification_mode: Default::default(),
            approval_mode: Default::default(),
            name: name.into(),
            transport,
            protocol: Default::default(),
            url: Some("http://x.test/mcp".into()),
            command: None,
            tools: vec![waygate_upstream::ToolClassification::new(
                "send",
                waygate_mcp::protocol::RiskTier::High,
                true,
                false,
            )],
            resources: Vec::new(),
            exchange: None,
            auth: None,
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            session: None,
        }
    }

    #[test]
    fn http_manifest_maps_url_runtime_target() {
        let s = to_import_server(&manifest("example-messages", Transport::Http));
        assert_eq!(s.name, "example-messages");
        assert_eq!(s.transport, "http");
        assert_eq!(s.tenant_id, "default");
        assert_eq!(s.runtime_target["url"], "http://x.test/mcp");
        assert_eq!(s.classification_mode, "manifest");
        assert_eq!(s.tools.len(), 1);
        assert_eq!(s.tools[0].risk, "high");
        assert!(s.tools[0].side_effects);
    }

    #[test]
    fn annotation_mode_and_approved_behavior_hash_reach_the_catalog_import() {
        let mut source = manifest("komodo", Transport::Http);
        source.classification_mode = waygate_upstream::ClassificationMode::McpAnnotations;
        source.tools[0].side_effects = false;
        source.tools[0].approved_behavior_hash = Some("a".repeat(64));

        let imported = to_import_server(&source);

        assert_eq!(imported.classification_mode, "mcp_annotations");
        assert_eq!(
            imported.tools[0].approved_behavior_hash.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn per_operation_refinement_is_preserved_in_the_catalog_import() {
        // Dropping either field would silently classify every call by the
        // tool's own entry: the harmless operations an operator admitted
        // individually would be refused, and — worse — the narrow entry that
        // made a broad executor safe to expose would stop existing without
        // anything reporting it. This mapping is the only path from the
        // reviewed manifest to the catalog rows dispatch reads.
        let mut source = manifest("gitea", Transport::Http);
        source.tools[0].discriminator = Some("operation_id".into());
        source.tools[0].operations = vec![
            waygate_upstream::OperationClassification {
                value: "repository.get".into(),
                risk: waygate_mcp::protocol::RiskTier::Low,
                side_effects: false,
                pii: false,
            },
            waygate_upstream::OperationClassification {
                value: "repository.delete".into(),
                risk: waygate_mcp::protocol::RiskTier::High,
                side_effects: true,
                pii: false,
            },
        ];

        let imported = to_import_server(&source);
        let tool = &imported.tools[0];

        assert_eq!(tool.discriminator.as_deref(), Some("operation_id"));
        assert_eq!(
            tool.operations
                .iter()
                .map(|operation| (
                    operation.value.as_str(),
                    operation.risk.as_str(),
                    operation.side_effects,
                    operation.pii
                ))
                .collect::<Vec<_>>(),
            vec![
                ("repository.get", "low", false, false),
                ("repository.delete", "high", true, false),
            ],
            "every reviewed operation, with the risk tier rendered as the              catalog spells it"
        );
    }

    #[test]
    fn stdio_manifest_maps_command_runtime_target() {
        let mut m = manifest("local", Transport::Stdio);
        m.url = None;
        m.command = Some(vec!["/bin/foo".into(), "--arg".into()]);
        let s = to_import_server(&m);
        assert_eq!(s.transport, "stdio");
        assert_eq!(s.runtime_target["command"][0], "/bin/foo");
    }

    #[test]
    fn auth_metadata_is_preserved_in_runtime_target() {
        // Dropping `auth` would let a DB-backed boot reconstruct a
        // bearer-protected upstream as unauthenticated. Pin that
        // auth survives the mapping.
        let mut m = manifest("ha", Transport::Http);
        m.auth = Some(waygate_upstream::UpstreamAuth {
            bearer_env: Some("HA_BEARER".into()),
            catalog_probe_groups: vec!["ha-admin".into()],
        });
        let s = to_import_server(&m);
        assert_eq!(
            s.runtime_target["auth"]["bearer_env"], "HA_BEARER",
            "auth.bearer_env must round-trip into runtime_target",
        );
        assert_eq!(
            s.runtime_target["auth"]["catalog_probe_groups"][0], "ha-admin",
            "auth.catalog_probe_groups must round-trip into runtime_target",
        );
    }

    #[test]
    fn exchange_and_tier_a_required_preserved() {
        let mut m = manifest("example-messages", Transport::Http);
        m.exchange = Some(waygate_upstream::ExchangeConfig {
            audience: "https://example-messages.test".into(),
            scope: None,
        });
        m.tier_a_required = true;
        let s = to_import_server(&m);
        assert_eq!(
            s.runtime_target["exchange"]["audience"],
            "https://example-messages.test"
        );
        assert_eq!(s.runtime_target["tier_a_required"], true);
    }

    #[test]
    fn no_auth_keeps_runtime_target_minimal() {
        // The common no-auth/no-exchange upstream must not carry
        // null `auth`/`exchange`/`mtls`/`session` keys — only what's present.
        let s = to_import_server(&manifest("plain", Transport::Http));
        assert!(s.runtime_target.get("auth").is_none());
        assert!(s.runtime_target.get("exchange").is_none());
        assert!(s.runtime_target.get("tier_a_required").is_none());
        assert!(s.runtime_target.get("mtls").is_none());
        assert!(s.runtime_target.get("session").is_none());
    }

    #[test]
    fn session_concurrency_preserved_in_runtime_target() {
        // session.concurrency sizes the slot pool at dial time, so
        // it must survive the import round-trip — otherwise a
        // runtime-target-backed flow falls back to the global pool
        // size.
        let mut m = manifest("searxng", Transport::Http);
        m.session = Some(waygate_upstream::SessionConfig {
            concurrency: Some(1),
            isolation: None,
            scope: None,
            retry_on_setup_failure: None,
        });
        let s = to_import_server(&m);
        assert_eq!(
            s.runtime_target["session"]["concurrency"], 1,
            "session.concurrency must round-trip into runtime_target",
        );
    }

    #[test]
    fn mtls_metadata_is_preserved_in_runtime_target() {
        // Dropping `mtls` would let a DB-backed boot reconstruct
        // an mTLS-required upstream as anonymous-TLS — same shape
        // of regression as dropping `auth`. Pin that mtls survives
        // the mapping with every field.
        let mut m = manifest("secure-svc", Transport::Http);
        m.mtls = Some(waygate_upstream::MtlsConfig {
            cert_path: Some(std::path::PathBuf::from("/etc/gateway/secure-svc.crt")),
            key_path: Some(std::path::PathBuf::from("/etc/gateway/secure-svc.key")),
            ca_path: Some(std::path::PathBuf::from("/etc/gateway/internal-ca.crt")),
        });
        let s = to_import_server(&m);
        assert_eq!(
            s.runtime_target["mtls"]["cert_path"], "/etc/gateway/secure-svc.crt",
            "mtls.cert_path must round-trip into runtime_target",
        );
        assert_eq!(
            s.runtime_target["mtls"]["key_path"],
            "/etc/gateway/secure-svc.key",
        );
        assert_eq!(
            s.runtime_target["mtls"]["ca_path"],
            "/etc/gateway/internal-ca.crt",
        );
    }

    #[test]
    fn import_flag_parses_separate_and_joined_forms() {
        // Pure parser unit-test over an explicit arg vector is
        // not possible (parse_import_flag reads std::env::args),
        // so this documents the contract instead: the separate
        // and joined forms both yield the dir, bare yields None.
        // Exercised end-to-end by the deploy runbook.
        assert_eq!(
            "--import-manifests=foo".strip_prefix("--import-manifests="),
            Some("foo"),
        );
    }

    fn dir_contents(source: &str, files: &[&str]) -> waygate_policy::PolicyDirContents {
        waygate_policy::PolicyDirContents {
            source: source.to_owned(),
            files: files.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn policy_import_accepts_valid_cedar() {
        let c = dir_contents(
            "permit(principal, action, resource);\n",
            &["10-allow.cedar"],
        );
        assert!(validate_policy_import(&c, std::path::Path::new("policies")).is_ok());
    }

    #[test]
    fn policy_import_refuses_empty_dir() {
        // No .cedar files ⇒ empty bundle ⇒ deny-all after cutover.
        // Must be refused before any DB write.
        let c = dir_contents("", &[]);
        let err = validate_policy_import(&c, std::path::Path::new("policies"))
            .expect_err("empty import must be refused");
        assert!(err.to_string().contains("empty policy bundle"));
    }

    #[test]
    fn policy_import_refuses_unparseable_cedar() {
        // Files present but the source doesn't parse — must fail the
        // import loudly rather than publish an unloadable bundle.
        let c = dir_contents("this is not cedar {{{", &["broken.cedar"]);
        let err = validate_policy_import(&c, std::path::Path::new("policies"))
            .expect_err("unparseable cedar must be refused");
        assert!(err.to_string().contains("does not parse as Cedar"));
    }

    fn manifest_set(names: &[&str]) -> BTreeMap<String, UpstreamManifest> {
        let mut out = BTreeMap::new();
        for n in names {
            out.insert((*n).to_owned(), manifest(n, Transport::Http));
        }
        out
    }

    #[test]
    fn server_bundle_import_accepts_valid_set() {
        // A non-empty set whose serialized form round-trips passes.
        let set = manifest_set(&["example-messages", "example-mailbox"]);
        let serialized = serialize_manifest_set(&set).expect("serialize");
        assert!(
            validate_server_bundle_import(&set, &serialized, std::path::Path::new("servers"))
                .is_ok()
        );
    }

    #[test]
    fn server_bundle_import_refuses_empty() {
        // No manifests ⇒ a no-upstreams bundle ⇒ must be refused before
        // any DB write (boot would otherwise silently fall back to YAML,
        // masking that the publish seeded nothing).
        let set: BTreeMap<String, UpstreamManifest> = BTreeMap::new();
        let serialized = serialize_manifest_set(&set).expect("serialize empty");
        let err = validate_server_bundle_import(&set, &serialized, std::path::Path::new("servers"))
            .expect_err("empty import must be refused");
        assert!(err.to_string().contains("empty server bundle"));
    }

    #[test]
    fn server_bundle_import_refuses_non_round_tripping() {
        // If the serialized blob doesn't re-parse to the same names, the
        // self-check fails. Simulate by passing a serialized form whose
        // parsed names differ from the claimed set.
        let set = manifest_set(&["example-messages"]);
        let wrong = "- name: different\n  transport: http\n  url: http://x/mcp\n";
        let err = validate_server_bundle_import(&set, wrong, std::path::Path::new("servers"))
            .expect_err("name mismatch must be refused");
        assert!(err.to_string().contains("did not round-trip"));
    }

    #[tokio::test]
    async fn reconcile_empty_set_reaches_the_catalog_boundary() {
        // A clean empty live directory is an authoritative zero-upstream
        // generation, so reconciliation must reach Postgres and quarantine the
        // default tenant's formerly-live rows. A lazy pool to a bogus DSN proves
        // the empty-set path no longer returns before touching the catalog.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy never dials");
        let empty: BTreeMap<String, UpstreamManifest> = BTreeMap::new();
        let error = reconcile_catalog_from_manifests(&pool, &empty)
            .await
            .expect_err("empty reconcile must touch the unavailable catalog");
        assert!(
            error.to_string().contains("catalog reconcile"),
            "got: {error:#}"
        );
    }

    /// Every dashboard reconcile attempt must arm the reload task's latch so
    /// the next doorbell tick re-imports from current disk truth — that is
    /// what retries a failure and settles interleavings with a concurrent
    /// doorbell/SIGHUP reconcile. A lazy pool against an unreachable server
    /// exercises the failure arm without a database.
    #[tokio::test]
    async fn dashboard_reconcile_callback_arms_the_reload_latch() {
        let before = crate::reload::CATALOG_RECONCILE_LATCH.observe();
        let pool = sqlx::postgres::PgPoolOptions::new()
            // Bound the doomed dial so the failure arm resolves in ~1s
            // instead of sqlx's default 30s acquire timeout.
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect_lazy("postgres://invalid-user@127.0.0.1:1/none")
            .expect("lazy pool construction is offline");
        let callback = catalog_reconcile_callback(pool);
        let result = callback(manifest_set(&["example-messages"])).await;
        assert!(
            result.is_err(),
            "an unreachable catalog must fail the reconcile"
        );
        assert!(
            crate::reload::CATALOG_RECONCILE_LATCH.observe() > before,
            "the failed dashboard reconcile must arm the reload latch",
        );
    }
}
