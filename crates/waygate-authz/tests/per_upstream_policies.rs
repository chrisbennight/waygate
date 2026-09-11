//! Exercises the per-server policies (`20-example-messages.cedar`,
//! `20-example-observability.cedar`, `20-example-memory-*.cedar`,
//! `20-example-deployer.cedar`, `20-example-secrets.cedar`,
//! `20-example-catalog.cedar`, `20-example-forge.cedar`) layered on top of the baseline forbid +
//! role-allow.
//!
//! These tests are intentionally separate from `authz_e2e.rs` because they
//! depend on specific group names (`message-operators`, `incident-responders`,
//! `code-memory-writers`, …) and server names (`example-messages`,
//! `example-observability`, `example-memory-code`, …) — binding the test
//! fixture to the policy's assumptions makes regressions obvious.

use std::path::PathBuf;
use std::sync::Arc;

use waygate_authz::{AuthzEngine, CedarEngine};
use waygate_mcp::authz::{AuthzGate, AuthzVerdict, ToolFacts};
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::Principal;

use waygate_authz::CedarGate;

fn policies_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("crates/waygate-authz/tests/fixtures/policies")
}

fn gate() -> CedarGate {
    let engine = CedarEngine::load_dir(&policies_dir()).expect("load policies");
    let arc: Arc<dyn AuthzEngine> = Arc::new(engine);
    CedarGate::new(arc)
}

/// Tests here probe per-upstream group permits, not the step-up gate. So every
/// principal carries `mcp:invoke:high` — callers are assumed to have already
/// re-authorized. Step-up behavior is covered in `step_up.rs` / `authz_e2e.rs`.
fn principal(sub: &str, groups: &[&str]) -> Principal {
    Principal {
        sub: sub.into(),
        email: Some(format!("{sub}@example.test")),
        groups: groups.iter().map(|g| (*g).to_string()).collect(),
        issuer: "https://auth.example.test".into(),
        scopes: vec!["mcp:invoke".into(), "mcp:invoke:high".into()],
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

fn principal_with_admin_scope(sub: &str, groups: &[&str]) -> Principal {
    let mut principal = principal(sub, groups);
    principal.scopes.push("mcp:admin".into());
    principal
}

fn tool(server: &str, name: &str, risk: RiskTier) -> ToolFacts {
    ToolFacts {
        server: server.into(),
        name: name.into(),
        risk,
        side_effects: risk == RiskTier::High,
        pii: false,
        requires_approval: false,
        requires_approval_known: true,
    }
}

/// Like `tool`, but with an explicit `side_effects` — needed for the
/// side-effecting-but-not-high tools (example-observability annotations/folders,
/// example-fetch fetches) whose permits key on `side_effects`, not the risk tier.
fn tool_se(server: &str, name: &str, risk: RiskTier, side_effects: bool) -> ToolFacts {
    ToolFacts {
        server: server.into(),
        name: name.into(),
        risk,
        side_effects,
        pii: false,
        requires_approval: false,
        requires_approval_known: true,
    }
}

fn is_allow(v: &AuthzVerdict) -> bool {
    matches!(v, AuthzVerdict::Allow { .. })
}

// ---------- Example catalog product guidance ----------

#[tokio::test]
async fn authenticated_users_can_read_only_reviewed_catalog_guides() {
    let p = principal("product-designer", &["mcp-users"]);
    let gate = gate();

    assert!(
        gate.may_list_resources(&p, "example-catalog").await,
        "authenticated Example catalog users should discover its product resources"
    );
    assert!(
        gate.authorize_resource_read(
            &p,
            "example-catalog",
            "example-catalog://example-guides/design-v1",
            RiskTier::Low,
        )
        .await
        .is_allow(),
        "authenticated Example catalog users should read the product design guide"
    );
    assert!(
        gate.authorize_resource_read(
            &p,
            "example-catalog",
            "example-catalog://example-guides/render-v1",
            RiskTier::Low,
        )
        .await
        .is_allow(),
        "authenticated Example catalog users should read the presentation guide"
    );
    assert!(
        !gate
            .authorize_resource_read(
                &p,
                "example-catalog",
                "example-catalog://private/operations",
                RiskTier::Low,
            )
            .await
            .is_allow(),
        "the product grant must not authorize an unreviewed Example catalog resource"
    );
    assert!(
        !gate.may_list_resources(&p, "example-messages").await,
        "the Example catalog grant must not widen another upstream"
    );
}

// ---------- example-messages ----------

#[tokio::test]
async fn message_operators_send_but_cannot_administer_account() {
    // message-operators is the messaging-tier operator group: it sends / reacts /
    // manages groups (low + side_effects) but the high account/identity surface
    // (register/unregister, device linking, PIN) is admin-only
    // (20-example-messages.cedar keys on `side_effects && risk != "high"`).
    // A messaging operator must not be able to unregister the account or link a
    // new device.
    let p = principal("alice", &["message-operators"]);
    let send = gate()
        .may_call_tool(
            &p,
            &tool_se("example-messages", "messages.send", RiskTier::Low, true),
        )
        .await;
    assert!(
        is_allow(&send),
        "message-operators should send at low+side_effects: {send:?}"
    );
    let admin = gate()
        .may_call_tool(
            &p,
            &tool_se(
                "example-messages",
                "accounts.register",
                RiskTier::High,
                true,
            ),
        )
        .await;
    assert!(
        !is_allow(&admin),
        "message-operators must NOT reach the high account/identity tier: {admin:?}"
    );
}

#[tokio::test]
async fn plain_user_cannot_send_example_messages_message() {
    let p = principal("carol", &["mcp-users"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se("example-messages", "messages.send", RiskTier::Low, true),
        )
        .await;
    assert!(!is_allow(&v), "mcp-users alone should be denied: {v:?}");
}

#[tokio::test]
async fn message_operators_do_not_leak_to_other_servers() {
    // Membership in message-operators must NOT grant example-observability high-risk — the
    // per-upstream grant is scoped on `resource.server`. If this fails, the
    // policy's `server` guard is wrong and we've leaked privilege.
    let p = principal("alice", &["message-operators"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool("example-observability", "incidents.create", RiskTier::High),
        )
        .await;
    assert!(
        !is_allow(&v),
        "message-operators must not cross to example-observability: {v:?}"
    );
}

#[tokio::test]
async fn message_reader_reads_but_cannot_send_side_effecting_low() {
    // message-reader is read/receive
    // only; its permit must NOT be keyed on bare `resource.risk == "low"`. The
    // medium->low sweep lands side-effecting example-messages writes (typing indicators) at
    // `low + side_effects: true`, which a bare risk-only permit would capture. The
    // `!side_effects` guard keeps the role receive-only across the reclassification.
    let p = principal("rita", &["message-reader"]);
    // read-only low example-messages tool -> allowed
    let read = gate()
        .may_call_tool(
            &p,
            &tool_se("example-messages", "messages.receive", RiskTier::Low, false),
        )
        .await;
    assert!(is_allow(&read), "receiver should read: {read:?}");
    // side-effecting low example-messages tool (demoted typing indicator) -> denied
    let write = gate()
        .may_call_tool(
            &p,
            &tool_se("example-messages", "messages.typing", RiskTier::Low, true),
        )
        .await;
    assert!(
        !is_allow(&write),
        "receiver must NOT call side-effecting example-messages writes: {write:?}"
    );
}

#[tokio::test]
async fn message_roles_split_is_access_preserving() {
    // Example messaging service's messaging surface is classified low+side_effects; the
    // account/identity/security surface stays high. Pin that this
    // classification governs access correctly:
    //   - the narrow message-sender (name-keyed permit) still sends messages.send,
    //     at low+side_effects;
    //   - the broad message-operators covers a reclassified operational tool;
    //   - a groupless principal reaches neither the operational tool nor a
    //     still-high account tool.
    let sender = principal("sam", &["message-sender"]);
    let send = gate()
        .may_call_tool(
            &sender,
            &tool_se("example-messages", "messages.send", RiskTier::Low, true),
        )
        .await;
    assert!(
        is_allow(&send),
        "message-sender should still send messages.send at low+side_effects: {send:?}"
    );

    let broad = principal("sue", &["message-operators"]);
    let react = gate()
        .may_call_tool(
            &broad,
            &tool_se("example-messages", "messages.react", RiskTier::Low, true),
        )
        .await;
    assert!(
        is_allow(&react),
        "message-operators should react: {react:?}"
    );

    let nobody = principal("nobody", &["mcp-users"]);
    let react_deny = gate()
        .may_call_tool(
            &nobody,
            &tool_se("example-messages", "messages.react", RiskTier::Low, true),
        )
        .await;
    assert!(
        !is_allow(&react_deny),
        "groupless must not call reclassified example-messages ops: {react_deny:?}"
    );
    let admin_deny = gate()
        .may_call_tool(
            &nobody,
            &tool("example-messages", "accounts.register", RiskTier::High),
        )
        .await;
    assert!(
        !is_allow(&admin_deny),
        "groupless must not reach still-high example-messages account tools: {admin_deny:?}"
    );
}

// ---------- example-observability ----------

#[tokio::test]
async fn any_user_can_run_observability_queries() {
    let p = principal("dave", &["mcp-users"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool("example-observability", "metrics.query", RiskTier::Medium),
        )
        .await;
    assert!(
        is_allow(&v),
        "example-observability medium should be allowed: {v:?}"
    );
}

#[tokio::test]
async fn observability_grant_does_not_cross_to_messages() {
    // The example-observability medium grant uses `resource.server == "example-observability"` — confirm
    // a hypothetical medium-risk example-messages tool would still be denied.
    let p = principal("dave", &["mcp-users"]);
    let v = gate()
        .may_call_tool(&p, &tool("example-messages", "react", RiskTier::Medium))
        .await;
    assert!(
        !is_allow(&v),
        "medium grant must not apply to example-messages: {v:?}"
    );
}

#[tokio::test]
async fn incident_responders_can_incidents_create() {
    let p = principal("erin", &["incident-responders"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool("example-observability", "incidents.create", RiskTier::High),
        )
        .await;
    assert!(is_allow(&v), "incident-responders allowed: {v:?}");
}

#[tokio::test]
async fn plain_user_cannot_incidents_create() {
    let p = principal("carol", &["mcp-users"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool("example-observability", "incidents.create", RiskTier::High),
        )
        .await;
    assert!(!is_allow(&v), "mcp-users alone should be denied: {v:?}");
}

#[tokio::test]
async fn observability_operators_can_annotations_create() {
    // The four side-effecting-but-not-high example-observability tools (annotations.create,
    // update_annotation, create_folder, add_activity_to_incident) are gated to
    // observability-operators. Keyed on `side_effects && risk != "high"`, so the test
    // sets side_effects=true explicitly. (Risk Medium today; this stays Allow
    // after the medium->low demotion because the guard is tier-independent.)
    let p = principal("gwen", &["observability-operators"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se(
                "example-observability",
                "annotations.create",
                RiskTier::Medium,
                true,
            ),
        )
        .await;
    assert!(
        is_allow(&v),
        "observability-operators should annotate: {v:?}"
    );
}

#[tokio::test]
async fn plain_user_cannot_annotations_create() {
    // annotations.create must never be world-callable under a blanket
    // `example-observability && risk == "medium"` grant. A mutating tool must require
    // observability-operators (or admin), never the bare baseline.
    let p = principal("carol", &["mcp-users"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se(
                "example-observability",
                "annotations.create",
                RiskTier::Medium,
                true,
            ),
        )
        .await;
    assert!(
        !is_allow(&v),
        "mcp-users must NOT create example-observability annotations: {v:?}"
    );
}

#[tokio::test]
async fn observability_operators_do_not_get_high_writes() {
    // The operator grant excludes `risk == "high"`, so observability-operators must NOT
    // reach the high-risk writes (alerting/incident/dashboard) — those stay with
    // incident-responders. If the `risk != "high"` guard is dropped, this fails.
    let p = principal("gwen", &["observability-operators"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se(
                "example-observability",
                "incidents.create",
                RiskTier::High,
                true,
            ),
        )
        .await;
    assert!(
        !is_allow(&v),
        "observability-operators must not reach high writes: {v:?}"
    );
}

// ---------- example-fetch (incident-triage, side_effects-keyed) ----------

#[tokio::test]
async fn triage_can_fetch_side_effecting_pages() {
    // 20-example-triage.cedar grants example-fetch side-effecting tools below
    // high to the triage role, keyed on `side_effects && risk != "high"` (not the
    // tier) so it survives the medium->low demotion of the fetch tools.
    let p = principal("svc:incident-triage", &["incident-triage"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se(
                "example-fetch",
                "pages.fetch_markdown",
                RiskTier::Medium,
                true,
            ),
        )
        .await;
    assert!(
        is_allow(&v),
        "triage should fetch example-fetch pages.fetch_markdown: {v:?}"
    );
}

#[tokio::test]
async fn plain_user_cannot_fetch_arbitrary_pages() {
    // The example-fetch fetch tools take a caller-supplied URL (SSRF / exfil surface),
    // so they carry side_effects:true and must stay confined to the triage role —
    // never world-callable, even after the medium tier retires.
    let p = principal("carol", &["mcp-users"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se(
                "example-fetch",
                "pages.fetch_markdown",
                RiskTier::Medium,
                true,
            ),
        )
        .await;
    assert!(
        !is_allow(&v),
        "mcp-users must NOT fetch arbitrary URLs via example-fetch: {v:?}"
    );
}

#[tokio::test]
async fn unrestricted_fetchers_fetch_and_browser_execute_script() {
    // 20-example-fetch.cedar grants the FULL side-effecting example-fetch surface to
    // Group::"unrestricted-fetchers": the fetch tools (low+side_effects) AND
    // browser.execute_script (high+side_effects / RCE). Unlike incident-triage, which
    // excludes browser.execute_script, this group intentionally includes it.
    let p = principal("assistant", &["unrestricted-fetchers"]);
    let fetched = gate()
        .may_call_tool(
            &p,
            &tool_se("example-fetch", "pages.fetch_markdown", RiskTier::Low, true),
        )
        .await;
    assert!(
        is_allow(&fetched),
        "unrestricted-fetchers should fetch pages.fetch_markdown: {fetched:?}"
    );
    let js = gate()
        .may_call_tool(
            &p,
            &tool_se(
                "example-fetch",
                "browser.execute_script",
                RiskTier::High,
                true,
            ),
        )
        .await;
    assert!(
        is_allow(&js),
        "unrestricted-fetchers should run browser.execute_script (this group includes it): {js:?}"
    );
}

#[tokio::test]
async fn unrestricted_fetchers_do_not_leak_to_other_servers() {
    // The example-fetch grant is server-scoped; membership must not cross to another
    // upstream's high tier.
    let p = principal("assistant", &["unrestricted-fetchers"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool("example-observability", "incidents.create", RiskTier::High),
        )
        .await;
    assert!(
        !is_allow(&v),
        "unrestricted-fetchers must not cross to example-observability: {v:?}"
    );
}

// ---------- example mailbox / example-mail-admin (mail-automation) ----------

#[tokio::test]
async fn mail_automation_manage_mailbox_fully() {
    // 20-example-mailbox.cedar grants the FULL side-effecting mailbox surface to
    // mail-automation (send + register/unregister account + mark/move/delete mail)
    // via a broad `resource.side_effects` grant — full mailbox management.
    let p = principal("mailer", &["mail-automation"]);
    for tool_name in [
        "messages.send",
        "accounts.register",
        "accounts.unregister",
        "messages.mark",
        "messages.move",
        "messages.delete",
    ] {
        let v = gate()
            .may_call_tool(
                &p,
                &tool_se("example-mailbox", tool_name, RiskTier::High, true),
            )
            .await;
        assert!(
            is_allow(&v),
            "mail-automation should manage mailbox.{tool_name}: {v:?}"
        );
    }
}

#[tokio::test]
async fn plain_user_cannot_manage_mailbox() {
    // The mailbox side-effecting tools are high; a groupless principal must not
    // reach them. (Read tools are baseline + pii-readers, not these.)
    let p = principal("carol", &["mcp-users"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se("example-mailbox", "messages.send", RiskTier::High, true),
        )
        .await;
    assert!(!is_allow(&v), "mcp-users must NOT send mail: {v:?}");
}

#[tokio::test]
async fn mail_automation_provision_example_mail_admin_accounts_only() {
    // 20-example-mail-admin.cedar is an EXPLICIT allowlist: mail-automation may create /
    // modify / delete email ACCOUNTS only — never the domain / DNS / forwarder /
    // pointer / catch-all / spam / mail-status administration surface.
    let p = principal("mailer", &["mail-automation"]);
    for ok in ["accounts.create", "accounts.update", "accounts.delete"] {
        let v = gate()
            .may_call_tool(&p, &tool_se("example-mail-admin", ok, RiskTier::High, true))
            .await;
        assert!(
            is_allow(&v),
            "mail-automation should provision example-mail-admin account {ok}: {v:?}"
        );
    }
    for denied in [
        "domains.create",
        "domains.delete",
        "routes.create",
        "filters.update",
        "catchall.update",
    ] {
        let v = gate()
            .may_call_tool(
                &p,
                &tool_se("example-mail-admin", denied, RiskTier::High, true),
            )
            .await;
        assert!(
            !is_allow(&v),
            "mail-automation must NOT administer example-mail-admin ({denied}): {v:?}"
        );
    }
}

#[tokio::test]
async fn mail_automation_do_not_leak_to_other_servers() {
    // Mail grants are server-scoped; mail-automation must not gain access elsewhere.
    let p = principal("mailer", &["mail-automation"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool("example-observability", "incidents.create", RiskTier::High),
        )
        .await;
    assert!(
        !is_allow(&v),
        "mail-automation must not cross to example-observability: {v:?}"
    );
}

// ---------- example facility service (home-control low+side_effects
//            opened to operators; instance administration stays high, admin-only) ----------

#[tokio::test]
async fn facility_operators_drive_control_not_admin_on_east() {
    // HA's home-control surface is low+side_effects and is
    // opened to facility-operators; the instance-administration surface
    // stays high and is NOT opened here — it falls through to the mcp-admins
    // blanket permit only (like example-observability's high tier). 20-example-facilities.cedar
    // keys on `side_effects && risk != "high"`, so operators get exactly the
    // control tier — matching the group's stated "control the home, not a full
    // mcp-admin" intent.
    let op = principal("frank", &["facility-operators"]);
    let control = gate()
        .may_call_tool(
            &op,
            &tool_se(
                "example-facility-east",
                "devices.invoke",
                RiskTier::Low,
                true,
            ),
        )
        .await;
    assert!(
        is_allow(&control),
        "facility-operators drive low+side_effects control on east: {control:?}"
    );
    let admin = gate()
        .may_call_tool(
            &op,
            &tool_se(
                "example-facility-east",
                "system.restart",
                RiskTier::High,
                true,
            ),
        )
        .await;
    assert!(
        !is_allow(&admin),
        "facility-operators must NOT reach the high instance-admin tier on east: {admin:?}"
    );
}

#[tokio::test]
async fn facility_operators_drive_control_not_admin_on_west() {
    // Pins the west-site grant AND the admin-tier exclusion on the second
    // upstream. If the control grant regresses, the operator-managed home stops
    // working; if the admin exclusion regresses, operators silently gain
    // restart/backup/addon control over the west instance.
    let op = principal("frank", &["facility-operators"]);
    let control = gate()
        .may_call_tool(
            &op,
            &tool_se(
                "example-facility-west",
                "devices.invoke",
                RiskTier::Low,
                true,
            ),
        )
        .await;
    assert!(
        is_allow(&control),
        "facility-operators drive control on west: {control:?}"
    );
    let admin = gate()
        .may_call_tool(
            &op,
            &tool_se(
                "example-facility-west",
                "system.restart",
                RiskTier::High,
                true,
            ),
        )
        .await;
    assert!(
        !is_allow(&admin),
        "facility-operators must NOT reach the high admin tier on west: {admin:?}"
    );
}

#[tokio::test]
async fn plain_user_cannot_call_side_effecting_facility_on_either_instance() {
    // Access-preservation for NON-operators: the demotion to low+side_effects
    // must NOT leak the home-control surface into the narrowed baseline, and the
    // still-high admin surface stays denied too. Groupless mcp-users reach
    // neither tier on either instance.
    let p = principal("carol", &["mcp-users"]);
    for server in ["example-facility-east", "example-facility-west"] {
        let control = gate()
            .may_call_tool(&p, &tool_se(server, "devices.invoke", RiskTier::Low, true))
            .await;
        assert!(
            !is_allow(&control),
            "mcp-users denied on demoted low+side_effects control {server}: {control:?}"
        );
        let admin = gate()
            .may_call_tool(&p, &tool_se(server, "system.restart", RiskTier::High, true))
            .await;
        assert!(
            !is_allow(&admin),
            "mcp-users denied on still-high admin {server}: {admin:?}"
        );
    }
}

#[tokio::test]
async fn facility_operator_grant_does_not_leak_to_other_servers() {
    // Regression: the disjunction in the policy must enumerate the facility
    // namespaces explicitly. If someone "simplifies" the when-clause to
    // something looser (e.g. a substring match) and a future upstream
    // reuses that prefix, this test fails before the grant accidentally
    // widens.
    let p = principal("frank", &["facility-operators"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool("example-messages", "messages.send", RiskTier::High),
        )
        .await;
    assert!(
        !is_allow(&v),
        "facility-operators must not gain access to example-messages: {v:?}"
    );
}

// ---------- example-deployer (open status, service-specific administration) ----------

#[tokio::test]
async fn deployer_reads_are_baseline_but_actions_require_deploy_operator() {
    let reader = principal("reader", &["mcp-users"]);
    let status = gate()
        .may_call_tool(
            &reader,
            &tool_se(
                "example-deployer",
                "deployments.status",
                RiskTier::Low,
                false,
            ),
        )
        .await;
    assert!(
        is_allow(&status),
        "authenticated baseline users should read bounded Example deployment service status: {status:?}"
    );

    let deploy = tool_se("example-deployer", "deployments.apply", RiskTier::Low, true);
    let reader_write = gate().may_call_tool(&reader, &deploy).await;
    assert!(
        !is_allow(&reader_write),
        "baseline users must not call side-effecting Example deployment service tools: {reader_write:?}"
    );

    let service_admin = principal("operator", &["deploy-operators"]);
    let service_write = gate().may_call_tool(&service_admin, &deploy).await;
    assert!(
        is_allow(&service_write),
        "deploy-operators should call side-effecting Example deployment service tools: {service_write:?}"
    );

    let waygate_admin = principal("gateway-admin", &["mcp-admins"]);
    let gateway_admin_write = gate().may_call_tool(&waygate_admin, &deploy).await;
    assert!(
        !is_allow(&gateway_admin_write),
        "mcp-admins alone must not bypass the Example deployment service-specific forbid: {gateway_admin_write:?}"
    );

    let both_admins = principal("dual-admin", &["mcp-admins", "deploy-operators"]);
    let dual_admin_write = gate().may_call_tool(&both_admins, &deploy).await;
    assert!(
        is_allow(&dual_admin_write),
        "a gateway admin who also holds deploy-operators should call example-deployer.deployments.apply: {dual_admin_write:?}"
    );

    let unrelated_write = gate()
        .may_call_tool(
            &service_admin,
            &tool_se("example-compute", "create_pod", RiskTier::Low, true),
        )
        .await;
    assert!(
        !is_allow(&unrelated_write),
        "deploy-operators must not grant writes on another upstream: {unrelated_write:?}"
    );

    // Sensitivity adds no Example deployment service-specific gate: a deploy-operators may perform a
    // sensitive (pii-tagged) write with no approval grant or authentication-
    // method requirement of its own. Cross-cutting PII rules for weaker auth
    // methods live in the general PII overlay, exercised by other tests.
    let mut sensitive_write = deploy.clone();
    sensitive_write.pii = true;
    let admin_sensitive_write = gate().may_call_tool(&service_admin, &sensitive_write).await;
    assert!(
        is_allow(&admin_sensitive_write),
        "deploy-operators may perform a sensitive Example deployment service write: {admin_sensitive_write:?}"
    );
}

// ---------- example-secrets (service-specific administration for every tool) ----------

#[tokio::test]
async fn secrets_require_service_operator_for_reads_and_writes() {
    let read = tool_se("example-secrets", "server.info", RiskTier::Low, false);
    let write = tool_se(
        "example-secrets",
        "service-tokens.create",
        RiskTier::High,
        true,
    );

    let baseline = principal("reader", &["mcp-users"]);
    let baseline_read = gate().may_call_tool(&baseline, &read).await;
    assert!(
        !is_allow(&baseline_read),
        "baseline users must not bypass Example secret service confinement: {baseline_read:?}"
    );

    let waygate_admin = principal("gateway-admin", &["mcp-admins"]);
    let gateway_admin_write = gate().may_call_tool(&waygate_admin, &write).await;
    assert!(
        !is_allow(&gateway_admin_write),
        "mcp-admins alone must not bypass Example secret service confinement: {gateway_admin_write:?}"
    );

    let example_secrets_admin = principal("secrets-operator", &["secret-operators"]);
    for facts in [&read, &write] {
        let verdict = gate().may_call_tool(&example_secrets_admin, facts).await;
        assert!(
            is_allow(&verdict),
            "secret-operators should reach {}: {verdict:?}",
            facts.name
        );
    }

    let unrelated = gate()
        .may_call_tool(
            &example_secrets_admin,
            &tool_se("unrelated", "status.read", RiskTier::High, false),
        )
        .await;
    assert!(
        !is_allow(&unrelated),
        "secret-operators must not grant access to another upstream: {unrelated:?}"
    );

    let mut pii_read = read.clone();
    pii_read.pii = true;
    let mut api_key_admin = principal("automation", &["secret-operators"]);
    api_key_admin.auth_method = waygate_oidc::AuthMethod::ApiKey;
    let pii_denied = gate().may_call_tool(&api_key_admin, &pii_read).await;
    assert!(
        !is_allow(&pii_denied),
        "service membership must not bypass the API-key PII overlay: {pii_denied:?}"
    );

    let mut api_key_pii_admin = principal("pii-automation", &["secret-operators", "pii-readers"]);
    api_key_pii_admin.auth_method = waygate_oidc::AuthMethod::ApiKey;
    let pii_allowed = gate().may_call_tool(&api_key_pii_admin, &pii_read).await;
    assert!(
        is_allow(&pii_allowed),
        "an API key satisfying both independent requirements should proceed: {pii_allowed:?}"
    );
}

// ---------- example-forge (complete administration behind gateway admin scope) ----------

#[tokio::test]
async fn forge_writes_require_gateway_admin_scope() {
    let bootstrap = tool_se("example-forge", "repositories.create", RiskTier::High, true);

    let ordinary_agent = principal("ordinary-agent", &["mcp-users"]);
    let denied = gate().may_call_tool(&ordinary_agent, &bootstrap).await;
    assert!(
        !is_allow(&denied),
        "an ordinary MCP client must not bootstrap repositories: {denied:?}"
    );

    let waygate_admin = principal_with_admin_scope("control-plane-agent", &["mcp-users"]);
    let allowed = gate().may_call_tool(&waygate_admin, &bootstrap).await;
    assert!(
        is_allow(&allowed),
        "mcp:admin should authorize the complete Example forge surface: {allowed:?}"
    );

    let unrelated = gate()
        .may_call_tool(
            &waygate_admin,
            &tool_se("example-compute", "workloads.create", RiskTier::Low, true),
        )
        .await;
    assert!(
        !is_allow(&unrelated),
        "the Example forge permit must not grant mutations on another upstream: {unrelated:?}"
    );
}

// ---------- example-compute (mutating tools classified low+side_effects) ----------

#[tokio::test]
async fn compute_operators_drive_lifecycle_but_groupless_cannot() {
    // Example compute service's mutating tools are classified low+side_effects (example-compute has
    // no gateway-administrative surface). compute-operators keeps access because
    // 20-example-compute.cedar is server-scoped, not risk-keyed; a groupless principal
    // still cannot reach them because the narrowed baseline excludes
    // side_effects:true. Pins that the classification is access-preserving.
    let op = principal("oscar", &["compute-operators"]);
    let allow = gate()
        .may_call_tool(
            &op,
            &tool_se("example-compute", "workloads.create", RiskTier::Low, true),
        )
        .await;
    assert!(
        is_allow(&allow),
        "compute-operators should provision pods at low+side_effects: {allow:?}"
    );

    let nobody = principal("nobody", &["mcp-users"]);
    let deny = gate()
        .may_call_tool(
            &nobody,
            &tool_se("example-compute", "workloads.create", RiskTier::Low, true),
        )
        .await;
    assert!(
        !is_allow(&deny),
        "groupless must not provision example-compute pods: {deny:?}"
    );
}

// ---------- example-memory (per-bank writers) ----------
//
// Three banks, three groups. Per-bank rather than a shared writers group so
// granting write access to one bank does not silently grant the others.

#[tokio::test]
async fn code_memory_writers_can_write() {
    let p = principal("alice", &["code-memory-writers"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se("example-memory-code", "memories.write", RiskTier::Low, true),
        )
        .await;
    assert!(is_allow(&v), "coding-writers should be allowed: {v:?}");
}

#[tokio::test]
async fn assistant_memory_writers_can_write() {
    let p = principal("alice", &["assistant-memory-writers"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se(
                "example-memory-assistant",
                "memories.write",
                RiskTier::Low,
                true,
            ),
        )
        .await;
    assert!(is_allow(&v), "assistant-writers should be allowed: {v:?}");
}

#[tokio::test]
async fn support_memory_writers_can_write() {
    let p = principal("alice", &["support-memory-writers"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool_se(
                "example-memory-support",
                "memories.write",
                RiskTier::Low,
                true,
            ),
        )
        .await;
    assert!(is_allow(&v), "support-writers should be allowed: {v:?}");
}

#[tokio::test]
async fn plain_user_cannot_write_any_memory_store() {
    let p = principal("carol", &["mcp-users"]);
    for server in [
        "example-memory-code",
        "example-memory-assistant",
        "example-memory-support",
    ] {
        let v = gate()
            .may_call_tool(&p, &tool_se(server, "memories.write", RiskTier::Low, true))
            .await;
        assert!(
            !is_allow(&v),
            "mcp-users alone should be denied on {server}: {v:?}"
        );
    }
}

#[tokio::test]
async fn code_memory_writers_do_not_leak_to_other_banks() {
    // Regression: membership in `code-memory-writers` must NOT grant
    // writes on the assistant or support banks. The per-upstream grant is scoped
    // on `resource.server`. If this fails, the policy's server guard has
    // widened and we've leaked the writer capability across banks.
    let p = principal("alice", &["code-memory-writers"]);
    for server in ["example-memory-assistant", "example-memory-support"] {
        let v = gate()
            .may_call_tool(&p, &tool_se(server, "memories.write", RiskTier::Low, true))
            .await;
        assert!(
            !is_allow(&v),
            "coding-writers must not cross to {server}: {v:?}"
        );
    }
}

#[tokio::test]
async fn assistant_memory_writers_do_not_leak_to_other_banks() {
    let p = principal("alice", &["assistant-memory-writers"]);
    for server in ["example-memory-code", "example-memory-support"] {
        let v = gate()
            .may_call_tool(&p, &tool_se(server, "memories.write", RiskTier::Low, true))
            .await;
        assert!(
            !is_allow(&v),
            "assistant-writers must not cross to {server}: {v:?}"
        );
    }
}

#[tokio::test]
async fn support_memory_writers_do_not_leak_to_other_banks() {
    let p = principal("alice", &["support-memory-writers"]);
    for server in ["example-memory-code", "example-memory-assistant"] {
        let v = gate()
            .may_call_tool(&p, &tool_se(server, "memories.write", RiskTier::Low, true))
            .await;
        assert!(
            !is_allow(&v),
            "support-writers must not cross to {server}: {v:?}"
        );
    }
}

#[tokio::test]
async fn memory_writers_do_not_leak_to_other_upstreams() {
    // Symmetric to example-messages_senders_do_not_leak_to_other_servers. A example-memory
    // writer group must not accidentally grant CallTool on example-observability/example-messages.
    let p = principal("alice", &["code-memory-writers"]);
    let v = gate()
        .may_call_tool(
            &p,
            &tool("example-messages", "messages.send", RiskTier::High),
        )
        .await;
    assert!(
        !is_allow(&v),
        "code-memory-writers must not cross to example-messages: {v:?}"
    );
}

#[tokio::test]
async fn memory_writers_cannot_reach_the_high_tier() {
    // The writer permits are keyed on
    // `side_effects && risk != "high"`, so each bank's two HIGH tools —
    // `memories.clear` (whole-bank memory wipe) and `delete_dataset` — are
    // admin-only, matching example-observability / example-facility / example-messages (operator/writer
    // roles never reach the high tier). A writer is denied BOTH even though the
    // test principal carries `mcp:invoke:high`: authorization closes the high
    // tier out before the step-up scope is ever consulted (there is no permit
    // for step-up to satisfy). Admins still reach memories.clear via the blanket
    // permit (see admin_keeps_access_across_servers_after_per_upstream_additions);
    // delete_dataset stays the step-up canary, covered in step_up.rs.
    for (group, server) in [
        ("code-memory-writers", "example-memory-code"),
        ("assistant-memory-writers", "example-memory-assistant"),
        ("support-memory-writers", "example-memory-support"),
    ] {
        let w = principal("alice", &[group]);
        for high_tool in ["memories.clear", "delete_dataset"] {
            let v = gate()
                .may_call_tool(&w, &tool_se(server, high_tool, RiskTier::High, true))
                .await;
            assert!(
                !is_allow(&v),
                "{group} must NOT reach high tool {server}.{high_tool} \
                 (admin-only): {v:?}"
            );
        }
    }
}

// ---------- admins still universal ----------

#[tokio::test]
async fn admin_keeps_access_across_servers_after_per_upstream_additions() {
    // Regression guard: per-upstream policies add permits; they must not
    // accidentally *restrict* what admins can already do. If a future
    // `forbid` policy lands here, this test would fail loudly.
    let p = principal("root", &["mcp-admins"]);
    for (server, name, risk) in [
        ("example-messages", "messages.send", RiskTier::High),
        ("example-observability", "incidents.create", RiskTier::High),
        ("example-messages", "contacts.list", RiskTier::Low),
        ("example-facility-east", "system.restart", RiskTier::High),
        ("example-facility-west", "system.restart", RiskTier::High),
        ("example-memory-code", "memories.write", RiskTier::Low),
        ("example-memory-assistant", "memories.write", RiskTier::Low),
        ("example-memory-support", "memories.write", RiskTier::Low),
        ("example-memory-code", "memories.clear", RiskTier::High),
    ] {
        let v = gate().may_call_tool(&p, &tool(server, name, risk)).await;
        assert!(is_allow(&v), "admin denied on {server}.{name}: {v:?}");
    }
}

// ---------- baseline narrowing ----------

#[tokio::test]
async fn baseline_grants_read_only_low_but_excludes_side_effecting_low() {
    // 10-role-allow's baseline CallTool grant is
    // `risk == "low" && !resource.side_effects`. A read-only low tool stays
    // callable by anyone; a side-effecting low tool is NOT baseline-callable —
    // it must be granted by a per-server operator/writer permit (or admin).
    //
    // Uses a synthetic server with NO per-upstream policy so ONLY the baseline
    // can decide. This is the property the manifest-driven linchpin cannot
    // exercise today (no low+side_effects tool exists yet) and is exactly what
    // makes the medium->low demotion safe: a demoted write lands at
    // low+side_effects:true and falls out of this grant.
    let g = gate();
    let anyone = principal("nobody", &["mcp-users"]);

    let read = g
        .may_call_tool(
            &anyone,
            &tool_se("synthetic_no_policy", "read_thing", RiskTier::Low, false),
        )
        .await;
    assert!(
        is_allow(&read),
        "read-only low must stay baseline-callable: {read:?}"
    );

    let write = g
        .may_call_tool(
            &anyone,
            &tool_se("synthetic_no_policy", "write_thing", RiskTier::Low, true),
        )
        .await;
    assert!(
        !is_allow(&write),
        "side-effecting low must be excluded from the narrowed baseline: {write:?}"
    );
}

// ---------- inference plane (models keep the low baseline) ----------

fn engine() -> CedarEngine {
    CedarEngine::load_dir(&policies_dir()).expect("load policies")
}

/// A model `Facts` for a groupless OAuth principal, matching what the invocation
/// pipeline's LLM path produces (`synthetic_model_facts`): `resource_type =
/// "model"`, `side_effects: true`, `pii: true`. Models go through `evaluate_facts`
/// directly (not `may_call_tool`), so the test builds `Facts` itself.
fn model_facts(risk: RiskTier) -> waygate_core::Facts {
    waygate_core::Facts {
        principal: waygate_core::PrincipalFacts {
            sub: "nobody".into(),
            email: None,
            groups: vec!["mcp-users".into()],
            scopes: vec!["mcp:invoke".into()],
            auth_method: "oauth".into(),
            roles: vec![],
            scim: None,
        },
        client: waygate_core::ClientFacts::default(),
        tenant: waygate_core::TenantFacts {
            tenant_id: waygate_core::TenantId::default(),
        },
        action: waygate_core::ActionFacts {
            kind: "CallTool".into(),
            required_scope: None,
        },
        resource: waygate_core::ResourceFacts {
            server: "example-code-runtime".into(),
            tool: "some-model".into(),
            risk,
            side_effects: true,
            pii: true,
            data_classification: None,
            cost_class: None,
            uri: None,
            source_origin: None,
            artifact_digest: None,
            source_tree_digest: None,
            skill_uri: None,
            revision_digest: None,
            content_digest: None,
            source_path: None,
            source_object: None,
            resource_type: Some(waygate_core::MODEL_RESOURCE_TYPE.into()),
            operation: None,
        },
        request: None,
        context: waygate_core::RuntimeContextFacts {
            approval_present: false,
            mfa: false,
            time: time::OffsetDateTime::now_utc(),
            source_ip: None,
            channel: waygate_core::InvocationChannelFact::Direct,
        },
    }
}

#[tokio::test]
async fn low_risk_model_stays_callable_by_a_groupless_principal() {
    // Narrowing the baseline CallTool
    // grant with `!side_effects` must NOT touch the inference plane. A model is
    // always `side_effects: true`, so an UNSCOPED `!side_effects` baseline would
    // deny EVERY low-risk model call. Models default to `low` and are open to any
    // authenticated principal (migrations/0057); the dedicated `resource is Model`
    // baseline preserves that.
    let e = engine();
    let r = e.evaluate_facts(&model_facts(RiskTier::Low)).expect("eval");
    assert_eq!(
        r.decision,
        waygate_authz::Decision::Allow,
        "low-risk model must stay baseline-callable by a groupless principal: {r:?}"
    );
}

#[tokio::test]
async fn high_risk_model_is_not_baseline_callable() {
    // The model baseline is scoped to `risk: low`; a high model is NOT opened by
    // it (admin-only) — proves the model permit didn't over-grant the inference
    // plane while fixing the low-model denial.
    let e = engine();
    let r = e
        .evaluate_facts(&model_facts(RiskTier::High))
        .expect("eval");
    assert_ne!(
        r.decision,
        waygate_authz::Decision::Allow,
        "high-risk model must not be baseline-callable by a groupless principal: {r:?}"
    );
}

// ---------- linchpin invariant (manifest-driven) ----------

#[derive(serde::Deserialize)]
struct ManifestTool {
    name: String,
    #[serde(default = "risk_low")]
    risk: RiskTier,
    #[serde(default)]
    side_effects: bool,
}

fn risk_low() -> RiskTier {
    RiskTier::Low
}

#[derive(serde::Deserialize)]
struct Manifest {
    name: String,
    #[serde(default)]
    tools: Vec<ManifestTool>,
}

fn servers_dir() -> PathBuf {
    // The gateway repo ships no deployment servers set; deployments own theirs.
    // These manifest-driven authz invariants run
    // against the representative manifest fixtures shared with waygate-upstream's
    // parse test, so they stay POLICY contract tests (does the baseline exclude
    // side-effecting tools? is the medium tier absent?) without a shipped served
    // set. The same invariants over a deployment's real served set are that
    // deployment's CI responsibility.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("waygate-upstream/tests/fixtures/servers")
}

/// Every `(server_id, tool)` across the fixture `servers/*.yaml` manifest set.
fn all_manifest_tools() -> Vec<(String, ManifestTool)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(servers_dir()).expect("read fixture servers dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read manifest");
        let m: Manifest =
            serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        for t in m.tools {
            out.push((m.name.clone(), t));
        }
    }
    out
}

#[tokio::test]
async fn no_side_effecting_tool_is_reachable_by_a_groupless_principal() {
    // THE LINCHPIN of the 3->4->2 reorder. A principal in no operator/writer
    // group (only `mcp-users`) — carrying a fresh `mcp:invoke:high` scope, so the
    // ONLY thing that can deny is authorization, never a missing step-up — must
    // never CallTool a tool that mutates state or has an outbound effect
    // (`side_effects: true`). The baseline opens read-only tools to everyone;
    // every side-effecting tool must require an explicit per-server operator /
    // writer group (or admin).
    //
    // This is exactly what makes a medium->low demotion safe, given the
    // baseline is narrowed to `low && !side_effects`: if a demoted side-effecting
    // tool fell into a still-wide `low` baseline, this test fails. It is driven
    // off the representative manifest fixtures (the gateway repo no longer ships a
    // served set); the same invariant over a deployment's real served
    // set is that deployment's CI responsibility. The fixtures carry side-effecting
    // tools at both low and high tiers, so a baseline that leaked side_effects
    // still trips it.
    let g = gate();
    let nobody = principal("nobody", &["mcp-users"]);
    let mut checked = 0usize;
    let (mut saw_low_se, mut saw_high_se) = (false, false);
    for (server, t) in all_manifest_tools() {
        if !t.side_effects {
            continue;
        }
        match t.risk {
            RiskTier::Low => saw_low_se = true,
            RiskTier::High => saw_high_se = true,
            _ => {}
        }
        let facts = tool_se(&server, &t.name, t.risk, true);
        let v = g.may_call_tool(&nobody, &facts).await;
        assert!(
            !is_allow(&v),
            "groupless principal must NOT call side-effecting {}.{} (risk={:?}): {v:?}",
            server,
            t.name,
            t.risk
        );
        checked += 1;
    }
    // Non-vacuity: the fixtures must exercise a side-effecting tool at BOTH the
    // low and high tiers, so this proves the baseline excludes side_effects
    // regardless of risk — not merely that the loop ran.
    assert!(
        checked >= 2 && saw_low_se && saw_high_se,
        "fixtures must contain side-effecting tools at low AND high \
         (checked={checked}, low_se={saw_low_se}, high_se={saw_high_se}) — fixture set broken?"
    );
}

#[test]
fn no_manifest_classifies_a_tool_medium() {
    // Standing invariant #3 (authorization-model.md §7): the `medium` tier is
    // retired. Every manifest tool is `low` or `high`. A surviving `medium`
    // classification is a tool the narrowed baseline neither opens (it is not
    // low) nor any per-server permit necessarily covers — a silent admin-only
    // deny, and a relic of the retired tier. Driven off the representative
    // manifest fixtures (de-baked — see servers_dir); a deployment's real served
    // set is checked for the same invariant in that deployment's CI.
    let all = all_manifest_tools();
    assert!(
        !all.is_empty(),
        "fixture manifest set is empty — fixtures broken?"
    );
    let medium: Vec<String> = all
        .into_iter()
        .filter(|(_, t)| t.risk == RiskTier::Medium)
        .map(|(server, t)| format!("{server}.{}", t.name))
        .collect();
    assert!(
        medium.is_empty(),
        "the medium tier is retired; tools still classified medium: {medium:?}"
    );
}
