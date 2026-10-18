//! Blocked tools page — `/admin/t/{tenant}/tools/blocked`.
//!
//! Lists every tool the gateway currently refuses to run, or holds as
//! temporarily unavailable, with the reason in plain English, where that
//! state applies, and the dashboard control that resolves it. The decisions
//! come from [`waygate_upstream::UpstreamPool::refusals`], which applies the
//! call path's admission checks without recording, logging, or dialing
//! anything.
//!
//! ## Admin gate and tenant scope
//!
//! The Catalog tab's gate: an `mcp:admin` session that is not a peer
//! assertion, reading as the principal's tenant. Without it nothing is read.
//! A configured server appears only when a catalog row for it is visible to
//! that tenant (its own or a global row), or when the viewer is in the
//! default tenant, which owns the gateway's server configuration. A resolving
//! link appears only where the viewer's tenant owns what the link changes:
//! the catalog row for Catalog controls, and the default tenant for the server
//! configuration, Servers page operations, and tool-change review.

use std::collections::BTreeMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use waygate_catalog::{CatalogServerStatus, CatalogServerSummary};
use waygate_mcp::catalog::{TemporaryUnavailability, ToolRefusal};
use waygate_oidc::Principal;
use waygate_upstream::{BlockedTool, ServerRefusals, ToolBlock, REFUSAL_REPORT_TOOL_LIMIT};

use crate::chrome::PageChrome;
use crate::dashboard::{render, urlencode, user_display};
use crate::dashboard_catalog::principal_has_dashboard_admin;
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};

/// The page's route suffix.
pub(crate) const BLOCKED_TOOLS_PATH: &str = "/tools/blocked";

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route(BLOCKED_TOOLS_PATH, get(blocked_tools_page))
}

/// The page URL limited to one server, for links from a refused call.
pub(crate) fn server_url(server: &str) -> String {
    format!("{BLOCKED_TOOLS_PATH}?server={}", urlencode(server))
}

/// Whether an audit reason records a refusal or a temporary unavailability.
pub(crate) fn is_refusal_reason(reason: &str) -> bool {
    reason.starts_with("refused:") || reason.starts_with("unavailable:")
}

#[derive(Debug, Default, Deserialize)]
struct BlockedQuery {
    /// Limit the page to one configured server.
    #[serde(default)]
    server: Option<String>,
}

#[derive(Template)]
#[template(path = "blocked_tools.html")]
struct BlockedToolsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// The session lacks the Catalog tab's admin gate; nothing was read.
    insufficient_scope: bool,
    /// The catalog could not be read, so catalog links are withheld and only
    /// a default-tenant viewer sees servers.
    catalog_unavailable: bool,
    /// The server the page is limited to, if any.
    server_filter: Option<String>,
    rows: Vec<BlockedRow>,
    /// Blocked tools across every row.
    blocked_count: usize,
    /// Servers whose report examined only the first [`Self::tool_limit`] names.
    truncated: Vec<String>,
    tool_limit: usize,
}

/// Tools on one server that share a reason and a resolving action.
struct BlockedRow {
    server: String,
    tools: Vec<String>,
    explanation: Explanation,
}

/// What a blocked tool's state means, where it applies, and what resolves it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Explanation {
    /// `refused:<code>` or `unavailable:<code>`, the reason Activity records
    /// for a refused call.
    audit_reason: String,
    title: &'static str,
    detail: &'static str,
    /// Where the state applies, and for how long.
    scope: &'static str,
    /// The state should clear without operator action.
    clears_on_its_own: bool,
    action: Option<ActionLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActionLink {
    href: String,
    label: &'static str,
}

const SCOPE_UNTIL_RESTART: &str =
    "This copy of the gateway only. The state is held in memory and is cleared when the gateway restarts.";
const SCOPE_CATALOG: &str =
    "Every copy of the gateway. The state is stored in the catalog database.";
const SCOPE_CONFIGURATION: &str = "Every copy of the gateway that loads this server configuration.";
const SCOPE_CONNECTIONS: &str =
    "This copy of the gateway, from its current connections to the server.";
const SCOPE_WHILE_IT_LASTS: &str = "This copy of the gateway, while the condition lasts.";

/// What the page may link to for one server.
struct Links<'a> {
    tenant_ctx: Option<&'a TenantContext>,
    /// The viewer's tenant owns the gateway's server configuration, which the
    /// Servers page operations, the manifest editor, and tool-change review
    /// change.
    owns_configuration: bool,
    /// The Server manifests editor has a store to edit.
    manifest_editor: bool,
    /// The server's catalog row, when the viewer's tenant owns it.
    owned_catalog_row: Option<&'a CatalogServerSummary>,
}

impl Links<'_> {
    fn url(&self, path: &str) -> String {
        tenant_ctx::nav_url(self.tenant_ctx, path)
    }

    fn catalog(&self, label: &'static str) -> Option<ActionLink> {
        self.owned_catalog_row.map(|row| ActionLink {
            href: format!("{}#srv-{}", self.url("/catalog"), row.id),
            label,
        })
    }

    fn configuration(&self, path: &str, label: &'static str) -> Option<ActionLink> {
        self.owns_configuration.then(|| ActionLink {
            href: self.url(path),
            label,
        })
    }

    fn manifest_editor(&self, label: &'static str) -> Option<ActionLink> {
        if self.manifest_editor {
            self.configuration("/server_manifests", label)
        } else {
            None
        }
    }
}

/// Explain one blocked tool on `server`. `connected` is whether any session
/// to the server is connected.
fn explain(server: &str, blocked: &BlockedTool, connected: bool, links: &Links<'_>) -> Explanation {
    let audit_reason = match blocked.block {
        ToolBlock::Refused(reason) => format!("refused:{}", reason.code()),
        ToolBlock::Unavailable(reason) => format!("unavailable:{}", reason.code()),
    };
    let refused = |title, detail, scope, action| Explanation {
        audit_reason: audit_reason.clone(),
        title,
        detail,
        scope,
        clears_on_its_own: false,
        action,
    };
    let clears = |title, detail, scope| Explanation {
        audit_reason: audit_reason.clone(),
        title,
        detail,
        scope,
        clears_on_its_own: true,
        action: None,
    };
    let review = || crate::dashboard_tool_reviews::review_url(server, &blocked.tool);
    match blocked.block {
        ToolBlock::Refused(ToolRefusal::ServerQuarantined) => refused(
            "Server quarantined",
            "The governed catalog has quarantined this server, so the gateway refuses every \
             call to its tools. An approved unquarantine change restores it.",
            SCOPE_CATALOG,
            links.catalog("Propose unquarantine in Catalog"),
        ),
        ToolBlock::Refused(ToolRefusal::ServerRetired) => refused(
            "Server retired",
            "The governed catalog has retired this server, so the gateway refuses every call \
             to its tools. No dashboard control restores a retired server.",
            SCOPE_CATALOG,
            None,
        ),
        ToolBlock::Refused(ToolRefusal::NotInCatalog) if !connected => refused(
            "Server not connected",
            "No session to this server is connected and the gateway has no current record of \
             this tool to admit, so it refuses calls to it. If the governed catalog has the \
             tool, this clears once the gateway reconnects. If it remains after the server \
             reconnects, reloading manifests imports the configured tools into the catalog.",
            SCOPE_CONNECTIONS,
            links.configuration("/servers", "Reload manifests on Servers"),
        ),
        ToolBlock::Refused(ToolRefusal::NotInCatalog) if blocked.advertised => refused(
            "Not in the catalog",
            "The server offers this tool, but the governed catalog has no record of it, so \
             the gateway refuses it. Reloading manifests imports the configured tools into \
             the catalog.",
            SCOPE_CATALOG,
            links.configuration("/servers", "Reload manifests on Servers"),
        ),
        ToolBlock::Refused(ToolRefusal::NotInCatalog) => refused(
            "Not offered by the server",
            "The server configuration names this tool, but no connected session to the \
             server offers it, so the gateway refuses calls to it. If the server offers it \
             again, refreshing the server's catalog picks it up.",
            SCOPE_CONNECTIONS,
            links.configuration("/servers", "Refresh the catalog on Servers"),
        ),
        ToolBlock::Refused(ToolRefusal::Unclassified) => refused(
            "Not classified",
            "The server offers this tool, but the server configuration does not classify \
             it. The gateway refuses a tool until an administrator classifies it.",
            SCOPE_CONFIGURATION,
            links.manifest_editor("Classify it in Server manifests"),
        ),
        ToolBlock::Refused(ToolRefusal::NotAdmitted) => refused(
            "Definition not approved",
            "The tool's annotation metadata is invalid, or its behavior hash differs from the \
             approved hash in the server configuration, so the gateway refuses it. After \
             checking the change, approve the observed hash in the server configuration, or \
             correct the server.",
            SCOPE_CONFIGURATION,
            links.manifest_editor("Edit Server manifests"),
        ),
        ToolBlock::Refused(ToolRefusal::LanesDisagree) => refused(
            "Connections disagree",
            "Some of this gateway's connections to the server offer this tool and others do \
             not, so the gateway refuses it rather than guess which definition would run. \
             Refreshing the server's catalog reads every connection again.",
            SCOPE_CONNECTIONS,
            links.configuration("/servers", "Refresh the catalog on Servers"),
        ),
        ToolBlock::Refused(ToolRefusal::DriftQuarantined) => refused(
            "Quarantined after a definition change",
            "The tool's definition changed while the gateway was running, so the gateway \
             quarantined it. No database records tool-change reviews, so clearing the \
             server's quarantine on the Servers page releases it.",
            SCOPE_UNTIL_RESTART,
            links.configuration("/servers", "Clear the quarantine on Servers"),
        ),
        ToolBlock::Refused(ToolRefusal::ReviewRequired) if !blocked.review_recorded => refused(
            "Held for review",
            "The tool's definition is larger than the gateway can store for comparison, so \
             the gateway holds it for review. Its review appears under Tool changes once the \
             gateway records it, on the next call to the tool or catalog refresh.",
            SCOPE_CATALOG,
            links.configuration("/servers/tool-changes", "Open Tool changes"),
        ),
        ToolBlock::Refused(ToolRefusal::ReviewRequired) => refused(
            "Definition change awaits review",
            "The tool's current definition differs from its approved definition. The gateway \
             refuses it until an administrator approves the change.",
            SCOPE_CATALOG,
            links.configuration(&review(), "Review the change"),
        ),
        ToolBlock::Refused(ToolRefusal::KeptBlocked) => refused(
            "Kept blocked after review",
            "An administrator reviewed this tool's changed definition and kept it blocked. \
             The change can still be approved from its review.",
            SCOPE_CATALOG,
            links.configuration(&review(), "Open the review"),
        ),
        ToolBlock::Refused(ToolRefusal::ApprovalPending) => refused(
            "Awaiting catalog approval",
            "The governed catalog has not approved this server or this tool's version, and \
             the gateway is set to refuse tools until they are approved.",
            SCOPE_CATALOG,
            links
                .owned_catalog_row
                .filter(|row| {
                    matches!(
                        row.status,
                        CatalogServerStatus::Proposed | CatalogServerStatus::Approved
                    )
                })
                .and_then(|_| links.catalog("Approve in Catalog")),
        ),
        ToolBlock::Unavailable(TemporaryUnavailability::CatalogUnavailable) => clears(
            "Catalog unavailable",
            "The gateway could not read the governed catalog, so it cannot confirm the tool \
             may run. This should clear on its own once the catalog database can be read \
             again.",
            SCOPE_WHILE_IT_LASTS,
        ),
        ToolBlock::Unavailable(TemporaryUnavailability::CatalogConverging) => clears(
            "Update in progress",
            "A server configuration or catalog update is in progress, or the configuration \
             and the catalog hold different versions of this tool. This should clear on its \
             own once the catalog update finishes.",
            SCOPE_WHILE_IT_LASTS,
        ),
        ToolBlock::Unavailable(TemporaryUnavailability::ReviewUnavailable) => clears(
            "Review records unavailable",
            "The gateway could not read its tool-change review records, so it cannot confirm \
             the tool may run. This should clear on its own once the catalog database can be \
             read again.",
            SCOPE_WHILE_IT_LASTS,
        ),
        ToolBlock::Unavailable(TemporaryUnavailability::NoConnectedLane) => clears(
            "Server not connected",
            "No session to this server is connected, so the gateway cannot check the tool \
             against its approved definition. This should clear on its own once the gateway \
             reconnects to the server.",
            SCOPE_CONNECTIONS,
        ),
    }
}

/// The catalog rows the page joins to configured servers.
enum CatalogRows {
    /// No catalog store is configured.
    NotConfigured,
    /// The catalog read failed.
    Unavailable,
    /// Rows visible to the viewer's tenant by server name. An own-tenant row
    /// shadows a global row of the same name, the precedence catalog
    /// resolution applies.
    Read(BTreeMap<String, CatalogServerSummary>),
}

impl CatalogRows {
    async fn read(state: &AdminState, tenant: &str) -> Self {
        let Some(store) = state.servers.catalog.get() else {
            return Self::NotConfigured;
        };
        match store.list_servers(tenant).await {
            Ok(rows) => {
                let mut by_name = BTreeMap::new();
                for row in rows {
                    if row.tenant_id == tenant || !by_name.contains_key(&row.name) {
                        by_name.insert(row.name.clone(), row);
                    }
                }
                Self::Read(by_name)
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    %tenant,
                    "blocked tools page: catalog list_servers failed",
                );
                Self::Unavailable
            }
        }
    }

    fn get(&self, server: &str) -> Option<&CatalogServerSummary> {
        match self {
            Self::Read(rows) => rows.get(server),
            Self::NotConfigured | Self::Unavailable => None,
        }
    }
}

/// The tenant-scoped refusal report: the servers the viewer may see, and
/// the catalog rows that decide which links they get.
struct Report {
    catalog: CatalogRows,
    servers: Vec<ServerRefusals>,
}

async fn read_report(state: &AdminState, tenant: &str, only: Option<&str>) -> Report {
    let catalog = CatalogRows::read(state, tenant).await;
    let default_tenant = tenant == waygate_core::TenantId::DEFAULT;
    let servers = state
        .upstreams
        .refusals(tenant, |server| {
            only.is_none_or(|only| only == server)
                && (default_tenant || catalog.get(server).is_some())
        })
        .await;
    Report { catalog, servers }
}

/// The number of tools the gateway does not run for `principal`'s tenant,
/// or `None` when the principal lacks the page's admin gate.
pub(crate) async fn blocked_tool_count(
    state: &AdminState,
    principal: Option<&Principal>,
) -> Option<usize> {
    let principal = principal.filter(|principal| principal_has_dashboard_admin(Some(principal)))?;
    let report = read_report(state, principal.tenant.as_str(), None).await;
    Some(report.servers.iter().map(|server| server.tools.len()).sum())
}

/// Group each server's blocked tools by explanation, keeping the report's
/// server and tool order.
fn blocked_rows(
    report: &Report,
    tenant: &str,
    tenant_ctx: Option<&TenantContext>,
    owns_configuration: bool,
    manifest_editor: bool,
) -> Vec<BlockedRow> {
    let mut rows = Vec::new();
    for server in &report.servers {
        let links = Links {
            tenant_ctx,
            owns_configuration,
            manifest_editor,
            owned_catalog_row: report
                .catalog
                .get(&server.server)
                .filter(|row| row.tenant_id == tenant),
        };
        let mut groups: Vec<BlockedRow> = Vec::new();
        for blocked in &server.tools {
            let explanation = explain(&server.server, blocked, server.connected, &links);
            match groups
                .iter_mut()
                .find(|group| group.explanation == explanation)
            {
                Some(group) => group.tools.push(blocked.tool.clone()),
                None => groups.push(BlockedRow {
                    server: server.server.clone(),
                    tools: vec![blocked.tool.clone()],
                    explanation,
                }),
            }
        }
        rows.extend(groups);
    }
    rows
}

async fn blocked_tools_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<crate::auth::CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(query): Query<BlockedQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let principal = user.as_ref().map(|Extension(p)| p);
    let insufficient_scope = !principal_has_dashboard_admin(principal);
    let tenant = crate::dashboard::principal_tenant(user.as_ref()).to_owned();
    let server_filter = query.server.filter(|server| !server.is_empty());

    let (rows, catalog_unavailable, truncated) = if insufficient_scope {
        (Vec::new(), false, Vec::new())
    } else {
        let report = read_report(&state, &tenant, server_filter.as_deref()).await;
        // Tool-change review also requires the URL tenant to be the default
        // tenant, so a cross-tenant view offers no configuration links.
        let owns_configuration = tenant == waygate_core::TenantId::DEFAULT
            && tenant_ctx
                .as_ref()
                .is_none_or(|ctx| ctx.slug == waygate_core::TenantId::DEFAULT);
        let rows = blocked_rows(
            &report,
            &tenant,
            tenant_ctx.as_ref(),
            owns_configuration,
            state.servers.manifest_store.enabled(),
        );
        let truncated = report
            .servers
            .iter()
            .filter(|server| server.truncated)
            .map(|server| server.server.clone())
            .collect();
        (
            rows,
            matches!(report.catalog, CatalogRows::Unavailable),
            truncated,
        )
    };

    render(&BlockedToolsPage {
        chrome: PageChrome::build(
            &state,
            "Blocked tools",
            BLOCKED_TOOLS_PATH,
            &headers,
            principal.map(user_display),
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        insufficient_scope,
        catalog_unavailable,
        server_filter,
        blocked_count: rows.iter().map(|row| row.tools.len()).sum(),
        rows,
        truncated,
        tool_limit: REFUSAL_REPORT_TOOL_LIMIT,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn chrome() -> PageChrome {
        PageChrome {
            title: "Blocked tools",
            env: "test",
            user: None,
            theme: None,
            nav: Vec::new(),
            tenant_ctx: None,
            csrf_token: String::new(),
        }
    }

    fn catalog_row(tenant: &str, status: CatalogServerStatus) -> CatalogServerSummary {
        CatalogServerSummary {
            id: Uuid::from_u128(0xa1),
            tenant_id: tenant.into(),
            name: "garage".into(),
            transport: "http".into(),
            status,
            visibility: waygate_catalog::CatalogVisibility::Global,
            owner: None,
        }
    }

    fn report(
        row: Option<CatalogServerSummary>,
        connected: bool,
        blocked: &[(&str, ToolBlock, bool)],
    ) -> Report {
        Report {
            catalog: CatalogRows::Read(
                row.map(|row| (row.name.clone(), row)).into_iter().collect(),
            ),
            servers: vec![ServerRefusals {
                server: "garage".into(),
                connected,
                tools: blocked
                    .iter()
                    .map(|(tool, block, advertised)| BlockedTool {
                        tool: (*tool).into(),
                        block: *block,
                        advertised: *advertised,
                        review_recorded: true,
                    })
                    .collect(),
                truncated: false,
            }],
        }
    }

    fn page(rows: Vec<BlockedRow>) -> String {
        BlockedToolsPage {
            chrome: chrome(),
            insufficient_scope: false,
            catalog_unavailable: false,
            server_filter: None,
            blocked_count: rows.iter().map(|row| row.tools.len()).sum(),
            rows,
            truncated: Vec::new(),
            tool_limit: REFUSAL_REPORT_TOOL_LIMIT,
        }
        .render()
        .expect("blocked tools page renders")
    }

    fn refused(reason: ToolRefusal) -> ToolBlock {
        ToolBlock::Refused(reason)
    }

    fn unavailable(reason: TemporaryUnavailability) -> ToolBlock {
        ToolBlock::Unavailable(reason)
    }

    /// One blocked tool's state and what its row must say.
    struct Case {
        block: ToolBlock,
        advertised: bool,
        connected: bool,
        text: &'static str,
        scope: &'static str,
        link: Option<String>,
    }

    fn case(
        block: ToolBlock,
        advertised: bool,
        connected: bool,
        text: &'static str,
        scope: &'static str,
        link: Option<String>,
    ) -> Case {
        Case {
            block,
            advertised,
            connected,
            text,
            scope,
            link,
        }
    }

    /// One rendered page per state, as an owning default-tenant
    /// administrator sees it: each reason's text, scope, and resolving link.
    #[test]
    fn each_reason_renders_its_scope_and_resolving_action() {
        let quarantined = catalog_row("default", CatalogServerStatus::Quarantined);
        let catalog_anchor = format!("/admin/catalog#srv-{}", quarantined.id);
        let cases = vec![
            case(
                refused(ToolRefusal::ServerQuarantined),
                true,
                true,
                "Server quarantined",
                SCOPE_CATALOG,
                Some(catalog_anchor.clone()),
            ),
            case(
                refused(ToolRefusal::ServerRetired),
                true,
                true,
                "No dashboard control restores a retired server",
                SCOPE_CATALOG,
                None,
            ),
            case(
                refused(ToolRefusal::Unclassified),
                true,
                true,
                "does not classify",
                SCOPE_CONFIGURATION,
                Some("/admin/server_manifests".into()),
            ),
            case(
                refused(ToolRefusal::NotAdmitted),
                true,
                true,
                "behavior hash",
                SCOPE_CONFIGURATION,
                Some("/admin/server_manifests".into()),
            ),
            case(
                refused(ToolRefusal::DriftQuarantined),
                true,
                true,
                "No database records tool-change reviews",
                SCOPE_UNTIL_RESTART,
                Some("/admin/servers".into()),
            ),
            case(
                refused(ToolRefusal::ReviewRequired),
                true,
                true,
                "awaits review",
                SCOPE_CATALOG,
                Some("/admin/servers/tool-changes?server=garage&#38;tool=t".into()),
            ),
            case(
                refused(ToolRefusal::KeptBlocked),
                true,
                true,
                "kept it blocked",
                SCOPE_CATALOG,
                Some("/admin/servers/tool-changes?server=garage&#38;tool=t".into()),
            ),
            case(
                refused(ToolRefusal::LanesDisagree),
                true,
                true,
                "others do not",
                SCOPE_CONNECTIONS,
                Some("/admin/servers".into()),
            ),
            case(
                refused(ToolRefusal::NotInCatalog),
                true,
                true,
                "the governed catalog has no record of it",
                SCOPE_CATALOG,
                Some("/admin/servers".into()),
            ),
            case(
                refused(ToolRefusal::NotInCatalog),
                false,
                true,
                "no connected session to the server offers it",
                SCOPE_CONNECTIONS,
                Some("/admin/servers".into()),
            ),
            case(
                refused(ToolRefusal::NotInCatalog),
                false,
                false,
                "If it remains after the server reconnects, reloading manifests",
                SCOPE_CONNECTIONS,
                Some("/admin/servers".into()),
            ),
            case(
                unavailable(TemporaryUnavailability::CatalogUnavailable),
                true,
                true,
                "should clear on its own once the catalog database can be read again",
                SCOPE_WHILE_IT_LASTS,
                None,
            ),
            case(
                unavailable(TemporaryUnavailability::CatalogConverging),
                true,
                true,
                "should clear on its own once the catalog update finishes",
                SCOPE_WHILE_IT_LASTS,
                None,
            ),
            case(
                unavailable(TemporaryUnavailability::ReviewUnavailable),
                true,
                true,
                "review records",
                SCOPE_WHILE_IT_LASTS,
                None,
            ),
            case(
                unavailable(TemporaryUnavailability::NoConnectedLane),
                true,
                false,
                "should clear on its own once the gateway reconnects",
                SCOPE_CONNECTIONS,
                None,
            ),
        ];
        for Case {
            block,
            advertised,
            connected,
            text,
            scope,
            link,
        } in cases
        {
            let rows = blocked_rows(
                &report(
                    Some(quarantined.clone()),
                    connected,
                    &[("t", block, advertised)],
                ),
                "default",
                None,
                true,
                true,
            );
            let html = page(rows);
            let case = format!("{block:?} advertised={advertised} connected={connected}");
            assert!(html.contains(text), "{case}: reason text: {html}");
            assert!(html.contains(scope), "{case}: scope");
            assert!(html.contains(block.code()), "{case}: audit reason code");
            match link {
                Some(link) => assert!(
                    html.contains(&format!("href=\"{link}\"")),
                    "{case}: resolving link {link}: {html}"
                ),
                None => assert!(
                    !html.contains("class=\"btn btn-secondary btn--sm\""),
                    "{case}: no resolving action: {html}"
                ),
            }
        }
    }

    #[test]
    fn in_memory_drift_quarantine_says_it_applies_to_this_copy_until_restart() {
        let rows = blocked_rows(
            &report(
                None,
                true,
                &[("t", refused(ToolRefusal::DriftQuarantined), true)],
            ),
            "default",
            None,
            true,
            true,
        );
        let html = page(rows);
        assert!(html.contains("This copy of the gateway only"));
        assert!(html.contains("cleared when the gateway restarts"));
    }

    #[test]
    fn links_appear_only_for_what_the_viewer_tenant_owns() {
        let blocked = [
            ("a", refused(ToolRefusal::ServerQuarantined), true),
            ("b", refused(ToolRefusal::ReviewRequired), true),
            ("c", refused(ToolRefusal::Unclassified), true),
        ];
        // Another tenant viewing a global row it does not own: no catalog
        // link, and no configuration or review links.
        let foreign = blocked_rows(
            &report(
                Some(catalog_row("default", CatalogServerStatus::Quarantined)),
                true,
                &blocked,
            ),
            "acme",
            None,
            false,
            true,
        );
        assert_eq!(foreign.len(), 3);
        assert!(foreign.iter().all(|row| row.explanation.action.is_none()));

        // The owning tenant gets every link.
        let owner = blocked_rows(
            &report(
                Some(catalog_row("acme", CatalogServerStatus::Quarantined)),
                true,
                &blocked,
            ),
            "acme",
            None,
            false,
            true,
        );
        let actions: Vec<_> = owner
            .iter()
            .map(|row| row.explanation.action.as_ref().map(|a| a.href.as_str()))
            .collect();
        assert_eq!(
            actions,
            vec![
                Some("/admin/catalog#srv-00000000-0000-0000-0000-0000000000a1"),
                None,
                None
            ],
            "the catalog row is acme's; the configuration and reviews are not",
        );

        // Approval links only where the Catalog tab offers its control.
        for (status, linked) in [
            (CatalogServerStatus::Proposed, true),
            (CatalogServerStatus::Approved, true),
            (CatalogServerStatus::Live, false),
        ] {
            let rows = blocked_rows(
                &report(
                    Some(catalog_row("default", status)),
                    true,
                    &[("t", refused(ToolRefusal::ApprovalPending), true)],
                ),
                "default",
                None,
                true,
                true,
            );
            assert_eq!(rows[0].explanation.action.is_some(), linked, "{status:?}");
        }
    }

    #[test]
    fn tools_sharing_a_reason_and_action_share_a_row() {
        let rows = blocked_rows(
            &report(
                None,
                true,
                &[
                    ("a", refused(ToolRefusal::Unclassified), true),
                    ("b", refused(ToolRefusal::ReviewRequired), true),
                    ("c", refused(ToolRefusal::Unclassified), true),
                    ("d", refused(ToolRefusal::ReviewRequired), true),
                ],
            ),
            "default",
            None,
            true,
            true,
        );
        let grouped: Vec<_> = rows.iter().map(|row| row.tools.join(",")).collect();
        assert_eq!(
            grouped,
            vec!["a,c", "b", "d"],
            "each review has its own link, so its row is its own",
        );
        let html = page(rows);
        assert!(html.contains("2 tools"));
    }

    /// A review-required tool with no stored review explains the hold and
    /// opens the Tool changes list, since its comparison does not exist yet.
    #[test]
    fn a_held_first_observation_opens_tool_changes_rather_than_a_missing_review() {
        let mut report = report(
            None,
            true,
            &[("t", ToolBlock::Refused(ToolRefusal::ReviewRequired), true)],
        );
        report.servers[0].tools[0].review_recorded = false;
        let html = page(blocked_rows(&report, "default", None, true, true));
        assert!(html.contains("larger than the gateway can store for comparison"));
        assert!(
            html.contains(r#"href="/admin/servers/tool-changes""#),
            "{html}"
        );
        assert!(!html.contains("tool-changes?server="), "{html}");
    }

    #[test]
    fn refusal_reasons_are_recognised_by_prefix() {
        assert!(is_refusal_reason("refused:server_quarantined"));
        assert!(is_refusal_reason("unavailable:catalog_converging"));
        assert!(!is_refusal_reason("policy denied"));
        assert_eq!(
            server_url("a b"),
            "/tools/blocked?server=a%20b",
            "the server name is encoded"
        );
    }
}
