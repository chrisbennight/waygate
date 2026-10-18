//! A read-only report of the tools the gateway currently refuses to run.
//!
//! Every tool in the report is decided by [`UpstreamPool::admit`], the same
//! function invocation uses, so the report cannot drift from the call path.
//! Its review and catalog reads are taken in bounded batches, and it has no
//! other effects: it logs nothing, writes no audit or review record, fills no
//! cache, signals nothing to discovery, and never dials an upstream.

use std::collections::BTreeSet;

use super::admission::{AdmissionSource, BatchReads};
use super::*;

/// The most tool names one server's report examines. An upstream that
/// advertises or classifies more is reported as truncated after the first
/// names in name order, so a misbehaving upstream cannot make the report
/// unbounded.
pub const REFUSAL_REPORT_TOOL_LIMIT: usize = 4 * waygate_catalog::TOOL_RESOLUTION_BATCH_SIZE;

/// Why the gateway does not run a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolBlock {
    /// The gateway refuses the tool until the cause is resolved.
    Refused(ToolRefusal),
    /// The tool cannot be resolved until the condition clears.
    Unavailable(TemporaryUnavailability),
}

impl ToolBlock {
    /// The code recorded in audit reasons, as `refused:<code>` or
    /// `unavailable:<code>`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Refused(reason) => reason.code(),
            Self::Unavailable(reason) => reason.code(),
        }
    }
}

/// One tool the gateway does not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedTool {
    pub tool: String,
    pub block: ToolBlock,
    /// Whether a connected session to the server advertises the name. A name
    /// only the manifest classifies is not advertised.
    pub advertised: bool,
}

/// The tools one configured server does not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRefusals {
    pub server: String,
    /// Whether any session to the server is connected.
    pub connected: bool,
    /// The blocked tools, in name order.
    pub tools: Vec<BlockedTool>,
    /// `true` when the server advertises or classifies more than
    /// [`REFUSAL_REPORT_TOOL_LIMIT`] names, so only the first were examined.
    pub truncated: bool,
}

impl UpstreamPool {
    /// Report, for each configured server `include` accepts, the tools that
    /// admission refuses or holds as temporarily unavailable for `tenant`.
    ///
    /// The examined names are those a connected session advertises plus those
    /// the manifest classifies. Each is decided exactly as a call to it would
    /// be at this moment, except that the call path records the first
    /// observation of a protected contract; this report leaves that
    /// observation unrecorded and lets the catalog check decide.
    pub async fn refusals(
        &self,
        tenant: &str,
        include: impl Fn(&str) -> bool,
    ) -> Vec<ServerRefusals> {
        let entries = self.entries.load_full();
        let mut names: Vec<&String> = entries.keys().filter(|name| include(name)).collect();
        names.sort();
        let mut report = Vec::with_capacity(names.len());
        for name in names {
            let entry = &entries[name];
            if entry.removed.load(Ordering::Acquire) {
                continue;
            }
            report.push(self.server_refusals(tenant, name, entry).await);
        }
        report
    }

    async fn server_refusals(
        &self,
        tenant: &str,
        server: &str,
        entry: &UpstreamEntry,
    ) -> ServerRefusals {
        let mut names: BTreeSet<String> = entry
            .manifest_snapshot()
            .tools
            .into_iter()
            .map(|classification| classification.name)
            .collect();
        let mut advertised = HashSet::new();
        let mut connected = false;
        for slot in &entry.slots {
            if let Some(connection) = slot.conn.read().await.as_ref() {
                connected = true;
                advertised.extend(
                    connection
                        .live_tools
                        .iter()
                        .map(|tool| tool.name.to_string()),
                );
            }
        }
        names.extend(advertised.iter().cloned());
        let truncated = names.len() > REFUSAL_REPORT_TOOL_LIMIT;
        let names: Vec<String> = names.into_iter().take(REFUSAL_REPORT_TOOL_LIMIT).collect();

        let mut tools = Vec::new();
        for chunk in names.chunks(waygate_catalog::TOOL_RESOLUTION_BATCH_SIZE) {
            // Captured before the reads, as the call path does, so a
            // transition that starts or settles meanwhile reads as converging.
            let transitions: Vec<_> = chunk
                .iter()
                .map(|name| self.catalog_transition_state(server, name))
                .collect();
            let reviews = match self.tool_reviews.as_ref() {
                Some(store) => store
                    .review_states(waygate_core::TenantId::DEFAULT, server, chunk)
                    .await
                    .map_err(|_| ()),
                None => Ok(HashMap::new()),
            };
            let mut catalog = match self.catalog.as_ref() {
                Some(catalog) => Some(
                    batch_catalog_rows(catalog.resolve_tools(tenant, server, chunk).await, chunk)
                        .into_iter(),
                ),
                None => None,
            };
            for (name, transition) in chunk.iter().zip(transitions) {
                let catalog_row = catalog
                    .as_mut()
                    .map(|rows| rows.next().expect("one catalog result per name"));
                // The call path gives a quarantined or retired server
                // precedence over every other reason; this batch's catalog
                // row is the same read it would take.
                let server_block = match &catalog_row {
                    Some(Ok(waygate_catalog::ResolvedTool::Quarantined { retired, .. })) => {
                        Some(*retired)
                    }
                    _ => None,
                };
                let reads = BatchReads {
                    review: reviews
                        .as_ref()
                        .map(|reviews| reviews.get(name).cloned())
                        .map_err(|_| ()),
                    catalog: catalog_row,
                    transition,
                };
                let resolved = self
                    .admit(tenant, server, name, AdmissionSource::Status(reads))
                    .await;
                let resolved = match server_block {
                    Some(retired) if super::defers_to_server_block(&resolved) => {
                        super::contract_binding::server_block_refusal(server, name, retired)
                    }
                    _ => resolved,
                };
                let block = match resolved {
                    ResolvedInvocationTool::Ready(_) => continue,
                    ResolvedInvocationTool::Refused { reason, .. } => ToolBlock::Refused(reason),
                    ResolvedInvocationTool::Unavailable { reason, .. } => {
                        ToolBlock::Unavailable(reason)
                    }
                };
                tools.push(BlockedTool {
                    advertised: advertised.contains(name),
                    tool: name.clone(),
                    block,
                });
            }
        }
        ServerRefusals {
            server: server.to_owned(),
            connected,
            tools,
            truncated,
        }
    }
}

/// One catalog result per requested name. A failed read, or a result that
/// does not answer every name, is a read failure for each name, which an
/// authoritative catalog reports as unavailable.
fn batch_catalog_rows(
    rows: Result<Vec<waygate_catalog::ResolvedTool>, waygate_catalog::CatalogError>,
    names: &[String],
) -> Vec<Result<waygate_catalog::ResolvedTool, Arc<waygate_catalog::CatalogError>>> {
    let error = match rows {
        Ok(rows) if rows.len() == names.len() => return rows.into_iter().map(Ok).collect(),
        Ok(_) => waygate_catalog::CatalogError::Unknown("catalog batch did not answer every tool"),
        Err(error) => error,
    };
    let error = Arc::new(error);
    names.iter().map(|_| Err(error.clone())).collect()
}
