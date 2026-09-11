//! Tantivy-backed BM25 index for the legacy `searchTools` compatibility adapter.
//!
//! ## Shape
//!
//! One in-memory tantivy index per gateway process. Each document is a single
//! upstream tool, keyed by `(server, name)` with a `text` field holding the
//! concatenation of `name`, `description`, and any schema hints. BM25 scoring
//! is tantivy's default, and we lean on it — no re-ranking on top.
//!
//! ## Lifecycle
//!
//! The pool owns the index and rebuilds document sets after a successful
//! `tools/list` (initial boot + forced catalog refresh). Structural changes
//! replace every affected server slice in one commit. Since the index is
//! RAM-resident there's no persistence concern; a fresh rebuild from the live
//! `tools/list` is the cheapest way to keep it in sync. A failed commit or
//! reader reload makes BM25 return no opinion so callers use their authoritative
//! catalog fallback instead of trusting an uncertain snapshot.
//!
//! ## What's indexed vs. post-filtered
//!
//! BM25 answers the free-text `query` field only. Risk tier, side effects,
//! Cedar authz, `action`, and `scope` filters remain post-filters applied by
//! the handler: indexing mutable state (risk, classification, policy) would
//! mean rebuilding on every SIGHUP, and authz state is per-principal anyway.
//! `scope` and `risk_level` derive from each tool's resolved facts so the
//! handler applies them in its per-tool loop; `resource_type` is reserved
//! (accepted-but-ignored — no per-tool resource model).

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rmcp::model::Tool;
use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, Query, QueryParser, TermQuery};
use tantivy::schema::{Field, IndexRecordOption, Schema, Value, STORED, STRING, TEXT};
use tantivy::{doc, Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term};

use crate::compat::search_tools_v1::{OperationDescriptor, OperationFilters};

/// Full-text search index over every upstream's tool catalog. Thread-safe;
/// cheap to clone (just an `Arc`). Construction allocates the tantivy index
/// and a writer — keep one instance per process.
#[derive(Clone)]
pub struct SearchIndex {
    inner: Arc<Inner>,
}

/// Operator-facing state for the legacy compatibility retrieval index.
///
/// The indexed counts cover upstream tools only. Gateway-local tools remain in
/// the canonical authorized catalog and are ranked directly by the gateway and
/// Code Mode discovery surfaces; they are not missing index documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchIndexHealth {
    pub generation: u64,
    pub healthy: bool,
    pub stable: bool,
    pub published_servers: usize,
    pub published_tools: usize,
}

struct Inner {
    index: Index,
    reader: IndexReader,
    /// Tantivy serializes writes through a single writer; we don't need to
    /// rebuild it per call.
    writer: Mutex<WriterState>,
    /// Advances after every successfully committed + reloaded catalog slice.
    /// Query-bearing discovery uses it as a generation fence around the
    /// separately-awaited catalog snapshot and BM25 lookup.
    generation: AtomicU64,
    /// A failed commit or reader reload makes BM25 advisory until a full
    /// rebuild publishes a coherent reader snapshot. The next ordinary slice
    /// publication upgrades itself to that full rebuild before recovering.
    healthy: AtomicBool,
    /// Counts from the last successful publication. Scrapes read these without
    /// waiting for the Tantivy writer's commit and reader reload.
    published_servers: AtomicUsize,
    published_tools: AtomicUsize,
    fields: Fields,
}

struct WriterState {
    writer: IndexWriter,
    /// Last slices whose index publication completed successfully. This is a
    /// recovery image for the advisory index, never a discovery authority.
    published: BTreeMap<String, Vec<Tool>>,
}

struct GenerationPublication<'a> {
    generation: &'a AtomicU64,
}

impl Drop for GenerationPublication<'_> {
    fn drop(&mut self) {
        self.generation.fetch_add(1, Ordering::Release);
    }
}

impl Inner {
    fn begin_publication(&self) -> GenerationPublication<'_> {
        let previous = self.generation.fetch_add(1, Ordering::AcqRel);
        debug_assert_eq!(previous & 1, 0, "index publications must serialize");
        GenerationPublication {
            generation: &self.generation,
        }
    }
}

#[derive(Clone, Copy)]
struct Fields {
    server: Field,
    name: Field,
    text: Field,
}

fn apply_updates(published: &mut BTreeMap<String, Vec<Tool>>, updates: &[(String, Vec<Tool>)]) {
    for (server, tools) in updates {
        if tools.is_empty() {
            published.remove(server);
        } else {
            published.insert(server.clone(), tools.clone());
        }
    }
}

fn add_tools(
    writer: &IndexWriter,
    fields: Fields,
    server: &str,
    tools: &[Tool],
) -> tantivy::Result<()> {
    // A descriptor reorder is semantically unchanged and deliberately emits
    // no catalog invalidation. Insert by stable identity so Tantivy's document
    // addresses — its fallback order for equal BM25 scores — cannot make a
    // reorder-only refresh splice legacy numeric cursor pages differently.
    let mut tools: Vec<_> = tools.iter().collect();
    tools.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    for tool in tools {
        let mut text = String::with_capacity(256);
        text.push_str(tool.name.as_ref());
        if let Some(desc) = tool.description.as_deref() {
            text.push(' ');
            text.push_str(desc);
        }
        writer.add_document(doc!(
            fields.server => server,
            fields.name => tool.name.as_ref(),
            fields.text => text.as_str(),
        ))?;
    }
    Ok(())
}

impl SearchIndex {
    /// Build an empty RAM-resident index. Callers populate it via
    /// [`SearchIndex::replace_server`].
    pub fn new() -> tantivy::Result<Self> {
        let mut schema_builder = Schema::builder();
        // STRING = untokenized, exact-match, indexed. We filter results by
        // server at query time with a term query.
        let server = schema_builder.add_text_field("server", STRING | STORED);
        let name = schema_builder.add_text_field("name", STRING | STORED);
        // TEXT = default English tokenizer (lowercase, ascii-fold, stemmed).
        // Relevance is entirely BM25 over this blob.
        let text = schema_builder.add_text_field("text", TEXT);
        let schema = schema_builder.build();

        let index = Index::create_in_ram(schema);
        // 15 MiB heap is the tantivy-recommended floor; our entire corpus is
        // dozens of tools so this is vastly over-provisioned.
        let writer = index.writer(15_000_000)?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()?;

        Ok(Self {
            inner: Arc::new(Inner {
                index,
                reader,
                writer: Mutex::new(WriterState {
                    writer,
                    published: BTreeMap::new(),
                }),
                generation: AtomicU64::new(0),
                healthy: AtomicBool::new(true),
                published_servers: AtomicUsize::new(0),
                published_tools: AtomicUsize::new(0),
                fields: Fields { server, name, text },
            }),
        })
    }

    /// Delete every document tagged with `server` and index `tools` in its
    /// place. Commits synchronously so the next `search()` sees the update.
    pub fn replace_server(&self, server: &str, tools: &[Tool]) -> tantivy::Result<()> {
        self.replace_servers([(server, tools)])
    }

    /// Replace several server slices in one index commit and reader reload.
    ///
    /// An empty tool slice removes that server. Callers can therefore publish
    /// structural additions, replacements, and removals as one searchable
    /// snapshot before exposing the matching authoritative catalog map.
    pub fn replace_servers<'a>(
        &self,
        servers: impl IntoIterator<Item = (&'a str, &'a [Tool])>,
    ) -> tantivy::Result<()> {
        self.publish(
            servers
                .into_iter()
                .map(|(server, tools)| (server.to_owned(), tools.to_vec()))
                .collect(),
            false,
        )
    }

    /// Snapshot the last completely published retrieval-index image without
    /// waiting for an in-progress Tantivy commit.
    pub fn health_snapshot(&self) -> SearchIndexHealth {
        let mut snapshot = SearchIndexHealth {
            generation: 0,
            healthy: true,
            stable: false,
            published_servers: 0,
            published_tools: 0,
        };
        for _ in 0..3 {
            let before = self.generation();
            snapshot.healthy = self.inner.healthy.load(Ordering::Acquire);
            snapshot.published_servers = self.inner.published_servers.load(Ordering::Acquire);
            snapshot.published_tools = self.inner.published_tools.load(Ordering::Acquire);
            let after = self.generation();
            snapshot.generation = after;
            if before == after && after & 1 == 0 {
                snapshot.stable = true;
                break;
            }
        }
        snapshot
    }

    /// Replace the complete index from one authoritative serving snapshot.
    ///
    /// A failed partial commit may already be present in Tantivy while the
    /// caller retained its prior serving map, so recovery always clears and
    /// rebuilds every document. Ordinary slice publication automatically uses
    /// this same path while unhealthy; callers do not need a structural change
    /// to restore BM25.
    pub fn replace_all_servers<'a>(
        &self,
        servers: impl IntoIterator<Item = (&'a str, &'a [Tool])>,
    ) -> tantivy::Result<()> {
        self.publish(
            servers
                .into_iter()
                .map(|(server, tools)| (server.to_owned(), tools.to_vec()))
                .collect(),
            true,
        )
    }

    fn publish(&self, updates: Vec<(String, Vec<Tool>)>, replace_all: bool) -> tantivy::Result<()> {
        let fields = self.inner.fields;
        let mut state = self
            .inner
            .writer
            .lock()
            .expect("search index writer poisoned");
        let _publication = self.inner.begin_publication();
        let recovering = !self.inner.healthy.load(Ordering::Acquire);
        let mut rebuilt = (replace_all || recovering).then(|| {
            let mut published = if replace_all {
                BTreeMap::new()
            } else {
                state.published.clone()
            };
            apply_updates(&mut published, &updates);
            published
        });
        let result = (|| {
            if recovering {
                // Discard uncommitted operations from the failed attempt. If
                // its commit succeeded but reader reload failed, the complete
                // delete-and-repopulate below still replaces that commit.
                state.writer.rollback()?;
            }
            if let Some(published) = rebuilt.as_ref() {
                state.writer.delete_all_documents()?;
                for (server, tools) in published {
                    add_tools(&state.writer, fields, server, tools)?;
                }
            } else {
                for (server, tools) in &updates {
                    // Tombstone by term: the STRING field matches exactly, so
                    // this removes only the slice being replaced.
                    state
                        .writer
                        .delete_term(Term::from_field_text(fields.server, server));
                    add_tools(&state.writer, fields, server, tools)?;
                }
            }
            state.writer.commit()?;
            // OnCommitWithDelay readers aren't guaranteed fresh by the time
            // commit returns; a `reload()` gives us a synchronous handoff.
            self.inner.reader.reload()?;
            Ok(())
        })();
        if result.is_ok() {
            if let Some(published) = rebuilt.take() {
                state.published = published;
            } else {
                apply_updates(&mut state.published, &updates);
            }
            self.inner
                .published_servers
                .store(state.published.len(), Ordering::Release);
            self.inner.published_tools.store(
                state.published.values().map(Vec::len).sum(),
                Ordering::Release,
            );
        }
        self.inner.healthy.store(result.is_ok(), Ordering::Release);
        let publication = if recovering {
            waygate_telemetry::metrics::DiscoveryIndexPublication::Recovery
        } else if replace_all {
            waygate_telemetry::metrics::DiscoveryIndexPublication::Full
        } else {
            waygate_telemetry::metrics::DiscoveryIndexPublication::Slice
        };
        waygate_telemetry::metrics::record_discovery_index_publication(publication, result.is_ok());
        result
    }

    /// Index publication generation. Even values are stable; odd values mean a
    /// writer is committing or reloading a new catalog slice.
    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    /// Whether `candidate` still names one fully published index generation.
    pub fn is_stable_generation(&self, candidate: u64) -> bool {
        candidate & 1 == 0 && self.generation() == candidate
    }

    /// Remove every document for `server`. Used when an upstream is dropped
    /// via `reload_manifests`.
    pub fn drop_server(&self, server: &str) -> tantivy::Result<()> {
        self.replace_servers([(server, &[] as &[Tool])])
    }

    /// BM25 search for `query` within `server`. Returns the top `limit` tool
    /// names in descending relevance order. Returns `Ok(None)` when `query` is
    /// empty — the handler should fall back to enumerating the full catalog
    /// in that case.
    pub fn search(
        &self,
        server: &str,
        query: &str,
        limit: usize,
    ) -> tantivy::Result<Option<Vec<String>>> {
        if !self.inner.healthy.load(Ordering::Acquire) {
            return Ok(None);
        }
        let query = query.trim();
        if query.is_empty() {
            return Ok(None);
        }

        let fields = self.inner.fields;
        let searcher = self.inner.reader.searcher();

        // Parse the user query against the `text` field only. Parse errors
        // (e.g. lone colon, unbalanced quote) degrade gracefully: we return
        // `None` so the handler falls back to a full enumeration — BM25 "no
        // results because the user typed a weird character" would be a worse
        // UX than just showing everything.
        let parser = QueryParser::for_index(&self.inner.index, vec![fields.text]);
        let Ok(text_query) = parser.parse_query(query) else {
            return Ok(None);
        };

        let server_query = TermQuery::new(
            Term::from_field_text(fields.server, server),
            IndexRecordOption::Basic,
        );

        let combined: Box<dyn Query> = Box::new(BooleanQuery::new(vec![
            (Occur::Must, Box::new(server_query)),
            (Occur::Must, text_query),
        ]));

        // `order_by_score` returns an `impl Collector` in tantivy 0.26 —
        // `TopDocs` itself no longer implements Collector directly.
        let top = searcher.search(
            &combined,
            &TopDocs::with_limit(limit.max(1)).order_by_score(),
        )?;
        let mut names = Vec::with_capacity(top.len());
        for (_score, addr) in top {
            let doc: TantivyDocument = searcher.doc(addr)?;
            if let Some(value) = doc.get_first(fields.name) {
                if let Some(name) = value.as_str() {
                    names.push(name.to_owned());
                }
            }
        }
        Ok(Some(names))
    }
}

/// Apply the name-only non-BM25 filters (currently just `action`). The
/// `query` field is excluded on purpose — when a query is present the handler
/// consults the tantivy index and skips this function. `scope` and
/// `risk_level` are NOT applied here: both derive from the tool's resolved
/// `ToolFacts`, so the handler applies them in its per-tool loop once facts
/// are looked up. `resource_type` is reserved (no per-tool model) and ignored.
pub fn matches_non_query(tool: &Tool, filters: Option<&OperationFilters>) -> bool {
    let Some(f) = filters else { return true };

    if let Some(action) = f.action.as_deref() {
        let action = action.to_ascii_lowercase();
        if !tool.name.to_ascii_lowercase().contains(&action) {
            return false;
        }
    }

    // `risk_level` and `scope` are fact-derived ⇒ applied in the handler.
    // `resource_type` is reserved (accepted-but-ignored; see
    // `OperationFilters::resource_type`).
    let _ = f.resource_type;

    true
}

/// Substring match — kept for the no-index fallback path (tests constructing
/// `GatewayServer` without a populated index, or fresh upstreams whose
/// catalog hasn't been indexed yet). Scores are irrelevant here.
pub fn matches(tool: &Tool, filters: Option<&OperationFilters>) -> bool {
    let Some(f) = filters else { return true };

    if let Some(q) = f.query.as_deref() {
        let q = q.to_ascii_lowercase();
        let name_hit = tool.name.to_ascii_lowercase().contains(&q);
        let desc_hit = tool
            .description
            .as_deref()
            .map(|d| d.to_ascii_lowercase().contains(&q))
            .unwrap_or(false);
        if !(name_hit || desc_hit) {
            return false;
        }
    }

    matches_non_query(tool, filters)
}

/// Reorder `tools` to match the BM25-ranked `names` order, dropping tools not
/// present in `names`. Stable for items that tie or fall off the top-k list:
/// callers pass an already-filtered full list so reordering is all we need.
pub fn reorder_by_names(tools: Vec<Tool>, names: &[String]) -> Vec<Tool> {
    let set: HashSet<&str> = names.iter().map(String::as_str).collect();
    let mut by_name: std::collections::HashMap<String, Tool> = tools
        .into_iter()
        .filter(|t| set.contains(t.name.as_ref()))
        .map(|t| (t.name.as_ref().to_owned(), t))
        .collect();
    names.iter().filter_map(|n| by_name.remove(n)).collect()
}

pub fn paginate(
    items: Vec<OperationDescriptor>,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> (Vec<OperationDescriptor>, Option<String>) {
    let start: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
    let limit = limit.unwrap_or(50).min(500) as usize;
    let total = items.len();

    let page: Vec<_> = items.into_iter().skip(start).take(limit).collect();
    let end = start + page.len();
    let next = (end < total).then(|| end.to_string());
    (page, next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::Tool;
    use serde_json::json;
    use std::sync::Arc;

    fn tool(name: &str, description: &str) -> Tool {
        let schema = json!({"type": "object"}).as_object().cloned().unwrap();
        Tool::new(name.to_owned(), description.to_owned(), Arc::new(schema))
    }

    #[test]
    fn generation_is_stable_only_outside_index_publication() {
        let idx = SearchIndex::new().unwrap();
        let before = idx.generation();
        assert!(idx.is_stable_generation(before));

        {
            let _publication = idx.inner.begin_publication();
            let in_progress = idx.generation();
            assert_ne!(in_progress, before);
            assert!(!idx.is_stable_generation(before));
            assert!(!idx.is_stable_generation(in_progress));
        }

        let after = idx.generation();
        assert_ne!(after, before);
        assert!(idx.is_stable_generation(after));
    }

    #[test]
    fn health_snapshot_tracks_the_last_successfully_published_upstream_slices() {
        let idx = SearchIndex::new().unwrap();
        assert_eq!(
            idx.health_snapshot(),
            SearchIndexHealth {
                generation: 0,
                healthy: true,
                stable: true,
                published_servers: 0,
                published_tools: 0,
            }
        );

        idx.replace_servers([
            ("first", &[tool("one", "first")][..]),
            (
                "second",
                &[tool("two", "second"), tool("three", "third")][..],
            ),
        ])
        .unwrap();
        let published = idx.health_snapshot();
        assert!(published.healthy);
        assert!(published.stable);
        assert_eq!(published.published_servers, 2);
        assert_eq!(published.published_tools, 3);
        assert_eq!(published.generation & 1, 0);

        idx.drop_server("first").unwrap();
        idx.inner.healthy.store(false, Ordering::Release);
        let degraded = idx.health_snapshot();
        assert!(!degraded.healthy);
        assert_eq!(degraded.published_servers, 1);
        assert_eq!(degraded.published_tools, 2);
    }

    #[test]
    fn health_snapshot_marks_an_in_progress_publication_as_unstable() {
        let idx = SearchIndex::new().unwrap();
        let _publication = idx.inner.begin_publication();

        let snapshot = idx.health_snapshot();

        assert!(!snapshot.stable);
        assert_eq!(snapshot.generation & 1, 1);
    }

    #[test]
    fn empty_query_returns_none() {
        let idx = SearchIndex::new().unwrap();
        idx.replace_server(
            "example-messages",
            &[tool("send_message", "Send a message")],
        )
        .unwrap();
        assert!(idx.search("example-messages", "", 10).unwrap().is_none());
        assert!(idx.search("example-messages", "   ", 10).unwrap().is_none());
    }

    #[test]
    fn bm25_ranks_name_match_over_unrelated_tool() {
        let idx = SearchIndex::new().unwrap();
        idx.replace_server(
            "example-messages",
            &[
                tool("send_message", "Send a message to a contact"),
                tool("list_contacts", "Enumerate contacts in the address book"),
            ],
        )
        .unwrap();
        let hits = idx
            .search("example-messages", "message", 10)
            .unwrap()
            .unwrap();
        assert_eq!(hits.first().map(String::as_str), Some("send_message"));
    }

    #[test]
    fn server_scope_filters_results() {
        let idx = SearchIndex::new().unwrap();
        idx.replace_server(
            "example-messages",
            &[tool("send_message", "Send a message")],
        )
        .unwrap();
        idx.replace_server(
            "example-observability",
            &[tool("send_alert", "Send an alert to a channel")],
        )
        .unwrap();

        let example_messages_hits = idx.search("example-messages", "send", 10).unwrap().unwrap();
        assert!(example_messages_hits.contains(&"send_message".to_owned()));
        assert!(!example_messages_hits.contains(&"send_alert".to_owned()));

        let example_observability_hits = idx
            .search("example-observability", "send", 10)
            .unwrap()
            .unwrap();
        assert!(example_observability_hits.contains(&"send_alert".to_owned()));
        assert!(!example_observability_hits.contains(&"send_message".to_owned()));
    }

    #[test]
    fn replace_server_drops_stale_tools() {
        let idx = SearchIndex::new().unwrap();
        idx.replace_server("example-messages", &[tool("old_tool", "will be gone")])
            .unwrap();
        idx.replace_server("example-messages", &[tool("new_tool", "the only survivor")])
            .unwrap();
        let hits = idx
            .search("example-messages", "survivor", 10)
            .unwrap()
            .unwrap();
        assert_eq!(hits, vec!["new_tool".to_owned()]);
        let gone = idx.search("example-messages", "gone", 10).unwrap().unwrap();
        assert!(gone.is_empty(), "old doc still indexed: {gone:?}");
    }

    #[test]
    fn reorder_only_refresh_preserves_equal_score_order() {
        let idx = SearchIndex::new().unwrap();
        let beta = tool("beta", "shared search term");
        let alpha = tool("alpha", "shared search term");
        idx.replace_server("example", &[beta.clone(), alpha.clone()])
            .unwrap();
        let before = idx.search("example", "shared", 10).unwrap().unwrap();

        idx.replace_server("example", &[alpha, beta]).unwrap();
        let after = idx.search("example", "shared", 10).unwrap().unwrap();

        assert_eq!(before, vec!["alpha".to_owned(), "beta".to_owned()]);
        assert_eq!(after, before);
    }

    #[test]
    fn drop_server_removes_all_its_docs() {
        let idx = SearchIndex::new().unwrap();
        idx.replace_server(
            "example-messages",
            &[tool("send_message", "send a message")],
        )
        .unwrap();
        idx.drop_server("example-messages").unwrap();
        let hits = idx
            .search("example-messages", "message", 10)
            .unwrap()
            .unwrap();
        assert!(hits.is_empty(), "drop_server left docs: {hits:?}");
    }

    #[test]
    fn batch_publication_replaces_and_removes_server_slices_together() {
        let idx = SearchIndex::new().unwrap();
        idx.replace_servers([
            ("removed", &[tool("old_tool", "old searchable term")][..]),
            ("replaced", &[tool("before", "before searchable term")][..]),
        ])
        .unwrap();

        idx.replace_servers([
            ("removed", &[] as &[Tool]),
            ("replaced", &[tool("after", "after searchable term")][..]),
        ])
        .unwrap();

        assert!(idx
            .search("removed", "old", 10)
            .unwrap()
            .unwrap()
            .is_empty());
        assert_eq!(
            idx.search("replaced", "after", 10).unwrap().unwrap(),
            vec!["after".to_owned()],
        );
        assert!(idx
            .search("replaced", "before", 10)
            .unwrap()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn malformed_query_degrades_to_none() {
        // Stray quote in the query string — the handler should treat this
        // as "no BM25 opinion" rather than surfacing a tantivy parse error.
        let idx = SearchIndex::new().unwrap();
        idx.replace_server("example-messages", &[tool("send_message", "send")])
            .unwrap();
        assert!(idx
            .search("example-messages", "\"unterminated", 10)
            .unwrap()
            .is_none());
    }

    #[test]
    fn unhealthy_index_defers_to_the_authoritative_catalog_fallback() {
        let idx = SearchIndex::new().unwrap();
        idx.replace_server("example-messages", &[tool("send_message", "send")])
            .unwrap();
        idx.inner.healthy.store(false, Ordering::Release);

        assert!(idx
            .search("example-messages", "message", 10)
            .unwrap()
            .is_none());
    }

    #[test]
    fn ordinary_slice_refresh_recovers_the_complete_published_index() {
        let idx = SearchIndex::new().unwrap();
        idx.replace_server("first", &[tool("old_tool", "old searchable term")])
            .unwrap();
        idx.inner.healthy.store(false, Ordering::Release);

        idx.replace_server("second", &[tool("new_tool", "new searchable term")])
            .unwrap();

        assert_eq!(
            idx.search("first", "old", 10).unwrap().unwrap(),
            vec!["old_tool".to_owned()],
        );
        assert_eq!(
            idx.search("second", "new", 10).unwrap().unwrap(),
            vec!["new_tool".to_owned()],
        );
    }

    #[test]
    fn full_rebuild_recovers_an_unhealthy_index_without_stale_slices() {
        let idx = SearchIndex::new().unwrap();
        idx.replace_server("removed", &[tool("old_tool", "old searchable term")])
            .unwrap();
        idx.inner.healthy.store(false, Ordering::Release);

        idx.replace_all_servers([(
            "current",
            &[tool("current_tool", "current searchable term")][..],
        )])
        .unwrap();

        assert_eq!(
            idx.search("current", "current", 10).unwrap().unwrap(),
            vec!["current_tool".to_owned()],
        );
        assert!(idx
            .search("removed", "old", 10)
            .unwrap()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reorder_by_names_preserves_rank_order_and_drops_unranked() {
        let tools = vec![tool("alpha", ""), tool("beta", ""), tool("gamma", "")];
        let ranked = vec!["beta".to_owned(), "alpha".to_owned()];
        let out = reorder_by_names(tools, &ranked);
        let names: Vec<&str> = out.iter().map(|t| t.name.as_ref()).collect();
        assert_eq!(names, vec!["beta", "alpha"]);
    }
}
