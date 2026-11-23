//! Opt-in client presentation of tool names without dots.
//!
//! MCP allows `.` in tool names, but some clients accept only
//! `^[a-zA-Z0-9_-]{1,64}$` and drop every tool whose name contains a dot.
//! For clients the operator names, `tools/list` shows each tool with `_` in
//! place of `.`, and `tools/call` maps such a name back to the real dotted
//! name before anything else sees the request. Catalog identity,
//! authorization, audit, tasks and routing keep using the real name.

use std::collections::HashMap;

use rmcp::model::Tool;

/// Initialize and discover instructions added for clients shown
/// underscore names.
pub const GUIDANCE: &str = "Tool names in tools/list use `_` in place of `.` for this client; \
     tools/call accepts either form.";

/// The name a client shown underscore names sees for a real tool name.
pub fn presented_name(name: &str) -> String {
    name.replace('.', "_")
}

/// Rename every tool to its presented name. Tools whose presented names
/// collide are all removed, because a call using that name could not be
/// mapped back to one tool.
pub fn adapt_tools(tools: &mut Vec<Tool>) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for tool in tools.iter() {
        *counts.entry(presented_name(&tool.name)).or_default() += 1;
    }
    tools.retain_mut(|tool| {
        let presented = presented_name(&tool.name);
        if counts.get(&presented).copied().unwrap_or_default() > 1 {
            tracing::warn!(
                tool = %tool.name,
                presented_name = %presented,
                "tool omitted for an underscore-name client because its presented name collides"
            );
            return false;
        }
        tool.name = presented.into();
        true
    });
}

/// How a name received from a client shown underscore names maps to a real
/// tool name.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Exactly one real name presents as the received name.
    Found(String),
    /// No real name presents as the received name.
    NotFound,
    /// More than one real name presents as the received name.
    Ambiguous,
}

/// Map `received` back to the one real name among `candidates` that
/// presents as it. Candidates are fully qualified real names.
pub fn resolve<I>(received: &str, candidates: I) -> Resolution
where
    I: IntoIterator<Item = String>,
{
    let mut found = None;
    for candidate in candidates {
        if presented_name(&candidate) != received {
            continue;
        }
        if found.as_ref().is_some_and(|found| found != &candidate) {
            return Resolution::Ambiguous;
        }
        found = Some(candidate);
    }
    found.map_or(Resolution::NotFound, Resolution::Found)
}

/// Whether a source's tools could present as `received`: its presented name
/// followed by `_` must prefix the received name.
pub fn source_may_match(source: &str, received: &str) -> bool {
    received
        .strip_prefix(presented_name(source).as_str())
        .is_some_and(|rest| rest.starts_with('_') && rest.len() > 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::JsonObject;
    use std::sync::Arc;

    fn tool(name: &str) -> Tool {
        Tool::new(name.to_owned(), "test tool", Arc::new(JsonObject::new()))
    }

    fn names(tools: &[Tool]) -> Vec<&str> {
        tools.iter().map(|tool| tool.name.as_ref()).collect()
    }

    #[test]
    fn presented_names_replace_every_dot() {
        assert_eq!(presented_name("codemode.search"), "codemode_search");
        assert_eq!(presented_name("files.docs.create"), "files_docs_create");
        assert_eq!(presented_name("gateway-skills.load"), "gateway-skills_load");
    }

    #[test]
    fn adapting_renames_tools_and_drops_collisions() {
        let mut tools = vec![
            tool("codemode.search"),
            tool("files.archive_list"),
            tool("files_archive.list"),
            tool("files.read"),
        ];
        adapt_tools(&mut tools);
        assert_eq!(names(&tools), vec!["codemode_search", "files_read"]);
    }

    #[test]
    fn resolution_uses_real_names_rather_than_splitting() {
        let candidates = || {
            vec![
                "files.read".to_owned(),
                "files_archive.list".to_owned(),
                "docs.drive.search".to_owned(),
            ]
        };
        assert_eq!(
            resolve("files_archive_list", candidates()),
            Resolution::Found("files_archive.list".to_owned())
        );
        assert_eq!(
            resolve("docs_drive_search", candidates()),
            Resolution::Found("docs.drive.search".to_owned())
        );
        assert_eq!(resolve("files_write", candidates()), Resolution::NotFound);
    }

    #[test]
    fn resolution_refuses_to_guess_between_colliding_names() {
        assert_eq!(
            resolve(
                "files_archive_list",
                vec![
                    "files.archive_list".to_owned(),
                    "files_archive.list".to_owned(),
                ],
            ),
            Resolution::Ambiguous
        );
        assert_eq!(
            resolve(
                "files_read",
                vec!["files.read".to_owned(), "files.read".to_owned()],
            ),
            Resolution::Found("files.read".to_owned())
        );
    }

    #[test]
    fn only_sources_whose_presented_prefix_matches_are_searched() {
        assert!(source_may_match("files", "files_archive_list"));
        assert!(source_may_match("files_archive", "files_archive_list"));
        assert!(!source_may_match("files_archive", "files_read"));
        assert!(!source_may_match("files", "files_"));
        assert!(!source_may_match("files", "filesystem_read"));
    }
}
