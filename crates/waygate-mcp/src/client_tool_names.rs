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

/// Rename every tool to its presented name. `published` is every real tool
/// name the gateway publishes, the same set a call resolves against. A tool
/// whose presented name matches more than one published name, or more than
/// one listed tool, is removed, because a call using that name could not be
/// mapped back to one tool.
pub fn adapt_tools(tools: &mut Vec<Tool>, published: &[String]) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for name in published {
        *counts.entry(presented_name(name)).or_default() += 1;
    }
    for tool in tools.iter() {
        if !published.iter().any(|name| name == tool.name.as_ref()) {
            *counts.entry(presented_name(&tool.name)).or_default() += 1;
        }
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

/// The one real name among `names` that presents as `received`, or `None`
/// when no name or more than one name does. A colliding name is also absent
/// from the presented list, so refusing it matches what the client was shown.
pub fn unique_match<'a, I>(received: &str, names: I) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut matches = names
        .into_iter()
        .filter(|name| presented_name(name) == received);
    match (matches.next(), matches.next()) {
        (Some(name), None) => Some(name),
        _ => None,
    }
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
        adapt_tools(&mut tools, &[]);
        assert_eq!(names(&tools), vec!["codemode_search", "files_read"]);
    }

    #[test]
    fn adapting_drops_a_listed_tool_that_collides_with_an_unlisted_one() {
        let published =
            ["files.archive_list", "files_archive.list", "files.read"].map(str::to_owned);
        let mut tools = vec![tool("files.archive_list"), tool("files.read")];
        adapt_tools(&mut tools, &published);
        assert_eq!(names(&tools), vec!["files_read"]);
    }

    #[test]
    fn matching_uses_real_names_rather_than_splitting() {
        let names = ["files.read", "files_archive.list", "docs.drive.search"];
        assert_eq!(
            unique_match("files_archive_list", names),
            Some("files_archive.list")
        );
        assert_eq!(
            unique_match("docs_drive_search", names),
            Some("docs.drive.search")
        );
        assert_eq!(unique_match("files_write", names), None);
    }

    #[test]
    fn matching_refuses_to_guess_between_colliding_names() {
        assert_eq!(
            unique_match(
                "files_archive_list",
                ["files.archive_list", "files_archive.list"]
            ),
            None
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
