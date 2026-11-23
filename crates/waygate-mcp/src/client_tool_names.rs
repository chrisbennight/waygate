//! Opt-in client presentation of tool names without dots.
//!
//! MCP allows `.` in tool names, but some clients accept only
//! `^[a-zA-Z0-9_-]{1,64}$` and drop every tool whose name contains a dot.
//! For clients the operator names, `tools/list` shows each tool with `_` in
//! place of `.`, and `tools/call` maps such a name back to the real dotted
//! name before anything else sees the request. Catalog identity,
//! authorization, audit, tasks and routing keep using the real name.
//!
//! The source a presented name belongs to is decided from configured source
//! names alone, never from which tools are currently connected, so an
//! upstream going up or down cannot move a name to another source.

/// Initialize and discover instructions added for clients shown
/// underscore names.
pub const GUIDANCE: &str = "Tool names in tools/list use `_` in place of `.` for this client; \
     tools/call accepts either form.";

/// The name a client shown underscore names sees for a real tool name.
pub fn presented_name(name: &str) -> String {
    name.replace('.', "_")
}

/// The one configured source whose presented name, followed by `_` and at
/// least one more character, begins `received`. `None` when no source or
/// more than one does, because the name could then belong to either.
pub fn alias_source<'a>(received: &str, sources: &'a [String]) -> Option<&'a str> {
    let mut matching = sources.iter().filter(|source| {
        received
            .strip_prefix(presented_name(source).as_str())
            .is_some_and(|rest| rest.len() > 1 && rest.starts_with('_'))
    });
    match (matching.next(), matching.next()) {
        (Some(source), None) => Some(source.as_str()),
        _ => None,
    }
}

/// The real name `received` addresses within `source`, whose current bare
/// tool names are `tools`. The one tool whose presented name matches wins;
/// with none, the remainder is used as written, so an unavailable source
/// still reaches dispatch for its ordinary refusal; with several distinct
/// matches the name is refused.
pub fn resolve_in_source(received: &str, source: &str, tools: &[String]) -> Option<String> {
    let rest = received
        .strip_prefix(presented_name(source).as_str())?
        .strip_prefix('_')?;
    let mut matches = tools.iter().filter(|tool| presented_name(tool) == rest);
    let tool = match matches.next() {
        None => rest,
        Some(first) if matches.all(|other| other == first) => first.as_str(),
        Some(_) => return None,
    };
    Some(format!("{source}.{tool}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn presented_names_replace_every_dot() {
        assert_eq!(presented_name("codemode.search"), "codemode_search");
        assert_eq!(presented_name("files.docs.create"), "files_docs_create");
        assert_eq!(presented_name("gateway-skills.load"), "gateway-skills_load");
    }

    #[test]
    fn a_source_is_chosen_only_when_configured_names_leave_one_choice() {
        let sources = owned(&["files", "codemode", "files_archive"]);
        assert_eq!(alias_source("codemode_search", &sources), Some("codemode"));
        assert_eq!(alias_source("files_read", &sources), Some("files"));
        // `files_archive_delete` could be `files.archive_delete` or
        // `files_archive.delete`; refusing it means no change in which
        // upstreams are connected can redirect it.
        assert_eq!(alias_source("files_archive_delete", &sources), None);
        assert_eq!(alias_source("files_", &sources), None);
        assert_eq!(alias_source("filesystem_read", &sources), None);
    }

    #[test]
    fn a_tool_is_restored_from_its_own_source() {
        let tools = owned(&["docs.create", "read", "read"]);
        assert_eq!(
            resolve_in_source("files_docs_create", "files", &tools),
            Some("files.docs.create".to_owned())
        );
        assert_eq!(
            resolve_in_source("files_read", "files", &tools),
            Some("files.read".to_owned())
        );
        // An empty inventory, as for a disconnected upstream, passes the
        // remainder through so dispatch gives its ordinary answer.
        assert_eq!(
            resolve_in_source("files_read", "files", &[]),
            Some("files.read".to_owned())
        );
    }

    #[test]
    fn distinct_tools_with_one_presented_name_are_refused() {
        let tools = owned(&["docs.create", "docs_create"]);
        assert_eq!(
            resolve_in_source("files_docs_create", "files", &tools),
            None
        );
    }
}
