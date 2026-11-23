//! Opt-in client presentation of built-in tool names without dots.
//!
//! MCP allows `.` in tool names, but some clients accept only
//! `^[a-zA-Z0-9_-]{1,64}$` and drop every tool whose name contains a dot.
//! For clients the operator names, `tools/list` shows each gateway built-in
//! tool with `_` in place of `.`, and `tools/call` maps such a name back to
//! the real dotted name before anything else sees the request. Catalog
//! identity, authorization, audit, tasks and routing keep using the real
//! name.
//!
//! Only built-ins are renamed. Their namespaces are reserved and their
//! catalogs are fixed in the gateway, so an underscore name maps to one tool
//! without depending on configuration, connections or catalog state.
//! Upstream server names are unrestricted apart from excluding `.`, so an
//! underscore form of an upstream tool could not be mapped back reliably.

/// Initialize and discover instructions added for clients shown
/// underscore names.
pub const GUIDANCE: &str = "Gateway built-in tool names in tools/list use `_` in place of `.` \
     for this client, for example `codemode_search`; tools/call accepts either form. Upstream \
     tools keep their dotted names.";

/// The name a client shown underscore names sees for a real tool name.
pub fn presented_name(name: &str) -> String {
    name.replace('.', "_")
}

/// The one real name among `names` that presents as `received`, or `None`
/// when no name or more than one distinct name does.
pub fn unique_match<'a, I>(received: &str, names: I) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut matches = names
        .into_iter()
        .filter(|name| presented_name(name) == received);
    let first = matches.next()?;
    matches.all(|other| other == first).then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presented_names_replace_every_dot() {
        assert_eq!(presented_name("codemode.search"), "codemode_search");
        assert_eq!(presented_name("gateway-skills.load"), "gateway-skills_load");
    }

    #[test]
    fn matching_uses_real_names_rather_than_splitting() {
        let names = [
            "codemode.search",
            "gateway-skills.load",
            "gateway-skills.read_file",
        ];
        assert_eq!(
            unique_match("codemode_search", names),
            Some("codemode.search")
        );
        assert_eq!(
            unique_match("gateway-skills_read_file", names),
            Some("gateway-skills.read_file")
        );
        assert_eq!(unique_match("codemode_missing", names), None);
    }

    #[test]
    fn matching_refuses_to_guess_between_distinct_names() {
        assert_eq!(unique_match("a_b_c", ["a.b_c", "a_b.c"]), None);
        assert_eq!(unique_match("a_b", ["a.b", "a.b"]), Some("a.b"));
    }
}
