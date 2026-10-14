//! Client-specific MCP tool-catalog compatibility settings.

/// Read `GATEWAY_CODEMODE_ONLY_CLIENTS`: the MCP clients whose `tools/list`
/// contains only authorized gateway built-ins.
pub(crate) fn from_env() -> Vec<String> {
    normalize_client_names(waygate_core::env::csv_default(
        "GATEWAY_CODEMODE_ONLY_CLIENTS",
        &[],
    ))
}

pub(crate) fn log_selection(compact: &[String]) {
    if !compact.is_empty() {
        tracing::info!(
            clients = ?compact,
            "compact Code Mode tool projection enabled for matching MCP clients"
        );
    }
}

/// Normalize a per-client projection allowlist for exact, case-insensitive
/// matching while preserving the operator's first-seen order.
pub(crate) fn normalize_client_names(raw: Vec<String>) -> Vec<String> {
    let mut clients = Vec::new();
    for client in raw {
        let normalized = client.trim().to_ascii_lowercase();
        if !normalized.is_empty() && !clients.contains(&normalized) {
            clients.push(normalized);
        }
    }
    clients
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_names_are_normalized_and_deduplicated() {
        assert!(normalize_client_names(Vec::new()).is_empty());
        assert_eq!(
            normalize_client_names(vec![
                " Claude-Code".to_owned(),
                "codex ".to_owned(),
                "CLAUDE-CODE ".to_owned(),
            ]),
            vec!["claude-code", "codex"]
        );
    }
}
