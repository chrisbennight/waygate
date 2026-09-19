//! Client-specific MCP tool-catalog compatibility settings.

use anyhow::Result;

pub(crate) const DEFAULT_EAGER_TOOLS_CLIENTS: &[&str] = &["claude-code", "codex-mcp-client"];

pub(crate) fn from_env(eager_tools_list: bool) -> Result<(Vec<String>, Vec<String>)> {
    let eager = normalize_client_names(waygate_core::env::csv_default(
        "GATEWAY_EAGER_TOOLS_CLIENTS",
        DEFAULT_EAGER_TOOLS_CLIENTS,
    ));
    let compact = normalize_client_names(waygate_core::env::csv_default(
        "GATEWAY_CODEMODE_ONLY_CLIENTS",
        &[],
    ));
    validate(eager_tools_list, &eager, &compact)?;
    Ok((eager, compact))
}

pub(crate) fn log_selection(eager_tools_list: bool, eager: &[String], compact: &[String]) {
    if eager_tools_list {
        tracing::warn!(
            "GATEWAY_EAGER_TOOLS_LIST=true — returning the full upstream catalog from \
             legacy-session tools/list. This is a compatibility override; legacy MCP clients \
             must otherwise honor notifications/tools/list_changed."
        );
    } else if !eager.is_empty() {
        tracing::info!(
            clients = ?eager,
            "configured per-session eager tool discovery fallbacks"
        );
    }
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

fn validate(eager_tools_list: bool, eager: &[String], compact: &[String]) -> Result<()> {
    if eager_tools_list && !compact.is_empty() {
        anyhow::bail!(
            "GATEWAY_EAGER_TOOLS_LIST=true conflicts with GATEWAY_CODEMODE_ONLY_CLIENTS; \
             disable the global eager override before selecting compact clients"
        );
    }
    if let Some(overlap) = compact.iter().find(|client| eager.contains(client)) {
        anyhow::bail!(
            "MCP client {overlap:?} appears in both GATEWAY_EAGER_TOOLS_CLIENTS and \
             GATEWAY_CODEMODE_ONLY_CLIENTS"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_blind_clients_receive_eager_tools_by_default() {
        assert_eq!(
            DEFAULT_EAGER_TOOLS_CLIENTS,
            &["claude-code", "codex-mcp-client"]
        );
    }

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

    #[test]
    fn eager_and_compact_client_postures_cannot_overlap() {
        assert!(validate(false, &[], &["cursor".to_owned()]).is_ok());
        assert!(validate(true, &[], &["cursor".to_owned()]).is_err());
        assert!(validate(false, &["cursor".to_owned()], &["cursor".to_owned()]).is_err());
    }
}
