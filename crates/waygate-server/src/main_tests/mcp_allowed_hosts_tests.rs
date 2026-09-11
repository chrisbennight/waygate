use super::resolve_mcp_allowed_hosts;

#[test]
fn defaults_from_public_url_include_host_and_loopback() {
    let h = resolve_mcp_allowed_hosts("https://gateway.example.com", None).unwrap();
    assert!(h.contains(&"gateway.example.com".into()));
    assert!(h.contains(&"localhost".into()));
    assert!(h.contains(&"127.0.0.1".into()));
    assert!(h.contains(&"::1".into()));
}

#[test]
fn default_includes_port_variant_when_public_url_has_port() {
    let h = resolve_mcp_allowed_hosts("http://gw.example:8443", None).unwrap();
    assert!(h.contains(&"gw.example".into()));
    assert!(h.contains(&"gw.example:8443".into()));
}

#[test]
fn override_wins_over_default() {
    let list = vec!["proxy.internal".to_string(), "gw.example".to_string()];
    let h = resolve_mcp_allowed_hosts("https://gateway.example.com", Some(&list)).unwrap();
    assert_eq!(h, list);
}

#[test]
fn empty_override_disables_guard() {
    let list: Vec<String> = vec![];
    let h = resolve_mcp_allowed_hosts("https://gateway.example.com", Some(&list)).unwrap();
    assert!(h.is_empty());
}

#[test]
fn default_rejects_invalid_public_url() {
    assert!(resolve_mcp_allowed_hosts("not a url", None).is_err());
}
