//! Explicit backend authentication configuration; client authorization is unchanged.
use super::*;

pub(super) fn no_auth(def: &ModelDef) -> anyhow::Result<bool> {
    let no_auth = match def.authentication.as_deref() {
        None | Some("bearer") => false,
        Some("none") => true,
        Some(_) => anyhow::bail!("model authentication must be bearer or none"),
    };
    if no_auth {
        let url = reqwest::Url::parse(&def.base_url)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || def
                .path
                .as_deref()
                .is_some_and(|path| path.contains(['?', '#']))
        {
            anyhow::bail!("credential-free backend URLs must use HTTP(S) without user information, queries, or fragments");
        }
        if !is_embeddings(def)
            || !def.provider.eq_ignore_ascii_case("openai")
            || !def.credential_label.is_empty()
            || def
                .credential_labels
                .as_ref()
                .is_some_and(|v| !v.is_empty())
            || !def.fallbacks.is_empty()
        {
            anyhow::bail!("authentication none requires one OpenAI-compatible embedding route without credentials or fallbacks");
        }
    } else if def.credential_label.trim().is_empty() {
        anyhow::bail!("authenticated model routes require a credential_label");
    }
    Ok(no_auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_credential_free_embedding_route_preserves_the_model_alias() {
        let defs = serde_json::from_value(json!([{
            "alias":"voyage-4-nano", "provider":"openai",
            "base_url":"http://voyager-embeddings:8080/v1",
            "upstream_model":"voyageai/voyage-4-nano",
            "kind":"embeddings", "authentication":"none"
        }]))
        .unwrap();
        let (_, resolver) = build_from_defs(defs, None).unwrap().unwrap();
        let model = resolver.resolve(LLM_SERVER, "voyage-4-nano").unwrap();
        assert!(model.route.embeddings_no_auth);
        assert_eq!(model.operation, LlmOperation::Embeddings);
        assert_eq!(model.route.upstream_model, "voyageai/voyage-4-nano");
        assert_eq!(model.route.path, "embeddings");
        assert!(model.fallbacks.is_empty());
    }

    #[test]
    fn invalid_auth_configuration_is_rejected_before_dispatch() {
        for extra in [
            json!({}),
            json!({"authentication":"typo"}),
            json!({"authentication":"none","kind":"chat"}),
            json!({"authentication":"none","credential_label":"MAIN"}),
            json!({"authentication":"none","credential_labels":["BACKUP"]}),
            json!({"authentication":"none","provider":"anthropic"}),
            json!({"authentication":"none","base_url":"http://user:password@backend/v1"}),
            json!({"authentication":"none","base_url":"file:///backend"}),
            json!({"authentication":"none","base_url":"http://backend/v1?api_key=synthetic"}),
            json!({"authentication":"none","base_url":"http://backend/v1#synthetic"}),
            json!({"authentication":"none","path":"embeddings?api_key=synthetic"}),
            json!({"authentication":"none","path":"embeddings#synthetic"}),
            json!({"authentication":"none","fallbacks":[{
                "provider":"openai","credential_label":"MAIN","base_url":"https://example.test"
            }]}),
        ] {
            let mut config = json!({"alias":"m","provider":"openai",
                "kind":"embeddings","base_url":"http://backend/v1"});
            config
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let defs = serde_json::from_value(json!([config])).unwrap();
            assert!(build_from_defs(defs, None).is_err());
        }
    }
}
