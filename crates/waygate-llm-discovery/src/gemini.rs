//! Bounded discovery through the documented Gemini Developer API.

use serde::Deserialize;

use super::{DiscoveredModel, DiscoveryError};

pub struct GeminiListing {
    pub models: Vec<DiscoveredModel>,
    pub raw_len: usize,
}

/// The API reports generation methods, but not every model's output modality.
/// Select operator-qualified models and require advertised generateContent.
pub async fn list_gemini(
    http: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    generate_content_models: &[String],
) -> Result<GeminiListing, DiscoveryError> {
    let mut page_token: Option<String> = None;
    let mut seen_tokens = std::collections::HashSet::new();
    let mut observed = std::collections::HashMap::new();
    let mut raw_len = 0;
    for _ in 0..10 {
        let mut url =
            reqwest::Url::parse(&format!("{}/v1beta/models", base_url.trim_end_matches('/')))
                .map_err(|_| DiscoveryError::Decode("invalid Gemini API base URL".into()))?;
        url.query_pairs_mut().append_pair("pageSize", "1000");
        if let Some(token) = page_token.as_deref() {
            url.query_pairs_mut().append_pair("pageToken", token);
        }
        let request = http
            .get(url)
            .header("x-goog-api-key", api_key)
            .header(reqwest::header::ACCEPT, "application/json");
        let response = request
            .send()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        let body = super::read_2xx_body(response)
            .await
            .map_err(|error| match error {
                DiscoveryError::Status { status, .. } => DiscoveryError::Status {
                    status,
                    body: "response body withheld".into(),
                },
                other => other,
            })?;
        let page: ModelsPage = serde_json::from_str(&body)
            .map_err(|error| DiscoveryError::Decode(error.to_string()))?;
        if page.models.len() > 1000 {
            return Err(DiscoveryError::Decode(
                "Gemini model page exceeds 1000 entries".into(),
            ));
        }
        raw_len += page.models.len();
        for model in page.models {
            let id = model
                .name
                .strip_prefix("models/")
                .filter(|id| {
                    !id.is_empty()
                        && id
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                })
                .ok_or_else(|| {
                    DiscoveryError::Decode("invalid Gemini model resource name".into())
                })?;
            if generate_content_models
                .iter()
                .any(|selected| selected == id)
            {
                let methods = model.supported_generation_methods.ok_or_else(|| {
                    DiscoveryError::Decode(
                        "selected Gemini model omits supportedGenerationMethods".into(),
                    )
                })?;
                observed.insert(
                    id.to_owned(),
                    methods.iter().any(|method| method == "generateContent"),
                );
            }
        }
        let next = page.next_page_token.filter(|token| !token.is_empty());
        if let Some(token) = next {
            if token.len() > 4096 || !seen_tokens.insert(token.clone()) {
                return Err(DiscoveryError::Decode(
                    "invalid or repeated Gemini model page token".into(),
                ));
            }
            page_token = Some(token);
        } else {
            let models = generate_content_models
                .iter()
                .filter(|id| observed.get(*id) == Some(&true))
                .map(|id| DiscoveredModel {
                    id: id.clone(),
                    pricing: None,
                    is_embeddings: false,
                })
                .collect();
            return Ok(GeminiListing { models, raw_len });
        }
    }
    Err(DiscoveryError::Decode(
        "Gemini model listing exceeds ten pages".into(),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelsPage {
    #[serde(default)]
    models: Vec<Model>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Model {
    name: String,
    supported_generation_methods: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::Query, http::HeaderMap, routing::get, Json, Router};
    use serde_json::json;

    #[cfg(test)]
    fn raw_test_http_client() -> reqwest::Client {
        reqwest::Client::new() // A raw test client isolates provider wire behavior from gateway policy.
    }

    #[tokio::test]
    async fn discovery_uses_header_auth_paginates_and_checks_advertised_methods() {
        let app = Router::new().route("/v1beta/models", get(|headers: HeaderMap, Query(query): Query<std::collections::HashMap<String,String>>| async move {
            assert_eq!(headers["x-goog-api-key"], "synthetic-google-key");
            assert!(!headers.contains_key("authorization"));
            assert!(!query.contains_key("key"));
            assert_eq!(query["pageSize"], "1000");
            if query.contains_key("pageToken") {
                assert_eq!(query["pageToken"], "next-page");
                Json(json!({"models":[{"name":"models/selected-chat","supportedGenerationMethods":["generateContent","countTokens"]}]}))
            } else {
                Json(json!({"models":[{"name":"models/selected-embedding","supportedGenerationMethods":["embedContent"]},{"name":"models/unselected-image","supportedGenerationMethods":["generateContent"]}],"nextPageToken":"next-page"}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let listing = list_gemini(
            &raw_test_http_client(),
            &base,
            "synthetic-google-key",
            &["selected-chat".into(), "selected-embedding".into()],
        )
        .await
        .unwrap();
        assert_eq!(listing.raw_len, 3);
        assert_eq!(listing.models.len(), 1);
        assert_eq!(listing.models[0].id, "selected-chat");
        assert!(listing.models[0].pricing.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn discovery_refuses_incomplete_metadata_and_pagination_without_exposing_error_bodies() {
        for (status, body, expected) in [
            (
                200,
                json!({"models":[{"name":"models/selected"}]}),
                "supportedGenerationMethods",
            ),
            (
                200,
                json!({"models":[{"name":"invalid-resource"}]}),
                "resource name",
            ),
            (
                200,
                json!({"models":[],"nextPageToken":"repeated"}),
                "repeated",
            ),
            (
                403,
                json!({"error":"synthetic-google-key"}),
                "response body withheld",
            ),
        ] {
            let app = Router::new().route(
                "/v1beta/models",
                get(move || {
                    let body = body.clone();
                    async move {
                        (
                            axum::http::StatusCode::from_u16(status).unwrap(),
                            Json(body),
                        )
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let result = list_gemini(
                &raw_test_http_client(),
                &base,
                "synthetic-google-key",
                &["selected".into()],
            )
            .await;
            let error = match result {
                Ok(_) => panic!("listing must fail"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("synthetic-google-key"));
            server.abort();
        }
    }
}
