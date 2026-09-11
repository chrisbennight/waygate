//! The `gateway-files.prepare_*` tool result as this helper consumes it, and
//! the checks applied to it before anything is dialled.
//!
//! The result reaches the helper by way of the caller's own context, which the
//! helper does not treat as trustworthy. The grant handle needs no protection
//! there — it is bound to a key this process holds — but the *addresses* in the
//! same object decide where bytes go, so they are checked against an origin the
//! operator recorded locally rather than taken at face value.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use url::{Origin, Url};

#[derive(Debug, Deserialize)]
pub struct PrepareUpload {
    pub file: FileValue,
    pub grant_handle: String,
    pub credential_exchange: CredentialExchange,
    pub upload: TransferDescriptor,
}

#[derive(Debug, Deserialize)]
pub struct PrepareDownload {
    pub file: FileValue,
    pub grant_handle: String,
    pub credential_exchange: CredentialExchange,
    pub download: TransferDescriptor,
}

#[derive(Debug, Deserialize)]
pub struct FileValue {
    pub uri: String,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub digest: Option<Digest>,
}

#[derive(Debug, Deserialize)]
pub struct Digest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialExchange {
    pub method: String,
    pub url: String,
    pub grant_handle_field: String,
    pub proof_header: String,
    pub access_token_field: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferDescriptor {
    pub method: String,
    pub url: String,
    pub authorization_scheme: String,
    pub proof_header: String,
    #[serde(default)]
    pub content_type: Option<String>,
}

/// Read a tool result from `reader`.
///
/// Accepts the `structuredContent` object on its own, a whole `CallToolResult`
/// carrying it, or the exact JSON object duplicated into a single text content
/// block by a client adapter. The fallback deliberately parses the entire text
/// block as JSON; it never scrapes JSON out of explanatory prose.
pub fn from_reader<T: serde::de::DeserializeOwned>(reader: impl std::io::Read) -> Result<T> {
    let raw: serde_json::Value =
        serde_json::from_reader(reader).context("input is not valid JSON")?;
    if raw.get("isError").and_then(serde_json::Value::as_bool) == Some(true) {
        bail!("the gateway-files tool call returned an error, not a prepare result");
    }
    let payload = if let Some(inner) = raw
        .get("structuredContent")
        .filter(|value| !value.is_null())
    {
        inner.clone()
    } else if let Some(content) = raw.get("content") {
        let blocks = content
            .as_array()
            .context("tool result `content` is not an array")?;
        let [block] = blocks.as_slice() else {
            bail!(
                "a content-only tool result must contain exactly one text block holding the JSON prepare result"
            );
        };
        if block.get("type").and_then(serde_json::Value::as_str) != Some("text") {
            bail!("the content-only tool result does not contain a text block");
        }
        let text = block
            .get("text")
            .and_then(serde_json::Value::as_str)
            .context("the content-only tool result's text block has no `text` string")?;
        serde_json::from_str(text)
            .context("the content-only tool result's entire text block is not valid JSON")?
    } else {
        raw
    };
    serde_json::from_value(payload).context(
        "input is not a gateway-files prepare result \
         (pipe the tool call's structuredContent in on stdin)",
    )
}

/// Reject an address that does not belong to the recorded gateway.
///
/// Without this a rewritten address in the tool result would send the file
/// somewhere else entirely, and the helper would have no way to notice.
pub fn check_address(raw: &str, expected: &Origin, field: &str) -> Result<Url> {
    let url = Url::parse(raw).with_context(|| format!("{field} is not a URL"))?;

    if !url.username().is_empty() || url.password().is_some() {
        bail!("{field} carries userinfo, which the transfer endpoints never require");
    }

    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!(
            "{field} uses {}, but transfers run over https (http is accepted only for loopback \
             during local development)",
            url.scheme()
        );
    }

    if &url.origin() != expected {
        bail!(
            "{field} points at {}, which is not the gateway recorded by `mcp-files init`. \
             Re-run init if the gateway moved; otherwise this result was altered in transit.",
            url.origin().ascii_serialization()
        );
    }

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway() -> Origin {
        Url::parse("https://gateway.example").expect("url").origin()
    }

    #[test]
    fn accepts_an_address_on_the_recorded_gateway() {
        let url = check_address(
            "https://gateway.example/n/content",
            &gateway(),
            "upload.url",
        )
        .expect("same origin is accepted");
        assert_eq!(url.path(), "/n/content");
    }

    #[test]
    fn refuses_an_address_on_another_host() {
        let error = check_address(
            "https://elsewhere.example/n/content",
            &gateway(),
            "upload.url",
        )
        .expect_err("a redirected upload must not be dialled");
        assert!(
            error.to_string().contains("elsewhere.example"),
            "the refusal should name where it was being sent: {error}"
        );
    }

    #[test]
    fn refuses_a_matching_host_on_another_port() {
        check_address(
            "https://gateway.example:8443/n/content",
            &gateway(),
            "upload.url",
        )
        .expect_err("origin includes the port, so a port change is a different destination");
    }

    #[test]
    fn refuses_plain_http_for_a_remote_host() {
        check_address("http://gateway.example/n/content", &gateway(), "upload.url")
            .expect_err("bytes must not leave over cleartext");
    }

    #[test]
    fn refuses_userinfo() {
        let local = Url::parse("https://user@gateway.example")
            .expect("url")
            .origin();
        check_address(
            "https://someone:secret@gateway.example/n/content",
            &local,
            "upload.url",
        )
        .expect_err("credentials in a URL are never required here");
    }

    #[test]
    fn reads_a_bare_structured_content_object() {
        let body = serde_json::json!({
            "file": {"uri": "mcp-file://gateway/abc"},
            "grant_handle": "handle",
            "credential_exchange": {
                "method": "POST",
                "url": "https://gateway.example/n/credentials",
                "grantHandleField": "grant_handle",
                "proofHeader": "DPoP",
                "accessTokenField": "access_token"
            },
            "upload": {
                "method": "PUT",
                "url": "https://gateway.example/n/content",
                "authorizationScheme": "DPoP",
                "proofHeader": "DPoP"
            }
        });

        let parsed: PrepareUpload =
            from_reader(body.to_string().as_bytes()).expect("structuredContent parses");
        assert_eq!(parsed.grant_handle, "handle");
        assert_eq!(parsed.file.uri, "mcp-file://gateway/abc");
    }

    #[test]
    fn unwraps_a_whole_tool_result() {
        let body = serde_json::json!({
            "content": [{"type": "text", "text": "ignored"}],
            "structuredContent": {
                "file": {"uri": "mcp-file://gateway/abc"},
                "grant_handle": "handle",
                "credential_exchange": {
                    "method": "POST",
                    "url": "https://gateway.example/n/credentials",
                    "grantHandleField": "grant_handle",
                    "proofHeader": "DPoP",
                    "accessTokenField": "access_token"
                },
                "upload": {
                    "method": "PUT",
                    "url": "https://gateway.example/n/content",
                    "authorizationScheme": "DPoP",
                    "proofHeader": "DPoP"
                }
            }
        });

        let parsed: PrepareUpload =
            from_reader(body.to_string().as_bytes()).expect("wrapped result parses");
        assert_eq!(parsed.grant_handle, "handle");
    }

    #[test]
    fn unwraps_an_exact_json_text_content_fallback() {
        let structured = serde_json::json!({
            "file": {"uri": "mcp-file://gateway/abc"},
            "grant_handle": "handle",
            "credential_exchange": {
                "method": "POST",
                "url": "https://gateway.example/n/credentials",
                "grantHandleField": "grant_handle",
                "proofHeader": "DPoP",
                "accessTokenField": "access_token"
            },
            "upload": {
                "method": "PUT",
                "url": "https://gateway.example/n/content",
                "authorizationScheme": "DPoP",
                "proofHeader": "DPoP"
            }
        });
        let body = serde_json::json!({
            "content": [{"type": "text", "text": structured.to_string()}]
        });

        let parsed: PrepareUpload =
            from_reader(body.to_string().as_bytes()).expect("text fallback parses");
        assert_eq!(parsed.grant_handle, "handle");
    }

    #[test]
    fn uses_the_text_fallback_when_an_adapter_serializes_structured_content_as_null() {
        let structured = serde_json::json!({
            "file": {"uri": "mcp-file://gateway/abc"},
            "grant_handle": "handle",
            "credential_exchange": {
                "method": "POST",
                "url": "https://gateway.example/n/credentials",
                "grantHandleField": "grant_handle",
                "proofHeader": "DPoP",
                "accessTokenField": "access_token"
            },
            "upload": {
                "method": "PUT",
                "url": "https://gateway.example/n/content",
                "authorizationScheme": "DPoP",
                "proofHeader": "DPoP"
            }
        });
        let body = serde_json::json!({
            "structuredContent": null,
            "content": [{"type": "text", "text": structured.to_string()}]
        });

        let parsed: PrepareUpload =
            from_reader(body.to_string().as_bytes()).expect("null falls back to exact text JSON");
        assert_eq!(parsed.grant_handle, "handle");
    }

    #[test]
    fn refuses_to_scrape_json_out_of_prose() {
        let body = serde_json::json!({
            "content": [{"type": "text", "text": "Result: {\"grant_handle\":\"handle\"}"}]
        });

        let error = from_reader::<PrepareUpload>(body.to_string().as_bytes())
            .expect_err("prose must not be scraped for an embedded object");
        assert!(error.to_string().contains("entire text block"));
    }

    #[test]
    fn refuses_ambiguous_content_fallbacks() {
        let body = serde_json::json!({
            "content": [
                {"type": "text", "text": "{}"},
                {"type": "text", "text": "{}"}
            ]
        });

        let error = from_reader::<PrepareUpload>(body.to_string().as_bytes())
            .expect_err("multiple blocks are ambiguous");
        assert!(error.to_string().contains("exactly one text block"));
    }

    #[test]
    fn refuses_an_error_tool_result() {
        let body = serde_json::json!({
            "isError": true,
            "content": [{"type": "text", "text": "{}"}]
        });

        let error = from_reader::<PrepareUpload>(body.to_string().as_bytes())
            .expect_err("an error result is not transfer authority");
        assert!(error.to_string().contains("returned an error"));
    }

    #[test]
    fn explains_itself_when_given_something_else() {
        let error = from_reader::<PrepareUpload>(b"{\"nope\": true}".as_slice())
            .expect_err("an unrelated object is not a prepare result");
        assert!(
            error.to_string().contains("structuredContent"),
            "the error should say what to pipe in: {error}"
        );
    }
}
