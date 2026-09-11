//! OpenAI Images requests and the Codex JSON image transport.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{InferenceRecord, TranslateError};

/// Validated image request. Options remain verbatim, including absent defaults.
pub struct ImagesRequest {
    pub model_requested: String,
    pub edit: bool,
    body: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters<'a> {
    model: &'a str,
    prompt: &'a str,
    n: Option<u64>,
    size: Option<&'a str>,
    quality: Option<&'a str>,
    background: Option<&'a str>,
    output_format: Option<&'a str>,
    output_compression: Option<u64>,
    moderation: Option<&'a str>,
    input_fidelity: Option<&'a str>,
    user: Option<&'a str>,
    stream: Option<bool>,
    partial_images: Option<u64>,
    response_format: Option<&'a str>,
    #[serde(borrow)]
    images: Option<Vec<ImageInput<'a>>>,
    #[serde(borrow)]
    mask: Option<ImageInput<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageInput<'a> {
    image_url: &'a str,
}

fn invalid(message: &str) -> TranslateError {
    TranslateError::Invalid(message.to_owned())
}

fn choice(value: Option<&str>, field: &str, choices: &[&str]) -> Result<(), TranslateError> {
    if value.is_some_and(|v| !choices.contains(&v)) {
        return Err(invalid(&format!(
            "invalid `{field}`; expected {}",
            choices.join(", ")
        )));
    }
    Ok(())
}

/// Validate before authorization quota debit or provider contact. Image URLs
/// are inline uploads only; this adapter does not fetch remote URLs or resolve
/// provider file identifiers using a different account's credential.
pub fn parse_images(body: Value, edit: bool) -> Result<ImagesRequest, TranslateError> {
    let p = Parameters::deserialize(&body)
        .map_err(|_| invalid("invalid image request fields or field types"))?;
    if p.model.trim().is_empty() || p.prompt.trim().is_empty() {
        return Err(invalid("`model` and `prompt` must be non-empty strings"));
    }
    if p.n.is_some_and(|n| !(1..=10).contains(&n)) {
        return Err(invalid("`n` must be between 1 and 10"));
    }
    choice(p.quality, "quality", &["auto", "low", "medium", "high"])?;
    choice(
        p.background,
        "background",
        &["auto", "opaque", "transparent"],
    )?;
    choice(p.output_format, "output_format", &["png", "jpeg", "webp"])?;
    choice(p.moderation, "moderation", &["auto", "low"])?;
    choice(p.input_fidelity, "input_fidelity", &["low", "high"])?;
    if p.output_compression.is_some_and(|n| n > 100) {
        return Err(invalid("`output_compression` must be between 0 and 100"));
    }
    if p.output_compression.is_some() && !matches!(p.output_format, Some("jpeg" | "webp")) {
        return Err(invalid(
            "`output_compression` requires output_format jpeg or webp",
        ));
    }
    if let Some(size) = p.size.filter(|s| *s != "auto") {
        let valid = size.split_once('x').is_some_and(|(w, h)| {
            matches!((w.parse::<u32>(), h.parse::<u32>()), (Ok(w), Ok(h)) if w > 0 && h > 0)
        });
        if !valid {
            return Err(invalid("`size` must be auto or WIDTHxHEIGHT"));
        }
    }
    if p.stream == Some(true) || p.partial_images.is_some() {
        return Err(invalid(
            "streaming and partial_images are not supported by this image adapter",
        ));
    }
    if p.response_format.is_some() {
        return Err(invalid(
            "GPT image models return b64_json; response_format is not supported",
        ));
    }
    if edit {
        let images = p
            .images
            .as_ref()
            .filter(|i| !i.is_empty() && i.len() <= 16)
            .ok_or_else(|| invalid("edits require between 1 and 16 image uploads"))?;
        for image in images.iter().chain(p.mask.iter()) {
            if ![
                "data:image/png;base64,",
                "data:image/jpeg;base64,",
                "data:image/webp;base64,",
            ]
            .iter()
            .any(|prefix| {
                image
                    .image_url
                    .strip_prefix(prefix)
                    .is_some_and(|v| !v.is_empty())
            }) {
                return Err(invalid(
                    "images and mask must be inline PNG, JPEG, or WebP uploads",
                ));
            }
        }
        if p.mask
            .as_ref()
            .is_some_and(|m| !m.image_url.starts_with("data:image/png;base64,"))
        {
            return Err(invalid("mask must be a PNG upload"));
        }
    } else if p.images.is_some() || p.mask.is_some() || p.input_fidelity.is_some() {
        return Err(invalid(
            "images, mask, and input_fidelity require /v1/images/edits",
        ));
    }
    // Read the optional identifier without interpreting or storing it separately.
    let _ = p.user;
    let model_requested = p.model.to_owned();
    drop(p);
    let Value::Object(body) = body else {
        unreachable!("validated object")
    };
    Ok(ImagesRequest {
        model_requested,
        edit,
        body,
    })
}

impl ImagesRequest {
    pub fn render(self, upstream_model: &str) -> Value {
        let mut body = self.body;
        body.insert("model".into(), Value::String(upstream_model.to_owned()));
        Value::Object(body)
    }
}

/// Preserve provider metadata and account only for reported usage.
pub fn extract_images(mut record: InferenceRecord, response: &Value) -> InferenceRecord {
    record.model_served = response
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(usage) = response.get("usage") {
        record.usage = crate::response::responses_token_usage_from(usage);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generation_options_are_forwarded_and_alias_is_replaced() {
        let body = json!({"model":"alias", "prompt":"a blue square", "n":2,
            "size":"1024x1024", "quality":"low", "background":"opaque",
            "output_format":"jpeg", "output_compression":80, "moderation":"auto", "user":"example"});
        let request = parse_images(body.clone(), false).unwrap();
        let mut expected = body;
        expected["model"] = json!("gpt-image-2");
        assert_eq!(request.render("gpt-image-2"), expected);
    }

    #[test]
    fn rejects_invalid_and_unsupported_options_before_dispatch() {
        for (field, value) in [
            ("n", json!(0)),
            ("n", json!(11)),
            ("quality", json!("ultra")),
            ("stream", json!(true)),
            ("partial_images", json!(1)),
            ("response_format", json!("url")),
            ("unknown", json!(true)),
            ("output_compression", json!(101)),
            ("size", json!("large")),
            ("images", json!([])),
            ("input_fidelity", json!("high")),
        ] {
            let mut body = json!({"model":"gpt-image-2","prompt":"a square"});
            body[field] = value;
            assert!(parse_images(body.clone(), false).is_err(), "{field}");
        }
    }

    #[test]
    fn edit_images_and_mask_survive_without_remote_fetches() {
        let image = json!({"image_url":"data:image/png;base64,aGVsbG8="});
        let body = json!({"model":"image-alias", "prompt":"make it blue", "images":[image.clone(),image.clone()], "mask":image});
        let req = parse_images(body.clone(), true).unwrap();
        assert_eq!(req.render("image-alias"), body);
        let mut remote = body;
        remote["images"][0]["image_url"] = json!("https://example.test/image.png");
        assert!(parse_images(remote, true).is_err());
    }

    #[test]
    fn usage_is_reported_without_inventing_absent_counts() {
        let record = crate::InferenceRecord::new(
            crate::LlmProvider::OpenAi,
            "TEST",
            "image",
            crate::Surface::ImagesGenerations,
            crate::UpstreamProtocol::OpenAiResponses,
        );
        let missing = extract_images(record.clone(), &json!({}));
        assert_eq!(missing.usage.input, None);
        assert_eq!(missing.model_served, None);
        let reported = extract_images(
            record,
            &json!({"usage":{"input_tokens":4,"output_tokens":30}}),
        );
        assert_eq!(reported.usage.input, Some(4));
        assert_eq!(reported.usage.output, Some(30));
    }
}
