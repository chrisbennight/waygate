//! Preserve actionable embedding backend statuses without exposing provider bodies.
use super::*;

pub(super) fn response(error: &InvocationError) -> Option<Response> {
    let InvocationError::Upstream(error) = error else {
        return None;
    };
    let data = error.data.as_ref()?;
    let code = data.get("embedding_http_status")?.as_u64()?;
    let (status, kind) = match code {
        429 => (StatusCode::TOO_MANY_REQUESTS, "rate_limit_error"),
        503 => (StatusCode::SERVICE_UNAVAILABLE, "upstream_unavailable"),
        504 => (StatusCode::GATEWAY_TIMEOUT, "timeout_error"),
        400..=499 if !matches!(code, 401 | 403) => (
            StatusCode::from_u16(code as u16).expect("valid client status"),
            "invalid_request_error",
        ),
        _ => (StatusCode::BAD_GATEWAY, "upstream_error"),
    };
    let mut response = error_response(status, kind, &error.message);
    if matches!(code, 429 | 503) {
        if let Some(seconds) = data.get("retry_after_seconds").and_then(Value::as_u64) {
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                seconds
                    .min(300)
                    .to_string()
                    .parse()
                    .expect("numeric header"),
            );
        }
    }
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_actionable_status_and_retry_advice() {
        for (upstream, expected) in [
            (400, 400),
            (413, 413),
            (422, 422),
            (429, 429),
            (503, 503),
            (504, 504),
            (401, 502),
            (403, 502),
            (500, 502),
        ] {
            let error = InvocationError::Upstream(rmcp::ErrorData::internal_error(
                "embedding backend request failed",
                Some(json!({"embedding_http_status":upstream,"retry_after_seconds":1})),
            ));
            let response = response(&error).unwrap();
            assert_eq!(response.status().as_u16(), expected);
            assert_eq!(
                response.headers().get("retry-after").is_some(),
                matches!(upstream, 429 | 503)
            );
        }
    }
}
