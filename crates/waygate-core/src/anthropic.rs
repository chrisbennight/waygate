//! Provider-native Messages metadata. Header values stay inside the runtime.

/// Anthropic's open-ended request negotiation headers. Gateway credentials and
/// general HTTP headers cannot enter this set.
#[derive(Clone, Default)]
pub struct RequestHeaders(http::HeaderMap);

impl RequestHeaders {
    pub fn from_headers(headers: &http::HeaderMap) -> Self {
        let mut selected = http::HeaderMap::new();
        for (name, value) in headers {
            if name.as_str().starts_with("anthropic-") {
                selected.append(name.clone(), value.clone());
            }
        }
        Self(selected)
    }

    pub fn as_header_map(&self) -> &http::HeaderMap {
        &self.0
    }
}

impl std::fmt::Debug for RequestHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

/// Status and client-relevant provider response headers. Cookies, credentials,
/// routing headers, and connection-specific framing are never relayed.
#[derive(Clone)]
pub struct ResponseMetadata {
    pub status: http::StatusCode,
    headers: http::HeaderMap,
}

impl ResponseMetadata {
    pub fn from_headers(status: http::StatusCode, headers: &http::HeaderMap) -> Self {
        let mut selected = http::HeaderMap::new();
        for (name, value) in headers {
            if name.as_str().starts_with("anthropic-ratelimit-")
                || matches!(
                    name.as_str(),
                    "content-type" | "request-id" | "retry-after" | "x-should-retry"
                )
            {
                selected.append(name.clone(), value.clone());
            }
        }
        Self {
            status,
            headers: selected,
        }
    }

    pub fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }
}

impl std::fmt::Debug for ResponseMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseMetadata")
            .field("status", &self.status)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .finish()
    }
}
