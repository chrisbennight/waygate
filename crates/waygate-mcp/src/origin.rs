//! Browser-origin checks for incoming MCP HTTP requests.

use http::{header::ORIGIN, HeaderMap};
use url::{Origin, Url};

#[derive(Clone, Debug)]
pub struct OriginPolicy {
    allowed: Vec<Origin>,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "MCP allowed origins must be HTTP(S) origins without credentials, paths, queries, or fragments"
)]
pub struct InvalidOrigin;

impl OriginPolicy {
    /// Default to the public URL's origin. An explicit empty list permits
    /// only clients that omit Origin; it never disables validation.
    pub fn from_config(
        public_url: &str,
        override_list: Option<&str>,
    ) -> Result<Self, InvalidOrigin> {
        let allowed = match override_list {
            Some(raw) if raw.trim().is_empty() => Vec::new(),
            Some(raw) => raw
                .split(',')
                .map(|s| parse_origin(s.trim()))
                .collect::<Result<_, _>>()?,
            None => {
                let public = Url::parse(public_url).map_err(|_| InvalidOrigin)?;
                vec![parse_origin(&public.origin().ascii_serialization())?]
            }
        };
        Ok(Self { allowed })
    }

    /// An absent header is valid for non-browser clients. Multiple, opaque,
    /// malformed, and unlisted origins are refused, regardless of Host/auth.
    pub fn allows(&self, headers: &HeaderMap) -> bool {
        let mut origins = headers.get_all(ORIGIN).iter();
        let Some(raw) = origins.next() else {
            return true;
        };
        if origins.next().is_some() {
            return false;
        }
        raw.to_str()
            .ok()
            .and_then(|raw| parse_origin(raw).ok())
            .is_some_and(|origin| self.allowed.contains(&origin))
    }
}

fn parse_origin(raw: &str) -> Result<Origin, InvalidOrigin> {
    let (scheme, authority) = raw.split_once("://").ok_or(InvalidOrigin)?;
    if !raw.is_ascii()
        || (!scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https"))
        || authority.is_empty()
        || authority.ends_with(':')
        || authority
            .chars()
            .any(|c| c.is_ascii_whitespace() || "/?#@\\%".contains(c))
    {
        return Err(InvalidOrigin);
    }
    // Validate authority syntax before URL normalization. Origin equality
    // then compares scheme, normalized host, and effective port exactly.
    authority
        .parse::<http::uri::Authority>()
        .map_err(|_| InvalidOrigin)?;
    match Url::parse(raw).map_err(|_| InvalidOrigin)?.origin() {
        origin @ Origin::Tuple(..) => Ok(origin),
        Origin::Opaque(_) => Err(InvalidOrigin),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn defaults_to_public_origin_with_exact_scheme_and_effective_port() {
        let policy = OriginPolicy::from_config("https://gateway.example/mcp", None).unwrap();
        assert!(policy.allows(&HeaderMap::new()));
        for (origin, allowed) in [
            ("https://gateway.example", true),
            ("https://GATEWAY.example:443", true),
            ("http://gateway.example", false),
            ("https://gateway.example:8443", false),
            ("https://evil.example", false),
            ("https://gateway.example.evil.example", false),
            ("null", false),
            ("https://gateway.example/", false),
            ("https://gateway.example/path", false),
            ("https://gateway.example?query", false),
            ("https://gateway.example#fragment", false),
            ("https://user@gateway.example", false),
            ("https://gateway.example:", false),
            ("https://gateway.example https://evil.example", false),
            (" https://gateway.example", false),
            ("https://gateway.example ", false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
            assert_eq!(policy.allows(&headers), allowed, "{origin}");
        }
    }

    #[test]
    fn explicit_list_replaces_default_and_empty_list_denies_all_present_origins() {
        let policy = OriginPolicy::from_config(
            "https://gateway.example",
            Some("http://localhost:3000, https://[::1]:8443"),
        )
        .unwrap();
        for origin in ["http://localhost:3000", "https://[::1]:8443"] {
            let mut headers = HeaderMap::new();
            headers.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
            assert!(policy.allows(&headers));
            assert!(
                !OriginPolicy::from_config("https://gateway.example", Some(""))
                    .unwrap()
                    .allows(&headers)
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://gateway.example"));
        assert!(!policy.allows(&headers));
        assert!(
            OriginPolicy::from_config("https://gateway.example", Some(""))
                .unwrap()
                .allows(&HeaderMap::new())
        );
        for configured in [
            "null",
            "*",
            "https://valid.example,",
            "https://valid.example/path",
        ] {
            assert!(
                OriginPolicy::from_config("https://gateway.example", Some(configured)).is_err()
            );
        }
    }

    #[test]
    fn duplicate_and_non_text_headers_are_refused() {
        let policy = OriginPolicy::from_config("https://gateway.example", None).unwrap();
        let mut headers = HeaderMap::new();
        headers.append(ORIGIN, HeaderValue::from_static("https://gateway.example"));
        headers.append(ORIGIN, HeaderValue::from_static("https://gateway.example"));
        assert!(!policy.allows(&headers));
        headers.insert(ORIGIN, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(!policy.allows(&headers));
    }
}
