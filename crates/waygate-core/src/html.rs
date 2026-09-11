//! The one HTML escaper for hand-built HTML strings.
//!
//! Before this module, five hand-rolled escapers existed across
//! `waygate-admin` and `waygate-as` with three different character sets —
//! one escaped only `< > &`, which is unsafe the moment a caller uses it
//! in an attribute context. Every surface that builds HTML by string
//! formatting (error pages, htmx fragments, the consent screen) must use
//! [`escape`]; CI fails on any new local `fn html_escape` / `fn
//! escape_html` definition (`scripts/check-no-local-escapers.sh`).
//!
//! Askama templates auto-escape their own interpolations — this is only
//! for HTML assembled outside the template engine.
//!
//! Contract: escapes exactly the five characters that can break out of an
//! element or (single- or double-quoted) attribute context — `&` `<` `>`
//! `"` `'` — matching OWASP's minimal entity set. Not a general-purpose
//! sanitizer: callers must still place untrusted input only in element
//! bodies or quoted attribute values, never in unquoted attributes, URLs,
//! `<script>` bodies, or event handlers.

/// Escape `& < > " '` for safe interpolation into element bodies and
/// quoted attribute values.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::escape;

    #[test]
    fn escapes_all_five_meta_chars() {
        assert_eq!(escape("&"), "&amp;");
        assert_eq!(escape("<"), "&lt;");
        assert_eq!(escape(">"), "&gt;");
        assert_eq!(escape("\""), "&quot;");
        assert_eq!(escape("'"), "&#x27;");
    }

    #[test]
    fn passes_benign_text_through_unchanged() {
        assert_eq!(escape("plain text 123 äöü"), "plain text 123 äöü");
        assert_eq!(escape(""), "");
    }

    #[test]
    fn neutralizes_element_context_payload() {
        assert_eq!(
            escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;",
        );
    }

    #[test]
    fn neutralizes_attribute_context_payload() {
        // Breaking out of a double-quoted attribute needs `"`; out of a
        // single-quoted one needs `'`. Both must be neutralized — this is
        // the case the weakest pre-consolidation escaper missed.
        assert_eq!(
            escape("\" onmouseover=\"alert(1)"),
            "&quot; onmouseover=&quot;alert(1)",
        );
        assert_eq!(escape("' onclick='x"), "&#x27; onclick=&#x27;x");
    }

    #[test]
    fn ampersand_escapes_first_no_double_escaping() {
        assert_eq!(escape("&lt;"), "&amp;lt;");
        assert_eq!(
            escape("</script>\"<img src=x onerror=alert(1)>"),
            "&lt;/script&gt;&quot;&lt;img src=x onerror=alert(1)&gt;",
        );
    }
}
