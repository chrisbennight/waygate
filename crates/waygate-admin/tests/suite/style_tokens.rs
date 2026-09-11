//! Dashboard styles use shared color and font tokens.
//! Templates contain no inline styles, colors, or font declarations.

use std::fs;
use std::path::{Path, PathBuf};

/// CSS files allowed to contain color and font-family literals.
const TOKEN_FILES: &[&str] = &["tokens.css", "fonts.css"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// True when `content` contains a CSS hex color literal (`#fff`,
/// `#ffffffcc`, …). Deliberately narrow on both sides:
///
/// - `#` must be followed by exactly 3, 4, 6, or 8 hex digits and then a
///   non-identifier character, so fragment anchors (`#main`, `#keys-table`)
///   and SVG sprite refs (`#chevron-right`) don't false-positive;
/// - all-numeric candidates must sit in *value position* — the previous
///   non-space character is `:`, `(`, `,`, or a quote — so prose references
///   like "see issue #217" in template comments don't false-positive (217 is
///   all hex digits). Candidates with
///   an alphabetic hex digit (`#c53030`) are flagged anywhere, which also
///   catches keyword-preceded values like `solid #c53030`. Residual gap:
///   an all-numeric hex preceded by a keyword (`solid #303030`) — rare,
///   and the value-position form is the one that occurs in this codebase.
fn has_hex_color(content: &str) -> Option<String> {
    let bytes = content.as_bytes();
    let mut i = 0;
    while let Some(off) = content[i..].find('#') {
        let hash = i + off;
        let start = hash + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
            end += 1;
        }
        let digits = end - start;
        let boundary_ok = end >= bytes.len()
            || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] == b'-');
        let value_position = content[..hash]
            .trim_end_matches([' ', '\t'])
            .chars()
            .next_back()
            .is_some_and(|c| matches!(c, ':' | '(' | ',' | '"' | '\''));
        let has_alpha_digit = bytes[start..end].iter().any(u8::is_ascii_alphabetic);
        if matches!(digits, 3 | 4 | 6 | 8) && boundary_ok && (value_position || has_alpha_digit) {
            return Some(content[start - 1..end].to_owned());
        }
        i = start;
    }
    None
}

/// True when `content` declares a font face inline: a `font-family:` or
/// `font:` shorthand. (`var(--font-*)` usages don't trip this in
/// templates because templates aren't allowed `<style>`/`style=` font
/// declarations at all; in CSS we separately check for quoted names.)
fn has_font_decl(content: &str) -> bool {
    content.contains("font-family")
        || content
            .lines()
            .any(|l| l.contains("font:") && !l.trim_start().starts_with("//"))
}

/// A `font-family:`/`font:` declaration whose value names a family
/// literally — quoted (`"Fira Sans"`) or unquoted (`Arial, sans-serif`).
/// The only legal forms outside the token files
/// are values that route through `var(--font-…)` or plain `inherit`.
/// (`font-size:`/`font-weight:`/`font-variant-…` never match `font:` or
/// `font-family`, so they aren't inspected.)
fn css_literal_font_line(content: &str) -> Option<String> {
    content
        .lines()
        .find(|l| {
            if !(l.contains("font-family") || l.contains("font:")) {
                return false;
            }
            let routes_through_token = l.contains("var(--font-");
            // Value = text after the property name, up to the first `;` or
            // `}` — single-line rules (`code { font-family: inherit; }`)
            // carry a trailing brace that a naive split-on-colon keeps.
            let is_inherit = l
                .split_once("font-family:")
                .or_else(|| l.split_once("font:"))
                .map(|(_, v)| v)
                .is_some_and(|v| v.split([';', '}']).next().unwrap_or("").trim() == "inherit");
            !(routes_through_token || is_inherit)
        })
        .map(|l| l.trim().to_owned())
}

/// A color-function literal (`rgb(…)`, `hsl(…)`, `oklch(…)`, …) — these
/// bypass the theme exactly like hex literals do.
/// `color-mix(in oklab, var(--x) …, var(--y))` stays legal: it derives
/// from tokens and never matches because `oklab` there is not followed
/// by `(`. Named colors (`white`, `red`) can't be caught mechanically
/// without false positives (`white-space`) — reviewers own those.
fn color_fn_literal(content: &str) -> Option<String> {
    const FNS: &[&str] = &[
        "rgb(", "rgba(", "hsl(", "hsla(", "hwb(", "lab(", "lch(", "oklab(", "oklch(",
    ];
    let bytes = content.as_bytes();
    for f in FNS {
        let mut i = 0;
        while let Some(off) = content[i..].find(f) {
            let at = i + off;
            let prev_ok =
                at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'-');
            if prev_ok {
                let end = (at + f.len() + 24).min(content.len());
                return Some(content[at..end].trim_end().to_owned());
            }
            i = at + f.len();
        }
    }
    None
}

fn template_violation(content: &str) -> Option<String> {
    if content.contains("<style") {
        return Some("<style> block".into());
    }
    if let Some(h) = has_hex_color(content) {
        return Some(format!("hex color literal {h}"));
    }
    if let Some(c) = color_fn_literal(content) {
        return Some(format!("color-function literal `{c}…`"));
    }
    if has_font_decl(content) {
        return Some("inline font declaration".into());
    }
    None
}

fn list_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == ext))
        .collect();
    out.sort();
    out
}

#[test]
fn templates_have_no_inline_style_or_color_or_font_literals() {
    let dir = manifest_dir().join("templates");
    let mut failures = Vec::new();
    for path in list_files(&dir, "html") {
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let content = fs::read_to_string(&path).unwrap();
        if let Some(violation) = template_violation(&content) {
            failures.push(format!(
                "templates/{name}: {violation} — use tokens.css variables and shared classes"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn css_color_and_font_literals_live_only_in_token_files() {
    let dir = manifest_dir().join("static").join("css");
    let mut failures = Vec::new();
    for path in list_files(&dir, "css") {
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if TOKEN_FILES.contains(&name.as_str()) {
            continue;
        }
        let content = fs::read_to_string(&path).unwrap();
        if let Some(h) = has_hex_color(&content) {
            failures.push(format!(
                "static/css/{name}: hex color literal {h} — move it into tokens.css"
            ));
        }
        if let Some(c) = color_fn_literal(&content) {
            failures.push(format!(
                "static/css/{name}: color-function literal `{c}…` — move it \
                 into tokens.css or derive via color-mix from tokens"
            ));
        }
        if let Some(line) = css_literal_font_line(&content) {
            failures.push(format!(
                "static/css/{name}: literal font name in `{line}` — go through \
                 var(--font-ui) / var(--font-mono) / var(--font-display)"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn shipped_font_files_match_fonts_css() {
    // fonts.css promises four self-hosted woff2 files; a missing file is
    // exactly the silent-fallback failure this gate exists
    // to prevent, so assert the binaries are actually present and
    // non-trivial.
    let fonts = manifest_dir().join("static").join("fonts");
    for f in [
        "source-serif-4-latin.woff2",
        "source-serif-4-italic-latin.woff2",
        "source-sans-3-latin.woff2",
        "source-code-pro-latin.woff2",
    ] {
        let path = fonts.join(f);
        let meta = fs::metadata(&path)
            .unwrap_or_else(|e| panic!("missing shipped font {}: {e}", path.display()));
        assert!(
            meta.len() > 4096,
            "{} is suspiciously small ({} bytes) — truncated download?",
            path.display(),
            meta.len()
        );
    }
    let css = fs::read_to_string(manifest_dir().join("static/css/fonts.css")).unwrap();
    for f in [
        "source-serif-4-latin.woff2",
        "source-serif-4-italic-latin.woff2",
        "source-sans-3-latin.woff2",
        "source-code-pro-latin.woff2",
    ] {
        assert!(css.contains(f), "fonts.css does not reference {f}");
    }
}

/// The Night theme is declared twice in tokens.css — once under
/// `[data-theme="dark"]` (explicit toggle) and once under
/// `@media (prefers-color-scheme: dark)` (OS preference, no cookie). The
/// duplication invites exactly one failure mode: a token added to one block
/// but not the other, leaving OS-preference users with the Day value on a
/// Night surface (e.g. `--on-err` missing from the
/// media block would put white text on the light Night error red at ~3.1:1).
/// Assert the two blocks always define the identical set of custom
/// properties.
#[test]
fn both_dark_theme_blocks_define_identical_token_sets() {
    let css = fs::read_to_string(manifest_dir().join("static/css/tokens.css")).unwrap();

    fn block_after<'a>(css: &'a str, marker: &str) -> &'a str {
        let start = css
            .find(marker)
            .unwrap_or_else(|| panic!("missing {marker}"));
        let open = css[start..].find('{').unwrap() + start + 1;
        let close = css[open..].find('}').unwrap() + open;
        &css[open..close]
    }

    fn custom_props(block: &str) -> Vec<String> {
        let mut props: Vec<String> = block
            .lines()
            .filter_map(|l| {
                let l = l.trim_start();
                l.starts_with("--")
                    .then(|| l.split(':').next().unwrap().trim().to_owned())
            })
            .collect();
        props.sort();
        props
    }

    // Anchor the toggled-theme marker to the selector at line start — the
    // file's header comment also mentions `[data-theme="dark"]`, and a bare
    // find() would land there and capture the `:root` Day block instead.
    // The media block nests `:root:not(...)` inside `@media { ... }`, so key
    // off the inner selector; both markers are unique in selector position.
    let toggled = custom_props(block_after(&css, "\n[data-theme=\"dark\"] {"));
    let os_pref = custom_props(block_after(&css, ":root:not([data-theme=\"light\"])"));
    assert_eq!(
        toggled, os_pref,
        "the [data-theme=dark] and prefers-color-scheme dark blocks have \
         drifted — every token must be set in both"
    );
}
