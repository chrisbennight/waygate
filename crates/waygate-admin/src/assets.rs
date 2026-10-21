//! Immutable snapshots of the configured public dashboard assets. Legacy file
//! serving remains available when a snapshot cannot be loaded and when an old
//! page requests a version no longer present on this process.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path as RequestPath, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use sha2::{Digest, Sha256};

const MAX_BYTES: usize = 16 * 1024 * 1024;
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const PATHS: &[&str] = include!(concat!(env!("OUT_DIR"), "/dashboard-assets.rs"));

#[derive(Default)]
pub(crate) struct Assets {
    version: String,
    files: BTreeMap<String, Asset>,
}

struct Asset {
    body: Bytes,
    content_type: &'static str,
    etag: HeaderValue,
}

pub(crate) fn static_dir() -> PathBuf {
    std::env::var_os("GATEWAY_STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"))
}

impl Assets {
    /// Snapshot failures disable only immutable caching. The ordinary static
    /// service keeps its existing behavior, without blocking gateway startup.
    pub(crate) fn load(directory: &Path) -> Self {
        match Self::try_load(directory) {
            Ok(assets) => assets,
            Err(error) => {
                tracing::warn!(error_kind = ?error.kind(), "immutable dashboard asset caching unavailable");
                Self::default()
            }
        }
    }

    fn try_load(directory: &Path) -> io::Result<Self> {
        let mut originals = BTreeMap::new();
        let mut total = 0;
        let root = directory.canonicalize()?;
        for relative in PATHS {
            let path = root.join(relative).canonicalize()?;
            if !path.starts_with(&root) || !path.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "asset outside public files",
                ));
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take((MAX_BYTES - total + 1) as u64)
                .read_to_end(&mut bytes)?;
            total += bytes.len();
            if total > MAX_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "asset snapshot limit exceeded",
                ));
            }
            originals.insert((*relative).to_owned(), bytes);
        }
        let mut digest = Sha256::new();
        // This identity covers both the source bundle and its CSS URL format.
        digest.update(b"waygate-dashboard-assets-v1\0");
        for (path, bytes) in &originals {
            digest.update((path.len() as u64).to_be_bytes());
            digest.update(path.as_bytes());
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
        let version = encode_hex(&digest.finalize());
        let prefix = format!("/admin/static/v/{version}/");
        let known_paths: BTreeSet<_> = originals.keys().cloned().collect();
        let mut files = BTreeMap::new();
        for (path, bytes) in originals {
            let body = if path.ends_with(".css") {
                let css = String::from_utf8(bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 stylesheet")
                })?;
                rewrite_css(&css, &prefix, &known_paths).into_bytes()
            } else {
                bytes
            };
            let etag =
                HeaderValue::from_str(&format!("W/\"{}\"", encode_hex(&Sha256::digest(&body))))
                    .expect("a hexadecimal digest is a valid entity tag");
            files.insert(
                path.clone(),
                Asset {
                    content_type: content_type(&path),
                    body: Bytes::from(body),
                    etag,
                },
            );
        }
        Ok(Self { version, files })
    }

    pub(crate) fn url(&self, path: &str) -> String {
        let Some(relative) = path.strip_prefix("/admin/static/") else {
            return path.to_owned();
        };
        let file = relative.split(['#', '?']).next().unwrap_or(relative);
        if self.files.contains_key(file) {
            format!("/admin/static/v/{}/{relative}", self.version)
        } else {
            path.to_owned()
        }
    }

    pub(crate) fn router(self: Arc<Self>) -> Router<()> {
        Router::new()
            .route("/v/{version}/{*path}", get(serve))
            .with_state(self)
    }
}

async fn serve(
    State(assets): State<Arc<Assets>>,
    RequestPath((version, path)): RequestPath<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let asset = assets.files.get(&path);
    if version != assets.version || asset.is_none() {
        // Old pages and relative custom CSS dependencies can reference files
        // absent from this snapshot. Keep their public static URL available
        // without caching different bytes under an immutable identity.
        if path.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || part.contains('\\')
                || part.chars().any(char::is_control)
        }) {
            return StatusCode::NOT_FOUND.into_response();
        }
        let mut location = url::Url::parse("http://localhost/").expect("fixed base URL");
        location
            .path_segments_mut()
            .expect("fixed hierarchical URL")
            .clear()
            .extend(["admin", "static"])
            .extend(path.split('/'));
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [
                (header::LOCATION, location.path()),
                (header::CACHE_CONTROL, "no-store"),
            ],
        )
            .into_response();
    }
    let asset = asset.expect("the current snapshot contains this asset");
    let current_tag = asset
        .etag
        .to_str()
        .expect("ASCII entity tag")
        .trim_start_matches("W/");
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || candidate.trim_start_matches("W/") == current_tag
            })
        });
    let mut response = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        Body::from(asset.body.clone()).into_response()
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(IMMUTABLE));
    response
        .headers_mut()
        .insert(header::ETAG, asset.etag.clone());
    response
}

fn rewrite_css(css: &str, prefix: &str, known_paths: &BTreeSet<String>) -> String {
    let mut parts = css.split("/admin/static/");
    let mut rewritten = parts.next().unwrap_or_default().to_owned();
    for suffix in parts {
        let path = suffix
            .split(['"', '\'', ')', '?', '#', ' ', '\t', '\r', '\n'])
            .next()
            .unwrap_or_default();
        // Operator-supplied files outside the shipped inventory continue to
        // resolve through the ordinary static service.
        rewritten.push_str(if known_paths.contains(path) {
            prefix
        } else {
            "/admin/static/"
        });
        rewritten.push_str(suffix);
    }
    rewritten
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("png") => "image/png",
        Some("json" | "map") => "application/json",
        Some("md" | "txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_snapshots_and_relative_custom_dependencies_use_legacy_urls() {
        let assets = Arc::new(Assets::default());
        let stylesheet =
            url::Url::parse("https://example.test/admin/static/v/old/css/fonts.css").unwrap();
        let font = stylesheet.join("../fonts/custom.woff2").unwrap();
        for (path, expected) in [
            ("css/base.css", "/admin/static/css/base.css"),
            (
                font.path().strip_prefix("/admin/static/v/old/").unwrap(),
                "/admin/static/fonts/custom.woff2",
            ),
        ] {
            let response = serve(
                State(assets.clone()),
                RequestPath(("old".into(), path.into())),
                HeaderMap::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
            assert_eq!(response.headers()[header::LOCATION], expected);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        for path in [
            "../private",
            "fonts/../../private",
            "fonts\\private",
            "//other.example/asset",
        ] {
            let response = serve(
                State(assets.clone()),
                RequestPath(("old".into(), path.into())),
                HeaderMap::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        let response = serve(
            State(assets),
            RequestPath(("old".into(), "fonts/%2e%2e/private".into())),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(
            response.headers()[header::LOCATION],
            "/admin/static/fonts/%252e%252e/private"
        );
    }

    #[test]
    fn bundle_identity_tracks_override_bytes_and_retains_snapshot() {
        let directory =
            std::env::temp_dir().join(format!("dashboard-assets-{}", uuid::Uuid::now_v7()));
        for path in PATHS {
            let file = directory.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, b"original").unwrap();
        }
        let css = "url(\"/admin/static/fonts/outfit.ttf\") url('/admin/static/fonts/custom.woff2')";
        std::fs::write(directory.join("css/base.css"), css).unwrap();
        let original = Assets::try_load(&directory).unwrap();
        let unchanged = Assets::try_load(&directory).unwrap();
        assert_eq!(original.version, unchanged.version);
        let relative = "css/base.css";
        std::fs::write(directory.join(relative), b"changed").unwrap();
        let changed = Assets::try_load(&directory).unwrap();
        assert_ne!(original.version, changed.version);
        let original_css = std::str::from_utf8(&original.files[relative].body).unwrap();
        assert!(original_css.contains(&format!(
            "/admin/static/v/{}/fonts/outfit.ttf",
            original.version
        )));
        assert!(original_css.contains("/admin/static/fonts/custom.woff2"));
        assert_eq!(changed.files[relative].body.as_ref(), b"changed");
        assert_ne!(original.files[relative].etag, changed.files[relative].etag);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
