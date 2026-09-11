//! Serves static CIMD documents out of a filesystem directory under
//! `/cimd/dev-clients/<name>`.
//!
//! This is the "Client ID Metadata Document Service" pattern from
//! [draft-ietf-oauth-client-id-metadata-document-01 §6][draft], narrowed to
//! the local-dev case: an operator drops a CIMD JSON into
//! `GATEWAY_AS_CIMD_DEV_DOC_DIR` and the AS serves it from its own origin.
//! Because the fetch target is the AS itself, the SSRF guard in
//! [`crate::cimd::fetch_with_ssrf_guard`] sees the AS's own public hostname
//! (not a LAN gitea's private IP) and passes.
//!
//! Opt-in: the route is only mounted when the directory is configured.
//! Unset the env var and the route returns 404.
//!
//! [draft]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-01#section-6

use std::path::{Path, PathBuf};

use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::router::AsState;

/// 5 KiB ceiling matches [`crate::cimd::MAX_BODY`] — anything larger than
/// that won't round-trip through the SSRF-guarded fetcher anyway.
const MAX_DOC_BYTES: u64 = 5 * 1024;

/// `GET /cimd/dev-clients/{name}`.
///
/// Returns `application/json` when the file exists and passes filename
/// validation. 404 otherwise (including when the feature is disabled).
pub async fn handler(State(state): State<AsState>, AxumPath(name): AxumPath<String>) -> Response {
    let Some(dir) = state.config.cimd_dev_doc_dir.as_ref() else {
        return not_found();
    };
    if !is_safe_filename(&name) {
        tracing::debug!(name = %name, "rejecting CIMD dev doc request: unsafe filename");
        return not_found();
    }
    let path = dir.join(&name);

    match read_capped(&path, MAX_DOC_BYTES).await {
        Ok(body) => {
            let mut resp = body.into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            );
            // Short cache — the AS's CIMD fetcher has its own cache policy
            // downstream, and dev iteration wants fast turnaround.
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );
            resp
        }
        Err(ReadError::NotFound) => not_found(),
        Err(ReadError::TooLarge) => {
            tracing::warn!(path = %path.display(), limit = MAX_DOC_BYTES, "CIMD dev doc exceeds limit");
            (StatusCode::PAYLOAD_TOO_LARGE, "cimd doc exceeds size limit").into_response()
        }
        Err(ReadError::Io(e)) => {
            // Surface the underlying error in logs for operators, but return
            // 404 to the client so the feature can't be probed via distinct
            // status codes (permission errors, EACCES, etc.).
            tracing::warn!(path = %path.display(), error = %e, "failed to read CIMD dev doc");
            not_found()
        }
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// Safe means `[A-Za-z0-9._-]+` and ends in `.json`, and does not start
/// with `.`. That rules out path traversal (`..`), absolute paths (`/`),
/// empty strings, and dotfiles.
///
/// Shared with [`crate::cimd::CimdFetcher`]: the fetcher applies the same
/// rule when deciding whether a same-origin URL can be served from this
/// directory.
pub(crate) fn is_safe_filename(name: &str) -> bool {
    if name.is_empty() || name.starts_with('.') || !name.ends_with(".json") {
        return false;
    }
    name.chars().all(is_safe_char)
}

fn is_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

#[derive(Debug)]
enum ReadError {
    NotFound,
    TooLarge,
    Io(std::io::Error),
}

async fn read_capped(path: &Path, limit: u64) -> Result<Vec<u8>, ReadError> {
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReadError::NotFound),
        Err(e) => return Err(ReadError::Io(e)),
    };
    if !meta.is_file() {
        return Err(ReadError::NotFound);
    }
    if meta.len() > limit {
        return Err(ReadError::TooLarge);
    }
    tokio::fs::read(path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ReadError::NotFound,
        _ => ReadError::Io(e),
    })
}

/// Returns `Some(cimd_dev_doc_dir)` if the configured path exists and is a
/// directory, else `None`. Used at router-build time so a stale/missing
/// directory logs once at boot instead of silently 404-ing forever.
pub fn canonicalize_doc_dir(dir: &Path) -> Option<PathBuf> {
    match std::fs::canonicalize(dir) {
        Ok(p) if p.is_dir() => Some(p),
        Ok(p) => {
            tracing::warn!(path = %p.display(), "GATEWAY_AS_CIMD_DEV_DOC_DIR is not a directory; dev-host disabled");
            None
        }
        Err(e) => {
            tracing::warn!(path = %dir.display(), error = %e, "GATEWAY_AS_CIMD_DEV_DOC_DIR could not be resolved; dev-host disabled");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "gateway-as-cimd-devhost-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn read_capped_reads_small_file() {
        let dir = scratch_dir("small");
        let path = dir.join("hello.json");
        std::fs::write(&path, b"{\"ok\":true}").unwrap();
        let bytes = read_capped(&path, 1024).await.unwrap();
        assert_eq!(bytes, b"{\"ok\":true}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn read_capped_rejects_oversized_file() {
        let dir = scratch_dir("big");
        let path = dir.join("big.json");
        std::fs::write(&path, vec![b'a'; 100]).unwrap();
        let err = read_capped(&path, 32).await.unwrap_err();
        assert!(matches!(err, ReadError::TooLarge));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn read_capped_rejects_missing_file() {
        let dir = scratch_dir("missing");
        let err = read_capped(&dir.join("nope.json"), 1024).await.unwrap_err();
        assert!(matches!(err, ReadError::NotFound));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn read_capped_rejects_directory() {
        let dir = scratch_dir("dir");
        let err = read_capped(&dir, 1024).await.unwrap_err();
        assert!(matches!(err, ReadError::NotFound));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn safe_filenames_accepted() {
        assert!(is_safe_filename("mcp-test-client.json"));
        assert!(is_safe_filename("a.json"));
        assert!(is_safe_filename("client_1.2.3.json"));
        assert!(is_safe_filename("CLIENT.json"));
    }

    #[test]
    fn unsafe_filenames_rejected() {
        for bad in [
            "",
            ".",
            "..",
            "../etc.json",
            "/etc/passwd",
            "foo/bar.json",
            "foo\\bar.json",
            ".hidden.json",
            "no-extension",
            "mcp test client.json",
            "mcp\0.json",
            "mcp;rm.json",
            "mcp.json.bak",
        ] {
            assert!(!is_safe_filename(bad), "should reject `{bad}`");
        }
    }
}
