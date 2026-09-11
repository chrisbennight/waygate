//! On-disk token cache. XDG config dir (`~/.config/mcp-test-client/tokens.json`),
//! 0600 permissions on Unix.
//!
//! Keyed by `gateway_base` URL so an operator running against two gateways
//! (dev + prod, say) doesn't clobber one login with the other.

use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::cli::Context;

const CACHE_FILENAME: &str = "tokens.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Wall-clock deadline for the access token, not the refresh token.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub token_type: String,
    #[serde(default)]
    pub scope: Option<String>,
    /// Issuer recorded at mint time so we can warn on unexpected rotation
    /// (e.g. the gateway reconfigured itself to point at a new IdP).
    #[serde(default)]
    pub issuer: Option<String>,
    /// CIMD `client_id` used to obtain this token — needed on refresh.
    #[serde(default)]
    pub client_id: Option<String>,
    /// AS token endpoint — cached so refresh doesn't need to re-run
    /// discovery when the network is flaky.
    #[serde(default)]
    pub token_endpoint: Option<String>,
}

impl Token {
    pub fn is_expired(&self, skew_secs: i64) -> bool {
        OffsetDateTime::now_utc() + time::Duration::seconds(skew_secs) >= self.expires_at
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    tokens: HashMap<String, Token>,
}

fn cache_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("locate XDG config dir (~/.config)")?;
    Ok(base.join("mcp-test-client"))
}

fn cache_path() -> Result<PathBuf> {
    Ok(cache_dir()?.join(CACHE_FILENAME))
}

fn load_file() -> Result<CacheFile> {
    let path = cache_path()?;
    match fs::read(&path) {
        Ok(bytes) if bytes.is_empty() => Ok(CacheFile::default()),
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parse token cache {}", path.display())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(CacheFile::default()),
        Err(e) => Err(e).with_context(|| format!("read token cache {}", path.display())),
    }
}

/// Write the cache file atomically (write-tmp + rename) with `0600` perms
/// on Unix. Atomic-rename keeps a crash mid-write from corrupting the
/// token store — important because every login replaces the whole file.
fn save_file(cache: &CacheFile) -> Result<()> {
    let dir = cache_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let path = cache_path()?;
    let tmp = path.with_extension("json.tmp");

    let bytes = serde_json::to_vec_pretty(cache).context("serialize token cache")?;
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        #[cfg(unix)]
        {
            let mut perms = f.metadata()?.permissions();
            perms.set_mode(0o600);
            f.set_permissions(perms)?;
        }
        f.write_all(&bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Normalise the gateway URL used as the cache key. Strips a trailing slash
/// and lowercases the host so `https://Mcp.example.org/` and
/// `https://mcp.example.org` resolve to the same entry.
fn key_for(ctx: &Context) -> String {
    let mut s = ctx.gateway_base.to_string();
    if let Some(stripped) = s.strip_suffix('/') {
        s = stripped.to_owned();
    }
    s.to_lowercase()
}

pub fn load(ctx: &Context) -> Result<Option<Token>> {
    let file = load_file()?;
    Ok(file.tokens.get(&key_for(ctx)).cloned())
}

pub fn store(ctx: &Context, token: &Token) -> Result<()> {
    let mut file = load_file()?;
    file.tokens.insert(key_for(ctx), token.clone());
    save_file(&file)
}

pub fn delete(ctx: &Context) -> Result<bool> {
    let mut file = load_file()?;
    let removed = file.tokens.remove(&key_for(ctx)).is_some();
    if removed {
        save_file(&file)?;
    }
    Ok(removed)
}

/// `logout` subcommand entry point.
pub async fn logout(ctx: &Context) -> Result<()> {
    if delete(ctx)? {
        eprintln!("logged out of {}", ctx.gateway_base);
    } else {
        eprintln!("no cached token for {}", ctx.gateway_base);
    }
    Ok(())
}
