//! Where the helper keeps its key and the gateway address it trusts.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use url::{Origin, Url};

const CONFIG_FILE: &str = "config.json";
const KEY_FILE: &str = "key.pem";

/// Resolved locations under the user's configuration directory.
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn resolve(override_dir: Option<PathBuf>) -> Result<Self> {
        let root = match override_dir {
            Some(dir) => dir,
            None => dirs::config_dir()
                .context("no user configuration directory on this platform; pass --config-dir")?
                .join("mcp-files"),
        };
        Ok(Self { root })
    }

    pub fn key(&self) -> PathBuf {
        self.root.join(KEY_FILE)
    }

    pub fn config(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }
}

/// Create a directory owner-only where the platform lets us say so.
///
/// The signing key shares this directory, and it is the whole reason a relayed
/// grant handle stays unusable to anyone else — so a directory another local
/// account can read undoes the arrangement. `init` writes the configuration
/// before the key exists, which is why this lives here rather than beside the
/// key: whichever file lands first has to create the directory correctly.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    // The parents are made first and separately so that the last component can
    // be created on its own. A recursive create reports success for a directory
    // that was already there, so its result cannot say which of the two
    // happened — and testing beforehand only narrows the window rather than
    // closing it, since anything may appear between the test and the create.
    // Created alone, `AlreadyExists` is the operating system's own answer, and
    // the one thing that settles it.
    //
    // That matters on Windows, where the difference is between restricting a
    // directory this call made and rewriting the list on one the caller
    // arranged deliberately. An existing directory is left exactly as it is;
    // the key's own check is what refuses if that leaves it exposed.
    if let Some(parent) = dir.parent() {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut ancestors = std::fs::DirBuilder::new();
        ancestors.recursive(true);
        // Ancestors this call brings into being are made private too. They are
        // on the way to a directory holding a signing key, and nothing else has
        // asked for them; one that already exists is left alone, as it always
        // was.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            ancestors.mode(0o700);
        }
        ancestors.create(parent)?;
    }

    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        // Windows takes the restriction as a second step, since a directory is
        // created carrying whatever its parent hands down.
        Ok(()) => {
            #[cfg(windows)]
            crate::acl_windows::restrict_to_owner(dir)?;
            Ok(())
        }
        other => other,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// The gateway every transfer address must belong to.
    pub gateway: Url,
}

impl Config {
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(self).context("encode configuration")?;
        std::fs::write(path, body).with_context(|| format!("write {}", path.display()))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let body = match std::fs::read_to_string(path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!(
                    "no gateway recorded yet — run `mcp-files init --gateway <url>` first \
                     (expected {})",
                    path.display()
                )
            }
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        serde_json::from_str(&body).with_context(|| format!("parse {}", path.display()))
    }

    pub fn origin(&self) -> Origin {
        self.gateway.origin()
    }
}

/// Reject a gateway address that could not be a control plane, so the mistake
/// surfaces at `init` rather than as a confusing refusal on first transfer.
pub fn validate_gateway(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("gateway is not a URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("gateway URL must not carry userinfo");
    }
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!(
            "gateway must be https (http is accepted only for loopback during local development)"
        );
    }
    if url.host_str().is_none() {
        bail!("gateway URL has no host");
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_recorded_gateway() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::resolve(Some(dir.path().to_path_buf())).expect("paths");
        let config = Config {
            gateway: validate_gateway("https://gateway.example").expect("valid"),
        };

        config.save(&paths.config()).expect("save");
        let loaded = Config::load(&paths.config()).expect("load");

        assert_eq!(loaded.origin(), config.origin());
    }

    #[test]
    fn missing_configuration_names_the_command_that_fixes_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::resolve(Some(dir.path().to_path_buf())).expect("paths");

        let error = Config::load(&paths.config()).expect_err("nothing recorded yet");

        assert!(
            error.to_string().contains("mcp-files init"),
            "the error should name the fix: {error}"
        );
    }

    #[test]
    fn refuses_a_cleartext_remote_gateway() {
        validate_gateway("http://gateway.example").expect_err("remote http is refused");
    }

    #[test]
    fn allows_loopback_over_http_for_local_development() {
        validate_gateway("http://127.0.0.1:8080").expect("loopback http is allowed");
    }

    /// Every directory this call brings into being is private, not just the last
    /// one. A caller naming a `--config-dir` several levels deep would otherwise
    /// have the key's own directory locked down while the ones above it were
    /// left open — and those exist only because the key needed them.
    #[cfg(unix)]
    #[test]
    fn directories_created_on_the_way_are_private_too() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let deep = dir.path().join("one").join("two").join("mcp-files");

        create_private_dir(&deep).expect("create");

        for made in [
            deep.as_path(),
            &dir.path().join("one").join("two"),
            &dir.path().join("one"),
        ] {
            let mode = std::fs::metadata(made).expect("stat").permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "{} has mode {mode:o}, which is readable beyond its owner",
                made.display()
            );
        }
    }

    /// A directory that was already there belongs to whoever made it. This call
    /// creates what is missing; it does not restyle what it finds.
    #[cfg(unix)]
    #[test]
    fn an_existing_directory_is_left_as_it_was() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let existing = dir.path().join("shared");
        std::fs::create_dir(&existing).expect("create");
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        create_private_dir(&existing).expect("accepts a directory that is already there");

        let mode = std::fs::metadata(&existing)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "an existing directory was rewritten");
    }

    #[test]
    fn key_and_config_share_the_resolved_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::resolve(Some(dir.path().to_path_buf())).expect("paths");

        assert_eq!(paths.key().parent(), paths.config().parent());
    }
}
