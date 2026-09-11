use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;

/// Ceiling on one staged file when the operator sets no explicit limit.
///
/// The cap used to default to "none", so a deployment that never set
/// `GATEWAY_FILE_MAX_BYTES` had no bound at all: an upstream declaring a file
/// with no `size` could stream into the storage root until the disk filled, and
/// the transfer-concurrency semaphore bounds simultaneous streams rather than
/// bytes, so one call sufficed. A protection that is off unless opted into is
/// not a protection.
///
/// 1 GiB is far above the documents, images, and archives tool calls actually
/// move, and is a bound rather than a tuned fit — the point is that a single
/// call can no longer consume the volume. Deployments that genuinely move
/// larger files raise `GATEWAY_FILE_MAX_BYTES`; there is deliberately no
/// "unlimited" setting, because that is the state this default exists to end.
pub(crate) const DEFAULT_FILE_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Retention windows for stored files. Which window a file gets is decided per
/// file from its declared sensitivity when it is staged.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FileRetention {
    /// Ordinary files live this long.
    pub(crate) general: Duration,
    /// Files an authorization marked secret-class: their delivery copy should
    /// live about as long as the handoff, not the general window.
    pub(crate) secret: Duration,
}

impl FileRetention {
    /// The documented env-var defaults: 24 hours general, 5 minutes secret.
    pub(crate) const DEFAULT: Self = Self {
        general: Duration::from_secs(24 * 3600),
        secret: Duration::from_secs(300),
    };
}

#[derive(Debug)]
pub(crate) struct FileTransferConfig {
    pub(crate) storage_dir: Option<PathBuf>,
    pub(crate) retention: FileRetention,
    pub(crate) max_bytes: Option<u64>,
    pub(crate) concurrency: usize,
}

impl FileTransferConfig {
    pub(crate) fn from_env(database_configured: bool) -> anyhow::Result<Self> {
        let storage_dir = waygate_core::env::optional("GATEWAY_FILE_STORAGE_DIR");
        let retention = waygate_core::env::duration_secs(
            "GATEWAY_FILE_RETENTION_SECONDS",
            FileRetention::DEFAULT.general.as_secs(),
            60..=30 * 24 * 3600,
            "pick 60 seconds through 30 days",
        )?;
        let secret_retention = waygate_core::env::duration_secs(
            "GATEWAY_FILE_SECRET_RETENTION_SECONDS",
            FileRetention::DEFAULT.secret.as_secs(),
            30..=3600,
            "pick 30 seconds through 1 hour",
        )?;
        let max_bytes = waygate_core::env::optional("GATEWAY_FILE_MAX_BYTES");
        let concurrency = waygate_core::env::u64_in(
            "GATEWAY_FILE_TRANSFER_CONCURRENCY",
            8,
            1..=1024,
            "pick 1 through 1024",
        )?;
        Self::from_values(
            database_configured,
            storage_dir,
            FileRetention {
                general: retention,
                secret: secret_retention,
            },
            max_bytes,
            concurrency,
        )
    }

    fn from_values(
        database_configured: bool,
        storage_dir: Option<String>,
        retention: FileRetention,
        max_bytes: Option<String>,
        concurrency: u64,
    ) -> anyhow::Result<Self> {
        let storage_dir = storage_dir.map(PathBuf::from);
        if storage_dir.is_some() && !database_configured {
            anyhow::bail!("GATEWAY_FILE_STORAGE_DIR requires GATEWAY_DATABASE_URL");
        }
        let max_bytes = max_bytes
            .map(|value| {
                value
                    .parse::<u64>()
                    .context("GATEWAY_FILE_MAX_BYTES must be a positive integer")
                    .and_then(|value| {
                        if value == 0 || value > i64::MAX as u64 {
                            anyhow::bail!("GATEWAY_FILE_MAX_BYTES must be between 1 and i64::MAX");
                        }
                        Ok(value)
                    })
            })
            .transpose()?
            // Unset means the default ceiling, not "no ceiling".
            .or(Some(DEFAULT_FILE_MAX_BYTES));
        let concurrency = usize::try_from(concurrency)
            .context("GATEWAY_FILE_TRANSFER_CONCURRENCY is not representable")?;
        // The secret hint may only shorten a file's life. A secret window above
        // the general one would invert the policy, so it is clamped rather than
        // rejected: a deployment with a short general retention and the secret
        // setting unset stays valid and simply keeps the tighter window.
        let retention = FileRetention {
            general: retention.general,
            secret: retention.secret.min(retention.general),
        };
        Ok(Self {
            storage_dir,
            retention,
            max_bytes,
            concurrency,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is a CEILING, not "no ceiling". Previously an operator who
    /// never set `GATEWAY_FILE_MAX_BYTES` — the common case — got no bound at
    /// all, so an upstream declaring a file with no `size` could stream until
    /// the volume filled.
    #[test]
    fn defaults_bound_the_file_size() {
        let defaults =
            FileTransferConfig::from_values(false, None, FileRetention::DEFAULT, None, 8)
                .expect("default file settings");
        assert!(defaults.storage_dir.is_none());
        assert_eq!(defaults.retention.general, Duration::from_secs(24 * 3600));
        assert_eq!(defaults.retention.secret, Duration::from_secs(300));
        assert_eq!(defaults.max_bytes, Some(DEFAULT_FILE_MAX_BYTES));
        assert_eq!(defaults.concurrency, 8);

        let error = FileTransferConfig::from_values(
            false,
            Some("/var/lib/mcp-gateway/files".to_owned()),
            FileRetention::DEFAULT,
            None,
            8,
        )
        .expect_err("file storage needs a database")
        .to_string();
        assert!(error.contains("requires GATEWAY_DATABASE_URL"));

        let configured = FileTransferConfig::from_values(
            true,
            Some("/var/lib/mcp-gateway/files".to_owned()),
            FileRetention {
                general: Duration::from_secs(3600),
                secret: Duration::from_secs(300),
            },
            Some("1099511627776".to_owned()),
            17,
        )
        .expect("configured file settings");
        assert_eq!(
            configured.storage_dir.as_deref(),
            Some(std::path::Path::new("/var/lib/mcp-gateway/files"))
        );
        assert_eq!(configured.retention.general, Duration::from_secs(3600));

        let inverted = FileTransferConfig::from_values(
            false,
            None,
            FileRetention {
                general: Duration::from_secs(60),
                secret: Duration::from_secs(300),
            },
            None,
            8,
        )
        .expect("short general retention");
        assert_eq!(
            inverted.retention.secret,
            Duration::from_secs(60),
            "the secret window is clamped to the general one, never longer"
        );
        assert_eq!(configured.max_bytes, Some(1_099_511_627_776));
        assert_eq!(configured.concurrency, 17);
    }
}
