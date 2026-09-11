use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeModeCapacityLimits {
    pub(crate) global: usize,
    pub(crate) per_tenant: usize,
    pub(crate) detached: usize,
}

impl Default for CodeModeCapacityLimits {
    fn default() -> Self {
        let limits = crate::codemode_limits::CodeModeLimits::default();
        let global = limits.execution_memory_bytes / limits.runner_peak_bytes;
        Self {
            global,
            per_tenant: global.div_ceil(4).max(1),
            detached: (global / 2).max(1),
        }
    }
}

impl CodeModeCapacityLimits {
    #[cfg(test)]
    pub(super) fn from_env() -> Result<Self> {
        Self::from_limits(&crate::codemode_limits::CodeModeLimits::default())
    }

    pub(super) fn from_limits(limits: &crate::codemode_limits::CodeModeLimits) -> Result<Self> {
        let max = u64::try_from(tokio::sync::Semaphore::MAX_PERMITS).unwrap_or(u64::MAX);
        let read = |name, default| -> Result<usize> {
            let value = waygate_core::env::u64_in(
                name,
                default,
                1..=max,
                "Code Mode concurrency limits must be positive",
            )?;
            usize::try_from(value).map_err(|_| anyhow::anyhow!("{name} does not fit this platform"))
        };
        let global = read(
            "GATEWAY_CODEMODE_MAX_CONCURRENT_EXECUTIONS",
            (limits.execution_memory_bytes / limits.runner_peak_bytes) as u64,
        )?;
        Self {
            global,
            per_tenant: read(
                "GATEWAY_CODEMODE_MAX_CONCURRENT_EXECUTIONS_PER_TENANT",
                global.div_ceil(4).max(1) as u64,
            )?,
            detached: read(
                "GATEWAY_CODEMODE_MAX_CONCURRENT_DETACHED_EXECUTIONS",
                (global / 2).max(1) as u64,
            )?,
        }
        .validate()
    }

    pub(crate) fn validate(self) -> Result<Self> {
        if self.per_tenant > self.global {
            anyhow::bail!(
                "GATEWAY_CODEMODE_MAX_CONCURRENT_EXECUTIONS_PER_TENANT must not exceed \
                 GATEWAY_CODEMODE_MAX_CONCURRENT_EXECUTIONS"
            );
        }
        if self.detached > self.global {
            anyhow::bail!(
                "GATEWAY_CODEMODE_MAX_CONCURRENT_DETACHED_EXECUTIONS cannot exceed \
                 GATEWAY_CODEMODE_MAX_CONCURRENT_EXECUTIONS"
            );
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeModeResultStorage {
    Disabled,
    Allow,
}

impl CodeModeResultStorage {
    pub(super) fn parse(raw: Option<&str>) -> Result<Self> {
        match raw {
            None | Some("disabled") => Ok(Self::Disabled),
            Some("allow") => Ok(Self::Allow),
            Some(other) => anyhow::bail!(
                "GATEWAY_CODEMODE_RESULT_STORAGE must be `disabled` or `allow` (got `{other}`)"
            ),
        }
    }

    pub fn allows_persistence(self) -> bool {
        self == Self::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_defaults_and_relationships_are_validated() {
        assert_eq!(
            CodeModeCapacityLimits::default(),
            CodeModeCapacityLimits {
                global: 7,
                per_tenant: 2,
                detached: 3,
            }
        );
        assert!(CodeModeCapacityLimits {
            global: 4,
            per_tenant: 5,
            detached: 2,
        }
        .validate()
        .unwrap_err()
        .to_string()
        .contains("PER_TENANT"));
        assert!(CodeModeCapacityLimits {
            global: 4,
            per_tenant: 2,
            detached: 5,
        }
        .validate()
        .unwrap_err()
        .to_string()
        .contains("DETACHED"));
    }

    #[test]
    fn capacity_env_values_are_parsed_and_invalid_relationships_refuse_boot() {
        let _guard = crate::config::ENV_GUARD
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let names = [
            "GATEWAY_CODEMODE_MAX_CONCURRENT_EXECUTIONS",
            "GATEWAY_CODEMODE_MAX_CONCURRENT_EXECUTIONS_PER_TENANT",
            "GATEWAY_CODEMODE_MAX_CONCURRENT_DETACHED_EXECUTIONS",
        ];
        let previous = names.map(waygate_core::env::optional);

        std::env::set_var(names[0], "7");
        std::env::set_var(names[1], "5");
        std::env::set_var(names[2], "3");
        let parsed = CodeModeCapacityLimits::from_env();
        std::env::set_var(names[1], "8");
        let invalid = CodeModeCapacityLimits::from_env();

        for (name, value) in names.into_iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }

        assert_eq!(
            parsed.unwrap(),
            CodeModeCapacityLimits {
                global: 7,
                per_tenant: 5,
                detached: 3,
            }
        );
        assert!(invalid.unwrap_err().to_string().contains("PER_TENANT"));
    }

    #[test]
    fn result_storage_requires_explicit_allow() {
        assert_eq!(
            CodeModeResultStorage::parse(None).unwrap(),
            CodeModeResultStorage::Disabled
        );
        assert_eq!(
            CodeModeResultStorage::parse(Some("disabled")).unwrap(),
            CodeModeResultStorage::Disabled
        );
        assert_eq!(
            CodeModeResultStorage::parse(Some("allow")).unwrap(),
            CodeModeResultStorage::Allow
        );
        assert!(CodeModeResultStorage::parse(Some("true")).is_err());
    }
}
