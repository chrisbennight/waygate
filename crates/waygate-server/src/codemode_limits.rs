//! Immutable process resource settings shared by admission and the confined runner.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const MIB: usize = 1024 * 1024;

/// Effective operator resource budgets. Byte limits count UTF-8 or serialized JSON bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub(crate) struct CodeModeLimits {
    /// Maximum JavaScript source size in UTF-8 bytes, for every source selector.
    pub source_bytes: usize,
    /// QuickJS heap allocation ceiling in bytes.
    pub heap_bytes: usize,
    /// QuickJS stack ceiling in bytes.
    pub stack_bytes: usize,
    /// Kernel process address-space ceiling in bytes.
    pub address_space_bytes: usize,
    /// Maximum serialized connector arguments, including mutation arguments.
    pub request_bytes: usize,
    /// Maximum serialized connector response materialized in JavaScript.
    pub connector_response_bytes: usize,
    /// Maximum serialized final program result.
    pub result_bytes: usize,
    /// Maximum serialized program input or resume input.
    pub input_bytes: usize,
    /// Maximum serialized checkpoint emitted by a program.
    pub checkpoint_bytes: usize,
    /// Maximum serialized individual artifact.
    pub artifact_bytes: usize,
    /// Maximum number of emitted artifacts per attempt.
    pub artifacts_per_attempt: usize,
    /// Maximum cumulative serialized artifact bytes per attempt.
    pub artifact_total_bytes: usize,
    /// Maximum search query length in UTF-8 bytes.
    pub query_bytes: usize,
    /// Maximum distinct files in a file bundle.
    pub file_count: usize,
    /// Maximum file reference locations in a bundle.
    pub file_locations: usize,
    /// Total file-backed resource preparation deadline in seconds.
    pub file_preparation_seconds: u64,
    /// Default program execution budget in seconds.
    pub execution_seconds: u64,
    /// Operator execution ceiling in seconds, at most 24 hours.
    pub execution_max_seconds: u64,
    /// Runner setup deadline in seconds, separate from execution.
    pub setup_seconds: u64,
    /// Maximum live retained-source bytes per authenticated owner.
    pub retained_owner_bytes: usize,
    /// Maximum live retained-source bytes per tenant.
    pub retained_tenant_bytes: usize,
    /// Maximum live retained sources per authenticated owner.
    pub retained_owner_count: usize,
    /// Maximum live retained sources per tenant.
    pub retained_tenant_count: usize,
    /// Operator memory allocation used to derive global runner concurrency.
    pub execution_memory_bytes: usize,
    /// Estimated peak total memory per runner, including native allocations and copies; not an RSS guarantee.
    pub runner_peak_bytes: usize,
    /// Derived maximum serialized runner control message.
    pub frame_bytes: usize,
    /// Derived maximum serialized start message, including escaped source and input.
    pub parent_frame_bytes: usize,
}

impl Default for CodeModeLimits {
    fn default() -> Self {
        let mut limits = Self {
            source_bytes: 4 * MIB,
            heap_bytes: 128 * MIB,
            stack_bytes: 2 * MIB,
            address_space_bytes: 1024 * MIB,
            request_bytes: 8 * MIB,
            connector_response_bytes: 32 * MIB,
            result_bytes: 8 * MIB,
            input_bytes: 8 * MIB,
            checkpoint_bytes: 8 * MIB,
            artifact_bytes: 8 * MIB,
            artifacts_per_attempt: 256,
            artifact_total_bytes: 128 * MIB,
            query_bytes: 4096,
            file_count: 64,
            file_locations: 512,
            file_preparation_seconds: 30,
            execution_seconds: 300,
            execution_max_seconds: 86_400,
            setup_seconds: 30,
            retained_owner_bytes: 64 * MIB,
            retained_tenant_bytes: 1024 * MIB,
            retained_owner_count: 64,
            retained_tenant_count: 1024,
            execution_memory_bytes: 4096 * MIB,
            runner_peak_bytes: 0,
            frame_bytes: 0,
            parent_frame_bytes: 0,
        }
        .derive_transport()
        .expect("default Code Mode limits fit supported platforms");
        limits.address_space_bytes = (limits.runner_peak_bytes * 2).max(1024 * MIB);
        limits
    }
}

impl CodeModeLimits {
    /// Account for escaped source, independently admitted inputs, and a bounded binding table.
    pub(crate) fn derive_transport(mut self) -> anyhow::Result<Self> {
        let add = |a: usize, b: usize| {
            a.checked_add(b)
                .ok_or_else(|| anyhow::anyhow!("Code Mode byte budget overflow"))
        };
        let mul = |a: usize, b: usize| {
            a.checked_mul(b)
                .ok_or_else(|| anyhow::anyhow!("Code Mode byte budget overflow"))
        };
        let envelope = MIB;
        self.frame_bytes = add(
            *[
                self.request_bytes,
                self.result_bytes,
                self.checkpoint_bytes,
                self.artifact_bytes,
            ]
            .iter()
            .max()
            .expect("nonempty"),
            envelope,
        )?;
        self.parent_frame_bytes = add(
            add(mul(self.source_bytes, 6)?, self.input_bytes)?,
            add(add(self.checkpoint_bytes, self.input_bytes)?, envelope)?,
        )?;
        self.parent_frame_bytes = self.parent_frame_bytes.max(self.frame_bytes);
        // This is an admission estimate, not an RSS guarantee: include native runtime
        // state, serialized transport copies, and materialized connector copies.
        self.runner_peak_bytes = add(
            add(mul(self.heap_bytes, 2)?, mul(self.parent_frame_bytes, 2)?)?,
            add(mul(self.connector_response_bytes, 4)?, 64 * MIB)?,
        )?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        let derived = self.clone().derive_transport()?;
        anyhow::ensure!(
            derived == *self,
            "Code Mode derived transport budgets do not match payload limits"
        );
        for size in [
            self.retained_owner_bytes,
            self.retained_tenant_bytes,
            self.retained_owner_count,
            self.retained_tenant_count,
        ] {
            anyhow::ensure!(
                i64::try_from(size).is_ok(),
                "Code Mode storage quotas must fit database counters"
            );
        }
        anyhow::ensure!(
            self.source_bytes > 0 && self.source_bytes <= self.heap_bytes,
            "Code Mode source budget must be positive and fit the heap"
        );
        for size in [
            self.request_bytes,
            self.connector_response_bytes,
            self.result_bytes,
            self.input_bytes,
            self.checkpoint_bytes,
            self.artifact_bytes,
            self.stack_bytes,
        ] {
            anyhow::ensure!(
                size > 0 && size <= self.heap_bytes,
                "Code Mode payload and stack budgets must be positive and fit the heap"
            );
        }
        anyhow::ensure!(
            self.artifacts_per_attempt > 0 && self.artifact_total_bytes >= self.artifact_bytes,
            "Code Mode artifact count must be positive and total bytes must admit one artifact"
        );
        anyhow::ensure!(
            self.execution_seconds > 0
                && self.execution_seconds <= self.execution_max_seconds
                && self.execution_max_seconds <= 86_400,
            "Code Mode execution default must fit the operator maximum and the 24-hour cap"
        );
        anyhow::ensure!(
            self.setup_seconds > 0 && self.file_preparation_seconds > 0,
            "Code Mode setup and file preparation timeouts must be positive"
        );
        anyhow::ensure!(self.query_bytes > 0 && self.file_count > 0 && self.file_locations >= self.file_count, "Code Mode query and file limits must be positive and locations must admit the file count");
        anyhow::ensure!(
            self.retained_owner_bytes >= self.source_bytes
                && self.retained_tenant_bytes >= self.retained_owner_bytes
                && self.retained_owner_count > 0
                && self.retained_tenant_count >= self.retained_owner_count,
            "Code Mode retained source quotas must admit a source and fit the tenant quota"
        );
        anyhow::ensure!(
            self.address_space_bytes >= self.runner_peak_bytes,
            "Code Mode address space must cover estimated runner peak memory"
        );
        anyhow::ensure!(
            self.execution_memory_bytes >= self.runner_peak_bytes,
            "Code Mode execution memory allocation must admit at least one runner"
        );
        Ok(())
    }
}

static LIMITS: OnceLock<CodeModeLimits> = OnceLock::new();

/// Boot installs the validated configuration before constructing any tool surface.
/// Standalone test fixtures use the same documented defaults without reading the environment.
pub(crate) fn limits() -> &'static CodeModeLimits {
    LIMITS.get_or_init(CodeModeLimits::default)
}

pub(crate) fn install(limits: CodeModeLimits) -> anyhow::Result<()> {
    limits.validate()?;
    LIMITS
        .set(limits)
        .map_err(|_| anyhow::anyhow!("Code Mode limits were already initialized"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_cover_default_source_and_transport_copies() {
        let limits = CodeModeLimits::default();
        limits.validate().expect("valid defaults");
        assert_eq!(limits.source_bytes, 4 * MIB);
        assert_eq!(limits.execution_seconds, 300);
        assert_eq!(limits.execution_max_seconds, 86_400);
        assert!(
            limits.parent_frame_bytes
                >= 6 * limits.source_bytes + 2 * limits.input_bytes + limits.checkpoint_bytes
        );
        assert!(limits.runner_peak_bytes > limits.heap_bytes + limits.parent_frame_bytes);
    }

    #[test]
    fn invalid_relationships_and_overflow_are_rejected() {
        let mut limits = CodeModeLimits {
            execution_seconds: 86_401,
            ..CodeModeLimits::default()
        };
        assert!(limits.validate().is_err());
        limits = CodeModeLimits::default();
        limits.execution_memory_bytes = limits.runner_peak_bytes - 1;
        assert!(limits.validate().is_err());
        limits = CodeModeLimits::default();
        limits.source_bytes = usize::MAX;
        assert!(limits.derive_transport().is_err());
        limits = CodeModeLimits::default();
        limits.frame_bytes = 1;
        assert!(limits.validate().is_err());
    }
}
