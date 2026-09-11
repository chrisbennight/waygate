use crate::codemode_limits::CodeModeLimits;

/// Resolve dependent defaults only after their operator inputs have been read.
pub(super) fn from_env() -> anyhow::Result<CodeModeLimits> {
    let mut limits = CodeModeLimits::default();
    let read = |name: &'static str, default: usize| -> anyhow::Result<usize> {
        let maximum = (usize::MAX as u64).min(i64::MAX as u64);
        Ok(usize::try_from(waygate_core::env::u64_in(
            name,
            default as u64,
            1..=maximum,
            "positive Code Mode resource budget",
        )?)?)
    };
    let multiply = |value: usize, factor: usize| {
        value
            .checked_mul(factor)
            .ok_or_else(|| anyhow::anyhow!("Code Mode derived default overflow"))
    };
    limits.source_bytes = read("GATEWAY_CODEMODE_SOURCE_MAX_BYTES", limits.source_bytes)?;
    limits.heap_bytes = read(
        "GATEWAY_CODEMODE_HEAP_BYTES",
        multiply(limits.source_bytes, 32)?.max(128 * 1024 * 1024),
    )?;
    limits.stack_bytes = read(
        "GATEWAY_CODEMODE_STACK_BYTES",
        (limits.heap_bytes / 64).clamp(512 * 1024, 8 * 1024 * 1024),
    )?;
    limits.request_bytes = read("GATEWAY_CODEMODE_REQUEST_MAX_BYTES", limits.heap_bytes / 16)?;
    limits.connector_response_bytes = read(
        "GATEWAY_CODEMODE_CONNECTOR_RESPONSE_MAX_BYTES",
        limits.heap_bytes / 4,
    )?;
    limits.result_bytes = read("GATEWAY_CODEMODE_RESULT_MAX_BYTES", limits.heap_bytes / 16)?;
    limits.input_bytes = read("GATEWAY_CODEMODE_INPUT_MAX_BYTES", limits.heap_bytes / 16)?;
    limits.checkpoint_bytes = read(
        "GATEWAY_CODEMODE_CHECKPOINT_MAX_BYTES",
        limits.heap_bytes / 16,
    )?;
    limits.artifact_bytes = read(
        "GATEWAY_CODEMODE_ARTIFACT_MAX_BYTES",
        limits.heap_bytes / 16,
    )?;
    limits.artifacts_per_attempt = read(
        "GATEWAY_CODEMODE_MAX_ARTIFACTS",
        limits.artifacts_per_attempt,
    )?;
    limits.artifact_total_bytes = read(
        "GATEWAY_CODEMODE_ARTIFACT_TOTAL_MAX_BYTES",
        multiply(limits.artifact_bytes, 16)?,
    )?;
    limits.query_bytes = read("GATEWAY_CODEMODE_QUERY_MAX_BYTES", limits.query_bytes)?;
    limits.file_count = read("GATEWAY_FILE_BUNDLE_MAX_FILES", limits.file_count)?;
    limits.file_locations = read(
        "GATEWAY_FILE_BUNDLE_MAX_LOCATIONS",
        multiply(limits.file_count, 8)?,
    )?;
    limits.file_preparation_seconds = read(
        "GATEWAY_RESOURCE_FILE_PREPARATION_SECONDS",
        limits.file_preparation_seconds as usize,
    )? as u64;
    limits.setup_seconds = read(
        "GATEWAY_CODEMODE_SETUP_TIMEOUT_SECONDS",
        limits.setup_seconds as usize,
    )? as u64;
    limits.execution_max_seconds = waygate_core::env::u64_in(
        "GATEWAY_CODEMODE_EXECUTION_MAX_SECONDS",
        limits.execution_max_seconds,
        1..=86_400,
        "operator maximum, at most 24 hours",
    )?;
    limits.execution_seconds = waygate_core::env::u64_in(
        "GATEWAY_CODEMODE_EXECUTION_LIMIT_SECONDS",
        limits.execution_seconds,
        1..=limits.execution_max_seconds,
        "default execution time must fit the operator maximum",
    )?;
    limits.retained_owner_bytes = read(
        "GATEWAY_CODEMODE_RETAINED_SOURCE_BYTES_PER_OWNER",
        multiply(limits.source_bytes, 16)?,
    )?;
    limits.retained_tenant_bytes = read(
        "GATEWAY_CODEMODE_RETAINED_SOURCE_BYTES_PER_TENANT",
        multiply(limits.retained_owner_bytes, 16)?,
    )?;
    limits.retained_owner_count = read(
        "GATEWAY_CODEMODE_RETAINED_SOURCES_PER_OWNER",
        limits.retained_owner_count,
    )?;
    limits.retained_tenant_count = read(
        "GATEWAY_CODEMODE_RETAINED_SOURCES_PER_TENANT",
        limits.retained_tenant_count,
    )?;
    limits.execution_memory_bytes = read(
        "GATEWAY_CODEMODE_EXECUTION_MEMORY_BYTES",
        limits.execution_memory_bytes,
    )?;
    limits = limits.derive_transport()?;
    limits.address_space_bytes = read(
        "GATEWAY_CODEMODE_ADDRESS_SPACE_BYTES",
        multiply(limits.runner_peak_bytes, 2)?.max(1024 * 1024 * 1024),
    )?;
    limits.validate()?;
    Ok(limits)
}
