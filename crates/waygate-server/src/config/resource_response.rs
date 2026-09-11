use anyhow::{Context, Result};

const MAX_RESOURCE_RESPONSE_BYTES: u64 = 1024 * 1024 * 1024;

pub(super) fn from_env() -> Result<usize> {
    let bytes = waygate_core::env::u64_in(
        "GATEWAY_RESOURCE_RESPONSE_MAX_BYTES",
        waygate_mcp::DEFAULT_RESOURCE_RESPONSE_MAX_BYTES as u64,
        1..=MAX_RESOURCE_RESPONSE_BYTES,
        "bytes; choose a positive value no larger than 1 GiB",
    )?;
    usize::try_from(bytes).context("GATEWAY_RESOURCE_RESPONSE_MAX_BYTES does not fit this platform")
}

#[cfg(test)]
mod tests {
    use crate::config::ENV_GUARD;

    #[test]
    fn defaults_and_rejects_zero_or_over_one_gibibyte() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|error| error.into_inner());
        let previous_limit = std::env::var_os("GATEWAY_RESOURCE_RESPONSE_MAX_BYTES");

        std::env::remove_var("GATEWAY_RESOURCE_RESPONSE_MAX_BYTES");
        let limit = super::from_env().expect("default resource response bound");
        assert_eq!(limit, waygate_mcp::DEFAULT_RESOURCE_RESPONSE_MAX_BYTES);

        std::env::set_var("GATEWAY_RESOURCE_RESPONSE_MAX_BYTES", "7340032");
        let limit = super::from_env().expect("explicit resource response bound");
        assert_eq!(limit, 7 * 1024 * 1024);

        for invalid in ["0", "1073741825"] {
            std::env::set_var("GATEWAY_RESOURCE_RESPONSE_MAX_BYTES", invalid);
            assert!(
                super::from_env().is_err(),
                "invalid resource response bound `{invalid}` must refuse boot",
            );
        }

        match previous_limit {
            Some(value) => std::env::set_var("GATEWAY_RESOURCE_RESPONSE_MAX_BYTES", value),
            None => std::env::remove_var("GATEWAY_RESOURCE_RESPONSE_MAX_BYTES"),
        }
    }
}
