use anyhow::{Context, Result};

pub(super) fn from_env() -> Result<usize> {
    let bytes = waygate_core::env::u64_in(
        "GATEWAY_UPSTREAM_CALL_RESPONSE_MAX_BYTES",
        waygate_upstream::DEFAULT_CALL_RESPONSE_MAX_BYTES as u64,
        1..=waygate_upstream::MAX_CALL_RESPONSE_BYTES,
        "bytes; choose a positive value no larger than 1 GiB",
    )?;
    usize::try_from(bytes)
        .context("GATEWAY_UPSTREAM_CALL_RESPONSE_MAX_BYTES does not fit this platform")
}

#[cfg(test)]
mod tests {
    use crate::config::ENV_GUARD;

    #[test]
    fn defaults_and_rejects_zero_or_over_one_gibibyte() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|error| error.into_inner());
        let previous_limit = std::env::var_os("GATEWAY_UPSTREAM_CALL_RESPONSE_MAX_BYTES");

        std::env::remove_var("GATEWAY_UPSTREAM_CALL_RESPONSE_MAX_BYTES");
        let limit = super::from_env().expect("default call response bound");
        assert_eq!(limit, waygate_upstream::DEFAULT_CALL_RESPONSE_MAX_BYTES);
        assert_eq!(limit, 64 * 1024 * 1024);

        std::env::set_var("GATEWAY_UPSTREAM_CALL_RESPONSE_MAX_BYTES", "1073741824");
        let limit = super::from_env().expect("the maximum is accepted");
        assert_eq!(limit, 1024 * 1024 * 1024);

        for invalid in ["0", "1073741825", "64MiB", " 1024"] {
            std::env::set_var("GATEWAY_UPSTREAM_CALL_RESPONSE_MAX_BYTES", invalid);
            assert!(
                super::from_env().is_err(),
                "invalid call response bound `{invalid}` must refuse boot",
            );
        }

        match previous_limit {
            Some(value) => std::env::set_var("GATEWAY_UPSTREAM_CALL_RESPONSE_MAX_BYTES", value),
            None => std::env::remove_var("GATEWAY_UPSTREAM_CALL_RESPONSE_MAX_BYTES"),
        }
    }
}
