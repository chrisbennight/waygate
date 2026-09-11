use std::time::Duration;

use anyhow::Result;

/// Parse the fleet retention scheduler cadence. The scheduler runs hourly by
/// default and is non-destructive until an operator creates a retention policy;
/// zero is the explicit opt-out. A one-minute floor prevents a typo from
/// multiplying sweep load across every configured tenant and category.
pub(crate) fn sweep_interval_from_env() -> Result<Option<Duration>> {
    Ok(waygate_core::env::duration_secs_zero_disables(
        "GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS",
        3600,
        60,
        "use 0 to disable, otherwise pick ≥60s — the scheduler iterates every retention policy \
         each tick and runs the per-tenant DELETE path",
    )?)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static ENV_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn scheduler_defaults_on_and_zero_disables() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|error| error.into_inner());
        let previous = std::env::var_os("GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS");

        std::env::remove_var("GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS");
        assert_eq!(
            sweep_interval_from_env().expect("default retention cadence parses"),
            Some(Duration::from_secs(3600)),
        );

        std::env::set_var("GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS", "75");
        assert_eq!(
            sweep_interval_from_env().expect("explicit retention cadence parses"),
            Some(Duration::from_secs(75)),
        );

        std::env::set_var("GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS", "0");
        assert_eq!(
            sweep_interval_from_env().expect("zero retention cadence parses"),
            None,
            "zero must remain the explicit scheduler opt-out",
        );

        std::env::set_var("GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS", "30");
        assert!(
            sweep_interval_from_env().is_err(),
            "a sub-floor cadence must fail boot instead of hammering Postgres",
        );

        match previous {
            Some(value) => std::env::set_var("GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS", value),
            None => std::env::remove_var("GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS"),
        }
    }
}
