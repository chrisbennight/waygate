use std::time::Duration;

use anyhow::Result;

pub(super) fn policy_from_env() -> Result<(Duration, Duration)> {
    let base_var = if std::env::var_os("GATEWAY_UPSTREAM_RECONNECT_BASE_SECONDS").is_some() {
        "GATEWAY_UPSTREAM_RECONNECT_BASE_SECONDS"
    } else {
        "GATEWAY_UPSTREAM_REPROBE_INTERVAL_SECONDS"
    };
    let base = waygate_core::env::duration_secs(base_var, 60, 5..=u64::MAX, "at least 5 seconds")?;
    // The legacy interval allowed every u64 value at or above the floor. When
    // an operator has not opted into a separate ceiling, preserve that full
    // domain instead of making the new default reject an old deployment.
    let ceiling = waygate_core::env::duration_secs(
        "GATEWAY_UPSTREAM_RECONNECT_CEILING_SECONDS",
        base.as_secs().max(900),
        5..=u64::MAX,
        "at least 5 seconds",
    )?;
    anyhow::ensure!(
        ceiling >= base,
        "GATEWAY_UPSTREAM_RECONNECT_CEILING_SECONDS must be >= reconnect base"
    );
    Ok((base, ceiling))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ENV_GUARD;

    #[test]
    fn legacy_interval_above_one_day_stays_valid() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let prev_base = std::env::var_os("GATEWAY_UPSTREAM_RECONNECT_BASE_SECONDS");
        let prev_legacy = std::env::var_os("GATEWAY_UPSTREAM_REPROBE_INTERVAL_SECONDS");
        let prev_ceiling = std::env::var_os("GATEWAY_UPSTREAM_RECONNECT_CEILING_SECONDS");

        std::env::remove_var("GATEWAY_UPSTREAM_RECONNECT_BASE_SECONDS");
        std::env::set_var("GATEWAY_UPSTREAM_REPROBE_INTERVAL_SECONDS", "172800");
        std::env::remove_var("GATEWAY_UPSTREAM_RECONNECT_CEILING_SECONDS");
        assert_eq!(
            policy_from_env().expect("legacy value remains boot-compatible"),
            (Duration::from_secs(172800), Duration::from_secs(172800)),
        );

        std::env::set_var("GATEWAY_UPSTREAM_RECONNECT_CEILING_SECONDS", "900");
        assert!(
            policy_from_env().is_err(),
            "an explicit ceiling below the effective base must still fail",
        );

        for (name, previous) in [
            ("GATEWAY_UPSTREAM_RECONNECT_BASE_SECONDS", prev_base),
            ("GATEWAY_UPSTREAM_REPROBE_INTERVAL_SECONDS", prev_legacy),
            ("GATEWAY_UPSTREAM_RECONNECT_CEILING_SECONDS", prev_ceiling),
        ] {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}
