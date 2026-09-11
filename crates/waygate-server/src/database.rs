//! Isolated Postgres workload pools: configuration, construction, pressure
//! telemetry, and bounded-shutdown cleanup.

use anyhow::{Context, Result};
use sqlx::postgres::PgPool;
use tokio_util::sync::CancellationToken;

/// Dedicated Postgres connection budgets for the gateway's three workload
/// classes. The pools point at the same database but never share connection
/// permits, so audit writes retain capacity when control-plane work or
/// dashboard reads saturate their own pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DatabasePoolConfig {
    pub(crate) audit_max_connections: u32,
    pub(crate) control_max_connections: u32,
    pub(crate) reader_max_connections: u32,
}

impl Default for DatabasePoolConfig {
    fn default() -> Self {
        Self {
            audit_max_connections: Self::DEFAULT_PER_ROLE,
            control_max_connections: Self::DEFAULT_PER_ROLE,
            reader_max_connections: Self::DEFAULT_PER_ROLE,
        }
    }
}

impl DatabasePoolConfig {
    const DEFAULT_PER_ROLE: u32 = 8;
    const MIN_CONTROL_CONNECTIONS: u64 = 3;
    const MAX_TOTAL_CONNECTIONS: u64 = 64;

    pub(crate) fn from_env_vars(
        audit_var: &'static str,
        control_var: &'static str,
        reader_var: &'static str,
    ) -> Result<Self> {
        let audit_max_connections = waygate_core::env::u64_in(
            audit_var,
            u64::from(Self::DEFAULT_PER_ROLE),
            1..=Self::MAX_TOTAL_CONNECTIONS,
            "connections reserved for audit persistence",
        )?;
        let control_max_connections = waygate_core::env::u64_in(
            control_var,
            u64::from(Self::DEFAULT_PER_ROLE),
            Self::MIN_CONTROL_CONNECTIONS..=Self::MAX_TOTAL_CONNECTIONS,
            "connections reserved for control-plane stores; the fleet doorbell listener and a \
             retention claim can each hold one connection while retention and other control \
             work use another",
        )?;
        let reader_max_connections = waygate_core::env::u64_in(
            reader_var,
            u64::from(Self::DEFAULT_PER_ROLE),
            1..=Self::MAX_TOTAL_CONNECTIONS,
            "connections reserved for dashboard reads",
        )?;
        Self::from_connection_counts(
            audit_max_connections,
            control_max_connections,
            reader_max_connections,
        )
    }

    fn from_connection_counts(
        audit_max_connections: u64,
        control_max_connections: u64,
        reader_max_connections: u64,
    ) -> Result<Self> {
        if control_max_connections < Self::MIN_CONTROL_CONNECTIONS {
            anyhow::bail!(
                "control-plane database pool requires at least {} connections because the fleet \
                 doorbell listener and a retention claim can each hold one connection while \
                 retention and other control work use another",
                Self::MIN_CONTROL_CONNECTIONS,
            );
        }
        let total = audit_max_connections
            .checked_add(control_max_connections)
            .and_then(|n| n.checked_add(reader_max_connections))
            .expect("three values capped at 64 cannot overflow u64");
        if total > Self::MAX_TOTAL_CONNECTIONS {
            anyhow::bail!(
                "database pool connection budget is {total}, above the process ceiling of {}; \
                 reduce GATEWAY_DATABASE_AUDIT_MAX_CONNECTIONS, \
                 GATEWAY_DATABASE_CONTROL_MAX_CONNECTIONS, or \
                 GATEWAY_DATABASE_READER_MAX_CONNECTIONS",
                Self::MAX_TOTAL_CONNECTIONS,
            );
        }
        Ok(Self {
            audit_max_connections: audit_max_connections as u32,
            control_max_connections: control_max_connections as u32,
            reader_max_connections: reader_max_connections as u32,
        })
    }
}

/// The process's isolated Postgres connection budgets. Cloning a handle keeps
/// it within its workload pool; no control-plane or reader operation can
/// consume a permit reserved for audit persistence.
pub(crate) struct DatabasePools {
    audit: PgPool,
    control: PgPool,
    reader: Option<PgPool>,
    capacities: DatabasePoolConfig,
}

impl DatabasePools {
    pub(crate) fn audit_pool(&self) -> PgPool {
        self.audit.clone()
    }

    pub(crate) fn control_pool(&self) -> PgPool {
        self.control.clone()
    }

    pub(crate) fn audit_reader_pool(&self) -> PgPool {
        self.reader.as_ref().unwrap_or(&self.control).clone()
    }

    pub(crate) fn reader_isolated(&self) -> bool {
        self.reader.is_some()
    }

    pub(crate) fn spawn_pressure_monitor(
        &self,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let mut pools = vec![
            MonitoredPool::new(
                waygate_telemetry::metrics::DatabasePoolRole::Audit,
                self.audit.clone(),
                self.capacities.audit_max_connections,
            ),
            MonitoredPool::new(
                waygate_telemetry::metrics::DatabasePoolRole::Control,
                self.control.clone(),
                self.capacities.control_max_connections,
            ),
        ];
        if let Some(reader) = &self.reader {
            pools.push(MonitoredPool::new(
                waygate_telemetry::metrics::DatabasePoolRole::Reader,
                reader.clone(),
                self.capacities.reader_max_connections,
            ));
        }
        tokio::spawn(monitor_database_pool_pressure(pools, shutdown))
    }

    pub(crate) async fn close(&self) {
        tokio::join!(
            async {
                tracing::info!(pool_role = "audit", "closing DB pool");
                self.audit.close().await;
            },
            async {
                tracing::info!(pool_role = "control", "closing DB pool");
                self.control.close().await;
            },
            async {
                if let Some(reader) = &self.reader {
                    tracing::info!(pool_role = "reader", "closing DB pool");
                    reader.close().await;
                }
            },
        );
    }
}

struct MonitoredPool {
    role: waygate_telemetry::metrics::DatabasePoolRole,
    pool: PgPool,
    max: u32,
    exhausted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PoolPressureTransition {
    None,
    Exhausted,
    Recovered,
}

impl MonitoredPool {
    fn new(role: waygate_telemetry::metrics::DatabasePoolRole, pool: PgPool, max: u32) -> Self {
        Self {
            role,
            pool,
            max,
            exhausted: false,
        }
    }

    fn sample(&mut self) -> PoolPressureTransition {
        let size = self.pool.size();
        let idle = u32::try_from(self.pool.num_idle())
            .unwrap_or(u32::MAX)
            .min(size);
        waygate_telemetry::metrics::record_database_pool_connections(
            self.role, size, idle, self.max,
        );
        let exhausted = size >= self.max && idle == 0;
        let transition = match (self.exhausted, exhausted) {
            (false, true) => PoolPressureTransition::Exhausted,
            (true, false) => PoolPressureTransition::Recovered,
            _ => PoolPressureTransition::None,
        };
        self.exhausted = exhausted;
        match transition {
            PoolPressureTransition::None => {}
            PoolPressureTransition::Exhausted => tracing::warn!(
                pool_role = self.role.as_str(),
                pool_size = size,
                pool_idle = idle,
                pool_max = self.max,
                "database pool exhausted; requests for this workload can hit the acquire timeout"
            ),
            PoolPressureTransition::Recovered => tracing::info!(
                pool_role = self.role.as_str(),
                pool_size = size,
                pool_idle = idle,
                pool_max = self.max,
                "database pool recovered from exhaustion"
            ),
        }
        transition
    }
}

async fn monitor_database_pool_pressure(
    mut pools: Vec<MonitoredPool>,
    shutdown: CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = interval.tick() => {
                for pool in &mut pools {
                    let _ = pool.sample();
                }
            }
        }
    }
}

pub(crate) async fn build_database_pools(
    url: &str,
    capacities: DatabasePoolConfig,
) -> Result<DatabasePools> {
    let audit = waygate_storage::build_pool(
        url,
        waygate_storage::PoolRole::Writer,
        capacities.audit_max_connections,
    )
    .await
    .context("connect audit DB (audit pool)")?;
    let control = waygate_storage::build_pool(
        url,
        waygate_storage::PoolRole::Writer,
        capacities.control_max_connections,
    )
    .await
    .context("connect audit DB (control pool)")?;
    let reader = match waygate_storage::build_pool(
        url,
        waygate_storage::PoolRole::Reader,
        capacities.reader_max_connections,
    )
    .await
    {
        Ok(pool) => Some(pool),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "reader pool connect failed; dashboard reads will share the control pool \
                 (degraded — audit-write capacity remains isolated)"
            );
            None
        }
    };
    Ok(DatabasePools {
        audit,
        control,
        reader,
        capacities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_reserves_roles_with_a_bounded_total() {
        const TEST_VARS: [&str; 3] = [
            "MCPGW_TEST_DATABASE_AUDIT_MAX_CONNECTIONS",
            "MCPGW_TEST_DATABASE_CONTROL_MAX_CONNECTIONS",
            "MCPGW_TEST_DATABASE_READER_MAX_CONNECTIONS",
        ];
        let previous = TEST_VARS.map(std::env::var_os);
        for (name, value) in TEST_VARS.into_iter().zip([10, 11, 12]) {
            std::env::set_var(name, value.to_string());
        }
        let from_env =
            DatabasePoolConfig::from_env_vars(TEST_VARS[0], TEST_VARS[1], TEST_VARS[2]).unwrap();
        for (name, value) in TEST_VARS.into_iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }

        assert_eq!(
            DatabasePoolConfig::default(),
            DatabasePoolConfig {
                audit_max_connections: DatabasePoolConfig::DEFAULT_PER_ROLE,
                control_max_connections: DatabasePoolConfig::DEFAULT_PER_ROLE,
                reader_max_connections: DatabasePoolConfig::DEFAULT_PER_ROLE,
            }
        );

        assert_eq!(
            from_env,
            DatabasePoolConfig {
                audit_max_connections: 10,
                control_max_connections: 11,
                reader_max_connections: 12,
            }
        );

        assert!(DatabasePoolConfig::from_connection_counts(1, 3, 1).is_ok());
        assert!(DatabasePoolConfig::from_connection_counts(21, 21, 22).is_ok());

        let error = DatabasePoolConfig::from_connection_counts(1, 2, 1)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("requires at least 3 connections"),
            "got: {error}",
        );

        let error = DatabasePoolConfig::from_connection_counts(22, 22, 22)
            .unwrap_err()
            .to_string();
        assert!(error.contains("budget is 66"), "got: {error}");
        assert!(
            error.contains(&format!(
                "ceiling of {}",
                DatabasePoolConfig::MAX_TOTAL_CONNECTIONS
            )),
            "got: {error}"
        );
    }

    #[tokio::test]
    async fn workloads_get_distinct_pool_budgets() {
        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping pool-isolation pg test: AUDIT_DATABASE_URL not set");
            return;
        };
        let capacities = DatabasePoolConfig {
            audit_max_connections: 2,
            control_max_connections: 3,
            reader_max_connections: 4,
        };
        let pools = build_database_pools(&url, capacities)
            .await
            .expect("build isolated database pools");

        assert_eq!(pools.audit.options().get_max_connections(), 2);
        assert_eq!(pools.control.options().get_max_connections(), 3);
        assert!(pools.reader_isolated());
        assert_eq!(
            pools
                .reader
                .as_ref()
                .expect("reader pool should connect in the pg suite")
                .options()
                .get_max_connections(),
            4
        );
        assert_eq!(pools.audit_reader_pool().options().get_max_connections(), 4);
        let degraded = DatabasePools {
            audit: pools.audit.clone(),
            control: pools.control.clone(),
            reader: None,
            capacities,
        };
        assert!(!degraded.reader_isolated());
        assert_eq!(
            degraded.audit_reader_pool().options().get_max_connections(),
            3
        );

        let shutdown = CancellationToken::new();
        let monitor_task = pools.spawn_pressure_monitor(shutdown.clone());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let metrics = waygate_telemetry::gather_text();
                if metrics.lines().any(|line| {
                    line.contains("mcp_database_pool_connections")
                        && line.contains("role=\"control\"")
                        && line.contains("state=\"max\"")
                        && line.trim_end().ends_with(" 3")
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pressure monitor should publish the control pool ceiling");
        shutdown.cancel();
        monitor_task.await.expect("pressure monitor joins cleanly");

        let first = pools.audit.acquire().await.expect("first audit permit");
        let second = pools.audit.acquire().await.expect("second audit permit");
        let mut monitor = MonitoredPool::new(
            waygate_telemetry::metrics::DatabasePoolRole::Audit,
            pools.audit.clone(),
            2,
        );
        assert_eq!(monitor.sample(), PoolPressureTransition::Exhausted);
        assert_eq!(monitor.sample(), PoolPressureTransition::None);
        assert!(monitor.exhausted, "both reserved permits are in use");
        drop(first);
        drop(second);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while pools.audit.num_idle() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("returned audit permit should become idle");
        assert_eq!(monitor.sample(), PoolPressureTransition::Recovered);
        assert_eq!(monitor.sample(), PoolPressureTransition::None);
        assert!(!monitor.exhausted, "returned permits clear exhaustion");

        let held_reader = pools
            .reader
            .as_ref()
            .expect("reader pool should exist")
            .acquire()
            .await
            .expect("hold one reader permit across shutdown");
        let mut close = Box::pin(pools.close());
        tokio::select! {
            () = &mut close => panic!("close should wait for the held reader permit"),
            () = tokio::task::yield_now() => {}
        }
        assert!(pools.audit.is_closed());
        assert!(pools.control.is_closed());
        assert!(pools
            .reader
            .as_ref()
            .expect("reader remains present after close")
            .is_closed());
        drop(held_reader);
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut close)
            .await
            .expect("all pool closes should finish after the permit returns");
    }
}
