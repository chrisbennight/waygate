//! Bounded, process-local compatibility observations, separate from identity authority.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use waygate_core::TenantId;
use waygate_oidc::Principal;

const CAPACITY: usize = 4096;
const RETENTION_SECONDS: i64 = 86_400;
// Identity-bearing rows are larger than ordinary catalog summaries; keep
// each protected report below the shared generic list ceiling.
pub const REPORT_PAGE_CAP: usize = 100;

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ClientObservationQuery {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub client: Option<String>,
    pub window_seconds: i64,
    pub offset: usize,
    pub limit: usize,
}

impl Default for ClientObservationQuery {
    fn default() -> Self {
        Self {
            subject: None,
            issuer: None,
            client: None,
            window_seconds: 3600,
            offset: 0,
            limit: waygate_core::page::DEFAULT_LIST_LIMIT as usize,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize)]
pub struct ClientObservationKey {
    pub tenant: TenantId,
    pub issuer: String,
    pub subject: String,
    pub auth_method: String,
    pub profile_id: Option<String>,
    /// Fingerprint of scope/profile metadata, never of a credential value.
    pub credential_context: String,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub client_metadata_truncated: bool,
    pub protocol_version: Option<String>,
    pub protocol_generation: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientObservation {
    #[serde(flatten)]
    pub key: ClientObservationKey,
    pub first_seen: i64,
    pub last_seen: i64,
    pub requests_observed: u64,
}

#[derive(Debug, Serialize)]
pub struct ClientObservationReport {
    pub scope: &'static str,
    pub observed_since: i64,
    pub as_of: i64,
    pub retention_seconds: i64,
    pub window_seconds: i64,
    pub fresh_within_seconds: i64,
    pub dropped_observations: u64,
    pub limit: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub rows: Vec<ClientObservation>,
}

struct State {
    rows: HashMap<ClientObservationKey, ClientObservation>,
    next_prune: i64,
}

/// Request admission never waits for the report lock and never starts a task.
/// Capacity/lock/oversize drops reduce coverage and are exposed in every report.
pub struct ClientObservationStore {
    started_at: i64,
    state: Mutex<State>,
    dropped: AtomicU64,
}

impl Default for ClientObservationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientObservationStore {
    pub fn new() -> Self {
        Self::at(OffsetDateTime::now_utc().unix_timestamp())
    }

    fn at(now: i64) -> Self {
        Self {
            started_at: now,
            state: Mutex::new(State {
                rows: HashMap::new(),
                next_prune: now,
            }),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn observe(
        &self,
        principal: &Principal,
        client_name: Option<&str>,
        client_version: Option<&str>,
        protocol_version: Option<&str>,
        generation: &'static str,
    ) {
        self.observe_at(
            principal,
            client_name,
            client_version,
            protocol_version,
            generation,
            OffsetDateTime::now_utc().unix_timestamp(),
        );
    }

    fn observe_at(
        &self,
        principal: &Principal,
        name: Option<&str>,
        version: Option<&str>,
        protocol: Option<&str>,
        generation: &str,
        now: i64,
    ) {
        let profile_id = principal
            .api_key_profile_restrictions
            .as_ref()
            .map(|p| &p.profile_id);
        // Authenticated identity is never truncated into another identity.
        if principal.issuer.len() > 512
            || principal.sub.len() > 512
            || profile_id.is_some_and(|v| v.len() > 256)
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let bounded = |v: Option<&str>| v.map(|v| v.chars().take(128).collect::<String>());
        let key = ClientObservationKey {
            tenant: principal.tenant.clone(),
            issuer: principal.issuer.clone(),
            subject: principal.sub.clone(),
            auth_method: principal.auth_method.as_str().to_owned(),
            profile_id: profile_id.cloned(),
            credential_context: credential_context(principal),
            client_name: bounded(name),
            client_version: bounded(version),
            client_metadata_truncated: [name, version, protocol]
                .into_iter()
                .flatten()
                .any(|v| v.chars().count() > 128),
            protocol_version: bounded(protocol),
            protocol_generation: generation.to_owned(),
        };
        let Ok(mut state) = self.state.try_lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if now >= state.next_prune {
            state
                .rows
                .retain(|_, r| now.saturating_sub(r.last_seen) <= RETENTION_SECONDS);
            state.next_prune = now.saturating_add(60);
        }
        if let Some(row) = state.rows.get_mut(&key) {
            row.last_seen = row.last_seen.max(now);
            row.requests_observed = row.requests_observed.saturating_add(1);
        } else if state.rows.len() < CAPACITY {
            state.rows.insert(
                key.clone(),
                ClientObservation {
                    key,
                    first_seen: now,
                    last_seen: now,
                    requests_observed: 1,
                },
            );
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Tenant is supplied by the authorized report handler, never by a filter.
    pub fn report(
        &self,
        tenant: TenantId,
        query: &ClientObservationQuery,
    ) -> ClientObservationReport {
        self.report_at(tenant, query, OffsetDateTime::now_utc().unix_timestamp())
    }

    fn report_at(
        &self,
        tenant: TenantId,
        query: &ClientObservationQuery,
        now: i64,
    ) -> ClientObservationReport {
        let window = query.window_seconds.clamp(1, RETENTION_SECONDS);
        let limit = query.limit.clamp(1, REPORT_PAGE_CAP);
        let offset = query.offset;
        let mut state = self
            .state
            .lock()
            .expect("client observation state poisoned");
        state
            .rows
            .retain(|_, r| now.saturating_sub(r.last_seen) <= RETENTION_SECONDS);
        let mut rows: Vec<_> = state
            .rows
            .values()
            .filter(|r| {
                r.key.tenant == tenant
                    && now.saturating_sub(r.last_seen) <= window
                    && query.subject.as_deref().is_none_or(|s| r.key.subject == s)
                    && query.issuer.as_deref().is_none_or(|s| r.key.issuer == s)
                    && query
                        .client
                        .as_deref()
                        .is_none_or(|c| r.key.client_name.as_deref() == Some(c))
            })
            .cloned()
            .collect();
        // Stable order for an unchanged snapshot. Offset pagination is explicitly
        // a live view; observations can move pages between requests.
        rows.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.key.issuer.cmp(&b.key.issuer))
                .then_with(|| a.key.subject.cmp(&b.key.subject))
                .then_with(|| a.key.credential_context.cmp(&b.key.credential_context))
                .then_with(|| a.key.client_name.cmp(&b.key.client_name))
                .then_with(|| a.key.client_version.cmp(&b.key.client_version))
                .then_with(|| a.key.protocol_version.cmp(&b.key.protocol_version))
                .then_with(|| a.key.protocol_generation.cmp(&b.key.protocol_generation))
                .then_with(|| {
                    a.key
                        .client_metadata_truncated
                        .cmp(&b.key.client_metadata_truncated)
                })
        });
        let next_offset =
            (rows.len().saturating_sub(offset) > limit).then(|| offset.saturating_add(limit));
        let rows = rows.into_iter().skip(offset).take(limit).collect();
        ClientObservationReport {
            scope: "current_process_only",
            observed_since: self.started_at,
            as_of: now,
            retention_seconds: RETENTION_SECONDS,
            window_seconds: window,
            fresh_within_seconds: 300,
            dropped_observations: self.dropped.load(Ordering::Relaxed),
            limit,
            offset,
            next_offset,
            rows,
        }
    }
}

fn credential_context(principal: &Principal) -> String {
    fn field(hash: &mut Sha256, value: &str) {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    fn values(hash: &mut Sha256, values: Option<&[String]>) {
        hash.update([u8::from(values.is_some())]);
        let mut values: Vec<_> = values.unwrap_or_default().iter().collect();
        values.sort();
        values.dedup();
        hash.update((values.len() as u64).to_be_bytes());
        for value in values {
            field(hash, value);
        }
    }
    let mut hash = Sha256::new();
    field(&mut hash, principal.auth_method.as_str());
    values(&mut hash, Some(&principal.scopes));
    if let Some(profile) = &principal.api_key_profile_restrictions {
        hash.update([1]);
        field(&mut hash, &profile.profile_id);
        values(&mut hash, profile.allowed_servers.as_deref());
        values(&mut hash, profile.allowed_tools.as_deref());
    } else {
        hash.update([0]);
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(tenant: &str) -> Principal {
        serde_json::from_value(serde_json::json!({"tenant":tenant,"issuer":"https://identity.example","sub":"shared-service","email":null,"groups":[],"scopes":["mcp:read"]})).unwrap()
    }

    #[test]
    fn shared_credentials_coalesce_but_changed_and_missing_declarations_remain_distinct() {
        let store = ClientObservationStore::at(100);
        let mut p = principal("acme");
        p.raw_token = Some("synthetic-token-must-not-be-recorded".into());
        for now in [100, 101] {
            store.observe_at(
                &p,
                Some("client"),
                Some("1"),
                Some("2026-07-28"),
                "2026-07-28",
                now,
            );
        }
        store.observe_at(
            &p,
            Some("client"),
            Some("2"),
            Some("2026-07-28"),
            "2026-07-28",
            102,
        );
        store.observe_at(&p, None, None, None, "legacy", 103);
        let report = store.report_at(p.tenant.clone(), &ClientObservationQuery::default(), 104);
        assert_eq!(report.rows.len(), 3);
        assert_eq!(
            report
                .rows
                .iter()
                .find(|r| r.key.client_version.as_deref() == Some("1"))
                .unwrap()
                .requests_observed,
            2
        );
        assert!(report
            .rows
            .iter()
            .any(|r| r.key.client_name.is_none() && r.key.protocol_version.is_none()));
        let before = credential_context(&p);
        p.scopes.push("mcp:invoke".into());
        assert_ne!(before, credential_context(&p));
        p.scopes.reverse();
        let reordered = credential_context(&p);
        p.scopes.reverse();
        assert_eq!(reordered, credential_context(&p));
        p.api_key_profile_restrictions = Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "restricted".into(),
            profile_name: "Example".into(),
            allowed_servers: Some(vec!["one".into()]),
            allowed_tools: None,
        });
        let profile_context = credential_context(&p);
        p.api_key_profile_restrictions
            .as_mut()
            .unwrap()
            .allowed_servers = Some(vec!["two".into()]);
        assert_ne!(profile_context, credential_context(&p));
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("synthetic-token"));
    }

    #[test]
    fn tenant_filters_live_pagination_and_retention_use_observed_evidence() {
        let store = ClientObservationStore::at(100);
        let p = principal("acme");
        let other = principal("other");
        for name in ["a", "b", "c"] {
            store.observe_at(&p, Some(name), Some("1"), Some("2025-11-25"), "legacy", 100);
        }
        store.observe_at(&other, Some("private-other"), None, None, "legacy", 100);
        let query = ClientObservationQuery {
            limit: 2,
            ..Default::default()
        };
        let first = store.report_at(p.tenant.clone(), &query, 400);
        assert_eq!(first.rows.len(), 2);
        assert_eq!(first.next_offset, Some(2));
        let second = store.report_at(
            p.tenant.clone(),
            &ClientObservationQuery {
                offset: 2,
                ..query.clone()
            },
            400,
        );
        assert_eq!(second.rows.len(), 1);
        assert_eq!(second.next_offset, None);
        assert!(!first
            .rows
            .iter()
            .any(|a| second.rows.iter().any(|b| a.key == b.key)));
        let filtered = store.report_at(
            p.tenant.clone(),
            &ClientObservationQuery {
                client: Some("b".into()),
                issuer: Some(p.issuer.clone()),
                subject: Some(p.sub.clone()),
                ..Default::default()
            },
            400,
        );
        assert_eq!(filtered.rows.len(), 1);
        assert_eq!(filtered.rows[0].key.client_name.as_deref(), Some("b"));
        assert!(store
            .report_at(p.tenant.clone(), &query, 100 + RETENTION_SECONDS + 1)
            .rows
            .is_empty());
        assert!(store.state.lock().unwrap().rows.is_empty());
    }

    #[test]
    fn bounded_admission_drops_contention_capacity_and_oversized_identity_without_aliasing() {
        let store = ClientObservationStore::at(0);
        let mut p = principal("acme");
        for i in 0..CAPACITY {
            store.observe_at(&p, Some(&i.to_string()), None, None, "legacy", 0);
        }
        store.observe_at(&p, Some("overflow"), None, None, "legacy", 1);
        store.observe_at(&p, Some("0"), None, None, "legacy", 2);
        {
            let _guard = store.state.lock().unwrap();
            store.observe_at(&p, None, None, None, "legacy", 3);
        }
        p.sub = "x".repeat(513);
        store.observe_at(&p, None, None, None, "legacy", 4);
        let report = store.report_at(
            p.tenant.clone(),
            &ClientObservationQuery {
                client: Some("0".into()),
                ..Default::default()
            },
            5,
        );
        assert_eq!(report.dropped_observations, 3);
        assert_eq!(report.rows[0].requests_observed, 2);
        assert_eq!(store.state.lock().unwrap().rows.len(), CAPACITY);
        p.sub = "shared-service".into();
        store.observe_at(
            &p,
            Some("recovered"),
            None,
            None,
            "legacy",
            RETENTION_SECONDS + 65,
        );
        assert_eq!(store.state.lock().unwrap().rows.len(), 1);
    }
}
