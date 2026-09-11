use super::AuditRow;
use sqlx::PgPool;
use time::OffsetDateTime;

const SQL: &str = r#"
    SELECT id, ts, category, tenant_id, action, outcome,
           principal_sub, principal_email, principal_groups, issuer,
           server, tool, operation, risk_level, pii,
           policy_ids, reason, trace_id, latency_ms,
           scim_active, scim_groups, target,
           req_scopes, auth_method, req_roles, side_effects,
           parent_execution_id, execution_step,
           execution_call_id, execution_attempt
    FROM audit_log
    WHERE tenant_id = $1 AND ts >= $2
      AND outcome <> 'success' AND reason IS DISTINCT FROM 'pre_call'
    ORDER BY ts DESC, id DESC
    LIMIT $3
"#;

pub(super) async fn read(
    pool: &PgPool,
    tenant: &str,
    since: OffsetDateTime,
    limit: i64,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    // Literal outcome/reason predicates let even a generic prepared plan use
    // the partial index; tenant and time bound constrain its ordered scan.
    sqlx::query_as(SQL)
        .bind(tenant)
        .bind(since)
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await
}

#[cfg(test)]
mod tests;
