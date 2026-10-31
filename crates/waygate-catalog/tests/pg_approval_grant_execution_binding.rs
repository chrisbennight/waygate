//! Postgres contract for direct-call and Code Mode execution-bound grants.

use std::env;

use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_catalog::{
    CatalogStore, GrantExecutionBinding, GrantLookup, NewApprovalGrant, PgCatalogStore,
};

#[tokio::test]
async fn execution_bound_grants_match_only_the_exact_execution_call() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping approval grant execution binding: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let store = PgCatalogStore::new(pool.clone());
    let tenant = format!("grant-binding-{}", Uuid::new_v4());
    let principal = "agent@example.com";
    let server_id = Uuid::new_v4();
    let tool_id = Uuid::new_v4();
    let argument_hash = "args-v1:test";
    let execution_id = Uuid::new_v4();
    let call_id = Uuid::new_v4();
    let expires_at = OffsetDateTime::now_utc() + time::Duration::minutes(5);

    let direct = store
        .create_grant(NewApprovalGrant {
            tenant_id: &tenant,
            principal_sub: principal,
            principal_issuer: "https://issuer.test",
            client_id: None,
            server_id,
            tool_id,
            argument_hash,
            execution_binding: None,
            expires_at,
            approver: "operator@example.com",
            reason: None,
        })
        .await
        .expect("create direct grant");
    let exact_binding = GrantExecutionBinding {
        execution_id,
        source_digest: "source-a",
        call_id,
    };
    let bound = store
        .create_grant(NewApprovalGrant {
            tenant_id: &tenant,
            principal_sub: principal,
            principal_issuer: "https://issuer.test",
            client_id: None,
            server_id,
            tool_id,
            argument_hash,
            execution_binding: Some(exact_binding),
            expires_at,
            approver: "operator@example.com",
            reason: None,
        })
        .await
        .expect("create execution-bound grant");

    let direct_match = store
        .find_grant(GrantLookup {
            tenant_id: &tenant,
            principal_sub: principal,
            principal_issuer: "https://issuer.test",
            client_id: None,
            tool_id,
            argument_hash,
            execution_binding: None,
        })
        .await
        .expect("find direct grant")
        .expect("direct grant matches");
    assert_eq!(direct_match.id, direct.id);
    assert!(direct_match.execution_binding.is_none());

    let bound_match = store
        .find_grant(GrantLookup {
            tenant_id: &tenant,
            principal_sub: principal,
            principal_issuer: "https://issuer.test",
            client_id: None,
            tool_id,
            argument_hash,
            execution_binding: Some(exact_binding),
        })
        .await
        .expect("find bound grant")
        .expect("exact bound grant matches");
    assert_eq!(bound_match.id, bound.id);
    assert_eq!(
        bound_match
            .execution_binding
            .as_ref()
            .map(|binding| binding.source_digest.as_str()),
        Some("source-a")
    );

    let drifted = store
        .find_grant(GrantLookup {
            tenant_id: &tenant,
            principal_sub: principal,
            principal_issuer: "https://issuer.test",
            client_id: None,
            tool_id,
            argument_hash,
            execution_binding: Some(GrantExecutionBinding {
                source_digest: "source-b",
                ..exact_binding
            }),
        })
        .await
        .expect("query drifted binding");
    assert!(
        drifted.is_none(),
        "source drift cannot fall back to the ordinary grant"
    );

    let claimed = store
        .claim_grant(GrantLookup {
            tenant_id: &tenant,
            principal_sub: principal,
            principal_issuer: "https://issuer.test",
            client_id: None,
            tool_id,
            argument_hash,
            execution_binding: Some(exact_binding),
        })
        .await
        .expect("claim exact binding")
        .expect("bound grant claims once");
    assert_eq!(claimed.id, bound.id);
    assert!(claimed.consumed_at.is_some());
    assert!(
        store
            .claim_grant(GrantLookup {
                tenant_id: &tenant,
                principal_sub: principal,
                principal_issuer: "https://issuer.test",
                client_id: None,
                tool_id,
                argument_hash,
                execution_binding: Some(exact_binding),
            })
            .await
            .expect("repeat claim")
            .is_none(),
        "execution-bound grant is single use"
    );

    sqlx::query("DELETE FROM approval_grants WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("clean test grants");
}

#[tokio::test]
async fn replaced_request_revocation_consumes_only_that_executions_bound_grants() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping approval grant revocation contract: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let store = PgCatalogStore::new(pool.clone());
    let tenant = format!("grant-revoke-{}", Uuid::new_v4());
    let server_id = Uuid::new_v4();
    let tool_id = Uuid::new_v4();
    let execution_id = Uuid::new_v4();
    let expires_at = OffsetDateTime::now_utc() + time::Duration::minutes(5);
    fn revocation_grant<'a>(
        tenant: &'a str,
        server_id: Uuid,
        tool_id: Uuid,
        expires_at: OffsetDateTime,
        binding: Option<GrantExecutionBinding<'a>>,
    ) -> NewApprovalGrant<'a> {
        NewApprovalGrant {
            tenant_id: tenant,
            principal_sub: "agent@example.com",
            principal_issuer: "https://issuer.test",
            client_id: None,
            server_id,
            tool_id,
            argument_hash: "args-v1:test",
            execution_binding: binding,
            expires_at,
            approver: "operator@example.com",
            reason: None,
        }
    }
    let bound = store
        .create_grant(revocation_grant(
            &tenant,
            server_id,
            tool_id,
            expires_at,
            Some(GrantExecutionBinding {
                execution_id,
                source_digest: "source-a",
                call_id: Uuid::new_v4(),
            }),
        ))
        .await
        .expect("create bound grant");
    let other_execution = store
        .create_grant(revocation_grant(
            &tenant,
            server_id,
            tool_id,
            expires_at,
            Some(GrantExecutionBinding {
                execution_id: Uuid::new_v4(),
                source_digest: "source-a",
                call_id: Uuid::new_v4(),
            }),
        ))
        .await
        .expect("create other execution's grant");
    let direct = store
        .create_grant(revocation_grant(
            &tenant, server_id, tool_id, expires_at, None,
        ))
        .await
        .expect("create direct grant");

    let revoked = store
        .revoke_execution_grants(&tenant, execution_id)
        .await
        .expect("revoke superseded execution grants");
    assert_eq!(revoked, 1);
    let survivors = store
        .list_grants(
            &tenant,
            waygate_catalog::GrantFilter {
                principal_sub: None,
                tool_id: None,
                server_id: None,
                include_consumed: false,
                lifecycle: None,
            },
        )
        .await
        .expect("list live grants");
    let mut survivor_ids: Vec<Uuid> = survivors.iter().map(|grant| grant.id).collect();
    survivor_ids.sort();
    let mut expected = vec![other_execution.id, direct.id];
    expected.sort();
    assert_eq!(
        survivor_ids, expected,
        "revocation touches only the named execution's bound grants"
    );
    assert!(!survivor_ids.contains(&bound.id));

    sqlx::query("DELETE FROM approval_grants WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("clean test grants");
}

/// Issuer-scoped ownership: a grant matches only the exact requester
/// issuer it was minted for, and a pre-upgrade issuer-less row matches no
/// claim at all (fail closed) — it simply ages out on its expiry clock.
#[tokio::test]
async fn grants_are_issuer_scoped_and_legacy_rows_fail_closed() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping issuer-scoped grant test: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let store = PgCatalogStore::new(pool.clone());
    let tenant = format!("grant-issuer-{}", Uuid::new_v4());
    let server_id = Uuid::new_v4();
    let tool_id = Uuid::new_v4();
    let argument_hash = "args-v1:test";
    let expires_at = OffsetDateTime::now_utc() + time::Duration::minutes(5);

    store
        .create_grant(NewApprovalGrant {
            tenant_id: &tenant,
            principal_sub: "agent@example.com",
            principal_issuer: "https://issuer-a.test",
            client_id: None,
            server_id,
            tool_id,
            argument_hash,
            execution_binding: None,
            expires_at,
            approver: "operator@example.com",
            reason: None,
        })
        .await
        .expect("create issuer-scoped grant");
    let lookup = |issuer: &'static str| GrantLookup {
        tenant_id: &tenant,
        principal_sub: "agent@example.com",
        principal_issuer: issuer,
        client_id: None,
        tool_id,
        argument_hash,
        execution_binding: None,
    };

    // The same sub under ANOTHER issuer is a different person: no match.
    assert!(store
        .find_grant(lookup("https://issuer-b.test"))
        .await
        .expect("cross-issuer find")
        .is_none());
    assert!(store
        .claim_grant(lookup("https://issuer-b.test"))
        .await
        .expect("cross-issuer claim")
        .is_none());
    // The minted-for issuer claims exactly once.
    let claimed = store
        .claim_grant(lookup("https://issuer-a.test"))
        .await
        .expect("issuer-matched claim")
        .expect("grant claimed");
    assert_eq!(
        claimed.principal_issuer.as_deref(),
        Some("https://issuer-a.test")
    );

    // A pre-upgrade row (NULL issuer, inserted below the typed API exactly
    // as an old deployment left it) can never be found or claimed again.
    sqlx::query(
        r#"
        INSERT INTO approval_grants
            (id, tenant_id, principal_sub, server_id, tool_id,
             argument_hash, expires_at, approver)
        VALUES ($1, $2, 'agent@example.com', $3, $4, $5, $6, 'operator@example.com')
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(&tenant)
    .bind(server_id)
    .bind(tool_id)
    .bind(argument_hash)
    .bind(expires_at)
    .execute(&pool)
    .await
    .expect("insert legacy issuer-less grant");
    for issuer in ["https://issuer-a.test", "https://issuer-b.test"] {
        assert!(
            store
                .claim_grant(lookup(issuer))
                .await
                .expect("legacy-row claim probe")
                .is_none(),
            "an issuer-less pre-upgrade grant must fail closed for {issuer}",
        );
    }
}
