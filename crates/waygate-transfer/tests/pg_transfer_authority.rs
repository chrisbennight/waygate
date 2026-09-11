use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use waygate_core::TenantId;
use waygate_evidence::audit::{InMemorySink, NullSink};
use waygate_oidc::{ApiKeyProfileRestrictions, AuthMethod, Principal};
use waygate_transfer::{
    AuthorityError, DpopVerifier, FileInspectionStatus, GatewayFileOwner, GatewayFileStorage,
    NewGatewayFile, NewTransferGrant, PgTransferStore, TransferAuthority, TransferCredential,
    TransferDigest, TransferDirection, TransferEndpoint, UploadState, NATIVE_MCP_CLIENT_REFERENCE,
};

struct HelperKey {
    jwk: Jwk,
    encoding: EncodingKey,
    jti_prefix: Uuid,
}

impl HelperKey {
    fn new(seed: u8) -> Self {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap();
        let encoding = EncodingKey::from_ed_pem(pem.as_bytes()).unwrap();
        let jwk = Jwk {
            common: CommonParameters {
                key_algorithm: Some(KeyAlgorithm::EdDSA),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x: URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
            }),
        };
        Self {
            jwk,
            encoding,
            jti_prefix: Uuid::now_v7(),
        }
    }

    fn thumbprint(&self) -> String {
        self.jwk
            .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
    }

    fn proof(
        &self,
        jti: &str,
        method: &str,
        uri: &str,
        token: Option<&str>,
        now: OffsetDateTime,
    ) -> String {
        let jti = format!("{}-{jti}", self.jti_prefix);
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(self.jwk.clone());
        encode(
            &header,
            &ProofClaims {
                jti: &jti,
                htm: method,
                htu: uri,
                iat: now.unix_timestamp(),
                ath: token.map(|value| URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))),
            },
            &self.encoding,
        )
        .unwrap()
    }
}

#[derive(Serialize)]
struct ProofClaims<'a> {
    jti: &'a str,
    htm: &'a str,
    htu: &'a str,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

fn principal(tenant: &str) -> Principal {
    Principal {
        sub: "transfer-user".to_owned(),
        email: None,
        groups: Vec::new(),
        issuer: "https://identity.example".to_owned(),
        scopes: Vec::new(),
        tenant: TenantId::parse(tenant).unwrap(),
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
        roles: Vec::new(),
    }
}

fn upload_grant(helper_jkt: String, now: OffsetDateTime) -> NewTransferGrant {
    NewTransferGrant {
        invocation_id: format!("call-{}", Uuid::new_v4()),
        file_uri: format!("mcp-file://gateway/{}", Uuid::new_v4()),
        direction: TransferDirection::Upload,
        source: TransferEndpoint::client("local-file").unwrap(),
        destination: TransferEndpoint::upstream("documents", "new-file").unwrap(),
        helper_jkt,
        max_bytes: i64::MAX as u64,
        expected_size: Some(3),
        media_type: Some("application/octet-stream".to_owned()),
        expected_digest: Some(TransferDigest {
            algorithm: "sha-256".to_owned(),
            value: vec![1, 2, 3],
        }),
        max_requests: 1,
        expires_at: now + Duration::minutes(10),
        credential_ttl: Duration::minutes(2),
    }
}

// A grant sweep is database-wide, even though each test owns a unique tenant.
// Keep its intermediate-state assertions isolated from the other sweeper
// fixture. The matching nextest group supplies isolation across processes.
static TRANSFER_SWEEP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn seed_tenant(pool: &sqlx::PgPool, tenant: &str) {
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1)")
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed transfer tenant");
}

#[tokio::test]
async fn upload_status_is_scoped_to_the_exact_owner_and_credential_profile() {
    let _sweep_guard = TRANSFER_SWEEP_LOCK.lock().await;
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("transfer-status-{}", Uuid::new_v4().simple());
    seed_tenant(&pool, &tenant).await;
    let store = Arc::new(PgTransferStore::new(pool.clone()));
    let authority = TransferAuthority::new(
        store.clone(),
        Arc::new(InMemorySink::new()),
        DpopVerifier::new(Duration::minutes(5), Duration::seconds(30)).unwrap(),
    );
    let file_root = tempfile::tempdir().expect("status file root");
    let storage = GatewayFileStorage::new(pool.clone(), file_root.path())
        .await
        .expect("status file storage");
    let now = OffsetDateTime::now_utc();
    let actor = principal(&tenant);
    let helper = HelperKey::new(40);
    let mut spec = upload_grant(helper.thumbprint(), now);
    let bytes = Bytes::from_static(b"abc");
    spec.expected_digest = Some(TransferDigest {
        algorithm: "sha-256".to_owned(),
        value: Sha256::digest(&bytes).to_vec(),
    });
    let file_uri = spec.file_uri.clone();
    let file_id = Uuid::parse_str(file_uri.rsplit('/').next().unwrap()).unwrap();
    let invocation_id = spec.invocation_id.clone();
    let source_reference = "local-file".to_owned();
    let prepared = authority.create_grant(&actor, spec, now).await.unwrap();

    let status = authority
        .upload_status(&actor, &file_uri, now)
        .await
        .unwrap()
        .expect("owner can reconcile upload");
    assert_eq!(status.state, UploadState::Prepared);
    assert_eq!(status.expected_size, Some(3));
    let status_again = authority
        .upload_status(&actor, &file_uri, now)
        .await
        .unwrap()
        .expect("repeated prepared lookup succeeds");
    assert_eq!(status_again.state, UploadState::Prepared);
    let prepared_counters: (i64, i64) = sqlx::query_as(
        r#"
        SELECT transfer_grant.requests_used,
               COUNT(transfer_request.id)
          FROM file_transfer_grants AS transfer_grant
          LEFT JOIN file_transfer_requests AS transfer_request
            ON transfer_request.grant_id = transfer_grant.id
         WHERE transfer_grant.file_uri = $1
         GROUP BY transfer_grant.requests_used
        "#,
    )
    .bind(&file_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(prepared_counters, (0, 0));

    let mut other_subject = principal(&tenant);
    other_subject.sub = "someone-else".to_owned();
    assert!(authority
        .upload_status(&other_subject, &file_uri, now)
        .await
        .unwrap()
        .is_none());

    let mut other_profile = actor.clone();
    other_profile.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
        profile_id: "another-profile".to_owned(),
        profile_name: "another profile".to_owned(),
        allowed_servers: None,
        allowed_tools: None,
    });
    assert!(authority
        .upload_status(&other_profile, &file_uri, now)
        .await
        .unwrap()
        .is_none());

    let exchange_uri = "https://gateway.example/file-transfers/credentials";
    let exchange_proof = helper.proof("status-exchange", "POST", exchange_uri, None, now);
    let issued = authority
        .exchange_credential(&prepared.handle, &exchange_proof, "POST", exchange_uri, now)
        .await
        .unwrap();
    let upload_uri = "https://gateway.example/file-transfers/status/content";
    let upload_proof = helper.proof(
        "status-upload",
        "PUT",
        upload_uri,
        Some(issued.credential.expose()),
        now,
    );
    let authorized = authority
        .authorize_request(&issued.credential, &upload_proof, "PUT", upload_uri, now)
        .await
        .unwrap();
    let owner = GatewayFileOwner {
        tenant_id: actor.tenant.clone(),
        principal_sub: actor.sub.clone(),
        principal_issuer: actor.issuer.clone(),
    };
    let staged = storage
        .stage_upload(
            file_id,
            NewGatewayFile {
                batch_id: file_id,
                owner,
                invocation_id,
                upstream_server: "gateway-files".to_owned(),
                upstream_tool: "prepare_upload".to_owned(),
                upstream_uri: source_reference,
                display_name: None,
                media_type: Some("application/octet-stream".to_owned()),
                expected_size: Some(bytes.len() as u64),
                expected_sha256: Some(Sha256::digest(&bytes).to_vec()),
                max_bytes: None,
                inspection_status: FileInspectionStatus::Uninspectable,
                retention: Duration::minutes(5),
            },
            futures::stream::iter([Ok::<_, std::io::Error>(bytes)]),
        )
        .await
        .unwrap();
    authority
        .complete_upload(
            &authorized,
            file_id,
            staged.size,
            &staged.sha256,
            Duration::minutes(5),
        )
        .await
        .unwrap();

    let counters_before_ready_reads: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT transfer_grant.requests_used,
               COUNT(transfer_request.id),
               COUNT(transfer_request.id) FILTER (WHERE transfer_request.status = 'completed')
          FROM file_transfer_grants AS transfer_grant
          LEFT JOIN file_transfer_requests AS transfer_request
            ON transfer_request.grant_id = transfer_grant.id
         WHERE transfer_grant.file_uri = $1
         GROUP BY transfer_grant.requests_used
        "#,
    )
    .bind(&file_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    for _ in 0..2 {
        let ready = authority
            .upload_status(&actor, &file_uri, OffsetDateTime::now_utc())
            .await
            .unwrap()
            .expect("lost upload response reconciles to ready");
        assert_eq!(ready.state, UploadState::Ready);
    }
    let counters_after_ready_reads: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT transfer_grant.requests_used,
               COUNT(transfer_request.id),
               COUNT(transfer_request.id) FILTER (WHERE transfer_request.status = 'completed')
          FROM file_transfer_grants AS transfer_grant
          LEFT JOIN file_transfer_requests AS transfer_request
            ON transfer_request.grant_id = transfer_grant.id
         WHERE transfer_grant.file_uri = $1
         GROUP BY transfer_grant.requests_used
        "#,
    )
    .bind(&file_uri)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(counters_before_ready_reads, (1, 1, 1));
    assert_eq!(counters_after_ready_reads, counters_before_ready_reads);

    sqlx::query("UPDATE file_transfer_grants SET expires_at = now() - interval '1 second' WHERE file_uri = $1")
        .bind(&file_uri)
        .execute(&pool)
        .await
        .unwrap();
    waygate_transfer::TransferStore::sweep_expired(store.as_ref(), 1_000)
        .await
        .unwrap();
    let retained = authority
        .upload_status(&actor, &file_uri, OffsetDateTime::now_utc())
        .await
        .unwrap()
        .expect("ready file retains its profile-scoped reconciliation grant");
    assert_eq!(retained.state, UploadState::Ready);

    sqlx::query("UPDATE gateway_files SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(file_id)
        .execute(&pool)
        .await
        .unwrap();
    waygate_transfer::TransferStore::sweep_expired(store.as_ref(), 1_000)
        .await
        .unwrap();
    assert!(authority
        .upload_status(&actor, &file_uri, OffsetDateTime::now_utc())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authority_transitions_are_atomic_and_sender_constrained() {
    let _sweep_guard = TRANSFER_SWEEP_LOCK.lock().await;
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("transfer-{}", Uuid::new_v4().simple());
    seed_tenant(&pool, &tenant).await;
    let store = Arc::new(PgTransferStore::new(pool.clone()));
    let evidence = Arc::new(InMemorySink::new());
    let authority = Arc::new(TransferAuthority::new(
        store.clone(),
        evidence.clone(),
        DpopVerifier::new(Duration::minutes(5), Duration::seconds(30)).unwrap(),
    ));
    let mut actor = principal(&tenant);
    actor.api_key_profile_restrictions = Some(ApiKeyProfileRestrictions {
        profile_id: "profile-with-minting-constraints".into(),
        profile_name: "minting-only".into(),
        allowed_servers: Some(Vec::new()),
        allowed_tools: Some(Vec::new()),
    });
    let helper = HelperKey::new(41);
    let wrong_helper = HelperKey::new(42);
    let now = OffsetDateTime::now_utc();
    let endpoint = "https://gateway.example/file-transfers/credentials";

    let unknown_credential =
        TransferCredential::parse(format!("ftc_{}", URL_SAFE_NO_PAD.encode([99_u8; 32]))).unwrap();
    let unknown_request_uri = "https://gateway.example/file-transfers/unknown/content";
    let unknown_proof = helper.proof(
        "unknown-credential",
        "PUT",
        unknown_request_uri,
        Some(unknown_credential.expose()),
        now,
    );
    let evidence_before = evidence.snapshot().await.len();
    assert!(matches!(
        authority
            .authorize_request(
                &unknown_credential,
                &unknown_proof,
                "PUT",
                unknown_request_uri,
                now,
            )
            .await,
        Err(AuthorityError::CredentialUnavailable)
    ));
    let unknown_replay_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
              FROM file_transfer_dpop_replays
             WHERE helper_jkt = $1 AND jti = $2
        )
        "#,
    )
    .bind(helper.thumbprint())
    .bind(format!("{}-unknown-credential", helper.jti_prefix))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!unknown_replay_exists);
    assert_eq!(evidence.snapshot().await.len(), evidence_before);

    let wrong_key_grant = authority
        .create_grant(&actor, upload_grant(helper.thumbprint(), now), now)
        .await
        .unwrap();
    let wrong_proof = wrong_helper.proof("wrong-key", "POST", endpoint, None, now);
    assert!(matches!(
        authority
            .exchange_credential(&wrong_key_grant.handle, &wrong_proof, "POST", endpoint, now)
            .await,
        Err(AuthorityError::GrantUnavailable)
    ));

    let public = authority
        .create_grant(&actor, upload_grant(helper.thumbprint(), now), now)
        .await
        .unwrap();
    let proof_a = helper.proof("exchange-a", "POST", endpoint, None, now);
    let proof_b = helper.proof("exchange-b", "POST", endpoint, None, now);
    let (first, second) = tokio::join!(
        authority.exchange_credential(&public.handle, &proof_a, "POST", endpoint, now),
        authority.exchange_credential(&public.handle, &proof_b, "POST", endpoint, now),
    );
    let issued = match (first, second) {
        (Ok(issued), Err(AuthorityError::GrantUnavailable))
        | (Err(AuthorityError::GrantUnavailable), Ok(issued)) => issued,
        other => panic!("exactly one exchange must win, got {other:?}"),
    };
    assert_eq!(
        issued.grant.owner.credential_profile_id.as_deref(),
        Some("profile-with-minting-constraints")
    );

    let request_uri = "https://gateway.example/file-transfers/grant/content";
    let request_a = helper.proof(
        "request-a",
        "PUT",
        request_uri,
        Some(issued.credential.expose()),
        now,
    );
    let request_b = helper.proof(
        "request-b",
        "PUT",
        request_uri,
        Some(issued.credential.expose()),
        now,
    );
    let (first, second) = tokio::join!(
        authority.authorize_request(&issued.credential, &request_a, "PUT", request_uri, now,),
        authority.authorize_request(&issued.credential, &request_b, "PUT", request_uri, now,),
    );
    let authorized = match (first, second) {
        (Ok(authorized), Err(AuthorityError::CredentialUnavailable))
        | (Err(AuthorityError::CredentialUnavailable), Ok(authorized)) => authorized,
        other => panic!("exactly one transfer request must win, got {other:?}"),
    };

    // Expiry governs whether a request may start. It must not become a hidden
    // total timeout after a potentially very large stream is already in flight.
    sqlx::query(
        "UPDATE file_transfer_grants SET expires_at = now() - interval '1 second', \
         credential_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(authorized.grant.id)
    .execute(&pool)
    .await
    .unwrap();
    waygate_transfer::TransferStore::sweep_expired(store.as_ref(), 1_000)
        .await
        .unwrap();
    let state: String = sqlx::query_scalar("SELECT status FROM file_transfer_grants WHERE id = $1")
        .bind(authorized.grant.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "active");
    authority.heartbeat(&authorized).await.unwrap();
    let heartbeat: OffsetDateTime =
        sqlx::query_scalar("SELECT active_heartbeat_at FROM file_transfer_grants WHERE id = $1")
            .bind(authorized.grant.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(heartbeat > OffsetDateTime::now_utc() - Duration::seconds(5));

    let completed = authority
        .complete(&authorized, 3, Some(&[1, 2, 3]))
        .await
        .unwrap();
    assert_eq!(completed.status.as_str(), "completed");
    let completed_grant_id = completed.id;

    let abandoned = authority
        .create_grant(&actor, upload_grant(helper.thumbprint(), now), now)
        .await
        .unwrap();
    let abandoned_exchange = helper.proof("exchange-abandoned", "POST", endpoint, None, now);
    let abandoned = authority
        .exchange_credential(
            &abandoned.handle,
            &abandoned_exchange,
            "POST",
            endpoint,
            now,
        )
        .await
        .unwrap();
    let abandoned_proof = helper.proof(
        "request-abandoned",
        "PUT",
        request_uri,
        Some(abandoned.credential.expose()),
        now,
    );
    let abandoned = authority
        .authorize_request(
            &abandoned.credential,
            &abandoned_proof,
            "PUT",
            request_uri,
            now,
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE file_transfer_grants \
            SET expires_at = now() - interval '1 second', \
                active_heartbeat_at = now() - interval '10 minutes' \
          WHERE id = $1",
    )
    .bind(abandoned.grant.id)
    .execute(&pool)
    .await
    .unwrap();
    waygate_transfer::TransferStore::sweep_expired(store.as_ref(), 1_000)
        .await
        .unwrap();
    let abandoned_state: String =
        sqlx::query_scalar("SELECT status FROM file_transfer_grants WHERE id = $1")
            .bind(abandoned.grant.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(abandoned_state, "failed");
    waygate_transfer::TransferStore::sweep_expired(store.as_ref(), 1_000)
        .await
        .unwrap();
    let abandoned_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_transfer_grants WHERE id = $1")
            .bind(abandoned.grant.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(abandoned_rows, 0);

    let mut multi_spec = upload_grant(helper.thumbprint(), now);
    multi_spec.max_requests = 3;
    let multi = authority
        .create_grant(&actor, multi_spec, now)
        .await
        .unwrap();
    let multi_exchange = helper.proof("exchange-multi", "POST", endpoint, None, now);
    let multi = authority
        .exchange_credential(&multi.handle, &multi_exchange, "POST", endpoint, now)
        .await
        .unwrap();
    let multi_request_a = helper.proof(
        "request-multi-a",
        "PUT",
        request_uri,
        Some(multi.credential.expose()),
        now,
    );
    let multi_request_b = helper.proof(
        "request-multi-b",
        "PUT",
        request_uri,
        Some(multi.credential.expose()),
        now,
    );
    let multi_request_c = helper.proof(
        "request-multi-c",
        "PUT",
        request_uri,
        Some(multi.credential.expose()),
        now,
    );
    let multi_a = authority
        .authorize_request(&multi.credential, &multi_request_a, "PUT", request_uri, now)
        .await
        .unwrap();
    let multi_b = authority
        .authorize_request(&multi.credential, &multi_request_b, "PUT", request_uri, now)
        .await
        .unwrap();
    let multi_c = authority
        .authorize_request(&multi.credential, &multi_request_c, "PUT", request_uri, now)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE file_transfer_grants SET expires_at = now() - interval '1 second', \
         credential_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(multi.grant.id)
    .execute(&pool)
    .await
    .unwrap();
    let after_first = authority
        .complete(&multi_a, 3, Some(&[1, 2, 3]))
        .await
        .unwrap();
    assert_eq!(after_first.status.as_str(), "active");
    assert!(matches!(
        authority.complete(&multi_b, 4, Some(&[1, 2, 3])).await,
        Err(AuthorityError::IntegrityMismatch)
    ));
    let after_failure: String =
        sqlx::query_scalar("SELECT status FROM file_transfer_grants WHERE id = $1")
            .bind(multi.grant.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after_failure, "active");
    let after_third = authority
        .complete(&multi_c, 3, Some(&[1, 2, 3]))
        .await
        .unwrap();
    assert_eq!(after_third.status.as_str(), "failed");
    let failed_grant_id = after_third.id;
    let completed_requests: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM file_transfer_requests \
         WHERE grant_id = $1 AND status = 'completed' AND observed_size = 3",
    )
    .bind(multi.grant.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(completed_requests, 2);
    let failed_requests: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM file_transfer_requests \
         WHERE grant_id = $1 AND status = 'failed'",
    )
    .bind(multi.grant.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(failed_requests, 1);

    // An integrity failure is a terminal use of its authorization. A caller
    // cannot retry the same durable start with different completion facts.
    let integrity = authority
        .create_grant(&actor, upload_grant(helper.thumbprint(), now), now)
        .await
        .unwrap();
    let integrity_proof = helper.proof("exchange-integrity", "POST", endpoint, None, now);
    let integrity = authority
        .exchange_credential(&integrity.handle, &integrity_proof, "POST", endpoint, now)
        .await
        .unwrap();
    let integrity_request = helper.proof(
        "request-integrity",
        "PUT",
        request_uri,
        Some(integrity.credential.expose()),
        now,
    );
    let integrity_authorized = authority
        .authorize_request(
            &integrity.credential,
            &integrity_request,
            "PUT",
            request_uri,
            now,
        )
        .await
        .unwrap();
    let unavailable_evidence = TransferAuthority::new(
        store.clone(),
        Arc::new(NullSink),
        DpopVerifier::new(Duration::minutes(5), Duration::seconds(30)).unwrap(),
    );
    assert!(matches!(
        unavailable_evidence
            .complete(&integrity_authorized, 4, Some(&[1, 2, 3]))
            .await,
        Err(AuthorityError::Evidence(_))
    ));
    let unchanged: (String, String) = sqlx::query_as(
        r#"
        SELECT transfer_grant.status, transfer_request.status
          FROM file_transfer_grants AS transfer_grant
          JOIN file_transfer_requests AS transfer_request
            ON transfer_request.grant_id = transfer_grant.id
         WHERE transfer_grant.id = $1 AND transfer_request.id = $2
        "#,
    )
    .bind(integrity_authorized.grant.id)
    .bind(integrity_authorized.authorization_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unchanged, ("active".into(), "authorized".into()));
    assert!(matches!(
        unavailable_evidence
            .fail_authorized_request(&integrity_authorized, "transfer_refused")
            .await,
        Err(AuthorityError::Evidence(_))
    ));
    assert!(matches!(
        authority
            .complete(&integrity_authorized, 3, Some(&[1, 2, 3]))
            .await,
        Err(AuthorityError::GrantUnavailable)
    ));
    let terminal: (String, Option<String>, String, Option<String>) = sqlx::query_as(
        r#"
        SELECT transfer_grant.status, transfer_grant.failure_code,
               transfer_request.status, transfer_request.failure_code
          FROM file_transfer_grants AS transfer_grant
          JOIN file_transfer_requests AS transfer_request
            ON transfer_request.grant_id = transfer_grant.id
         WHERE transfer_grant.id = $1 AND transfer_request.id = $2
        "#,
    )
    .bind(integrity_authorized.grant.id)
    .bind(integrity_authorized.authorization_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        terminal,
        (
            "failed".into(),
            Some("transfer_refused".into()),
            "failed".into(),
            Some("transfer_refused".into()),
        )
    );

    let revocable = authority
        .create_grant(&actor, upload_grant(helper.thumbprint(), now), now)
        .await
        .unwrap();
    let revocable_proof = helper.proof("exchange-revocable", "POST", endpoint, None, now);
    let revocable = authority
        .exchange_credential(&revocable.handle, &revocable_proof, "POST", endpoint, now)
        .await
        .unwrap();
    assert!(authority
        .revoke(&revocable.grant, "caller_revoked")
        .await
        .unwrap());
    let revoked_request = helper.proof(
        "request-revoked",
        "PUT",
        request_uri,
        Some(revocable.credential.expose()),
        now,
    );
    assert!(matches!(
        authority
            .authorize_request(
                &revocable.credential,
                &revoked_request,
                "PUT",
                request_uri,
                now,
            )
            .await,
        Err(AuthorityError::CredentialUnavailable)
    ));

    let expired = authority
        .create_grant(&actor, upload_grant(helper.thumbprint(), now), now)
        .await
        .unwrap();
    let expired_grant_id: Uuid =
        sqlx::query_scalar("SELECT id FROM file_transfer_grants WHERE file_uri = $1")
            .bind(&expired.file_uri)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("UPDATE file_transfer_grants SET expires_at = now() WHERE id = $1")
        .bind(expired_grant_id)
        .execute(&pool)
        .await
        .unwrap();
    let expired_proof = helper.proof("exchange-expired", "POST", endpoint, None, now);
    assert!(matches!(
        authority
            .exchange_credential(&expired.handle, &expired_proof, "POST", endpoint, now)
            .await,
        Err(AuthorityError::GrantUnavailable)
    ));

    let events = evidence.snapshot().await;
    let key_mismatch = events
        .iter()
        .find(|event| event.reason.as_deref() == Some("helper_key_mismatch"))
        .expect("helper-key mismatch evidence");
    assert!(key_mismatch.principal.is_none());
    assert_eq!(key_mismatch.tenant, actor.tenant);
    let target: serde_json::Value = serde_json::from_str(
        key_mismatch
            .target
            .as_deref()
            .expect("transfer evidence target"),
    )
    .expect("structured transfer evidence target");
    let wrong_key_invocation: String =
        sqlx::query_scalar("SELECT invocation_id FROM file_transfer_grants WHERE file_uri = $1")
            .bind(&wrong_key_grant.file_uri)
            .fetch_one(&pool)
            .await
            .expect("wrong-key grant invocation");
    assert_eq!(target["file_uri"], wrong_key_grant.file_uri);
    assert_eq!(target["invocation_id"], wrong_key_invocation);
    assert!(target["grant_id"]
        .as_str()
        .is_some_and(|id| Uuid::parse_str(id).is_ok()));
    assert!(events
        .iter()
        .any(|event| event.action == "file_transfer.credential.exchanged"));
    assert!(events
        .iter()
        .any(|event| event.action == "file_transfer.completion.refused"));
    assert!(events
        .iter()
        .any(|event| event.action == "file_transfer.completion.authorized"));

    let revoked_grant_id = revocable.grant.id;
    sqlx::query(
        "UPDATE file_transfer_grants SET expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(revoked_grant_id)
    .execute(&pool)
    .await
    .unwrap();
    waygate_transfer::TransferStore::sweep_expired(store.as_ref(), 1_000)
        .await
        .unwrap();
    let terminal_grant_ids = [completed_grant_id, failed_grant_id, revoked_grant_id];
    let retained_grants: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_transfer_grants WHERE id = ANY($1)")
            .bind(&terminal_grant_ids[..])
            .fetch_one(&pool)
            .await
            .unwrap();
    let retained_requests: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_transfer_requests WHERE grant_id = ANY($1)")
            .bind(&terminal_grant_ids[..])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained_grants, 0);
    assert_eq!(retained_requests, 0);
}

#[tokio::test]
async fn native_download_credentials_are_narrow_and_single_use() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("native-transfer-{}", Uuid::new_v4().simple());
    seed_tenant(&pool, &tenant).await;
    let authority = TransferAuthority::new(
        Arc::new(PgTransferStore::new(pool)),
        Arc::new(InMemorySink::new()),
        DpopVerifier::new(Duration::minutes(5), Duration::seconds(30)).unwrap(),
    );
    let actor = principal(&tenant);
    let now = OffsetDateTime::now_utc();
    let digest = Sha256::digest(b"file bytes").to_vec();
    let issued = authority
        .issue_native_download_credential(
            &actor,
            NewTransferGrant {
                invocation_id: format!("call-{}", Uuid::new_v4()),
                file_uri: format!("mcp-file://gateway/{}", Uuid::new_v4()),
                direction: TransferDirection::Download,
                source: TransferEndpoint::upstream("printable", "output").unwrap(),
                destination: TransferEndpoint::client(NATIVE_MCP_CLIENT_REFERENCE).unwrap(),
                helper_jkt: String::new(),
                max_bytes: 10,
                expected_size: Some(10),
                media_type: Some("application/octet-stream".to_owned()),
                expected_digest: Some(TransferDigest {
                    algorithm: "sha-256".to_owned(),
                    value: digest,
                }),
                max_requests: 1,
                expires_at: now + Duration::minutes(10),
                credential_ttl: Duration::minutes(2),
            },
            now,
        )
        .await
        .expect("issue native credential");

    let authorized = authority
        .authorize_native_request(&issued.credential)
        .await
        .expect("authorize native download once");
    assert_eq!(authorized.grant.direction, TransferDirection::Download);
    assert!(matches!(
        authority.authorize_native_request(&issued.credential).await,
        Err(AuthorityError::CredentialUnavailable)
    ));
}

#[tokio::test]
async fn dpop_credential_cannot_be_used_as_a_native_bearer() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("generic-transfer-{}", Uuid::new_v4().simple());
    seed_tenant(&pool, &tenant).await;
    let authority = TransferAuthority::new(
        Arc::new(PgTransferStore::new(pool)),
        Arc::new(InMemorySink::new()),
        DpopVerifier::new(Duration::minutes(5), Duration::seconds(30)).unwrap(),
    );
    let actor = principal(&tenant);
    let helper = HelperKey::new(44);
    let now = OffsetDateTime::now_utc();
    let exchange_uri = "https://gateway.example/file-transfers/credentials";
    let request_uri = "https://gateway.example/file-transfers/content";
    let grant = authority
        .create_grant(
            &actor,
            NewTransferGrant {
                invocation_id: format!("call-{}", Uuid::new_v4()),
                file_uri: format!("mcp-file://gateway/{}", Uuid::new_v4()),
                direction: TransferDirection::Download,
                source: TransferEndpoint::upstream("printable", "output").unwrap(),
                destination: TransferEndpoint::client(waygate_transfer::GENERIC_HELPER_REFERENCE)
                    .unwrap(),
                helper_jkt: helper.thumbprint(),
                max_bytes: 10,
                expected_size: Some(10),
                media_type: Some("application/octet-stream".to_owned()),
                expected_digest: None,
                max_requests: 1,
                expires_at: now + Duration::minutes(10),
                credential_ttl: Duration::minutes(2),
            },
            now,
        )
        .await
        .expect("create generic grant");
    let exchange_proof = helper.proof("generic-exchange", "POST", exchange_uri, None, now);
    let issued = authority
        .exchange_credential(&grant.handle, &exchange_proof, "POST", exchange_uri, now)
        .await
        .expect("exchange generic credential");

    assert!(matches!(
        authority.authorize_native_request(&issued.credential).await,
        Err(AuthorityError::CredentialUnavailable)
    ));
    let request_proof = helper.proof(
        "generic-request",
        "GET",
        request_uri,
        Some(issued.credential.expose()),
        now,
    );
    authority
        .authorize_request(&issued.credential, &request_proof, "GET", request_uri, now)
        .await
        .expect("native refusal does not consume generic credential");
}
