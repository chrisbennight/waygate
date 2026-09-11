use std::convert::Infallible;
use std::future::IntoFuture;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use bytes::Bytes;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::sync::{mpsc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;
use waygate_core::TenantId;
use waygate_evidence::audit::{EvidencePosture, InMemorySink};
use waygate_oidc::{AuthMethod, Principal};
use waygate_transfer::{
    file_download_router, file_transfer_router, DpopVerifier, FileInspectionStatus,
    GatewayFileOwner, GatewayFileStorage, NewGatewayFile, NewTransferGrant, PgTransferStore,
    StoredGatewayFile, TransferAuthority, TransferDigest, TransferDirection, TransferEndpoint,
    FILE_DOWNLOAD_PATH, FILE_UPLOAD_PATH, NATIVE_MCP_CLIENT_REFERENCE,
};

type ChunkReceiver = mpsc::Receiver<Bytes>;

fn principal(tenant: &str) -> Principal {
    Principal {
        sub: "file-user".to_owned(),
        email: None,
        groups: Vec::new(),
        issuer: "test-issuer".to_owned(),
        scopes: Vec::new(),
        tenant: TenantId::parse(tenant).expect("valid tenant"),
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
        roles: Vec::new(),
    }
}

#[tokio::test]
async fn recovered_bytes_preserve_content_and_owner_scoped_expiry() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("retained-file-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1)")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");
    let root = tempfile::tempdir().expect("file root");
    let storage = GatewayFileStorage::new(pool.clone(), root.path())
        .await
        .expect("storage");
    let owner = GatewayFileOwner {
        tenant_id: TenantId::parse(&tenant).expect("tenant"),
        principal_sub: "reader".into(),
        principal_issuer: "test-issuer".into(),
    };
    let bytes = b"complete retained body\0including binary bytes\xff".to_vec();
    let batch_id = Uuid::new_v4();
    let file = storage
        .stage_bytes(
            NewGatewayFile {
                batch_id,
                owner: owner.clone(),
                invocation_id: "retained-call".into(),
                upstream_server: "connector".into(),
                upstream_tool: "download".into(),
                upstream_uri: "connector-response:/body".into(),
                display_name: None,
                media_type: Some("application/octet-stream".into()),
                expected_size: Some(bytes.len() as u64),
                expected_sha256: None,
                max_bytes: Some(1024),
                inspection_status: FileInspectionStatus::Uninspectable,
                retention: Duration::minutes(5),
            },
            bytes.clone(),
        )
        .await
        .expect("stage recovered bytes");
    assert!(
        storage.find_ready(&owner, file.id).await.unwrap().is_none(),
        "unpublished bytes are private"
    );
    storage.publish_batch(batch_id, 1).await.expect("publish");
    let ready = storage
        .find_ready(&owner, file.id)
        .await
        .unwrap()
        .expect("owner access");
    assert_eq!(ready.sha256, Sha256::digest(&bytes).to_vec());
    assert_eq!(
        tokio::fs::read(storage.path_for(&ready)).await.unwrap(),
        bytes
    );
    let mut other = owner.clone();
    other.principal_sub = "another-reader".into();
    assert!(storage.find_ready(&other, file.id).await.unwrap().is_none());
    other = owner.clone();
    other.tenant_id = TenantId::parse("another-tenant").unwrap();
    assert!(storage.find_ready(&other, file.id).await.unwrap().is_none());
    sqlx::query("UPDATE gateway_files SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(file.id)
        .execute(&pool)
        .await
        .expect("expire file");
    assert!(storage.find_ready(&owner, file.id).await.unwrap().is_none());
    sqlx::query("DELETE FROM gateway_files WHERE id = $1")
        .bind(file.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn native_upload_stream_becomes_an_exact_ready_gateway_file() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("file-upload-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1)")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed upload tenant");
    let root = tempfile::tempdir().expect("upload file root");
    let storage = Arc::new(
        GatewayFileStorage::new(pool.clone(), root.path())
            .await
            .expect("build upload storage"),
    );
    let evidence = Arc::new(InMemorySink::new());
    let authority = Arc::new(TransferAuthority::new(
        Arc::new(PgTransferStore::new(pool.clone())),
        evidence.clone(),
        DpopVerifier::new(Duration::minutes(5), Duration::seconds(30)).expect("DPoP verifier"),
    ));
    let actor = principal(&tenant);
    let bytes = b"caller-file-stream";
    let file_id = Uuid::new_v4();
    let file_uri = format!("mcp-file://gateway/{file_id}");
    let now = OffsetDateTime::now_utc();
    let issued = authority
        .issue_native_upload_credential(
            &actor,
            NewTransferGrant {
                invocation_id: "client-upload-call".to_owned(),
                file_uri: file_uri.clone(),
                direction: TransferDirection::Upload,
                source: TransferEndpoint::client(NATIVE_MCP_CLIENT_REFERENCE)
                    .expect("native client endpoint"),
                destination: TransferEndpoint::upstream("gateway", file_uri.clone())
                    .expect("gateway endpoint"),
                helper_jkt: String::new(),
                max_bytes: i64::MAX as u64,
                expected_size: Some(bytes.len() as u64),
                media_type: Some("application/octet-stream".to_owned()),
                expected_digest: Some(TransferDigest {
                    algorithm: "sha-256".to_owned(),
                    value: Sha256::digest(bytes).to_vec(),
                }),
                max_requests: 1,
                expires_at: now + Duration::minutes(5),
                credential_ttl: Duration::minutes(2),
            },
            now,
        )
        .await
        .expect("issue native upload credential");
    let app = file_transfer_router(
        authority.clone(),
        storage.clone(),
        "https://gateway.example",
        waygate_transfer::FileTransferAdmission::new(2),
        Duration::minutes(5),
    );
    let body = Body::from_stream(futures::stream::iter([
        Ok::<_, Infallible>(Bytes::from_static(b"caller-file-")),
        Ok::<_, Infallible>(Bytes::from_static(b"stream")),
    ]));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("PUT")
                .uri(FILE_UPLOAD_PATH)
                .header(
                    "authorization",
                    format!("Bearer {}", issued.credential.expose()),
                )
                .header("content-type", "application/octet-stream")
                .body(body)
                .expect("upload request"),
        )
        .await
        .expect("upload response");
    assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    let ready = storage
        .find_ready(
            &GatewayFileOwner {
                tenant_id: actor.tenant.clone(),
                principal_sub: actor.sub.clone(),
                principal_issuer: actor.issuer.clone(),
            },
            file_id,
        )
        .await
        .expect("ready upload lookup")
        .expect("ready uploaded file");
    assert_eq!(ready.size, bytes.len() as u64);
    assert_eq!(ready.sha256, Sha256::digest(bytes).to_vec());
    assert_eq!(
        tokio::fs::read(storage.path_for(&ready))
            .await
            .expect("read uploaded file"),
        bytes
    );
    let states: (String, String, String, String, String) = sqlx::query_as(
        r#"
        SELECT transfer_grant.status, transfer_request.status, gateway_file.state,
               gateway_file.upstream_server, gateway_file.upstream_tool
          FROM file_transfer_grants AS transfer_grant
          JOIN file_transfer_requests AS transfer_request
            ON transfer_request.grant_id = transfer_grant.id
          JOIN gateway_files AS gateway_file
            ON gateway_file.id = $2
         WHERE transfer_grant.id = $1
        "#,
    )
    .bind(issued.grant.id)
    .bind(file_id)
    .fetch_one(&pool)
    .await
    .expect("upload completion states");
    assert_eq!(
        states,
        (
            "completed".to_owned(),
            "completed".to_owned(),
            "ready".to_owned(),
            "gateway-files".to_owned(),
            "prepare_upload".to_owned(),
        )
    );
    let upload_evidence = evidence.snapshot_with_posture().await;
    for action in [
        "file_transfer.bytes.received",
        "file_transfer.file.verified",
    ] {
        let recorded = upload_evidence
            .iter()
            .find(|record| record.event.action == action)
            .unwrap_or_else(|| panic!("missing {action} evidence"));
        assert_eq!(recorded.posture, EvidencePosture::Required);
        let target: serde_json::Value = serde_json::from_str(
            recorded
                .event
                .target
                .as_deref()
                .expect("upload evidence target"),
        )
        .expect("upload evidence target JSON");
        assert_eq!(target["file_uri"], file_uri);
        assert_eq!(target["invocation_id"], "client-upload-call");
        assert_eq!(target["size_bytes"], bytes.len() as u64);
        assert_eq!(
            target["sha256_digest"],
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
        );
        assert_eq!(target["media_type"], "application/octet-stream");
    }

    let refused_id = Uuid::new_v4();
    let refused_uri = format!("mcp-file://gateway/{refused_id}");
    let refused_bytes = b"not-published";
    let refused_issued = authority
        .issue_native_upload_credential(
            &actor,
            NewTransferGrant {
                invocation_id: "refused-upload-call".to_owned(),
                file_uri: refused_uri.clone(),
                direction: TransferDirection::Upload,
                source: TransferEndpoint::client(NATIVE_MCP_CLIENT_REFERENCE)
                    .expect("native client endpoint"),
                destination: TransferEndpoint::upstream("gateway", refused_uri)
                    .expect("gateway endpoint"),
                helper_jkt: String::new(),
                max_bytes: i64::MAX as u64,
                expected_size: Some(refused_bytes.len() as u64),
                media_type: Some("application/octet-stream".to_owned()),
                expected_digest: Some(TransferDigest {
                    algorithm: "sha-256".to_owned(),
                    value: Sha256::digest(refused_bytes).to_vec(),
                }),
                max_requests: 1,
                expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
                credential_ttl: Duration::minutes(2),
            },
            OffsetDateTime::now_utc(),
        )
        .await
        .expect("issue refused upload credential");
    let refused_authorized = authority
        .authorize_native_request(&refused_issued.credential)
        .await
        .expect("authorize refused upload request");
    let refused_staged = storage
        .stage_upload(
            refused_id,
            NewGatewayFile {
                batch_id: refused_id,
                owner: GatewayFileOwner {
                    tenant_id: actor.tenant.clone(),
                    principal_sub: actor.sub.clone(),
                    principal_issuer: actor.issuer.clone(),
                },
                invocation_id: "refused-upload-call".to_owned(),
                upstream_server: "gateway-files".to_owned(),
                upstream_tool: "prepare_upload".to_owned(),
                upstream_uri: NATIVE_MCP_CLIENT_REFERENCE.to_owned(),
                display_name: None,
                media_type: Some("application/octet-stream".to_owned()),
                expected_size: Some(refused_bytes.len() as u64),
                expected_sha256: Some(Sha256::digest(refused_bytes).to_vec()),
                max_bytes: None,
                inspection_status: FileInspectionStatus::Uninspectable,
                retention: Duration::days(30),
            },
            futures::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(refused_bytes))]),
        )
        .await
        .expect("stage refused upload");
    assert!(
        refused_staged.expires_at < OffsetDateTime::now_utc() + Duration::minutes(10),
        "an unpublished upload must use the short cleanup window"
    );
    sqlx::query("UPDATE gateway_files SET state = 'deleting' WHERE id = $1")
        .bind(refused_id)
        .execute(&pool)
        .await
        .expect("make publication unavailable");
    authority
        .complete_upload(
            &refused_authorized,
            refused_id,
            refused_staged.size,
            &refused_staged.sha256,
            Duration::minutes(5),
        )
        .await
        .expect_err("missing pending file must refuse the whole transition");
    let refused_states: (String, String, String) = sqlx::query_as(
        r#"
        SELECT transfer_grant.status, transfer_request.status, gateway_file.state
          FROM file_transfer_grants AS transfer_grant
          JOIN file_transfer_requests AS transfer_request
            ON transfer_request.grant_id = transfer_grant.id
          JOIN gateway_files AS gateway_file ON gateway_file.id = $2
         WHERE transfer_grant.id = $1
        "#,
    )
    .bind(refused_issued.grant.id)
    .bind(refused_id)
    .fetch_one(&pool)
    .await
    .expect("refused upload states");
    assert_eq!(
        refused_states,
        (
            "active".to_owned(),
            "authorized".to_owned(),
            "deleting".to_owned(),
        )
    );
    storage
        .sweep_expired(10)
        .await
        .expect("clean refused upload file");

    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("clean upload tenant");
    storage
        .sweep_expired(10)
        .await
        .expect("remove uploaded test files");
    let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM gateway_files WHERE id = $1")
        .bind(file_id)
        .fetch_one(&pool)
        .await
        .expect("count retained upload file");
    assert_eq!(retained, 0);
}

async fn native_credential(
    authority: &TransferAuthority,
    actor: &Principal,
    file: &StoredGatewayFile,
) -> waygate_transfer::IssuedNativeCredential {
    let now = OffsetDateTime::now_utc();
    authority
        .issue_native_download_credential(
            actor,
            NewTransferGrant {
                invocation_id: Uuid::now_v7().to_string(),
                file_uri: file.uri(),
                direction: TransferDirection::Download,
                source: TransferEndpoint::upstream(
                    file.upstream_server.clone(),
                    file.upstream_uri.clone(),
                )
                .expect("upstream endpoint"),
                destination: TransferEndpoint::client(NATIVE_MCP_CLIENT_REFERENCE)
                    .expect("native client endpoint"),
                helper_jkt: String::new(),
                max_bytes: file.size.max(1),
                expected_size: Some(file.size),
                media_type: file.media_type.clone(),
                expected_digest: Some(TransferDigest {
                    algorithm: "sha-256".to_owned(),
                    value: file.sha256.clone(),
                }),
                max_requests: 1,
                expires_at: file.expires_at,
                credential_ttl: Duration::minutes(2),
            },
            now,
        )
        .await
        .expect("issue native credential")
}

async fn streamed_body(State(receiver): State<Arc<Mutex<Option<ChunkReceiver>>>>) -> Response {
    let receiver = receiver
        .lock()
        .await
        .take()
        .expect("test endpoint is called once");
    let stream = futures::stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|chunk| (Ok::<Bytes, Infallible>(chunk), receiver))
    });
    Response::new(Body::from_stream(stream))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "wall-clock integration check; run explicitly on an idle host (docs/testing.md)"]
async fn file_storage_writes_chunks_before_the_response_finishes() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("file-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1)")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed file tenant");
    let root = tempfile::tempdir().expect("temp file root");
    let file_root = root.path().join("files");
    let storage = Arc::new(
        GatewayFileStorage::new(pool.clone(), &file_root)
            .await
            .expect("build file storage"),
    );

    let (sender, receiver) = mpsc::channel(2);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test file server");
    let address = listener.local_addr().expect("test server address");
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/file", get(streamed_body))
                .route("/bad", get(|| async { "helloworld" }))
                .with_state(Arc::new(Mutex::new(Some(receiver)))),
        )
        .into_future(),
    );
    let response = reqwest::get(format!("http://{address}/file"))
        .await
        .expect("start streamed response");
    let batch_id = Uuid::now_v7();
    let owner = GatewayFileOwner {
        tenant_id: TenantId::parse(&tenant).expect("valid tenant"),
        principal_sub: "file-user".to_owned(),
        principal_issuer: "test-issuer".to_owned(),
    };
    let stage_storage = storage.clone();
    let stage_owner = owner.clone();
    let stage = tokio::spawn(async move {
        stage_storage
            .stage_response(
                NewGatewayFile {
                    batch_id,
                    owner: stage_owner,
                    invocation_id: "call-file-storage-test".to_owned(),
                    upstream_server: "printable".to_owned(),
                    upstream_tool: "render".to_owned(),
                    upstream_uri: "mcp-file://printable/output".to_owned(),
                    display_name: Some("output.bin".to_owned()),
                    media_type: Some("application/octet-stream".to_owned()),
                    expected_size: Some(10),
                    expected_sha256: Some(Sha256::digest(b"helloworld").to_vec()),
                    max_bytes: None,
                    inspection_status: FileInspectionStatus::Uninspectable,
                    retention: Duration::minutes(5),
                },
                response,
            )
            .await
    });

    sender
        .send(Bytes::from_static(b"hello"))
        .await
        .expect("send first chunk");
    let partial_len = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let mut entries = tokio::fs::read_dir(&file_root)
                .await
                .expect("read file root");
            while let Some(entry) = entries.next_entry().await.expect("read entry") {
                if entry.file_name().to_string_lossy().ends_with(".part") {
                    let len = entry.metadata().await.expect("partial metadata").len();
                    if len == 5 {
                        return len;
                    }
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first chunk is written before completion");
    assert_eq!(partial_len, 5);
    assert!(
        !stage.is_finished(),
        "storage must still be waiting for chunk two"
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let completion_started_at = OffsetDateTime::now_utc();
    sender
        .send(Bytes::from_static(b"world"))
        .await
        .expect("send second chunk");
    drop(sender);
    let stored = stage.await.expect("stage task").expect("stage response");
    assert_eq!(stored.size, 10);
    assert!(
        stored.expires_at > completion_started_at + Duration::minutes(4) + Duration::seconds(59),
        "retention starts after the stream completes"
    );
    sqlx::query(
        "UPDATE gateway_files SET updated_at = now() - INTERVAL '10 minutes' WHERE id = $1",
    )
    .bind(stored.id)
    .execute(&pool)
    .await
    .expect("age complete pending file");
    storage
        .sweep_expired(10)
        .await
        .expect("sweep complete pending file");
    let state: String = sqlx::query_scalar("SELECT state FROM gateway_files WHERE id = $1")
        .bind(stored.id)
        .fetch_one(&pool)
        .await
        .expect("read complete pending file state");
    assert_eq!(
        state, "pending",
        "a completed batch member uses retention, not the abandoned-write clock"
    );
    assert!(matches!(
        storage.publish_batch(batch_id, 2).await,
        Err(waygate_transfer::FileStorageError::BatchUnavailable)
    ));

    let second_response = reqwest::get(format!("http://{address}/bad"))
        .await
        .expect("second file response");
    let second = storage
        .stage_response(
            NewGatewayFile {
                batch_id,
                owner: owner.clone(),
                invocation_id: "call-file-storage-test".to_owned(),
                upstream_server: "printable".to_owned(),
                upstream_tool: "render".to_owned(),
                upstream_uri: "mcp-file://printable/second".to_owned(),
                display_name: Some("second.bin".to_owned()),
                media_type: Some("application/octet-stream".to_owned()),
                expected_size: Some(10),
                expected_sha256: Some(Sha256::digest(b"helloworld").to_vec()),
                max_bytes: None,
                inspection_status: FileInspectionStatus::Uninspectable,
                retention: Duration::minutes(5),
            },
            second_response,
        )
        .await
        .expect("stage second file");
    sqlx::query("UPDATE gateway_files SET expires_at = now() - INTERVAL '1 second' WHERE id = $1")
        .bind(stored.id)
        .execute(&pool)
        .await
        .expect("expire completed sibling");
    storage
        .heartbeat_pending_batch(batch_id, second.id)
        .await
        .expect("renew active batch");
    storage.sweep_expired(10).await.expect("sweep active batch");
    let sibling_state: String = sqlx::query_scalar("SELECT state FROM gateway_files WHERE id = $1")
        .bind(stored.id)
        .fetch_one(&pool)
        .await
        .expect("read completed sibling state");
    assert_eq!(
        sibling_state, "pending",
        "an active batch keeps its completed siblings"
    );
    assert!(matches!(
        storage.publish_batch(batch_id, 1).await,
        Err(waygate_transfer::FileStorageError::BatchUnavailable)
    ));
    let published_at = OffsetDateTime::now_utc();
    storage
        .publish_batch(batch_id, 2)
        .await
        .expect("publish batch");
    let ready = storage
        .find_ready(&owner, stored.id)
        .await
        .expect("find ready file")
        .expect("ready file exists");
    assert!(
        ready.expires_at > published_at + Duration::minutes(4) + Duration::seconds(59),
        "retention starts when the complete batch is published"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        assert_eq!(
            tokio::fs::metadata(&file_root)
                .await
                .expect("file root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            tokio::fs::metadata(storage.path_for(&ready))
                .await
                .expect("stored file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let mut other_owner = owner.clone();
    other_owner.principal_sub = "another-user".to_owned();
    assert!(storage
        .find_ready(&other_owner, stored.id)
        .await
        .expect("other owner lookup")
        .is_none());
    assert_eq!(
        tokio::fs::read(storage.path_for(&ready))
            .await
            .expect("read saved file"),
        b"helloworld"
    );

    let bad_batch = Uuid::now_v7();
    let bad_response = reqwest::get(format!("http://{address}/bad"))
        .await
        .expect("bad response");
    assert!(storage
        .stage_response(
            NewGatewayFile {
                batch_id: bad_batch,
                owner: owner.clone(),
                invocation_id: "call-bad-size".to_owned(),
                upstream_server: "printable".to_owned(),
                upstream_tool: "render".to_owned(),
                upstream_uri: "mcp-file://printable/bad".to_owned(),
                display_name: None,
                media_type: None,
                expected_size: Some(9),
                expected_sha256: None,
                max_bytes: None,
                inspection_status: FileInspectionStatus::Uninspectable,
                retention: Duration::minutes(5),
            },
            bad_response,
        )
        .await
        .is_err());
    let bad_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM gateway_files WHERE batch_id = $1")
            .bind(bad_batch)
            .fetch_one(&pool)
            .await
            .expect("count failed file rows");
    assert_eq!(bad_rows, 0, "failed file row is removed");

    let authority = Arc::new(TransferAuthority::new(
        Arc::new(PgTransferStore::new(pool.clone())),
        Arc::new(InMemorySink::new()),
        DpopVerifier::new(Duration::minutes(5), Duration::seconds(30)).expect("DPoP verifier"),
    ));
    let actor = principal(&tenant);
    let first = native_credential(&authority, &actor, &ready).await;
    let app = file_download_router(
        authority.clone(),
        storage.clone(),
        "https://gateway.example",
        waygate_transfer::FileTransferAdmission::new(2),
    );
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(FILE_DOWNLOAD_PATH)
                .header(
                    "authorization",
                    format!("Bearer {}", first.credential.expose()),
                )
                .body(Body::empty())
                .expect("download request"),
        )
        .await
        .expect("download response");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(response.headers()["content-length"], "10");
    let body = axum::body::to_bytes(response.into_body(), 32)
        .await
        .expect("read download body");
    assert_eq!(body, b"helloworld"[..]);
    let completed: String =
        sqlx::query_scalar("SELECT status FROM file_transfer_requests WHERE grant_id = $1")
            .bind(first.grant.id)
            .fetch_one(&pool)
            .await
            .expect("completed request status");
    assert_eq!(completed, "completed");

    let interrupted = native_credential(&authority, &actor, &ready).await;
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(FILE_DOWNLOAD_PATH)
                .header(
                    "authorization",
                    format!("Bearer {}", interrupted.credential.expose()),
                )
                .body(Body::empty())
                .expect("interrupted request"),
        )
        .await
        .expect("interrupted response");
    let mut body = response.into_body().into_data_stream();
    assert_eq!(
        body.next()
            .await
            .expect("first body chunk")
            .expect("read first body chunk"),
        b"helloworld"[..]
    );
    drop(body);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let status: String =
                sqlx::query_scalar("SELECT status FROM file_transfer_requests WHERE grant_id = $1")
                    .bind(interrupted.grant.id)
                    .fetch_one(&pool)
                    .await
                    .expect("interrupted request status");
            if status == "failed" {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropped download is marked failed");

    sqlx::query("UPDATE gateway_files SET expires_at = now() WHERE id = $1")
        .bind(stored.id)
        .execute(&pool)
        .await
        .expect("expire file");
    assert_eq!(storage.sweep_expired(10).await.expect("sweep file"), 1);
    assert!(!storage.path_for(&ready).exists());
    server.abort();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("remove test tenant");
    storage
        .sweep_expired(10)
        .await
        .expect("remove files marked by tenant deletion");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_retention_follows_each_files_own_class() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("file-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1)")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed file tenant");
    let root = tempfile::tempdir().expect("temp file root");
    let storage = Arc::new(
        GatewayFileStorage::new(pool.clone(), &root.path().join("files"))
            .await
            .expect("build file storage"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test file server");
    let address = listener.local_addr().expect("test server address");
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/secret", get(|| async { "helloworld" }))
                .route("/plain", get(|| async { "helloworld" })),
        )
        .into_future(),
    );

    let batch_id = Uuid::now_v7();
    let stored = storage
        .stage_response(
            NewGatewayFile {
                batch_id,
                owner: GatewayFileOwner {
                    tenant_id: TenantId::parse(&tenant).expect("valid tenant"),
                    principal_sub: "file-user".to_owned(),
                    principal_issuer: "test-issuer".to_owned(),
                },
                invocation_id: "call-secret-retention-test".to_owned(),
                upstream_server: "example-secrets".to_owned(),
                upstream_tool: "example-secrets.read".to_owned(),
                upstream_uri: "mcp-file://example-secrets/secret".to_owned(),
                display_name: Some("secrets.reveal.json".to_owned()),
                media_type: Some("application/json".to_owned()),
                expected_size: Some(10),
                expected_sha256: Some(Sha256::digest(b"helloworld").to_vec()),
                max_bytes: None,
                inspection_status: FileInspectionStatus::Uninspectable,
                // The secret-class window selected at staging time.
                retention: Duration::minutes(2),
            },
            reqwest::get(format!("http://{address}/secret"))
                .await
                .expect("fetch staged body"),
        )
        .await
        .expect("stage secret-class file");
    let ordinary = storage
        .stage_response(
            NewGatewayFile {
                batch_id,
                owner: GatewayFileOwner {
                    tenant_id: TenantId::parse(&tenant).expect("valid tenant"),
                    principal_sub: "file-user".to_owned(),
                    principal_issuer: "test-issuer".to_owned(),
                },
                invocation_id: "call-secret-retention-test".to_owned(),
                upstream_server: "example-secrets".to_owned(),
                upstream_tool: "example-secrets.read".to_owned(),
                upstream_uri: "mcp-file://example-secrets/plain".to_owned(),
                display_name: Some("listing.json".to_owned()),
                media_type: Some("application/json".to_owned()),
                expected_size: Some(10),
                expected_sha256: Some(Sha256::digest(b"helloworld").to_vec()),
                max_bytes: None,
                inspection_status: FileInspectionStatus::Uninspectable,
                // An ordinary sibling in the same batch keeps the general window.
                retention: Duration::hours(24),
            },
            reqwest::get(format!("http://{address}/plain"))
                .await
                .expect("fetch ordinary body"),
        )
        .await
        .expect("stage ordinary sibling");

    // A sibling keepalive between staging and publication must not erase the
    // secret file's class: publication starts each row's own class window, so
    // the secret file stays short and the ordinary sibling gets its full
    // general window.
    storage
        .heartbeat_pending_batch(batch_id, ordinary.id)
        .await
        .expect("keepalive while the sibling streams");
    storage
        .publish_batch(batch_id, 2)
        .await
        .expect("publish batch");
    let published_at = OffsetDateTime::now_utc();
    let secret_expiry: OffsetDateTime =
        sqlx::query_scalar("SELECT expires_at FROM gateway_files WHERE id = $1")
            .bind(stored.id)
            .fetch_one(&pool)
            .await
            .expect("read secret expiry");
    assert!(
        secret_expiry <= published_at + Duration::minutes(3),
        "a secret-class file keeps its short window through keepalive and publication"
    );
    let ordinary_expiry: OffsetDateTime =
        sqlx::query_scalar("SELECT expires_at FROM gateway_files WHERE id = $1")
            .bind(ordinary.id)
            .fetch_one(&pool)
            .await
            .expect("read ordinary expiry");
    assert!(
        ordinary_expiry > published_at + Duration::hours(23),
        "an ordinary sibling keeps the general window"
    );
    // The database is shared across suites; remove this test's rows so they
    // cannot expire into another test's storage-global sweep, and its tenant
    // so reruns do not accumulate rows.
    sqlx::query("DELETE FROM gateway_files WHERE batch_id = $1")
        .bind(batch_id)
        .execute(&pool)
        .await
        .expect("remove test file rows");
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("remove test tenant");
    server.abort();
}
