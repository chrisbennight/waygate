use std::num::NonZeroUsize;
use std::sync::Arc;
use waygate_dashboard_stores::response_settings::{
    PgResponseSettingsStore, ResponseSettingsError, ResponseSettingsService, ResponseSettingsStore,
};
use waygate_test_support::response_settings::InMemoryResponseSettingsStore;

#[tokio::test]
async fn saved_default_is_shared_and_environment_override_is_optional() {
    let store = Arc::new(InMemoryResponseSettingsStore::default());
    let first = ResponseSettingsService::new(Some(store.clone()), None);
    let second = ResponseSettingsService::new(Some(store.clone()), None);
    let overridden = ResponseSettingsService::new(Some(store), NonZeroUsize::new(131072));
    assert_eq!(first.effective_threshold().await.unwrap().get(), 16384);
    first
        .update(0, NonZeroUsize::new(65536).unwrap(), "operator")
        .await
        .unwrap();
    assert_eq!(second.effective_threshold().await.unwrap().get(), 65536);
    assert_eq!(
        overridden.effective_threshold().await.unwrap().get(),
        131072
    );
    assert_eq!(
        overridden
            .get()
            .await
            .unwrap()
            .inline_response_threshold_bytes
            .get(),
        65536
    );
    assert!(matches!(
        second
            .update(0, NonZeroUsize::new(1).unwrap(), "stale")
            .await,
        Err(ResponseSettingsError::Conflict)
    ));
    let no_database = ResponseSettingsService::new(None, None);
    assert_eq!(
        no_database.effective_threshold().await.unwrap().get(),
        16384
    );
    assert!(!no_database.writable());
    assert!(matches!(
        no_database
            .update(0, NonZeroUsize::new(1).unwrap(), "operator")
            .await,
        Err(ResponseSettingsError::Unavailable)
    ));
}

#[tokio::test]
async fn postgres_settings_persist_and_concurrent_edits_have_one_winner() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let first = PgResponseSettingsStore::new(pool.clone());
    let second = PgResponseSettingsStore::new(pool.clone());
    let original = first.get().await.unwrap();
    let (a, b) = tokio::join!(
        first.update(
            original.revision,
            NonZeroUsize::new(65536).unwrap(),
            "operator-a"
        ),
        second.update(
            original.revision,
            NonZeroUsize::new(131072).unwrap(),
            "operator-b"
        ),
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let loser = if a.is_err() { &a } else { &b };
    assert!(matches!(loser, Err(ResponseSettingsError::Conflict)));
    let saved = first.get().await.unwrap();
    let reopened = PgResponseSettingsStore::new(pool.clone());
    assert_eq!(reopened.get().await.unwrap(), saved);
    let actor: String = sqlx::query_scalar(
        "SELECT updated_by FROM response_delivery_settings WHERE singleton = TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(actor == "operator-a" || actor == "operator-b");
    assert!(sqlx::query("UPDATE response_delivery_settings SET inline_response_threshold_bytes = 0 WHERE singleton = TRUE").execute(&pool).await.is_err());
    first
        .update(
            saved.revision,
            original.inline_response_threshold_bytes,
            "test-cleanup",
        )
        .await
        .unwrap();
}
