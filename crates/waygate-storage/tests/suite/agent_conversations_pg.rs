//! Live Postgres smoke test for [`PgConversationStore`].
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset (CI provisions Postgres and
//! exports it). Pins the SQL-layer behaviours the chat handler depends on:
//!
//! 1. create → append → messages round-trip, ordered by `seq` (BIGSERIAL).
//! 2. Owner scoping on get / append / messages / set_title / delete.
//! 3. The `WHERE EXISTS` append guard: appending to a non-owned conversation
//!    writes nothing and returns None.
//! 4. Activity bump: an append moves the conversation to the top of `list`.
//! 5. Cascade delete removes the conversation's messages.
//! 6. `origin_page` (migration 0070) round-trips: set on create, surfaced on
//!    get/list, left untouched by retitle, and `None` when not supplied.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_storage::{ConversationStore, NewConversation, PgAuditSink, PgConversationStore};

async fn connect() -> Option<sqlx::PgPool> {
    let url = env::var("AUDIT_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    PgAuditSink::migrate(&pool).await.expect("apply migrations");
    Some(pool)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conversation_lifecycle_and_owner_isolation() {
    let Some(pool) = connect().await else {
        eprintln!("skipping conversations Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let store = PgConversationStore::new(pool.clone());
    let suffix = Uuid::new_v4().to_string();
    let alice = format!("alice-{suffix}");
    let bob = format!("bob-{suffix}");
    let tenant = format!("conv-{suffix}");

    // 1. Create two conversations for alice. c1 records an originating page;
    //    c2 leaves it unset (the pre-0070 / no-context shape).
    let c1 = store
        .create(NewConversation {
            tenant_id: &tenant,
            user_sub: &alice,
            agent_name: "ops-chat",
            title: "first",
            origin_page: Some("/policies"),
        })
        .await
        .expect("create c1");
    let c2 = store
        .create(NewConversation {
            tenant_id: &tenant,
            user_sub: &alice,
            agent_name: "ops-chat",
            title: "second",
            origin_page: None,
        })
        .await
        .expect("create c2");
    // 6. origin_page is persisted on create and reads back NULL when unset.
    assert_eq!(c1.origin_page.as_deref(), Some("/policies"));
    assert_eq!(c2.origin_page, None);

    // Append to c1; the two messages come back ordered by seq.
    store
        .append_message(
            &tenant,
            &alice,
            c1.id,
            "user",
            &serde_json::json!([{"type":"text","text":"hi"}]),
        )
        .await
        .expect("append")
        .expect("owned -> inserted");
    let m2 = store
        .append_message(
            &tenant,
            &alice,
            c1.id,
            "assistant",
            &serde_json::json!([{"type":"text","text":"yo"}]),
        )
        .await
        .expect("append")
        .expect("owned -> inserted");
    let msgs = store
        .messages(&tenant, &alice, c1.id, 100)
        .await
        .expect("messages");
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].role, "user");
    assert_eq!(msgs[1].role, "assistant");
    assert!(msgs[0].seq < msgs[1].seq, "BIGSERIAL seq orders messages");
    assert_eq!(msgs[1].id, m2.id);

    // 4. The append bumped c1's updated_at, so it now sorts ahead of c2.
    let list = store.list(&tenant, &alice, 100, 0).await.expect("list");
    assert_eq!(list.len(), 2);
    assert_eq!(
        list[0].id, c1.id,
        "the just-appended conversation sorts first"
    );
    // 6. list surfaces origin_page per row.
    assert_eq!(list[0].origin_page.as_deref(), Some("/policies"));

    // 2/3. Owner isolation: bob sees/touches none of alice's.
    assert!(store
        .get(&tenant, &bob, c1.id)
        .await
        .expect("get")
        .is_none());
    assert!(
        store
            .append_message(&tenant, &bob, c1.id, "user", &serde_json::json!([]))
            .await
            .expect("cross append")
            .is_none(),
        "WHERE EXISTS guard: appending to a non-owned conversation is a no-op",
    );
    assert!(store
        .messages(&tenant, &bob, c1.id, 100)
        .await
        .expect("cross messages")
        .is_empty());
    assert!(!store
        .set_title(&tenant, &bob, c1.id, "hacked")
        .await
        .expect("cross retitle"));
    assert!(!store
        .delete(&tenant, &bob, c1.id)
        .await
        .expect("cross delete"));
    // bob's cross-append wrote nothing — alice still has exactly 2 messages.
    assert_eq!(
        store
            .messages(&tenant, &alice, c1.id, 100)
            .await
            .unwrap()
            .len(),
        2
    );

    // retitle (owner) + the updated_at trigger fires.
    assert!(store
        .set_title(&tenant, &alice, c1.id, "renamed")
        .await
        .expect("retitle"));
    let after_retitle = store.get(&tenant, &alice, c1.id).await.unwrap().unwrap();
    assert_eq!(after_retitle.title, "renamed");
    // 6. retitle leaves origin_page untouched.
    assert_eq!(after_retitle.origin_page.as_deref(), Some("/policies"));

    // 5. Delete c1 cascades its messages; c2 is untouched.
    assert!(store
        .delete(&tenant, &alice, c1.id)
        .await
        .expect("delete c1"));
    assert!(store
        .messages(&tenant, &alice, c1.id, 100)
        .await
        .unwrap()
        .is_empty());
    assert!(store.get(&tenant, &alice, c1.id).await.unwrap().is_none());
    assert!(store.get(&tenant, &alice, c2.id).await.unwrap().is_some());

    // Cleanup: drop the remaining conversation (cascades).
    store
        .delete(&tenant, &alice, c2.id)
        .await
        .expect("cleanup c2");
}
