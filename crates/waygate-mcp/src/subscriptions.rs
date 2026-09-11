//! Downstream `subscriptions/listen` fan-out (MCP 2026-07-28).
//!
//! One accepted subscription is one long-lived stream that wakes on the
//! process-wide [`ToolCatalogEpoch`](crate::ToolCatalogEpoch): upstream
//! publications, reloads, and quarantine transitions can change the stable,
//! authorization-filtered 2026 `tools/list`. Search and invocation calls do
//! not mutate that projection and therefore do not wake a subscription.
//!
//! The signal is a coalescing watch channel: a `tools/list_changed`
//! notification means "refetch current state", never "replay every change",
//! so bursts collapse and multiple subscriptions each wake independently.

use rmcp::model::{
    PromptListChangedNotification, ServerNotification, SubscriptionFilter,
    ToolListChangedNotification,
};
use rmcp::service::{SubscriptionContext, SubscriptionSendError};
use tokio::sync::watch;

/// The subset of a requested filter the gateway serves.
///
/// Tools use the shared catalog signal. Configured skills also expose prompt
/// changes through that signal. Resource updates remain unsupported.
pub(crate) fn accepted_filter(
    requested: &SubscriptionFilter,
    prompts_enabled: bool,
) -> SubscriptionFilter {
    let mut accepted = SubscriptionFilter::new();
    if requested.tools_list_changed == Some(true) {
        accepted.tools_list_changed = Some(true);
    }
    if prompts_enabled && requested.prompts_list_changed == Some(true) {
        accepted.prompts_list_changed = Some(true);
    }
    accepted
}

/// Run one accepted subscription until the client cancels, the transport
/// closes, or the gateway shuts down the stream.
///
/// `catalog_changes` is `None` when no [`ToolCatalogEpoch`] was wired (test
/// servers). A subscription whose accepted filter carries no category just
/// parks on cancellation — the acknowledgment already told the client
/// nothing will fire.
pub(crate) async fn run_subscription(
    context: SubscriptionContext,
    catalog_changes: Option<watch::Receiver<u64>>,
) -> Result<(), rmcp::ErrorData> {
    let tools = context.accepted().tools_list_changed == Some(true);
    let prompts = context.accepted().prompts_list_changed == Some(true);
    if !tools && !prompts {
        context.cancelled().await;
        return Ok(());
    }
    let mut catalog = catalog_changes;
    loop {
        tokio::select! {
            _ = context.cancelled() => return Ok(()),
            changed = watch_changed(&mut catalog) => {
                if changed.is_err() {
                    // The process-wide epoch sender dropped during shutdown.
                    // No remaining source can change the stable projection.
                    context.cancelled().await;
                    return Ok(());
                }
                if (tools && notify(&context, ServerNotification::ToolListChangedNotification(
                    ToolListChangedNotification::default())).await.is_err())
                    || (prompts && notify(&context, ServerNotification::PromptListChangedNotification(
                        PromptListChangedNotification::default())).await.is_err()) {
                    return Ok(());
                }
            }
        }
    }
}

/// Wait on the optional catalog receiver; pends forever when absent so the
/// `select!` above reduces to the remaining arms.
async fn watch_changed(
    receiver: &mut Option<watch::Receiver<u64>>,
) -> Result<(), watch::error::RecvError> {
    match receiver {
        Some(receiver) => receiver.changed().await,
        None => std::future::pending().await,
    }
}

/// Send an accepted catalog notification through the filter-enforcing sink.
/// `Err(())` means the subscription is over (closed or cancelled mid-send);
/// a filter refusal cannot occur — the caller checked the accepted filter.
async fn notify(context: &SubscriptionContext, notification: ServerNotification) -> Result<(), ()> {
    match context.sink().send(notification).await {
        Ok(()) => Ok(()),
        Err(SubscriptionSendError::SubscriptionClosed) => Err(()),
        Err(error) => {
            tracing::debug!(%error, "subscription notify failed; ending stream");
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_filter_serves_tools_list_changed_only() {
        let mut requested = SubscriptionFilter::new();
        requested.tools_list_changed = Some(true);
        requested.prompts_list_changed = Some(true);
        requested.resources_list_changed = Some(true);
        requested.resource_subscriptions = Some(vec!["demo://guide".into()]);
        let accepted = accepted_filter(&requested, false);
        assert_eq!(accepted.tools_list_changed, Some(true));
        assert_eq!(accepted.prompts_list_changed, None);
        assert_eq!(accepted.resources_list_changed, None);
        assert_eq!(accepted.resource_subscriptions, None);

        let none = accepted_filter(&SubscriptionFilter::new(), false);
        assert_eq!(none.tools_list_changed, None);
        let with_skills = accepted_filter(&requested, true);
        assert_eq!(with_skills.prompts_list_changed, Some(true));
    }
}
