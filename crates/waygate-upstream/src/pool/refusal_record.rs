//! What the operator has already been told about upstreams serving tools with
//! a refused output schema.
//!
//! A refusal row is an EVENT: the gateway is publishing a tool whose advertised
//! `outputSchema` cannot describe a `structuredContent` object. It is owed once
//! per refusal that starts being served, not once per publication — a redial or
//! a rebuild that observes an unchanged refusal has nothing new to say.
//!
//! Deciding that requires knowing what came before, and the transitions that
//! change what is served run concurrently. Each one therefore stamps its sample
//! with a monotonic observation number taken WHILE it holds the lane guards
//! that make the sample true. Because those guards serialize the transitions
//! themselves, the stamps order the samples the same way the served set
//! actually changed, and the record keeps the highest stamp — per tool, and
//! per server for the tools an observation did not list at all. That ordering
//! is what lets a transition record both halves of a change — a tool that
//! starts being served and one that stops — without a later, slower task
//! undoing it, and without holding this lock across the lane guards.

use std::collections::HashMap;

use tokio::sync::Mutex;

use super::tool_listing::RejectedOutputSchema;

/// A monotonic stamp identifying one observation of a server's served set.
///
/// Taken under the lane guards that produced the sample, so a larger stamp is
/// a strictly later state of that server. The default is the stamp no
/// observation carries, meaning "nothing has been applied yet".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Observation(u64);

/// What one server has told the operator so far.
#[derive(Default)]
struct Served {
    /// Per unqualified tool name, the stamp of the observation that reported
    /// it. A tool ABSENT from this map is not being served, so the map holds
    /// only the refusals currently being served rather than every name ever
    /// seen — an upstream whose malformed tool names churn does not accumulate
    /// history here for the lifetime of the process.
    marks: HashMap<String, Observation>,
    /// Stamp of the newest observation applied for this server.
    ///
    /// Every observation carries the WHOLE served set, so this stamp dates the
    /// absences as well — including tools that appear in no mark at all.
    /// Without it an absence could only be recorded against a name already
    /// present, so a newer empty observation applied before a tool's first
    /// appearance would vanish and the overtaken sample that followed would
    /// leave the record claiming the tool is served now.
    newest: Observation,
}

#[derive(Default)]
pub(super) struct RefusalRecord {
    servers: Mutex<HashMap<String, Served>>,
    observations: std::sync::atomic::AtomicU64,
}

impl RefusalRecord {
    /// Stamp an observation. Call this while holding the lane guards whose
    /// contents the sample describes; that is what makes the stamps an order
    /// over the served set rather than over task wake-ups.
    pub(super) fn observe(&self) -> Observation {
        // Counts from one so that no real observation collides with the
        // "nothing applied yet" default.
        Observation(
            self.observations
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
                .saturating_add(1),
        )
    }

    /// Apply one complete observation of `server`'s served refusals and return
    /// those that owe a row.
    ///
    /// `served` must be the WHOLE set for that server at `at`, because the
    /// absences carry meaning: a tool the record believes is being served and
    /// this observation does not list has stopped being served, and a later
    /// observation that finds it again owes a fresh row.
    ///
    /// `may_open` governs only whether a server absent from the record may be
    /// added to it. A retired server has had its record dropped so a re-added
    /// name reports afresh; re-creating it here would hand that re-add a
    /// silence it never earned. The rows are returned either way, because an
    /// event stays true after the entry that served it goes away.
    ///
    /// It is a predicate rather than a `bool` on purpose: retirement erases the
    /// record under this same lock, so a value decided before the lock was held
    /// could be stale by the time it is used and would resurrect a record that
    /// [`Self::forget`] had already dropped. Taking a closure means the answer
    /// is necessarily read while the erasure cannot interleave, so the caller
    /// cannot express the racy version.
    pub(super) async fn apply(
        &self,
        server: &str,
        at: Observation,
        served: &[RejectedOutputSchema],
        may_open: impl FnOnce() -> bool,
    ) -> Vec<RejectedOutputSchema> {
        let mut servers = self.servers.lock().await;
        if !servers.contains_key(server) && !may_open() {
            // Nothing to record against, but the observation still happened.
            return served.to_vec();
        }
        let record = servers.entry(server.to_owned()).or_default();
        let newest = record.newest;

        let mut owed = Vec::new();
        for rejected in served {
            match record.marks.get(rejected.tool()) {
                // Already known to be served: the standing row says it. Only a
                // newer sample may move the stamp — an overtaken one describes
                // the same uninterrupted serving and has nothing to add.
                Some(marked_at) => {
                    if at > *marked_at {
                        record.marks.insert(rejected.tool().to_owned(), at);
                    }
                }
                // Not currently believed served, so this is a serving the
                // operator has not been told about. The row is owed even when a
                // newer observation has already overtaken this sample: the
                // interval was real while it lasted. Only a sample newer than
                // everything applied so far may claim the tool is served NOW —
                // an overtaken one leaves the later absence standing, which is
                // what makes the next resume a fresh event rather than a repeat.
                None => {
                    owed.push(rejected.clone());
                    if at > newest {
                        record.marks.insert(rejected.tool().to_owned(), at);
                    }
                }
            }
        }

        // The absences. A refusal this observation did not list has stopped
        // being served, so the next observation that finds it owes a row.
        // Skipped for an overtaken sample, whose view of what is absent a
        // newer observation has already superseded — and every mark is at or
        // below `newest`, so there is nothing newer here for it to discard.
        if at >= newest {
            record
                .marks
                .retain(|tool, _| served.iter().any(|rejected| rejected.tool() == tool));
        }

        record.newest = newest.max(at);
        owed
    }

    /// Drop everything recorded for `server`. Called when it leaves the
    /// registry: the record describes an upstream, and a name that comes back
    /// is a different arrangement that has told the operator nothing yet.
    pub(super) async fn forget(&self, server: &str) {
        self.servers.lock().await.remove(server);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(tool: &str) -> RejectedOutputSchema {
        RejectedOutputSchema::for_test(tool, "array")
    }

    fn tools(owed: &[RejectedOutputSchema]) -> Vec<&str> {
        owed.iter().map(|r| r.tool()).collect()
    }

    #[tokio::test]
    async fn a_first_observation_owes_a_row_and_a_repeat_does_not() {
        let record = RefusalRecord::default();
        let first = record.observe();
        assert_eq!(
            tools(&record.apply("s", first, &[refusal("t")], || true).await),
            vec!["t"],
        );
        let again = record.observe();
        assert!(
            record
                .apply("s", again, &[refusal("t")], || true)
                .await
                .is_empty(),
            "an unchanged refusal has nothing new to tell the operator",
        );
    }

    /// The window this ordering exists for: a tool stops being served and
    /// starts again before anything re-samples. Both halves are recorded by
    /// the transitions themselves, so the second serving owes its own row.
    #[tokio::test]
    async fn a_refusal_that_stops_and_resumes_owes_a_second_row() {
        let record = RefusalRecord::default();
        let served = record.observe();
        record.apply("s", served, &[refusal("t")], || true).await;

        let withheld = record.observe();
        assert!(
            record.apply("s", withheld, &[], || true).await.is_empty(),
            "withholding a tool is not itself something to report",
        );

        let resumed = record.observe();
        assert_eq!(
            tools(&record.apply("s", resumed, &[refusal("t")], || true).await),
            vec!["t"],
            "serving it again is a new event, not a repeat of the first",
        );
    }

    /// One direction of an overtaken transition: a stale view of an absent tool
    /// must not clear a serving that a newer observation already recorded, or
    /// the next observation would re-report a refusal already told.
    #[tokio::test]
    async fn a_stale_absence_does_not_clear_a_newer_serving() {
        let record = RefusalRecord::default();
        let stale = record.observe();
        let fresh = record.observe();

        assert_eq!(
            tools(&record.apply("s", fresh, &[refusal("t")], || true).await),
            vec!["t"],
        );
        assert!(
            record.apply("s", stale, &[], || true).await.is_empty(),
            "an older view of an absent tool must not clear a newer serving",
        );

        let later = record.observe();
        assert!(
            record
                .apply("s", later, &[refusal("t")], || true)
                .await
                .is_empty(),
            "the newer serving still stands, so there is nothing to re-report",
        );
    }

    /// The other direction, and the one a per-tool record alone cannot express:
    /// the newer observation finds the tool absent and lands FIRST, before the
    /// tool has ever been marked. Its absence must still stand, or the
    /// overtaken sample leaves the record claiming the tool is served now and
    /// swallows the row owed by the next genuine resume.
    #[tokio::test]
    async fn a_newer_absence_outlives_a_stale_serving_applied_after_it() {
        let record = RefusalRecord::default();
        let stale = record.observe();
        let fresh = record.observe();

        assert!(
            record.apply("s", fresh, &[], || true).await.is_empty(),
            "an absence is not itself something to report",
        );
        assert_eq!(
            tools(&record.apply("s", stale, &[refusal("t")], || true).await),
            vec!["t"],
            "the overtaken observation still owes its row: it was served then",
        );

        let resumed = record.observe();
        assert_eq!(
            tools(&record.apply("s", resumed, &[refusal("t")], || true).await),
            vec!["t"],
            "the newer absence stood, so serving it again is its own event",
        );
    }

    /// An overtaken resume where the record already carried a CLEARED mark. The
    /// newer withholding advances that mark, so the resume finds a stamp above
    /// its own; suppressing on stamp alone would drop a serving interval the
    /// operator was never told about.
    #[tokio::test]
    async fn an_overtaken_resume_owes_its_row_when_the_record_believed_it_absent() {
        let record = RefusalRecord::default();
        let served = record.observe();
        record.apply("s", served, &[refusal("t")], || true).await;
        let cleared = record.observe();
        record.apply("s", cleared, &[], || true).await;

        // The resume is stamped before the withholding but applies after it.
        let resumed = record.observe();
        let withheld = record.observe();
        assert!(
            record.apply("s", withheld, &[], || true).await.is_empty(),
            "withholding a tool is not itself something to report",
        );
        assert_eq!(
            tools(&record.apply("s", resumed, &[refusal("t")], || true).await),
            vec!["t"],
            "the resumed interval was real even though a newer sample passed it",
        );

        // The newer withholding still governs the state, so the next resume is
        // its own event rather than a repeat.
        let again = record.observe();
        assert_eq!(
            tools(&record.apply("s", again, &[refusal("t")], || true).await),
            vec!["t"],
        );
    }

    /// A continuously served refusal must not gain a row per redial just
    /// because two samples of it arrive out of order.
    #[tokio::test]
    async fn an_overtaken_sample_of_an_unbroken_serving_adds_nothing() {
        let record = RefusalRecord::default();
        let stale = record.observe();
        let fresh = record.observe();

        assert_eq!(
            tools(&record.apply("s", fresh, &[refusal("t")], || true).await),
            vec!["t"],
        );
        assert!(
            record
                .apply("s", stale, &[refusal("t")], || true)
                .await
                .is_empty(),
            "the same uninterrupted serving, seen twice, is one event",
        );
    }

    #[tokio::test]
    async fn forgetting_a_server_makes_its_next_refusal_new_again() {
        let record = RefusalRecord::default();
        let first = record.observe();
        record.apply("s", first, &[refusal("t")], || true).await;
        record.forget("s").await;

        let readded = record.observe();
        assert_eq!(
            tools(&record.apply("s", readded, &[refusal("t")], || true).await),
            vec!["t"],
            "a re-added server has told the operator nothing yet",
        );
    }

    /// A retired server's rows are still owed — the interval it served them was
    /// real — but its record must not come back, or a re-add inherits a
    /// silence it never earned.
    #[tokio::test]
    async fn a_retired_server_owes_its_rows_without_reopening_a_record() {
        let record = RefusalRecord::default();
        let at = record.observe();
        assert_eq!(
            tools(&record.apply("gone", at, &[refusal("t")], || false).await),
            vec!["t"],
        );

        let readded = record.observe();
        assert_eq!(
            tools(
                &record
                    .apply("gone", readded, &[refusal("t")], || true)
                    .await
            ),
            vec!["t"],
            "nothing was recorded for the retired server, so this is still new",
        );
    }
}
