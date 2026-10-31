//! Browse source metadata and review exact skill contents without executing them.

use crate::{
    auth::CsrfToken,
    chrome::PageChrome,
    dashboard::{
        csrf_matches, format_ts_abs, overview_break_glass_admin, render, urlencode, user_display,
    },
    error::ApiError,
    review_diff::{self, DiffSection, DiffView, SectionBody, Segment, ViewLink},
    skill_reviews::{current_review, decide_core, review_error, SkillDecisionParams},
    state::AdminState,
    tenant_ctx::{self, TenantContext},
};
use askama::Template;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Router,
};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc};
use waygate_oidc::Principal;
use waygate_skills::review::{CandidateStatus, ReviewCandidate, ReviewDecision, SkillReview};

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/skills", get(skills_page))
        .route("/skills/review", get(review_page))
        .route("/skills/decision", post(decide))
}

pub(crate) async fn current_reviews(
    state: &AdminState,
    tenant: &str,
) -> Result<Vec<SkillReview>, ApiError> {
    let snapshot = state
        .hitl
        .skills
        .require()?
        .current()
        .ok_or(ApiError::ServiceUnavailable(
            state.hitl.skills.unavailable_msg(),
        ))?;
    let source = snapshot.source();
    let key = ReviewCandidate::source_key_for(&source.origin, &source.reference);
    let store =
        state.hitl.reviewed_skills.require()?.store().map_err(|_| {
            ApiError::ServiceUnavailable(state.hitl.reviewed_skills.unavailable_msg())
        })?;
    let mut after = String::new();
    let mut result = Vec::new();
    loop {
        let page = store
            .list(tenant, &key, &after, 200)
            .await
            .map_err(review_error)?;
        if page.is_empty() {
            break;
        }
        for review in page {
            after = review.skill_uri.clone();
            if snapshot
                .skills()
                .iter()
                .any(|skill| skill.uri == review.skill_uri)
            {
                result.push(review);
            }
        }
    }
    Ok(result)
}

pub(crate) fn review_url(uri: &str) -> String {
    format!("/skills/review?uri={}", urlencode(uri))
}

pub(crate) fn review_trigger(review: &SkillReview) -> String {
    let Some(serving) = &review.serving else {
        return "Initial approval required".into();
    };
    let mut triggers = Vec::new();
    if serving.skill().frontmatter != review.candidate.skill().frontmatter {
        triggers.push("Skill metadata changed");
    }
    let before: BTreeMap<_, _> = serving
        .skill()
        .resources
        .iter()
        .map(|file| (&file.uri, file))
        .collect();
    let after: BTreeMap<_, _> = review
        .candidate
        .skill()
        .resources
        .iter()
        .map(|file| (&file.uri, file))
        .collect();
    if before.get(&review.skill_uri) != after.get(&review.skill_uri) {
        triggers.push("Instructions changed");
    }
    if after.keys().any(|uri| !before.contains_key(uri)) {
        triggers.push("Files added");
    }
    if before.keys().any(|uri| !after.contains_key(uri)) {
        triggers.push("Files removed");
    }
    if before.iter().any(|(uri, file)| {
        *uri != &review.skill_uri && after.get(uri).is_some_and(|other| other != file)
    }) {
        triggers.push("Supporting files changed");
    }
    if serving.source().origin != review.candidate.source().origin
        || serving.source().reference != review.candidate.source().reference
    {
        triggers.push("Source changed");
    }
    if triggers.is_empty() {
        "Approved content".into()
    } else {
        triggers.join("; ")
    }
}

fn status(review: &SkillReview) -> &'static str {
    if review.quarantined {
        "Quarantined"
    } else {
        match review.candidate_status {
            CandidateStatus::Pending => "Needs review",
            CandidateStatus::Approved => "Approved",
            CandidateStatus::Rejected => "Rejected",
        }
    }
}

struct SkillRow {
    choice: Option<String>,
    name: String,
    description: String,
    status: &'static str,
    delivery: &'static str,
    trigger: String,
    url: String,
}

#[derive(Template)]
#[template(path = "skills.html")]
struct SkillsPage {
    bulk_skills_available: bool,
    chrome: PageChrome,
    rows: Vec<SkillRow>,
    query: String,
    error: Option<String>,
    source: String,
    source_health: &'static str,
    next: Option<String>,
}

#[derive(Default, Deserialize)]
struct SkillsQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    after: String,
}

async fn skills_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(query): Query<SkillsQuery>,
) -> Response {
    let principal = user.as_ref().map(|Extension(p)| p);
    let bulk_skills_available = state.hitl.decision_batches.get().is_some()
        && overview_break_glass_admin(principal)
        && tenant
            .as_ref()
            .is_none_or(|Extension(t)| principal.is_some_and(|p| t.slug == p.tenant.as_str()));
    let chrome = PageChrome::build(
        &state,
        "Skills",
        "/skills",
        &headers,
        principal.map(user_display),
        tenant.map(|Extension(t)| t),
        csrf.map(|Extension(c)| c.0).unwrap_or_default(),
    );
    let mut page = SkillsPage {
        bulk_skills_available,
        chrome,
        rows: Vec::new(),
        query: query.q.clone(),
        error: None,
        source: String::new(),
        source_health: "Unavailable",
        next: None,
    };
    if !overview_break_glass_admin(principal) {
        page.error = Some("An administrator session is required to browse skill reviews.".into());
        return render(&page);
    }
    if let Some(catalog) = state.hitl.skills.get() {
        let health = catalog.status();
        page.source_health = if health.latest_refresh_failed || health.resource_read_failed {
            "Source needs attention"
        } else {
            "Source available"
        };
        if let Some(snapshot) = health.snapshot {
            page.source = format!(
                "{} · {}",
                snapshot.source().origin,
                snapshot.source().reference
            );
        }
    }
    match current_reviews(&state, principal.expect("admin checked").tenant.as_str()).await {
        Err(error) => page.error = Some(error.detail()),
        Ok(reviews) => {
            let available = if reviews
                .iter()
                .any(|review| review.serving.is_some() && !review.quarantined)
            {
                match state.hitl.reviewed_skills.get() {
                    Some(reviewed) => reviewed
                        .list(principal.expect("admin checked").tenant.as_str(), None)
                        .await
                        .ok()
                        .map(|listing| {
                            listing
                                .skills
                                .into_iter()
                                .map(|skill| skill.uri)
                                .collect::<std::collections::BTreeSet<_>>()
                        }),
                    None => None,
                }
            } else {
                None
            };
            let words = query.q.to_lowercase();
            let mut matches = reviews
                .into_iter()
                .filter(|review| {
                    let fields = &review.candidate.skill().frontmatter;
                    review.skill_uri > query.after
                        && (words.is_empty()
                            || fields
                                .values()
                                .filter_map(|value| value.as_str())
                                .any(|value| value.to_lowercase().contains(&words))
                            || review.skill_uri.to_lowercase().contains(&words))
                })
                .peekable();
            while page.rows.len() < 40 {
                let Some(review) = matches.next() else {
                    break;
                };
                let fields = &review.candidate.skill().frontmatter;
                page.rows.push(SkillRow {
                    choice: crate::dashboard_bulk_skills::choice(&review),
                    name: fields
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&review.skill_uri)
                        .into(),
                    description: fields
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .into(),
                    status: status(&review),
                    trigger: review_trigger(&review),
                    delivery: delivery_status(&review, available.as_ref()),
                    url: review_url(&review.skill_uri),
                });
                if page.rows.len() == 40 && matches.peek().is_some() {
                    page.next = Some(format!(
                        "/skills?q={}&after={}",
                        urlencode(&query.q),
                        urlencode(&review.skill_uri)
                    ));
                }
            }
        }
    }
    render(&page)
}

fn delivery_status(
    review: &SkillReview,
    available: Option<&std::collections::BTreeSet<String>>,
) -> &'static str {
    if review.quarantined || review.serving.is_none() {
        "Not approved"
    } else {
        match available {
            Some(available) if available.contains(&review.skill_uri) => {
                "Approved metadata available"
            }
            Some(_) => "Approved · source unavailable",
            None => "Approved · availability unknown",
        }
    }
}

struct FileRow {
    path: String,
    change: &'static str,
    before: String,
    after: String,
    url: String,
    execution: &'static str,
}
struct HistoryRow {
    action: String,
    actor: String,
    reason: String,
    at: String,
    digest: String,
}
/// One version of the selected file, shown whole or described.
struct Pane {
    /// Why the content is not shown, when it is not.
    message: Option<&'static str>,
    text: Vec<Segment>,
}

impl From<Preview> for Pane {
    fn from(preview: Preview) -> Self {
        match preview {
            Preview::Text(text) => Self {
                message: None,
                text: review_diff::text_segments(&text),
            },
            Preview::Unavailable(message) => Self {
                message: Some(message),
                text: Vec::new(),
            },
        }
    }
}

#[derive(Template)]
#[template(path = "skill_review.html")]
struct ReviewPage {
    chrome: PageChrome,
    review: SkillReview,
    state: &'static str,
    files: Vec<FileRow>,
    history: Vec<HistoryRow>,
    file: String,
    /// The selected file's comparison, when both versions are text.
    content: Option<DiffSection>,
    /// Each version described or shown whole when they cannot be compared.
    before_pane: Pane,
    after_pane: Pane,
    /// Changed skill metadata, compared with the approved version when one exists.
    metadata: Option<DiffSection>,
    view: DiffView,
    view_links: Vec<ViewLink>,
    before_label: &'static str,
    after_label: &'static str,
    error: Option<String>,
    can_reject: bool,
    can_approve: bool,
    source_url: Option<String>,
    compatibility: String,
    trigger: String,
}

fn source_url(candidate: &ReviewCandidate) -> Option<String> {
    let mut url = url::Url::parse(candidate.source().origin.strip_prefix("git+")?).ok()?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    // Gitea's conventional API prefix has a corresponding repository web path.
    // Custom API origins remain navigable as source metadata without guessing.
    if let Some((base, repository)) = url.path().rsplit_once("/api/v1/") {
        let path = format!("{base}/{repository}");
        url.set_path(&path);
        if let Some(commit) = candidate.source().resolved_digest.strip_prefix("git-sha1:") {
            let mut segments = url.path_segments_mut().ok()?;
            segments.extend(["src", "commit", commit]);
            let root = candidate
                .skill()
                .resources
                .iter()
                .find(|file| file.uri == candidate.skill().uri)?;
            segments.extend(root.source_path.split('/'));
        }
    }
    Some(url.into())
}
#[derive(Deserialize)]
struct ReviewQuery {
    uri: String,
    file: Option<String>,
    view: Option<DiffView>,
}

/// One version of a file: its text, or why its text cannot be shown.
enum Preview {
    Text(String),
    Unavailable(&'static str),
}

async fn preview(state: &AdminState, candidate: Option<&ReviewCandidate>, uri: &str) -> Preview {
    let Some(candidate) = candidate else {
        return Preview::Unavailable("No approved version.");
    };
    if !candidate
        .skill()
        .resources
        .iter()
        .any(|file| file.uri == uri)
    {
        return Preview::Unavailable("File absent in this version.");
    }
    let Some(catalog) = state.hitl.reviewed_skills.get() else {
        return Preview::Unavailable("Review service unavailable.");
    };
    let Ok(snapshot) = catalog.review_snapshot(candidate).await else {
        return Preview::Unavailable(
            "Exact source revision unavailable. No replacement content was substituted.",
        );
    };
    match snapshot.load_resource(uri).await {
        Ok(Some(resource)) => match std::str::from_utf8(&resource.bytes) {
            Ok(text) => Preview::Text(text.to_owned()),
            Err(_) => Preview::Unavailable(
                "Binary content. Review the file's size, media type, and immutable object identity in the inventory.",
            ),
        },
        _ => Preview::Unavailable("Exact file unavailable. No replacement content was substituted."),
    }
}

/// Compare two versions of the selected file when both are text. Added,
/// removed, binary, and unavailable versions are described instead, so a
/// message is never compared as if it were content.
fn content_view(file: &str, before: Preview, after: Preview) -> (Option<DiffSection>, Pane, Pane) {
    match (before, after) {
        (Preview::Text(old), Preview::Text(new)) => {
            let section = DiffSection {
                name: file.to_owned(),
                body: SectionBody::Compared(review_diff::compare(Some(&old), Some(&new))),
            };
            let empty = || Pane {
                message: None,
                text: Vec::new(),
            };
            (Some(section), empty(), empty())
        }
        (before, after) => (None, before.into(), after.into()),
    }
}

/// Changed skill metadata as formatted JSON: compared with the approved
/// version, or shown whole when nothing has been approved.
fn metadata_section(review: &SkillReview) -> Option<DiffSection> {
    let text = |value: &serde_json::Map<String, serde_json::Value>| {
        serde_json::to_string_pretty(value).expect("skill metadata serializes")
    };
    let candidate = &review.candidate.skill().frontmatter;
    let body = match &review.serving {
        Some(serving) if &serving.skill().frontmatter == candidate => return None,
        Some(serving) => SectionBody::Compared(review_diff::compare(
            Some(&text(&serving.skill().frontmatter)),
            Some(&text(candidate)),
        )),
        None => SectionBody::Definition(review_diff::text_segments(&text(candidate))),
    };
    Some(DiffSection {
        name: "Skill metadata".into(),
        body,
    })
}

async fn review_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(query): Query<ReviewQuery>,
) -> Response {
    let principal = user.as_ref().map(|Extension(p)| p);
    if !overview_break_glass_admin(principal) {
        return (
            StatusCode::FORBIDDEN,
            "Skill reviews require an administrator session",
        )
            .into_response();
    }
    let principal = principal.expect("admin checked");
    let review = match current_review(&state, principal.tenant.as_str(), &query.uri).await {
        Ok(review) => review,
        Err(error) => return error.into_response(),
    };
    let file = query.file.unwrap_or_else(|| review.skill_uri.clone());
    let mut inventory = BTreeMap::new();
    if let Some(serving) = &review.serving {
        for descriptor in &serving.skill().resources {
            inventory.insert(descriptor.uri.clone(), (Some(descriptor), None));
        }
    }
    for descriptor in &review.candidate.skill().resources {
        inventory.entry(descriptor.uri.clone()).or_default().1 = Some(descriptor);
    }
    if !inventory.contains_key(&file) {
        return (StatusCode::NOT_FOUND, "File is not in this skill").into_response();
    }
    let candidate_entry = waygate_skills::SkillEntry {
        uri: review.skill_uri.clone(),
        frontmatter: review.candidate.skill().frontmatter.clone(),
        resources: review.candidate.skill().resources.clone().into(),
    };
    let files = inventory
        .into_iter()
        .map(|(uri, (before, after))| FileRow {
            path: uri.clone(),
            change: match (before, after) {
                (None, _) => "Added",
                (_, None) => "Removed",
                (Some(a), Some(b)) if a == b => "Unchanged",
                _ => "Changed",
            },
            before: before
                .map(|file| {
                    format!(
                        "{} · {} bytes · {}",
                        file.source_object, file.size, file.media_type
                    )
                })
                .unwrap_or_else(|| "Absent".into()),
            after: after
                .map(|file| {
                    format!(
                        "{} · {} bytes · {}",
                        file.source_object, file.size, file.media_type
                    )
                })
                .unwrap_or_else(|| "Absent".into()),
            url: format!("{}&file={}", review_url(&review.skill_uri), urlencode(&uri)),
            execution: candidate_entry.code_mode_compatibility_hint(&uri),
        })
        .collect();
    let (before, after) = tokio::join!(
        preview(&state, review.serving.as_ref(), &file),
        preview(&state, Some(&review.candidate), &file)
    );
    let (content, before_pane, after_pane) = content_view(&file, before, after);
    let metadata = metadata_section(&review);
    let view = DiffView::select(query.view, &headers);
    let view_links = if [&content, &metadata]
        .into_iter()
        .flatten()
        .any(|section| section.comparison().is_some())
    {
        review_diff::view_links(
            &format!(
                "{}&file={}",
                review_url(&review.skill_uri),
                urlencode(&file)
            ),
            view,
            "Full content",
        )
    } else {
        Vec::new()
    };
    let history = state
        .hitl
        .reviewed_skills
        .get()
        .expect("current_review checked capability")
        .store()
        .expect("current_review checked store")
        .history(
            principal.tenant.as_str(),
            &review.source_key,
            &review.skill_uri,
            i64::MAX,
            30,
        )
        .await;
    let (history, error) = match history {
        Ok(rows) => (
            rows.into_iter()
                .map(|row| HistoryRow {
                    action: format!("{:?}", row.decision),
                    actor: format!("{} · {}", row.actor, row.actor_issuer),
                    reason: row.reason,
                    at: format_ts_abs(row.decided_at),
                    digest: row.candidate.content_digest().into(),
                })
                .collect(),
            None,
        ),
        Err(_) => (
            Vec::new(),
            Some("Decision history could not be loaded.".into()),
        ),
    };
    let page = ReviewPage {
        chrome: PageChrome::build(
            &state,
            "Skill review",
            "/skills",
            &headers,
            Some(user_display(principal)),
            tenant.map(|Extension(t)| t),
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        state: status(&review),
        trigger: review_trigger(&review),
        content,
        before_pane,
        after_pane,
        metadata,
        view,
        view_links,
        before_label: "Approved",
        after_label: "Candidate",
        can_reject: review.candidate_status == CandidateStatus::Pending,
        can_approve: review.candidate_status != CandidateStatus::Approved || review.quarantined,
        source_url: source_url(&review.candidate),
        compatibility: review
            .candidate
            .skill()
            .frontmatter
            .get("compatibility")
            .and_then(|value| value.as_str())
            .unwrap_or("No runtime compatibility declared")
            .into(),
        review,
        files,
        history,
        file,
        error,
    };
    let mut response = render(&page);
    DiffView::remember(query.view, response.headers_mut());
    response
}

#[derive(Deserialize)]
struct DecisionForm {
    csrf: String,
    action: String,
    skill_uri: String,
    generation: i64,
    content_digest: String,
    reason: String,
}
async fn decide(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    Form(form): Form<DecisionForm>,
) -> Response {
    let principal = user.as_ref().map(|Extension(p)| p);
    if !overview_break_glass_admin(principal) {
        return (
            StatusCode::FORBIDDEN,
            "Skill decisions require an administrator session",
        )
            .into_response();
    }
    if csrf
        .as_ref()
        .is_some_and(|Extension(token)| form.csrf.is_empty() || !csrf_matches(&token.0, &form.csrf))
    {
        return (
            StatusCode::FORBIDDEN,
            "Session expired. Refresh before deciding.",
        )
            .into_response();
    }
    let decision = match form.action.as_str() {
        "approve" => ReviewDecision::Approve,
        "reject" => ReviewDecision::Reject,
        "quarantine" => ReviewDecision::Quarantine,
        _ => return (StatusCode::BAD_REQUEST, "Unknown skill decision").into_response(),
    };
    let principal = principal.expect("admin checked");
    let params = SkillDecisionParams {
        skill_uri: form.skill_uri,
        generation: form.generation,
        content_digest: form.content_digest,
        reason: form.reason,
    };
    match decide_core(
        &state,
        principal.tenant.as_str(),
        principal,
        &params,
        decision,
    )
    .await
    {
        Ok(_) => Redirect::to(&tenant_ctx::nav_url(
            tenant.as_ref().map(|Extension(t)| t),
            &review_url(&params.skill_uri),
        ))
        .into_response(),
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod review_trigger_tests {
    use super::*;
    use waygate_skills::{
        verify_in_memory_catalog, CatalogManifest, CatalogSkill, CatalogSourceIdentity,
        SkillResourceDescriptor, CATALOG_SCHEMA_VERSION,
    };

    fn candidate(instructions: &str, description: &str, files: &[(&str, &str)]) -> ReviewCandidate {
        let uri = "skill://fixture/review-fixture/SKILL.md";
        let main =
            format!("---\nname: review-fixture\ndescription: {description}\n---\n{instructions}\n");
        let mut contents = BTreeMap::new();
        let mut resources = Vec::new();
        for (path, text) in
            std::iter::once(("SKILL.md", main.as_str())).chain(files.iter().copied())
        {
            let file_uri = format!("skill://fixture/review-fixture/{path}");
            let bytes = text.as_bytes().to_vec();
            resources.push(SkillResourceDescriptor {
                uri: file_uri.clone(),
                source_path: format!("review-fixture/{path}"),
                source_object: waygate_skills::sha256_digest(&bytes),
                size: bytes.len() as u64,
                media_type: if path == "SKILL.md" {
                    "text/markdown"
                } else {
                    "text/plain"
                }
                .into(),
            });
            contents.insert(file_uri, bytes);
        }
        let snapshot = verify_in_memory_catalog(
            CatalogSourceIdentity {
                origin: "git+https://fixture.test/skills".into(),
                reference: "main".into(),
                resolved_digest: waygate_skills::sha256_digest(main.as_bytes()),
                resolved_tree_digest: waygate_skills::sha256_digest(main.as_bytes()),
            },
            CatalogManifest {
                schema_version: CATALOG_SCHEMA_VERSION,
                skills: vec![CatalogSkill {
                    uri: uri.into(),
                    frontmatter: serde_json::from_value(
                        serde_json::json!({"name":"review-fixture","description":description}),
                    )
                    .unwrap(),
                    resources,
                }],
            },
            contents,
        )
        .unwrap();
        ReviewCandidate::from_snapshot(&snapshot, uri).unwrap()
    }

    #[test]
    fn metadata_and_files_are_compared_only_when_both_versions_are_text() {
        let before = candidate("Instructions", "Original description", &[]);
        let after = candidate("Instructions", "Changed description", &[]);
        let mut review = SkillReview {
            tenant_id: "default".into(),
            source_key: after.source_key(),
            skill_uri: after.skill().uri.clone(),
            generation: 1,
            candidate: after.clone(),
            serving: None,
            candidate_status: CandidateStatus::Pending,
            quarantined: false,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let first = metadata_section(&review).unwrap();
        assert!(
            first.comparison().is_none(),
            "nothing approved to compare with"
        );
        assert!(first.definition().is_some());
        review.serving = Some(before);
        let changed = metadata_section(&review).unwrap();
        let comparison = changed.comparison().unwrap();
        assert_eq!((comparison.added, comparison.removed), (1, 1));
        review.serving = Some(after);
        assert!(metadata_section(&review).is_none());

        let (section, _, _) = content_view(
            "skill://fixture/review-fixture/SKILL.md",
            Preview::Text("one\ntwo\n".into()),
            Preview::Text("one\nthree\n".into()),
        );
        let comparison = section.unwrap();
        let comparison = comparison.comparison().unwrap();
        assert_eq!((comparison.added, comparison.removed), (1, 1));
        let (section, before, after) = content_view(
            "skill://fixture/review-fixture/SKILL.md",
            Preview::Unavailable("No approved version."),
            Preview::Text("new\u{200B}".into()),
        );
        assert!(section.is_none(), "a message is never compared as content");
        assert_eq!(before.message, Some("No approved version."));
        assert!(after.message.is_none());
        assert!(after.text.iter().any(|segment| segment.text == "U+200B"));
    }

    #[test]
    fn summaries_identify_initial_review_and_actual_content_changes() {
        let before = candidate(
            "Original instructions",
            "Original description",
            &[("removed.txt", "old"), ("changed.txt", "before")],
        );
        let after = candidate(
            "Replacement instructions",
            "Changed description",
            &[("added.txt", "new"), ("changed.txt", "after")],
        );
        let mut review = SkillReview {
            tenant_id: "default".into(),
            source_key: before.source_key(),
            skill_uri: before.skill().uri.clone(),
            generation: 1,
            candidate: before.clone(),
            serving: None,
            candidate_status: CandidateStatus::Pending,
            quarantined: false,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(review_trigger(&review), "Initial approval required");
        review.serving = Some(before.clone());
        review.candidate = after;
        let trigger = review_trigger(&review);
        for expected in [
            "Instructions changed",
            "Skill metadata changed",
            "Files added",
            "Files removed",
            "Supporting files changed",
        ] {
            assert!(
                trigger.contains(expected),
                "{trigger} must identify {expected}"
            );
        }
        assert!(!trigger.contains("Source changed"));
        review.candidate = before;
        assert_eq!(review_trigger(&review), "Approved content");
    }
}
