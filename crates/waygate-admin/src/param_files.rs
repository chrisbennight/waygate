//! Out-of-context document submission for proposed changes.
//!
//! A maker authoring a control-plane document — a full manifest set, a Cedar
//! statement, a long agent instruction — should not have to push it through
//! MCP JSON-RPC and the model's context to get it into a change request. The
//! gateway already runs a governed file plane for exactly this
//! (`gateway-files.prepare_upload` → `mcp-file://gateway/<id>`), so a maker
//! uploads the document there and submits the returned URI at the
//! `<field>_file` key instead of the text at `<field>`.
//!
//! This module is the seam where that URI becomes text.
//! [`resolve_param_files`] runs FIRST on every propose and preview path,
//! before the freshness witness is captured, before the params are validated
//! against the action's schema, and before anything is stored. It reads the
//! file, writes the text at the declared pointer, and removes the `_file` key.
//!
//! ## Why the reference never survives
//!
//! The stored params are the approver's review surface, the executor's input,
//! and the durable record of what a human agreed to. A persisted file
//! reference would break all three: the approver would review a pointer rather
//! than the change, the file's retention window could expire before a decision
//! (leaving an approved change that cannot execute), and the bytes behind the
//! reference would be resolved after review rather than before. Resolving at
//! submission keeps one shape everywhere — the captured intent is the
//! document, exactly as it will execute.
//!
//! ## Trust boundary
//!
//! Recognizing [`waygate_core::GATEWAY_FILE_URI_PREFIX`] is not authorization.
//! The [`ProposalFileReader`] impl resolves the id against the file plane,
//! which enforces owner-scoped lookup and the caller's credential-profile
//! restrictions, and refuses anything it cannot serve. The gateway never
//! fetches a caller-supplied URL: any other string is left exactly where the
//! caller put it.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use waygate_oidc::Principal;

use crate::capability::Capability;
use crate::change_executor::registry;
use crate::error::ApiError;
use crate::state::AdminState;

/// One params field an action accepts as an uploaded file instead of inline
/// text — the out-of-context authoring path for documents too large to ride in
/// MCP JSON-RPC (a full manifest set, a Cedar statement, a long instruction).
///
/// The maker uploads the document through the governed file plane
/// (`gateway-files.prepare_upload`) and puts the returned
/// `mcp-file://gateway/<id>` URI at [`Self::file_pointer`] instead of the text
/// at [`Self::pointer`]. The submission layer ([`resolve_param_files`]) reads
/// the file, writes its text at `pointer`, and REMOVES the `_file` key before
/// anything else sees the params.
///
/// That ordering is the invariant the rest of the system rests on: stored
/// params are always the resolved form, so schema validation, the freshness
/// witness, the approver's review render, and the executor all read one shape
/// and never a reference. It is also why an executor's params schema — which
/// describes the stored, reviewed, and executed params — shows the text field
/// rather than the URI; the `_file` alternative exists only at submission and
/// is advertised through `describe_action`.
#[derive(Debug, Clone, Copy)]
pub struct FileBackedParam {
    /// JSON pointer of the resolved text field, e.g. `/content` or
    /// `/config/instructions`.
    pub pointer: &'static str,
    /// What the uploaded file must contain. Surfaced by `describe_action` and
    /// repeated in the teaching error a malformed submission gets back.
    pub description: &'static str,
}

impl FileBackedParam {
    /// JSON pointer of the submission-only key carrying the gateway file URI.
    /// Derived from [`Self::pointer`] so the two cannot drift.
    pub fn file_pointer(&self) -> String {
        format!("{}_file", self.pointer)
    }
}

/// A document read out of the gateway file plane for a submission.
pub struct ProposalFileContent {
    /// The file's decoded text. Bounded by the `max_bytes` the caller passed.
    pub text: String,
    /// Lowercase hex SHA-256 of the bytes this text was decoded from. Non-secret
    /// provenance for the propose audit entry, so an implementation must verify
    /// it against what it actually read rather than repeat a recorded value.
    pub sha256: String,
    /// Byte count the digest covers.
    pub size: u64,
}

/// Reads a gateway-owned file on behalf of a principal, for use as a change
/// request's document param.
///
/// The impl lives with the rest of the file plane (`waygate-server`) rather
/// than here: owner-scoped lookup, credential-profile restrictions, and the
/// transfer admission limit are that plane's rules, and a second copy of them
/// in the control plane would drift. This trait is the narrow slice the
/// submission path needs — read one owned file as bounded text — and it
/// deliberately exposes no way to enumerate, write, or authorize a transfer.
#[async_trait]
pub trait ProposalFileReader: Send + Sync {
    /// Resolve `uri` as a file this principal owns and return its text.
    ///
    /// Refuses with [`ApiError::BadRequest`] when the URI is malformed, the
    /// file is unavailable to this principal, it exceeds `max_bytes`, or its
    /// bytes are not UTF-8. A file that exists but is not the caller's is
    /// indistinguishable from one that does not exist.
    async fn read_text(
        &self,
        principal: &Principal,
        uri: &str,
        max_bytes: usize,
    ) -> Result<ProposalFileContent, ApiError>;
}

/// Non-secret provenance of one document read into a submission's params.
/// Recorded on the propose audit entry so an operator can tie the reviewed
/// text back to the upload that produced it.
#[derive(Debug)]
pub struct ResolvedParamFile {
    /// JSON pointer the text was written to, e.g. `/content`.
    pub pointer: String,
    /// The `mcp-file://gateway/<id>` URI the maker submitted.
    pub uri: String,
    pub sha256: String,
    pub size: u64,
}

/// Replace every declared `<field>_file` URI in `params` with the text of the
/// uploaded file it names, in place.
///
/// Returns the provenance of what was read, in declaration order. Runs on the
/// REST propose handler, the `propose_change` tool, and the `preview_change`
/// tool, so a candidate that previews clean submits identically.
pub async fn resolve_param_files(
    state: &Arc<AdminState>,
    action_type: &str,
    params: &mut Value,
    actor: &Principal,
    max_bytes: usize,
) -> Result<Vec<ResolvedParamFile>, ApiError> {
    resolve_with_reader(
        &state.hitl.proposal_files,
        action_type,
        params,
        actor,
        max_bytes,
    )
    .await
}

/// [`resolve_param_files`] against a reader handle rather than the whole admin
/// state.
///
/// The handle stays a [`Capability`] instead of a plain reference because
/// whether the file plane is required is a property of the SUBMISSION, not of
/// the deployment: a gateway with no file storage must still accept every
/// inline proposal, and only a submission that actually names a file may be
/// refused for the missing capability.
async fn resolve_with_reader(
    reader: &Capability<Arc<dyn ProposalFileReader>>,
    action_type: &str,
    params: &mut Value,
    actor: &Principal,
    max_bytes: usize,
) -> Result<Vec<ResolvedParamFile>, ApiError> {
    let declared = registry().file_params(action_type);
    // Judge the SUBMISSION, before any substitution: a reference anywhere but a
    // declared upload field is a caller mistake, whereas resolved text is the
    // gateway's own output and must never be re-inspected as if the caller had
    // written it (a document may legitimately begin with anything at all).
    reject_stray_file_references(action_type, params, declared)?;
    let mut resolved = Vec::new();

    for spec in declared {
        let file_pointer = spec.file_pointer();
        let Some(submitted) = params.pointer(&file_pointer) else {
            continue;
        };
        let uri = submitted.as_str().ok_or_else(|| {
            ApiError::BadRequest(format!(
                "`{}` must be a string holding the `{}<id>` URI returned by \
                 `gateway-files.prepare_upload`",
                json_field_path(&file_pointer),
                waygate_core::GATEWAY_FILE_URI_PREFIX,
            ))
        })?;
        // Exactly one of the two: a submission carrying both leaves it
        // ambiguous which one the approver would be agreeing to, and silently
        // preferring either is the kind of guess that ships the wrong change.
        if params
            .pointer(spec.pointer)
            .is_some_and(|inline| !inline.is_null())
        {
            return Err(ApiError::BadRequest(format!(
                "params carry both `{}` and `{}`; supply exactly one — the inline text or the \
                 uploaded file, not both",
                json_field_path(spec.pointer),
                json_field_path(&file_pointer),
            )));
        }
        if !uri.starts_with(waygate_core::GATEWAY_FILE_URI_PREFIX) {
            return Err(ApiError::BadRequest(format!(
                "`{}` must be a `{}<id>` URI returned by `gateway-files.prepare_upload`; the \
                 gateway reads only its own stored files and never fetches a supplied URL",
                json_field_path(&file_pointer),
                waygate_core::GATEWAY_FILE_URI_PREFIX,
            )));
        }
        let uri = uri.to_owned();

        let content = reader
            .require()?
            .read_text(actor, &uri, max_bytes)
            .await
            .map_err(|e| annotate_read_error(e, spec))?;

        set_pointer(params, spec.pointer, Value::String(content.text)).map_err(|missing| {
            ApiError::BadRequest(format!(
                "cannot place the uploaded document at `{}`: the enclosing `{}` object is \
                 missing from params",
                json_field_path(spec.pointer),
                json_field_path(&missing),
            ))
        })?;
        remove_pointer(params, &file_pointer);
        resolved.push(ResolvedParamFile {
            pointer: spec.pointer.to_owned(),
            uri,
            sha256: content.sha256,
            size: content.size,
        });
    }

    Ok(resolved)
}

/// Whether resolving this submission can reach the file plane or refuse.
///
/// Lets a submission surface tell "this call needs the reader handle" from
/// "this call is plain JSON" before reaching for a handle it may not have yet.
/// Outside this predicate [`resolve_param_files`] is a provable no-op: no
/// declared upload key is present to read, and no reference is present to
/// refuse.
///
/// It deliberately keys on the presence of a declared upload KEY, not on
/// whether its value looks like a gateway URI. A foreign URL or a non-string at
/// an upload field is exactly what the resolver exists to refuse, and the
/// params schemas admit unknown keys, so a predicate that inspected the value
/// would let such a candidate past one surface and not the other.
pub fn engages_the_file_plane(action_type: &str, params: &Value) -> bool {
    registry()
        .file_params(action_type)
        .iter()
        .any(|spec| params.pointer(&spec.file_pointer()).is_some())
        || find_file_reference(params, String::new(), &[]).is_some()
}

/// Refuse a submission that names a gateway file anywhere but a declared
/// upload field.
///
/// Without this, a file reference placed at a field the action does not read
/// as a document is silently accepted: the maker believes it submitted a
/// document, the approver reviews a URI, and the executor writes the literal
/// string into live configuration. Teaching the caller where the upload path
/// actually exists is the only useful answer.
fn reject_stray_file_references(
    action_type: &str,
    params: &Value,
    declared: &[FileBackedParam],
) -> Result<(), ApiError> {
    let upload_fields: Vec<String> = declared.iter().map(|s| s.file_pointer()).collect();
    let Some(pointer) = find_file_reference(params, String::new(), &upload_fields) else {
        return Ok(());
    };
    let accepted = if declared.is_empty() {
        format!("action {action_type:?} accepts no uploaded document")
    } else {
        format!(
            "action {action_type:?} accepts an uploaded document only at {}",
            declared
                .iter()
                .map(|s| format!("`{}`", json_field_path(&s.file_pointer())))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Err(ApiError::BadRequest(format!(
        "`{}` holds a gateway file reference, which would be stored and executed verbatim \
         rather than read; {accepted}. Call `gateway-admin.describe_action` for the fields \
         that accept one.",
        json_field_path(&pointer),
    )))
}

/// First JSON pointer (depth-first) whose string value names a gateway file,
/// skipping the pointers in `allowed`.
///
/// The skip list must be applied during the walk, not to the result: a
/// submission that puts a reference at its declared upload field AND at some
/// other field would otherwise report the legitimate one and hide the stray.
fn find_file_reference(value: &Value, at: String, allowed: &[String]) -> Option<String> {
    if allowed.contains(&at) {
        return None;
    }
    match value {
        Value::String(s) if s.starts_with(waygate_core::GATEWAY_FILE_URI_PREFIX) => Some(at),
        Value::Object(map) => map.iter().find_map(|(k, v)| {
            find_file_reference(v, format!("{at}/{}", escape_token(k)), allowed)
        }),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, v)| find_file_reference(v, format!("{at}/{i}"), allowed)),
        _ => None,
    }
}

/// Write `value` at `pointer`, creating nothing. Returns the pointer of the
/// enclosing object when it is absent, so the caller can name it.
fn set_pointer(root: &mut Value, pointer: &str, value: Value) -> Result<(), String> {
    let (parent_pointer, key) = split_pointer(pointer);
    let parent = root
        .pointer_mut(parent_pointer)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| parent_pointer.to_owned())?;
    parent.insert(unescape_token(key), value);
    Ok(())
}

fn remove_pointer(root: &mut Value, pointer: &str) {
    let (parent_pointer, key) = split_pointer(pointer);
    if let Some(parent) = root
        .pointer_mut(parent_pointer)
        .and_then(Value::as_object_mut)
    {
        parent.remove(&unescape_token(key));
    }
}

fn split_pointer(pointer: &str) -> (&str, &str) {
    match pointer.rfind('/') {
        Some(i) => (&pointer[..i], &pointer[i + 1..]),
        None => ("", pointer),
    }
}

/// Render a JSON pointer as the dotted field path a caller wrote, so the error
/// names `config.instructions_file` rather than `/config/instructions_file`.
fn json_field_path(pointer: &str) -> String {
    pointer
        .trim_start_matches('/')
        .split('/')
        .map(unescape_token)
        .collect::<Vec<_>>()
        .join(".")
}

fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn unescape_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

/// Name the field and the expected document in a read failure, so a maker that
/// uploaded the wrong file learns which one and what it should have held.
fn annotate_read_error(error: ApiError, spec: &FileBackedParam) -> ApiError {
    match error {
        ApiError::BadRequest(detail) => ApiError::BadRequest(format!(
            "`{}`: {detail}. The file must contain {}.",
            json_field_path(&spec.file_pointer()),
            spec.description,
        )),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    use waygate_oidc::AuthMethod;

    /// A stand-in for the file plane that records every URI it was asked for,
    /// so a test can assert that a refused submission never reached storage.
    struct RecordingReader {
        answer: Result<&'static str, &'static str>,
        asked: Mutex<Vec<String>>,
    }

    impl RecordingReader {
        fn returning(text: &'static str) -> Arc<Self> {
            Arc::new(Self {
                answer: Ok(text),
                asked: Mutex::new(Vec::new()),
            })
        }

        fn refusing(detail: &'static str) -> Arc<Self> {
            Arc::new(Self {
                answer: Err(detail),
                asked: Mutex::new(Vec::new()),
            })
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ProposalFileReader for RecordingReader {
        async fn read_text(
            &self,
            _principal: &Principal,
            uri: &str,
            _max_bytes: usize,
        ) -> Result<ProposalFileContent, ApiError> {
            self.asked.lock().unwrap().push(uri.to_owned());
            match self.answer {
                Ok(text) => Ok(ProposalFileContent {
                    text: text.to_owned(),
                    sha256: "abc123".to_owned(),
                    size: text.len() as u64,
                }),
                Err(detail) => Err(ApiError::BadRequest(detail.to_owned())),
            }
        }
    }

    fn wired(reader: Arc<dyn ProposalFileReader>) -> Capability<Arc<dyn ProposalFileReader>> {
        Capability::new("file uploads are not configured", Some(reader))
    }

    fn unwired() -> Capability<Arc<dyn ProposalFileReader>> {
        Capability::absent("file uploads are not configured")
    }

    fn maker() -> Principal {
        Principal {
            sub: "agent-1".into(),
            email: None,
            groups: vec![],
            issuer: "local-test".into(),
            scopes: vec!["mcp:propose".to_owned()],
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    const A_FILE: &str = "mcp-file://gateway/019a0000-0000-7000-8000-000000000001";

    async fn resolve(
        reader: &Capability<Arc<dyn ProposalFileReader>>,
        action_type: &str,
        params: &mut Value,
    ) -> Result<Vec<ResolvedParamFile>, ApiError> {
        resolve_with_reader(reader, action_type, params, &maker(), 384 * 1024).await
    }

    fn detail(error: ApiError) -> String {
        match error {
            ApiError::BadRequest(detail) => detail,
            ApiError::ServiceUnavailable(detail) => detail.to_owned(),
            _ => panic!("expected a caller-facing error"),
        }
    }

    #[tokio::test]
    async fn an_uploaded_document_becomes_the_text_field_and_the_reference_is_dropped() {
        let reader = RecordingReader::returning("- name: example-messages\n");
        let mut params = json!({ "base_hash": "h", "content_file": A_FILE });

        let resolved = resolve(
            &wired(reader.clone()),
            "manifest.stage_and_publish",
            &mut params,
        )
        .await
        .expect("resolve");

        // The stored params are the resolved form: the document is inline and
        // the submission-only key is gone, so the approver reviews the change
        // itself and the executor never sees a reference.
        assert_eq!(params["content"], json!("- name: example-messages\n"));
        assert!(params.get("content_file").is_none());
        assert_eq!(params["base_hash"], json!("h"));
        // Provenance survives for the audit entry even though the params no
        // longer name the file.
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].pointer, "/content");
        assert_eq!(resolved[0].uri, A_FILE);
        assert_eq!(resolved[0].sha256, "abc123");
        assert_eq!(reader.asked(), vec![A_FILE.to_owned()]);
    }

    #[tokio::test]
    async fn a_nested_uploaded_document_lands_inside_its_own_object() {
        let reader = RecordingReader::returning("be concise");
        let mut params = json!({
            "agent_id": "019a0000-0000-7000-8000-00000000000a",
            "config": { "name": "triage", "instructions_file": A_FILE },
        });

        resolve(&wired(reader), "agent_config.update", &mut params)
            .await
            .expect("resolve");

        assert_eq!(params["config"]["instructions"], json!("be concise"));
        assert!(params["config"].get("instructions_file").is_none());
        assert_eq!(params["config"]["name"], json!("triage"));
    }

    #[tokio::test]
    async fn supplying_both_the_text_and_the_upload_is_refused() {
        let reader = RecordingReader::returning("- name: example-messages\n");
        let mut params = json!({
            "base_hash": "h",
            "content": "- name: other\n",
            "content_file": A_FILE,
        });

        let error = resolve(
            &wired(reader.clone()),
            "manifest.stage_and_publish",
            &mut params,
        )
        .await
        .expect_err("ambiguous submission");

        let detail = detail(error);
        assert!(detail.contains("content"), "{detail}");
        assert!(detail.contains("exactly one"), "{detail}");
        // Refused before any byte moved — the ambiguity is decidable from the
        // submission alone.
        assert!(reader.asked().is_empty(), "storage must not be consulted");
    }

    #[tokio::test]
    async fn a_url_the_gateway_does_not_own_is_refused_without_being_fetched() {
        let reader = RecordingReader::returning("- name: example-messages\n");
        let mut params =
            json!({ "base_hash": "h", "content_file": "https://example.com/manifests.yaml" });

        let error = resolve(
            &wired(reader.clone()),
            "manifest.stage_and_publish",
            &mut params,
        )
        .await
        .expect_err("foreign URL");

        assert!(detail(error).contains(waygate_core::GATEWAY_FILE_URI_PREFIX));
        assert!(
            reader.asked().is_empty(),
            "the gateway fetches no caller URL"
        );
    }

    #[tokio::test]
    async fn a_file_reference_at_an_undeclared_field_is_refused_rather_than_stored() {
        let reader = RecordingReader::returning("unused");
        // A reference where the executor expects a literal would otherwise be
        // written into live configuration verbatim.
        let mut params = json!({ "base_hash": A_FILE, "content": "- name: example-messages\n" });

        let error = resolve(
            &wired(reader.clone()),
            "manifest.stage_and_publish",
            &mut params,
        )
        .await
        .expect_err("stray reference");

        let detail = detail(error);
        assert!(detail.contains("base_hash"), "{detail}");
        assert!(detail.contains("content_file"), "{detail}");
        assert!(reader.asked().is_empty());
    }

    #[tokio::test]
    async fn an_inline_submission_succeeds_without_any_file_plane() {
        let mut params = json!({ "base_hash": "h", "content": "- name: example-messages\n" });

        let resolved = resolve(&unwired(), "manifest.stage_and_publish", &mut params)
            .await
            .expect("inline submission must not need file storage");

        assert!(resolved.is_empty());
        assert_eq!(params["content"], json!("- name: example-messages\n"));
    }

    #[tokio::test]
    async fn naming_a_file_without_file_storage_is_refused_with_the_capability_message() {
        let mut params = json!({ "base_hash": "h", "content_file": A_FILE });

        let error = resolve(&unwired(), "manifest.stage_and_publish", &mut params)
            .await
            .expect_err("no file plane");

        assert!(detail(error).contains("not configured"));
    }

    #[tokio::test]
    async fn a_read_failure_names_the_field_and_what_the_file_should_hold() {
        let reader = RecordingReader::refusing("the uploaded file is unavailable or expired");
        let mut params = json!({ "base_hash": "h", "content_file": A_FILE });

        let error = resolve(&wired(reader), "manifest.stage_and_publish", &mut params)
            .await
            .expect_err("unavailable file");

        let detail = detail(error);
        assert!(detail.contains("content_file"), "{detail}");
        assert!(detail.contains("unavailable or expired"), "{detail}");
        assert!(detail.contains("upstream manifests"), "{detail}");
    }

    #[tokio::test]
    async fn a_stray_reference_beside_a_legitimate_upload_is_still_caught() {
        let reader = RecordingReader::returning("- name: example-messages\n");
        // The declared upload field is legitimate; `base_hash` is not. Reporting
        // the first reference found would name the legitimate one and let the
        // stray through.
        let mut params = json!({ "base_hash": A_FILE, "content_file": A_FILE });

        let error = resolve(
            &wired(reader.clone()),
            "manifest.stage_and_publish",
            &mut params,
        )
        .await
        .expect_err("stray reference beside a real upload");

        let detail = detail(error);
        assert!(detail.contains("base_hash"), "{detail}");
        assert!(reader.asked().is_empty(), "refused before any byte moved");
    }

    #[tokio::test]
    async fn a_document_whose_text_starts_with_the_file_prefix_still_resolves() {
        // The resolved text is the gateway's own output, not caller input, so it
        // must never be re-inspected as though the caller had written it there.
        let reader = RecordingReader::returning("mcp-file://gateway/not-a-reference");
        let mut params = json!({ "base_hash": "h", "content_file": A_FILE });

        resolve(&wired(reader), "manifest.stage_and_publish", &mut params)
            .await
            .expect("resolved text is output, not a submission to re-judge");

        assert_eq!(
            params["content"],
            json!("mcp-file://gateway/not-a-reference")
        );
    }

    #[tokio::test]
    async fn an_action_with_no_document_field_ignores_the_file_plane() {
        let mut params = json!({ "version": 3 });

        let resolved = resolve(&unwired(), "manifest.rollback", &mut params)
            .await
            .expect("scalar action");

        assert!(resolved.is_empty());
        assert_eq!(params, json!({ "version": 3 }));
    }

    fn manifest_spec() -> FileBackedParam {
        FileBackedParam {
            pointer: "/content",
            description: "a manifest set",
        }
    }

    fn nested_spec() -> FileBackedParam {
        FileBackedParam {
            pointer: "/config/instructions",
            description: "an instruction",
        }
    }

    #[test]
    fn file_pointer_appends_the_suffix_to_the_declared_pointer() {
        assert_eq!(manifest_spec().file_pointer(), "/content_file");
        assert_eq!(nested_spec().file_pointer(), "/config/instructions_file");
    }

    #[test]
    fn set_pointer_replaces_a_top_level_field() {
        let mut params = json!({ "base_hash": "abc" });
        set_pointer(&mut params, "/content", json!("servers: []")).expect("write");
        assert_eq!(params["content"], json!("servers: []"));
    }

    #[test]
    fn set_pointer_writes_into_a_nested_object() {
        let mut params = json!({ "agent_id": "a", "config": { "name": "n" } });
        set_pointer(&mut params, "/config/instructions", json!("be brief")).expect("write");
        assert_eq!(params["config"]["instructions"], json!("be brief"));
    }

    #[test]
    fn set_pointer_names_the_missing_enclosing_object() {
        let mut params = json!({ "agent_id": "a" });
        let missing = set_pointer(&mut params, "/config/instructions", json!("x"))
            .expect_err("no config object");
        assert_eq!(missing, "/config");
    }

    #[test]
    fn remove_pointer_drops_the_submission_only_key() {
        let mut params = json!({ "content_file": "mcp-file://gateway/x", "base_hash": "h" });
        remove_pointer(&mut params, "/content_file");
        assert!(params.get("content_file").is_none());
        assert_eq!(params["base_hash"], json!("h"));
    }

    #[test]
    fn stray_reference_is_reported_with_its_dotted_path() {
        let params = json!({
            "config": { "name": "mcp-file://gateway/0199-fake" }
        });
        let error = reject_stray_file_references("agent_config.update", &params, &[nested_spec()])
            .expect_err("stray reference");
        let ApiError::BadRequest(detail) = error else {
            panic!("expected a caller error");
        };
        assert!(detail.contains("config.name"), "{detail}");
        assert!(detail.contains("config.instructions_file"), "{detail}");
    }

    #[test]
    fn stray_reference_inside_an_array_is_found() {
        let params = json!({ "server_names": ["ok", "mcp-file://gateway/0199-fake"] });
        let error = reject_stray_file_references("manifest.remove_servers", &params, &[])
            .expect_err("stray reference");
        let ApiError::BadRequest(detail) = error else {
            panic!("expected a caller error");
        };
        assert!(detail.contains("server_names.1"), "{detail}");
        assert!(detail.contains("accepts no uploaded document"), "{detail}");
    }

    #[test]
    fn resolved_params_carry_no_reference_and_pass_the_stray_check() {
        let params = json!({ "base_hash": "h", "content": "servers: []" });
        reject_stray_file_references("manifest.stage_and_publish", &params, &[manifest_spec()])
            .expect("resolved params are clean");
    }

    #[test]
    fn field_path_unescapes_pointer_tokens() {
        assert_eq!(
            json_field_path("/config/instructions"),
            "config.instructions"
        );
        assert_eq!(json_field_path("/a~1b"), "a/b");
    }
}
