//! A bounded record of the HTTP exchanges one streamable-HTTP dial makes.
//!
//! The SDK reports a failed dial with its own error alone, often only
//! `Transport closed`, which never says what the upstream answered. Each dial
//! therefore records the exchanges its HTTP client makes, and a failed dial
//! appends that record to its error.
//!
//! An exchange records only metadata: the gateway's own JSON-RPC method label
//! (taken from the message the gateway sends, never from upstream data), the
//! HTTP method, the shape of the outcome, event counts for an event stream and
//! how it ended, the elapsed time, and for a failure the HTTP status when it is
//! known plus a short error text. For a request's event stream it also notes
//! whether a readable answer arrived and describes the first data event that
//! was not one: its JSON-RPC kind, an error's code and bounded message, or why
//! the SDK cannot read it. It never records a request, a result, a header
//! value, the bearer token, or the session id.
//!
//! Recording ends with the dial. [`DialTrace`] owns the record and every
//! recorder holds only a weak reference to it, so once the dial's owner drops
//! the trace, traffic on the established connection cannot be recorded.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::stream::BoxStream;
use futures::{Stream, StreamExt as _};
use rmcp::model::{
    ClientJsonRpcMessage, ClientNotification, ConstString as _, JsonRpcMessage, NumberOrString,
    RequestId, ServerJsonRpcMessage,
};
use rmcp::transport::streamable_http_client::{
    SseError, StreamableHttpError, StreamableHttpPostResponse,
};
use sse_stream::Sse;

/// The most recent exchanges one dial keeps. Older exchanges are only counted,
/// so a dial that pages through a long catalog still has a bounded record.
const MAX_RECORDED_EXCHANGES: usize = 12;
/// Byte cap on the error text kept for one exchange.
const MAX_EXCHANGE_ERROR_BYTES: usize = 256;
/// Byte cap on a method label. A custom request may carry any method name.
const MAX_LABEL_BYTES: usize = 64;
const TRUNCATION_MARKER: &str = "...";

type EventStream = BoxStream<'static, Result<Sse, SseError>>;
type PostResult = Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>>;
type StreamResult = Result<EventStream, StreamableHttpError<reqwest::Error>>;

/// `text` with control characters escaped, cut to at most `max_bytes` bytes.
///
/// Error text that an upstream can influence reaches operator logs, where a
/// raw newline could forge a log line and an unbounded body could flood one.
pub(crate) fn bounded_text(text: &str, max_bytes: usize) -> String {
    fn escaped_len(character: char) -> usize {
        if character.is_control() {
            character.escape_default().len()
        } else {
            character.len_utf8()
        }
    }
    let fits = text
        .chars()
        .try_fold(0_usize, |len, character| {
            let len = len + escaped_len(character);
            (len <= max_bytes).then_some(len)
        })
        .is_some();
    let budget = if fits {
        max_bytes
    } else {
        max_bytes.saturating_sub(TRUNCATION_MARKER.len())
    };
    let mut bounded = String::with_capacity(budget.min(text.len()) + TRUNCATION_MARKER.len());
    for character in text.chars() {
        if bounded.len() + escaped_len(character) > budget {
            break;
        }
        if character.is_control() {
            bounded.extend(character.escape_default());
        } else {
            bounded.push(character);
        }
    }
    if !fits {
        bounded.push_str(TRUNCATION_MARKER);
    }
    bounded
}

/// Owns one dial's exchange record. Recording ends when this is dropped.
pub(crate) struct DialTrace {
    record: Arc<Mutex<Record>>,
}

impl DialTrace {
    pub(crate) fn new() -> Self {
        Self {
            record: Arc::new(Mutex::new(Record::default())),
        }
    }

    /// A recorder for one HTTP client of this dial. Every attempt of a
    /// logical dial records into the same trace.
    pub(crate) fn recorder(&self) -> ExchangeRecorder {
        ExchangeRecorder {
            record: Arc::downgrade(&self.record),
        }
    }

    /// The exchanges in the order they started, or `None` when the dial made
    /// no HTTP exchange, as on SSE and stdio.
    pub(crate) fn summary(&self) -> Option<String> {
        let record = self.record.lock().expect("dial trace lock poisoned");
        if record.exchanges.is_empty() {
            return None;
        }
        let mut summary = String::from("HTTP exchanges on this dial: ");
        if record.dropped > 0 {
            let _ = write!(summary, "{} earlier not shown; ", record.dropped);
        }
        for (index, exchange) in record.exchanges.iter().enumerate() {
            if index > 0 {
                summary.push_str("; ");
            }
            exchange.render(&mut summary);
        }
        Some(summary)
    }
}

/// Starts exchanges in a [`DialTrace`] while that trace is still live. The
/// default recorder belongs to no trace and records nothing.
#[derive(Clone, Default)]
pub(crate) struct ExchangeRecorder {
    record: Weak<Mutex<Record>>,
}

impl ExchangeRecorder {
    pub(crate) fn post(&self, message: &ClientJsonRpcMessage) -> PendingExchange {
        let mut exchange = self.start(HttpMethod::Post, || Some(message_label(message)));
        if let JsonRpcMessage::Request(request) = message {
            exchange.request = Some(AwaitedResponse {
                id: request.id.clone(),
            });
        }
        exchange
    }

    pub(crate) fn get(&self) -> PendingExchange {
        self.start(HttpMethod::Get, || None)
    }

    pub(crate) fn delete(&self) -> PendingExchange {
        self.start(HttpMethod::Delete, || None)
    }

    #[cfg(test)]
    pub(crate) fn is_recording(&self) -> bool {
        self.record.strong_count() > 0
    }

    fn start(&self, method: HttpMethod, label: impl FnOnce() -> Option<String>) -> PendingExchange {
        let Some(record) = self.record.upgrade() else {
            return PendingExchange::inert();
        };
        let id = record
            .lock()
            .expect("dial trace lock poisoned")
            .push(Exchange {
                method,
                label: label(),
                started: Instant::now(),
                finished: None,
                outcome: Outcome::Pending,
            });
        PendingExchange {
            slot: Slot {
                record: Arc::downgrade(&record),
                id,
            },
            settled: false,
            request: None,
        }
    }
}

/// The request a POST carries, which its event stream should answer.
#[derive(Clone)]
struct AwaitedResponse {
    id: RequestId,
}

/// One started exchange. Settling it with the request's result records the
/// outcome; dropping it unsettled records that the gateway abandoned it.
pub(crate) struct PendingExchange {
    slot: Slot,
    settled: bool,
    request: Option<AwaitedResponse>,
}

impl PendingExchange {
    fn inert() -> Self {
        Self {
            slot: Slot {
                record: Weak::new(),
                id: 0,
            },
            settled: true,
            request: None,
        }
    }

    /// Record a POST's outcome. An event-stream response is handed back
    /// wrapped in a tap that counts its events without changing them.
    pub(crate) fn post_result(mut self, result: PostResult) -> PostResult {
        self.settled = true;
        match result {
            Ok(StreamableHttpPostResponse::Accepted) => {
                self.slot.settle(Outcome::Accepted);
                Ok(StreamableHttpPostResponse::Accepted)
            }
            Ok(StreamableHttpPostResponse::Json(message, session)) => {
                self.slot.settle(Outcome::Json);
                Ok(StreamableHttpPostResponse::Json(message, session))
            }
            Ok(StreamableHttpPostResponse::Sse(stream, session)) => {
                let request = self.request.take();
                Ok(StreamableHttpPostResponse::Sse(
                    self.slot.tap(stream, request),
                    session,
                ))
            }
            Ok(other) => {
                self.slot.settle(Outcome::Unrecognized);
                Ok(other)
            }
            Err(error) => {
                self.slot.settle(failure(&error));
                Err(error)
            }
        }
    }

    /// Record a GET's outcome, wrapping an opened stream in the same tap.
    pub(crate) fn stream_result(mut self, result: StreamResult) -> StreamResult {
        self.settled = true;
        match result {
            Ok(stream) => Ok(self.slot.tap(stream, None)),
            Err(error) => {
                self.slot.settle(failure(&error));
                Err(error)
            }
        }
    }

    /// Record the outcome of a request whose success carries no response.
    pub(crate) fn unit_result(
        mut self,
        result: Result<(), StreamableHttpError<reqwest::Error>>,
    ) -> Result<(), StreamableHttpError<reqwest::Error>> {
        self.settled = true;
        match &result {
            Ok(()) => self.slot.settle(Outcome::Succeeded),
            Err(error) => self.slot.settle(failure(error)),
        }
        result
    }
}

impl Drop for PendingExchange {
    fn drop(&mut self) {
        if !self.settled {
            self.slot.settle(Outcome::Abandoned);
        }
    }
}

/// The address of one exchange in a trace that may already be gone.
struct Slot {
    record: Weak<Mutex<Record>>,
    id: u64,
}

impl Slot {
    fn update(&self, update: impl FnOnce(&mut Exchange)) {
        let Some(record) = self.record.upgrade() else {
            return;
        };
        let mut record = record.lock().expect("dial trace lock poisoned");
        if let Some(exchange) = record.get_mut(self.id) {
            update(exchange);
        }
    }

    fn settle(&self, outcome: Outcome) {
        self.update(|exchange| {
            exchange.finished = Some(exchange.started.elapsed());
            exchange.outcome = outcome;
        });
    }

    fn tap(&self, stream: EventStream, request: Option<AwaitedResponse>) -> EventStream {
        // A response that arrives after the dial ends belongs to the
        // established connection and passes through unwrapped.
        if self.record.strong_count() == 0 {
            return stream;
        }
        let answered = request.as_ref().map(|_| false);
        self.update(|exchange| {
            exchange.outcome = Outcome::EventStream {
                events: 0,
                data_events: 0,
                end: StreamEnd::Open,
                answered,
                first_other: None,
            };
        });
        StreamTap {
            inner: stream,
            slot: Slot {
                record: self.record.clone(),
                id: self.id,
            },
            ended: false,
            request,
        }
        .boxed()
    }
}

/// Passes an event stream through unchanged while counting its events and
/// noting how it ends. While the dial records, each data event on a request's
/// stream is also read once to tell whether it answers the request; nothing
/// from it is kept but a bounded description of the first one that does not.
struct StreamTap {
    inner: EventStream,
    slot: Slot,
    ended: bool,
    request: Option<AwaitedResponse>,
}

impl StreamTap {
    fn observe(&mut self, update: impl FnOnce(&mut usize, &mut usize, &mut StreamEnd)) {
        self.slot.update(|exchange| {
            if let Outcome::EventStream {
                events,
                data_events,
                end,
                ..
            } = &mut exchange.outcome
            {
                update(events, data_events, end);
            }
        });
    }

    fn note_data(&mut self, data: &str) {
        let Some(request) = self.request.as_ref() else {
            return;
        };
        if self.slot.record.strong_count() == 0 {
            return;
        }
        let read = read_data_event(data, request);
        self.slot.update(|exchange| {
            let Outcome::EventStream {
                answered,
                first_other,
                ..
            } = &mut exchange.outcome
            else {
                return;
            };
            match read {
                DataEvent::Answer => {
                    if let Some(answered) = answered {
                        *answered = true;
                    }
                }
                DataEvent::Other(description) => {
                    first_other.get_or_insert(description);
                }
            }
        });
    }

    fn end(&mut self, how: StreamEnd) {
        self.ended = true;
        self.slot.update(|exchange| {
            if let Outcome::EventStream { end, .. } = &mut exchange.outcome {
                if matches!(end, StreamEnd::Open) {
                    *end = how;
                }
                exchange.finished = Some(exchange.started.elapsed());
            }
        });
    }
}

impl Stream for StreamTap {
    type Item = Result<Sse, SseError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polled = self.inner.poll_next_unpin(cx);
        match &polled {
            Poll::Ready(Some(Ok(event))) => {
                let data = event.data.as_deref().filter(|data| !data.trim().is_empty());
                self.observe(|events, data_events, _| {
                    *events += 1;
                    *data_events += usize::from(data.is_some());
                });
                if let Some(data) = data {
                    self.note_data(data);
                }
            }
            Poll::Ready(Some(Err(error))) => {
                let detail = sse_failure(error);
                self.observe(|events, _, end| {
                    *events += 1;
                    *end = StreamEnd::Error(detail);
                });
            }
            Poll::Ready(None) => self.end(StreamEnd::Normal),
            Poll::Pending => {}
        }
        polled
    }
}

impl Drop for StreamTap {
    fn drop(&mut self) {
        if !self.ended {
            self.end(StreamEnd::Closed);
        }
    }
}

#[derive(Default)]
struct Record {
    exchanges: VecDeque<Exchange>,
    /// The id of the oldest exchange still kept.
    first_id: u64,
    dropped: usize,
}

impl Record {
    fn push(&mut self, exchange: Exchange) -> u64 {
        if self.exchanges.len() == MAX_RECORDED_EXCHANGES {
            self.exchanges.pop_front();
            self.first_id += 1;
            self.dropped += 1;
        }
        self.exchanges.push_back(exchange);
        self.first_id + self.exchanges.len() as u64 - 1
    }

    fn get_mut(&mut self, id: u64) -> Option<&mut Exchange> {
        let index = usize::try_from(id.checked_sub(self.first_id)?).ok()?;
        self.exchanges.get_mut(index)
    }
}

#[derive(Clone, Copy)]
enum HttpMethod {
    Post,
    Get,
    Delete,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Get => "GET",
            Self::Delete => "DELETE",
        }
    }
}

struct Exchange {
    method: HttpMethod,
    label: Option<String>,
    started: Instant,
    finished: Option<Duration>,
    outcome: Outcome,
}

enum Outcome {
    Pending,
    Abandoned,
    Accepted,
    Json,
    Succeeded,
    /// A response shape this gateway does not know how to describe.
    Unrecognized,
    EventStream {
        events: usize,
        data_events: usize,
        end: StreamEnd,
        /// For a request's stream, whether a readable answer to that request
        /// arrived; `None` for a stream that answers no request.
        answered: Option<bool>,
        /// The first data event that was not that answer, described.
        first_other: Option<String>,
    },
    Failed {
        status: Option<u16>,
        detail: Option<String>,
    },
}

enum StreamEnd {
    Open,
    Normal,
    Error(String),
    /// The gateway stopped reading, as it does once a request's response has
    /// arrived or the request is cancelled.
    Closed,
}

impl Exchange {
    fn render(&self, out: &mut String) {
        out.push_str(self.method.as_str());
        if let Some(label) = &self.label {
            out.push(' ');
            out.push_str(label);
        }
        out.push_str(" -> ");
        let elapsed = format_elapsed(self.finished.unwrap_or_else(|| self.started.elapsed()));
        match &self.outcome {
            Outcome::Pending => {
                let _ = write!(out, "no response after {elapsed}");
            }
            Outcome::Abandoned => {
                let _ = write!(out, "abandoned by the gateway after {elapsed}");
            }
            Outcome::Accepted => {
                let _ = write!(out, "accepted after {elapsed}");
            }
            Outcome::Json => {
                let _ = write!(out, "JSON after {elapsed}");
            }
            Outcome::Succeeded => {
                let _ = write!(out, "succeeded after {elapsed}");
            }
            Outcome::Unrecognized => {
                let _ = write!(out, "unrecognized response after {elapsed}");
            }
            Outcome::EventStream {
                events,
                data_events,
                end,
                answered,
                first_other,
            } => {
                let _ = write!(
                    out,
                    "event stream, {}, {}, ",
                    counted(*events, "event"),
                    counted(*data_events, "data event"),
                );
                if *answered == Some(false) && !matches!(end, StreamEnd::Open) {
                    out.push_str("no readable answer to this request, ");
                }
                if let Some(first_other) = first_other {
                    let _ = write!(out, "first other data event: {first_other}, ");
                }
                match end {
                    StreamEnd::Open => {
                        let _ = write!(out, "still open after {elapsed}");
                    }
                    StreamEnd::Normal => {
                        let _ = write!(out, "ended normally after {elapsed}");
                    }
                    StreamEnd::Closed => {
                        let _ = write!(out, "closed by the gateway after {elapsed}");
                    }
                    StreamEnd::Error(detail) => {
                        let _ = write!(out, "ended with an error after {elapsed}: {detail}");
                    }
                }
            }
            Outcome::Failed { status, detail } => {
                match status {
                    Some(status) => {
                        let _ = write!(out, "HTTP {status} after {elapsed}");
                    }
                    None => {
                        let _ = write!(out, "failed after {elapsed}");
                    }
                }
                if let Some(detail) = detail {
                    let _ = write!(out, ": {detail}");
                }
            }
        }
    }
}

fn counted(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

fn format_elapsed(elapsed: Duration) -> String {
    if elapsed < Duration::from_secs(1) {
        format!("{} ms", elapsed.as_millis())
    } else {
        format!("{:.1} s", elapsed.as_secs_f64())
    }
}

/// The gateway's own name for the message a POST carries.
fn message_label(message: &ClientJsonRpcMessage) -> String {
    let label = match message {
        JsonRpcMessage::Request(request) => request.request.method(),
        JsonRpcMessage::Notification(notification) => {
            notification_method(&notification.notification)
        }
        JsonRpcMessage::Response(_) => "response",
        JsonRpcMessage::Error(_) => "error",
    };
    bounded_text(label, MAX_LABEL_BYTES)
}

fn notification_method(notification: &ClientNotification) -> &str {
    match notification {
        ClientNotification::CancelledNotification(notification) => notification.method.as_str(),
        ClientNotification::ProgressNotification(notification) => notification.method.as_str(),
        ClientNotification::InitializedNotification(notification) => notification.method.as_str(),
        ClientNotification::RootsListChangedNotification(notification) => {
            notification.method.as_str()
        }
        ClientNotification::CustomNotification(notification) => notification.method.as_str(),
        _ => "notification",
    }
}

/// Describe a failed request without upstream payload or header values.
///
/// rmcp's reqwest client turns these statuses into dedicated errors, so the
/// error alone names the status. It reports any other refused response as
/// `HTTP {status}: {body}`; only that status is kept, because the body is
/// upstream data.
fn failure(error: &StreamableHttpError<reqwest::Error>) -> Outcome {
    let (status, detail) = match error {
        StreamableHttpError::Client(error) => client_failure(error),
        StreamableHttpError::AuthRequired(_) => (Some(401), None),
        StreamableHttpError::InsufficientScope(_) => (Some(403), None),
        StreamableHttpError::SessionExpired => (Some(404), Some("session expired".to_owned())),
        StreamableHttpError::ServerDoesNotSupportSse => (Some(405), None),
        StreamableHttpError::UnexpectedServerResponse(text) => match refused_status(text) {
            Some(status) => (Some(status), None),
            None => (None, Some("unexpected server response".to_owned())),
        },
        StreamableHttpError::UnexpectedContentType(_) => {
            (None, Some("unexpected content type".to_owned()))
        }
        StreamableHttpError::Deserialize(_) => {
            (None, Some("response is not a JSON-RPC message".to_owned()))
        }
        StreamableHttpError::Sse(error) => (None, Some(sse_failure(error))),
        other => (
            None,
            Some(bounded_text(&other.to_string(), MAX_EXCHANGE_ERROR_BYTES)),
        ),
    };
    Outcome::Failed { status, detail }
}

/// reqwest's own message names the request URL, whose query can carry
/// credentials, so only the kind of failure is kept.
fn client_failure(error: &reqwest::Error) -> (Option<u16>, Option<String>) {
    let status = error.status().map(|status| status.as_u16());
    let kind = if error.is_connect() {
        Some("connection failed")
    } else if error.is_timeout() {
        Some("timed out")
    } else if status.is_some() {
        None
    } else {
        Some("request failed")
    };
    (status, kind.map(str::to_owned))
}

fn refused_status(text: &str) -> Option<u16> {
    let code: u16 = text.strip_prefix("HTTP ")?.get(..3)?.parse().ok()?;
    (100..=599).contains(&code).then_some(code)
}

/// What one event-stream data event was, relative to the request it streams.
enum DataEvent {
    /// The answer to the request, in a form the SDK reads.
    Answer,
    /// Anything else: a notification, an answer to another request, an
    /// error the SDK cannot route, or text the SDK cannot read.
    Other(String),
}

/// Read a data event the way the SDK will, and describe anything that will
/// not complete the request. The SDK skips an unreadable event and an error
/// without an id without reporting them, so a stream that carried one ends
/// with only `Transport closed`. The description keeps JSON-RPC structure,
/// error codes, and a bounded error message; never a result.
fn read_data_event(data: &str, request: &AwaitedResponse) -> DataEvent {
    let value: serde_json::Value = match serde_json::from_str(data) {
        Ok(value) => value,
        Err(error) => return DataEvent::Other(format!("not JSON ({})", decode_error(&error))),
    };
    let Some(object) = value.as_object() else {
        return DataEvent::Other("JSON that is not a JSON-RPC message".to_owned());
    };
    if let Some(method) = object.get("method").and_then(serde_json::Value::as_str) {
        let kind = if object.contains_key("id") {
            "request"
        } else {
            "notification"
        };
        return DataEvent::Other(format!("{kind} {}", bounded_text(method, MAX_LABEL_BYTES)));
    }
    let answers = id_matches(object.get("id"), &request.id);
    let whose = match object.get("id") {
        None | Some(serde_json::Value::Null) => "without an id",
        Some(_) if answers => "for this request",
        Some(_) => "for another request",
    };
    let kind = if let Some(error) = object.get("error") {
        if !answers {
            let code = error
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .map_or_else(|| "unknown".to_owned(), |code| code.to_string());
            let message = error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            return DataEvent::Other(format!(
                "error {whose}, code {code}: {}",
                bounded_text(message, MAX_EXCHANGE_ERROR_BYTES)
            ));
        }
        "error"
    } else if object.contains_key("result") {
        if !answers {
            return DataEvent::Other(format!("response {whose}"));
        }
        "response"
    } else {
        return DataEvent::Other("JSON-RPC message without a method, result, or error".to_owned());
    };
    // A routed answer completes the request only if the SDK can read it; the
    // SDK reports a readable error itself.
    match serde_json::from_value::<ServerJsonRpcMessage>(value.clone()) {
        Ok(_) => DataEvent::Answer,
        Err(error) => DataEvent::Other(format!(
            "{kind} for this request that the SDK cannot read ({})",
            unreadable_envelope(&value, &error)
        )),
    }
}

fn id_matches(id: Option<&serde_json::Value>, expected: &RequestId) -> bool {
    match (id, expected) {
        (Some(serde_json::Value::Number(id)), NumberOrString::Number(expected)) => {
            id.as_i64() == Some(*expected)
        }
        (Some(serde_json::Value::String(id)), NumberOrString::String(expected)) => {
            id.as_str() == expected.as_ref()
        }
        _ => false,
    }
}

/// Why the SDK cannot read an answer. Its result type accepts any object, so
/// an unreadable answer has a malformed envelope: its version marker or its
/// error object. The SDK's own error names no member.
fn unreadable_envelope(value: &serde_json::Value, error: &serde_json::Error) -> String {
    match value.get("jsonrpc") {
        Some(serde_json::Value::String(version)) if version == "2.0" => {}
        Some(_) => return "its jsonrpc member is not \"2.0\"".to_owned(),
        None => return "it has no jsonrpc member".to_owned(),
    }
    if let Some(member) = value.get("error") {
        let is_error_object = member.get("code").is_some_and(serde_json::Value::is_i64)
            && member
                .get("message")
                .is_some_and(serde_json::Value::is_string);
        if !is_error_object {
            return "its error member is not a JSON-RPC error object".to_owned();
        }
    }
    decode_error(error)
}

fn decode_error(error: &serde_json::Error) -> String {
    bounded_text(&error.to_string(), MAX_EXCHANGE_ERROR_BYTES)
}

/// A body error wraps the HTTP client's error, which names the request URL.
/// Every other event-stream parse error is a fixed description.
fn sse_failure(error: &SseError) -> String {
    match error {
        SseError::Body(_) => "response body failed".to_owned(),
        other => bounded_text(&other.to_string(), MAX_EXCHANGE_ERROR_BYTES),
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use futures::stream;
    use rmcp::model::{
        ClientRequest, ClientResult, CustomRequest, ErrorData, InitializedNotification,
        ListToolsRequest, PaginatedRequestParams, RequestId,
    };

    use super::*;

    fn request(request: ClientRequest) -> ClientJsonRpcMessage {
        ClientJsonRpcMessage::request(request, RequestId::Number(1))
    }

    fn list_tools() -> ClientJsonRpcMessage {
        request(ClientRequest::ListToolsRequest(
            ListToolsRequest::with_param(PaginatedRequestParams::default()),
        ))
    }

    fn event(data: Option<&str>) -> Result<Sse, SseError> {
        Ok(Sse {
            data: data.map(str::to_owned),
            ..Sse::default()
        })
    }

    /// The trace's summary with every elapsed time replaced by `T`, so an
    /// assertion never depends on how fast the test ran.
    fn summary(trace: &DialTrace) -> String {
        let summary = trace.summary().expect("the trace recorded an exchange");
        let mut parts = summary.split("after ");
        let mut normalized = parts.next().unwrap_or_default().to_owned();
        for part in parts {
            let rest = part.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.');
            let rest = rest
                .strip_prefix(" ms")
                .or_else(|| rest.strip_prefix(" s"))
                .expect("every `after` names an elapsed time");
            normalized.push_str("after T");
            normalized.push_str(rest);
        }
        normalized
    }

    #[test]
    fn a_dial_without_http_exchanges_has_no_summary() {
        assert_eq!(DialTrace::new().summary(), None);
    }

    #[test]
    fn labels_name_the_message_the_gateway_sends() {
        let trace = DialTrace::new();
        let recorder = trace.recorder();
        let initialized = ClientJsonRpcMessage::notification(
            ClientNotification::InitializedNotification(InitializedNotification::default()),
        );
        let reply = ClientJsonRpcMessage::response(ClientResult::empty(()), RequestId::Number(9));
        let refusal =
            ClientJsonRpcMessage::error(ErrorData::internal_error("declined", None), None);
        let custom_method = format!("vendor/{}", "x".repeat(200));
        let custom = request(ClientRequest::CustomRequest(CustomRequest::new(
            custom_method.clone(),
            None,
        )));

        for message in [&list_tools(), &initialized, &reply, &refusal, &custom] {
            recorder
                .post(message)
                .post_result(Ok(StreamableHttpPostResponse::Accepted))
                .expect("an accepted POST passes through");
        }
        recorder
            .delete()
            .unit_result(Ok(()))
            .expect("a unit result passes through");

        let custom_label = bounded_text(&custom_method, MAX_LABEL_BYTES);
        assert!(custom_label.len() <= MAX_LABEL_BYTES);
        assert_eq!(
            summary(&trace),
            format!(
                "HTTP exchanges on this dial: POST tools/list -> accepted after T; \
                 POST notifications/initialized -> accepted after T; \
                 POST response -> accepted after T; POST error -> accepted after T; \
                 POST {custom_label} -> accepted after T; DELETE -> succeeded after T"
            ),
        );
    }

    #[test]
    fn the_record_keeps_the_most_recent_exchanges_and_counts_the_rest() {
        let trace = DialTrace::new();
        let recorder = trace.recorder();
        for _ in 0..MAX_RECORDED_EXCHANGES + 3 {
            recorder
                .post(&list_tools())
                .post_result(Ok(StreamableHttpPostResponse::Accepted))
                .expect("an accepted POST passes through");
        }
        recorder
            .delete()
            .unit_result(Ok(()))
            .expect("a unit result passes through");

        let summary = summary(&trace);
        assert!(
            summary.starts_with("HTTP exchanges on this dial: 4 earlier not shown; "),
            "{summary}"
        );
        assert_eq!(summary.matches(" -> ").count(), MAX_RECORDED_EXCHANGES);
        assert!(
            summary.ends_with("; DELETE -> succeeded after T"),
            "{summary}"
        );
    }

    #[tokio::test]
    async fn an_event_stream_passes_through_while_its_events_are_counted() {
        let trace = DialTrace::new();
        let recorder = trace.recorder();
        let events = vec![
            event(Some("{\"jsonrpc\":\"2.0\"}")),
            event(None),
            event(Some("  ")),
        ];
        let expected: Vec<Sse> = events
            .iter()
            .map(|event| event.as_ref().expect("fixture events are valid").clone())
            .collect();
        let Ok(StreamableHttpPostResponse::Sse(tapped, session)) = recorder
            .post(&list_tools())
            .post_result(Ok(StreamableHttpPostResponse::Sse(
                stream::iter(events).boxed(),
                Some("session".into()),
            )))
        else {
            panic!("an event stream stays an event stream");
        };
        assert_eq!(session.as_deref(), Some("session"));
        assert_eq!(
            summary(&trace),
            "HTTP exchanges on this dial: POST tools/list -> event stream, 0 events, \
             0 data events, still open after T",
        );

        let received: Vec<Sse> = tapped
            .map(|event| event.expect("no stream error"))
            .collect()
            .await;
        assert_eq!(
            received, expected,
            "the tap must not change what the SDK receives"
        );
        assert_eq!(
            summary(&trace),
            "HTTP exchanges on this dial: POST tools/list -> event stream, 3 events, \
             1 data event, no readable answer to this request, first other data event: \
             JSON-RPC message without a method, result, or error, ended normally after T",
        );
    }

    #[test]
    fn a_data_event_is_described_by_its_role_never_by_its_result() {
        let request = AwaitedResponse {
            id: RequestId::Number(1),
        };
        let read = |data: &str| match read_data_event(data, &request) {
            DataEvent::Answer => "answer".to_owned(),
            DataEvent::Other(description) => description,
        };
        assert_eq!(
            read(r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#),
            "answer"
        );
        assert_eq!(
            read(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}"#),
            "answer",
            "the SDK reports a routed error itself"
        );
        assert_eq!(
            read(r#"{"jsonrpc":"2.0","id":1,"error":null}"#),
            "error for this request that the SDK cannot read \
             (its error member is not a JSON-RPC error object)",
            "an error the SDK cannot read never completes the request"
        );
        assert_eq!(
            read(r#"{"jsonrpc":"2.0","id":7,"result":{"secret":"value"}}"#),
            "response for another request"
        );
        assert_eq!(
            read(r#"{"jsonrpc":"2.0","id":"1","result":{}}"#),
            "response for another request",
            "a string id never answers a numeric request id"
        );
        assert_eq!(
            read(r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"x"}}"#),
            "notification notifications/message"
        );
        assert_eq!(
            read(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#),
            "request ping"
        );
        assert_eq!(
            read(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Bad Request"}}"#),
            "error without an id, code -32600: Bad Request"
        );
        assert_eq!(
            read(r#"{"id":1,"result":{"secret":"value"}}"#),
            "response for this request that the SDK cannot read (it has no jsonrpc member)"
        );
        assert_eq!(
            read(r#"{"jsonrpc":"1.0","id":1,"result":{}}"#),
            "response for this request that the SDK cannot read \
             (its jsonrpc member is not \"2.0\")"
        );
        assert_eq!(
            read("retry later"),
            "not JSON (expected value at line 1 column 1)"
        );

        let forged = format!(
            r#"{{"jsonrpc":"2.0","error":{{"code":-32000,"message":"line\nforged {}"}}}}"#,
            "x".repeat(4 * MAX_EXCHANGE_ERROR_BYTES)
        );
        let described = read(&forged);
        let prefix = "error without an id, code -32000: line\\nforged ";
        assert!(described.starts_with(prefix), "{described}");
        assert!(
            described.len()
                <= "error without an id, code -32000: ".len() + MAX_EXCHANGE_ERROR_BYTES,
            "{} bytes",
            described.len()
        );
    }

    #[tokio::test]
    async fn a_request_stream_notes_only_what_does_not_answer_it() {
        let trace = DialTrace::new();
        let recorder = trace.recorder();
        let answered =
            recorder
                .post(&list_tools())
                .post_result(Ok(StreamableHttpPostResponse::Sse(
                    stream::iter(vec![
                        event(Some(
                            r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#,
                        )),
                        event(Some(r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#)),
                    ])
                    .boxed(),
                    None,
                )));
        let Ok(StreamableHttpPostResponse::Sse(answered, _)) = answered else {
            panic!("an event stream stays an event stream");
        };
        let _: Vec<_> = answered.collect().await;
        assert_eq!(
            summary(&trace),
            "HTTP exchanges on this dial: POST tools/list -> event stream, 2 events, \
             2 data events, first other data event: notification notifications/progress, \
             ended normally after T",
        );
    }

    #[tokio::test]
    async fn an_event_stream_records_an_error_end_and_an_early_close() {
        let trace = DialTrace::new();
        let recorder = trace.recorder();
        let failing = recorder
            .get()
            .stream_result(Ok(stream::iter(vec![
                event(Some("data")),
                Err(SseError::InvalidLine),
            ])
            .boxed()))
            .expect("the stream opened");
        let _: Vec<_> = failing.collect().await;

        let mut closed_early = recorder
            .get()
            .stream_result(Ok(stream::iter(vec![
                event(Some("first")),
                event(Some("second")),
            ])
            .boxed()))
            .expect("the stream opened");
        assert!(closed_early.next().await.is_some());
        drop(closed_early);

        assert_eq!(
            summary(&trace),
            "HTTP exchanges on this dial: GET -> event stream, 2 events, 1 data event, \
             ended with an error after T: invalid line; GET -> event stream, 1 event, \
             1 data event, closed by the gateway after T",
        );
    }

    #[tokio::test]
    async fn an_unsettled_request_reads_as_pending_or_abandoned() {
        let trace = DialTrace::new();
        let recorder = trace.recorder();
        let in_flight = recorder.post(&list_tools());
        assert_eq!(
            summary(&trace),
            "HTTP exchanges on this dial: POST tools/list -> no response after T",
        );
        drop(in_flight);
        assert_eq!(
            summary(&trace),
            "HTTP exchanges on this dial: POST tools/list -> abandoned by the gateway after T",
        );
    }

    #[test]
    fn failures_name_the_status_without_upstream_data() {
        let trace = DialTrace::new();
        let recorder = trace.recorder();
        let failures = [
            StreamableHttpError::UnexpectedServerResponse(Cow::Borrowed(
                "HTTP 401 Unauthorized: upstream body text",
            )),
            StreamableHttpError::UnexpectedServerResponse(Cow::Borrowed(
                "could not parse JSON response: upstream body text",
            )),
            StreamableHttpError::ServerDoesNotSupportSse,
            StreamableHttpError::SessionExpired,
            StreamableHttpError::UnexpectedContentType(Some("text/html; upstream".into())),
            StreamableHttpError::Deserialize(
                serde_json::from_str::<serde_json::Value>("{\"upstream\"")
                    .expect_err("truncated JSON"),
            ),
            StreamableHttpError::TransportChannelClosed,
        ];
        for error in failures {
            assert!(recorder
                .post(&list_tools())
                .post_result(Err(error))
                .is_err());
        }

        let summary = summary(&trace);
        assert_eq!(
            summary,
            "HTTP exchanges on this dial: POST tools/list -> HTTP 401 after T; \
             POST tools/list -> failed after T: unexpected server response; \
             POST tools/list -> HTTP 405 after T; \
             POST tools/list -> HTTP 404 after T: session expired; \
             POST tools/list -> failed after T: unexpected content type; \
             POST tools/list -> failed after T: response is not a JSON-RPC message; \
             POST tools/list -> failed after T: Transport channel closed",
        );
        assert!(!summary.contains("upstream"), "{summary}");
    }

    #[test]
    fn error_text_is_escaped_and_capped() {
        let forged = format!("first\nsecond\u{1b}[31m{}", "é".repeat(300));
        let bounded = bounded_text(&forged, MAX_EXCHANGE_ERROR_BYTES);
        assert!(
            bounded.len() <= MAX_EXCHANGE_ERROR_BYTES,
            "{}",
            bounded.len()
        );
        assert!(
            bounded.starts_with("first\\nsecond\\u{1b}[31m"),
            "{bounded}"
        );
        assert!(bounded.ends_with(TRUNCATION_MARKER));
        assert!(!bounded.chars().any(char::is_control));

        assert_eq!(bounded_text("short", MAX_EXCHANGE_ERROR_BYTES), "short");
        let exact = "x".repeat(MAX_EXCHANGE_ERROR_BYTES);
        assert_eq!(bounded_text(&exact, MAX_EXCHANGE_ERROR_BYTES), exact);
        let one_over = "x".repeat(MAX_EXCHANGE_ERROR_BYTES + 1);
        assert_eq!(
            bounded_text(&one_over, MAX_EXCHANGE_ERROR_BYTES).len(),
            MAX_EXCHANGE_ERROR_BYTES
        );

        let trace = DialTrace::new();
        let failure = StreamableHttpError::<reqwest::Error>::Io(std::io::Error::other(forged));
        assert!(trace
            .recorder()
            .post(&list_tools())
            .post_result(Err(failure))
            .is_err());
        let summary = summary(&trace);
        let detail = summary
            .split_once("failed after T: ")
            .expect("the failure has a detail")
            .1;
        assert!(detail.len() <= MAX_EXCHANGE_ERROR_BYTES, "{}", detail.len());
        assert!(!summary.chars().any(char::is_control), "{summary}");
    }

    #[tokio::test]
    async fn a_reqwest_failure_keeps_its_kind_but_never_its_url() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a free port");
        let address = listener.local_addr().expect("free port address");
        drop(listener);
        let error =
            waygate_core::http_client::client(waygate_core::http_client::Profile::NoTotalTimeout)
                .expect("build the shared test client")
                .get(format!(
                    "http://{address}/private-path?credential=query-value"
                ))
                .send()
                .await
                .expect_err("nothing listens on the released port");
        assert!(
            error.to_string().contains("private-path"),
            "the fixture must prove reqwest's own message names the URL: {error}"
        );

        let trace = DialTrace::new();
        assert!(trace
            .recorder()
            .post(&list_tools())
            .post_result(Err(StreamableHttpError::Client(error)))
            .is_err());

        let summary = summary(&trace);
        assert_eq!(
            summary,
            "HTTP exchanges on this dial: POST tools/list -> failed after T: connection failed",
        );
    }

    #[tokio::test]
    async fn recording_stops_when_the_dial_finishes() {
        let trace = DialTrace::new();
        let recorder = trace.recorder();
        let open = recorder
            .get()
            .stream_result(Ok(stream::iter(vec![event(Some("first"))]).boxed()))
            .expect("the stream opened");
        let in_flight = recorder.post(&list_tools());
        assert!(recorder.is_recording());

        drop(trace);

        // A request started later, a result that arrives later, and an open
        // stream all reach nothing, while the traffic itself passes through.
        assert!(!recorder.is_recording());
        assert!(recorder
            .post(&list_tools())
            .post_result(Ok(StreamableHttpPostResponse::Accepted))
            .is_ok());
        assert!(in_flight
            .post_result(Ok(StreamableHttpPostResponse::Accepted))
            .is_ok());
        let received: Vec<_> = open.collect().await;
        assert_eq!(received.len(), 1);
    }
}
