//! Minimal Server-Sent-Events framing over a byte stream. Enough of the SSE
//! grammar (https://html.spec.whatwg.org/multipage/server-sent-events.html) to
//! carry an LLM provider's `data:` frames: events are separated by a blank
//! line; within an event, `data:` lines are concatenated with `\n`; `:` comment
//! lines and non-`data` fields (`event:`/`id:`/`retry:`) are ignored. The
//! caller interprets the `data` payload (JSON delta, or the `[DONE]` sentinel).
//!
//! Framing is resilient to arbitrary chunk boundaries: raw bytes are buffered
//! and decoded only up to the last *complete* UTF-8 code point (so a multi-byte
//! character split across reads is reassembled, never replaced); CRLF is
//! normalized without prematurely consuming a trailing lone `\r`; and only
//! *complete* frames (terminated by a blank line) are emitted, so a frame split
//! across reads is reassembled. A trailing frame with no terminating blank line
//! is flushed when the stream closes.

use std::collections::VecDeque;

use futures::stream::{BoxStream, StreamExt};

use crate::ProviderError;

/// One SSE event carrying its (possibly multi-line) `data` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The event's `data` payload — for OpenAI-style streams this is a JSON
    /// delta object, or the literal `[DONE]` terminal sentinel.
    pub data: String,
}

impl SseEvent {
    /// Whether this is the OpenAI/OpenRouter end-of-stream sentinel (`[DONE]`).
    pub fn is_done(&self) -> bool {
        self.data.trim() == "[DONE]"
    }
}

/// Max bytes a single in-progress SSE event (decoded, not-yet-framed text) may
/// occupy before it is rejected. Real provider events are KB-scale; this 1 MiB
/// cap bounds memory against an oversized or unterminated event from a
/// hostile/buggy provider, rather than letting `buf` grow without limit.
const MAX_SSE_BUFFER: usize = 1024 * 1024;

/// Incremental SSE decoder: feed it transport byte chunks, drain decoded
/// events. Holds the bytes that did not yet form a complete UTF-8 code point
/// (`pending`), the decoded-but-not-yet-framed text (`buf`), ready events, and
/// a terminal error (set when `buf` exceeds [`MAX_SSE_BUFFER`]).
#[derive(Default)]
struct Decoder {
    pending: Vec<u8>,
    buf: String,
    queue: VecDeque<SseEvent>,
    error: Option<ProviderError>,
}

impl Decoder {
    /// Feed one transport chunk: decode the valid UTF-8 prefix and extract any
    /// complete frames. If the not-yet-framed buffer exceeds [`MAX_SSE_BUFFER`]
    /// a terminal [`ProviderError::Protocol`] is recorded (surfaced after any
    /// already-decoded events drain). `pending` is naturally bounded (an
    /// incomplete trailing code point is < 4 bytes), so only `buf` is capped.
    fn push_chunk(&mut self, chunk: &[u8]) {
        if self.error.is_some() {
            return;
        }
        decode_append(&mut self.pending, &mut self.buf, chunk);
        for ev in extract_frames(&mut self.buf) {
            self.queue.push_back(ev);
        }
        if self.buf.len() > MAX_SSE_BUFFER {
            self.error = Some(ProviderError::Protocol(format!(
                "SSE event exceeded {MAX_SSE_BUFFER} bytes without a frame terminator"
            )));
        }
    }

    /// At stream close, flush any leftover bytes (an incomplete trailing code
    /// point, lossily) and any trailing unterminated frame.
    fn finish(&mut self) {
        if !self.pending.is_empty() {
            self.buf.push_str(&String::from_utf8_lossy(&self.pending));
            self.pending.clear();
        }
        if let Some(ev) = flush_final(&mut self.buf) {
            self.queue.push_back(ev);
        }
    }

    fn pop(&mut self) -> Option<SseEvent> {
        self.queue.pop_front()
    }

    fn take_error(&mut self) -> Option<ProviderError> {
        self.error.take()
    }
}

/// Adapt a reqwest byte stream into a stream of [`SseEvent`]s. The byte-stream
/// item type is inferred (no `bytes` dependency needed).
pub(crate) fn into_event_stream(
    resp: reqwest::Response,
) -> BoxStream<'static, Result<SseEvent, ProviderError>> {
    // State: (boxed byte stream, incremental decoder, eof flag).
    let init = (resp.bytes_stream().boxed(), Decoder::default(), false);
    futures::stream::try_unfold(init, |(mut bytes, mut dec, mut finished)| async move {
        loop {
            if let Some(ev) = dec.pop() {
                return Ok(Some((ev, (bytes, dec, finished))));
            }
            // Surface a terminal decode error only after draining buffered
            // events, then end the stream.
            if let Some(err) = dec.take_error() {
                return Err(err);
            }
            if finished {
                return Ok(None);
            }
            match bytes.next().await {
                Some(Ok(chunk)) => dec.push_chunk(chunk.as_ref()),
                Some(Err(e)) => return Err(ProviderError::Transport(e.to_string())),
                None => {
                    finished = true;
                    dec.finish();
                }
            }
        }
    })
    .boxed()
}

/// Append `chunk` to `buf` as UTF-8 text, carrying any incomplete trailing code
/// point in `pending` until the rest of its bytes arrive. This is what makes
/// framing resilient to a multi-byte character split across transport chunks —
/// the split bytes are held, not turned into replacement characters. A
/// genuinely invalid sequence (its `error_len()` is `Some`, so it cannot be a
/// mere split) becomes a single replacement character.
fn decode_append(pending: &mut Vec<u8>, buf: &mut String, chunk: &[u8]) {
    pending.extend_from_slice(chunk);
    loop {
        match std::str::from_utf8(pending) {
            Ok(s) => {
                buf.push_str(s);
                pending.clear();
                return;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                if valid > 0 {
                    // The first `valid` bytes are valid UTF-8 by definition.
                    buf.push_str(std::str::from_utf8(&pending[..valid]).expect("valid prefix"));
                }
                match e.error_len() {
                    // Incomplete trailing sequence: keep it for the next chunk.
                    None => {
                        pending.drain(..valid);
                        return;
                    }
                    // A real invalid sequence: emit one replacement, continue.
                    Some(bad) => {
                        buf.push('\u{FFFD}');
                        pending.drain(..valid + bad);
                    }
                }
            }
        }
    }
}

/// Drain all *complete* frames (terminated by a blank line) from `buf`,
/// leaving any trailing partial frame in place.
fn extract_frames(buf: &mut String) -> Vec<SseEvent> {
    if buf.contains('\r') {
        // Normalize CRLF to LF only. A lone trailing '\r' may be the first half
        // of a CRLF split across reads, so leaving bare CR (rather than forcing
        // it to LF) lets the next chunk resolve it correctly.
        *buf = buf.replace("\r\n", "\n");
    }
    let mut events = Vec::new();
    while let Some(idx) = buf.find("\n\n") {
        let frame = buf[..idx].to_string();
        buf.drain(..idx + 2);
        if let Some(ev) = parse_frame(&frame) {
            events.push(ev);
        }
    }
    events
}

/// At stream close, treat any remaining buffered text as a final frame (some
/// servers omit the trailing blank line on the last event).
fn flush_final(buf: &mut String) -> Option<SseEvent> {
    if buf.trim().is_empty() {
        buf.clear();
        return None;
    }
    let frame = std::mem::take(buf);
    parse_frame(frame.trim_end_matches(['\n', '\r']))
}

/// Parse a single frame (text between blank-line separators) into an event,
/// or `None` if it carries no `data:` lines (e.g. a comment-only frame).
fn parse_frame(frame: &str) -> Option<SseEvent> {
    let mut data: Vec<&str> = Vec::new();
    for line in frame.split('\n') {
        // Tolerate a bare CR line ending that survived CRLF normalization.
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            // SSE strips a single optional leading space after the colon.
            data.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
        // Non-`data` fields are not needed for OpenAI-style streams.
    }
    if data.is_empty() {
        None
    } else {
        Some(SseEvent {
            data: data.join("\n"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_complete_frame_and_keeps_remainder() {
        let mut buf = String::from("data: {\"a\":1}\n\ndata: partial");
        let evs = extract_frames(&mut buf);
        assert_eq!(
            evs,
            vec![SseEvent {
                data: "{\"a\":1}".into()
            }]
        );
        // The partial (no trailing blank line) stays buffered.
        assert_eq!(buf, "data: partial");
    }

    #[test]
    fn reassembles_a_frame_split_across_chunks() {
        let mut buf = String::from("data: hel");
        assert!(extract_frames(&mut buf).is_empty());
        buf.push_str("lo\n\n");
        let evs = extract_frames(&mut buf);
        assert_eq!(
            evs,
            vec![SseEvent {
                data: "hello".into()
            }]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn two_frames_in_one_buffer() {
        let mut buf = String::from("data: a\n\ndata: b\n\n");
        let evs = extract_frames(&mut buf);
        assert_eq!(
            evs,
            vec![SseEvent { data: "a".into() }, SseEvent { data: "b".into() }]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn multi_data_lines_join_with_newline_and_comments_skipped() {
        let mut buf = String::from(": a comment\ndata: line1\ndata: line2\n\n");
        let evs = extract_frames(&mut buf);
        assert_eq!(
            evs,
            vec![SseEvent {
                data: "line1\nline2".into()
            }]
        );
    }

    #[test]
    fn crlf_line_endings_are_normalized() {
        let mut buf = String::from("data: x\r\n\r\n");
        let evs = extract_frames(&mut buf);
        assert_eq!(evs, vec![SseEvent { data: "x".into() }]);
    }

    #[test]
    fn done_sentinel_is_detected() {
        let mut buf = String::from("data: [DONE]\n\n");
        let evs = extract_frames(&mut buf);
        assert_eq!(evs.len(), 1);
        assert!(evs[0].is_done());
    }

    #[test]
    fn comment_only_frame_yields_no_event() {
        let mut buf = String::from(": keepalive\n\n");
        assert!(extract_frames(&mut buf).is_empty());
    }

    #[test]
    fn flush_final_emits_unterminated_trailing_frame() {
        let mut buf = String::from("data: tail");
        let ev = flush_final(&mut buf).expect("trailing frame");
        assert_eq!(ev.data, "tail");
        assert!(buf.is_empty());
        // A whitespace-only buffer flushes to nothing.
        let mut blank = String::from("\n\n");
        assert!(flush_final(&mut blank).is_none());
    }

    #[test]
    fn multibyte_codepoint_split_across_chunks_is_not_corrupted() {
        // "café" — the 'é' is 0xC3 0xA9, split between two chunks. The first
        // byte must be held, not turned into a replacement character.
        let mut d = Decoder::default();
        d.push_chunk(b"data: caf");
        d.push_chunk(&[0xC3]); // first byte of 'é'
        assert!(d.pop().is_none());
        d.push_chunk(&[0xA9]); // second byte of 'é'
        d.push_chunk(b"\n\n");
        let ev = d.pop().expect("frame");
        assert_eq!(ev.data, "café");
        assert!(d.pop().is_none());
    }

    #[test]
    fn crlf_frame_terminator_split_across_chunks() {
        // "data: x\r\n\r\n" split so the CR/LF halves land in different chunks.
        let mut d = Decoder::default();
        d.push_chunk(b"data: x\r");
        assert!(d.pop().is_none(), "no complete frame yet");
        d.push_chunk(b"\n\r\n");
        let ev = d.pop().expect("frame");
        assert_eq!(ev.data, "x");
    }

    #[test]
    fn genuinely_invalid_bytes_become_one_replacement_char() {
        // 0xFF is never valid UTF-8 (error_len = Some), so it is not held as a
        // split code point — it becomes a single replacement character.
        let mut d = Decoder::default();
        d.push_chunk(&[b'd', b'a', b't', b'a', b':', b' ', 0xFF, b'\n', b'\n']);
        let ev = d.pop().expect("frame");
        assert_eq!(ev.data, "\u{FFFD}");
    }

    #[test]
    fn oversized_unterminated_event_is_rejected() {
        // An event that grows past the cap without a frame terminator must
        // produce a terminal Protocol error rather than buffer unboundedly.
        let mut d = Decoder::default();
        d.push_chunk(b"data: ");
        d.push_chunk(&vec![b'x'; MAX_SSE_BUFFER + 1]);
        assert!(d.pop().is_none(), "no complete frame was emitted");
        assert!(
            matches!(d.take_error(), Some(ProviderError::Protocol(_))),
            "an oversized unterminated event must error"
        );
    }
}
