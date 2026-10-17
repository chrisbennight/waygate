use crate::codemode_limits::limits;
use std::io::{self, Write};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RUNNER_FLAG: &str = "--codemode-runner";
pub const RUNNER_SPOOL_FLAG: &str = "--codemode-result-spool";
pub const CONFINEMENT_PROFILE: &str = "linux-seccomp-v1";
pub const MAX_FAILURE_MESSAGE_CHARS: usize = 1024;

pub fn bounded_failure_message(message: &str) -> String {
    message.chars().take(MAX_FAILURE_MESSAGE_CHARS).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerBinding {
    pub connector: String,
    pub operation: String,
    pub call_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerResumeContext {
    pub checkpoint: Value,
    pub input: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerFailureCode {
    ExecutionTimeout,
    ProgramFailed,
    ConnectorResultTooLarge,
    ResultTooLarge,
    ResultNotJson,
    ArtifactTooLarge,
    RunnerInternal,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ParentFrame {
    Start {
        source: String,
        bindings: Vec<RunnerBinding>,
        resume: Option<RunnerResumeContext>,
        /// Caller-supplied data the program reads as `execution.input`. Data
        /// only: the runner installs it as an already-parsed value and never
        /// evaluates it. Defaulted for the same reason as the budget below —
        /// a frame written without it can only come from a build predating
        /// the field, and no input is the right answer for that frame.
        #[serde(default)]
        input: Value,
        artifacts_available: bool,
        /// Wall-clock budget this runner may spend before its interrupt
        /// handler terminates the program, in milliseconds.
        ///
        /// The parent decides it per execution, bounded by operator policy,
        /// so the runner never chooses its own deadline. Standalone runner
        /// callers may omit it to use the documented default; the gateway
        /// always supplies the boot-resolved or caller-narrowed budget.
        #[serde(default = "default_execution_limit_ms")]
        execution_limit_ms: u64,
    },
    CallResult {
        id: u32,
        result: Result<ConnectorCallResult, String>,
    },
    ArtifactResult {
        id: u32,
        result: Result<Value, String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "storage", rename_all = "snake_case")]
pub enum ConnectorCallResult {
    Inline { value: Value },
    Spool { bytes: u64 },
}

/// Budget applied to a start frame that carries none.
///
/// Standalone runner invocations use the documented default. The gateway
/// always supplies its boot-resolved budget explicitly.
pub const fn default_execution_limit_ms() -> u64 {
    300_000
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunnerFrame {
    Ready {
        confinement_profile: String,
    },
    Call {
        id: u32,
        call_id: String,
        arguments: Value,
    },
    Complete {
        result: Value,
    },
    Pause {
        checkpoint: Value,
    },
    Artifact {
        id: u32,
        value: Value,
    },
    Failed {
        code: RunnerFailureCode,
        message: String,
    },
    /// One `console` call, already formatted. The runner stops sending once
    /// the console budget is spent; the parent applies the same budget again
    /// and keeps only what fits.
    Console {
        level: ConsoleLevel,
        text: String,
    },
    /// Output past the console budget was cut or dropped. Sent once, when the
    /// runner's accounting first truncates, so the parent reports truncation
    /// even when the shortened entry it received fits its own budget exactly.
    ConsoleTruncated,
}

// The severity a `console` method reports, named as programs know them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleLevel {
    Debug,
    Info,
    Log,
    Warn,
    Error,
}

// One line of program console output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConsoleEntry {
    /// The `console` method's severity.
    pub level: ConsoleLevel,
    /// The formatted output of that call.
    pub text: String,
}

// Console output a program produced during one runner attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConsoleOutput {
    /// Output in call order.
    pub entries: Vec<ConsoleEntry>,
    /// True when output beyond the console budget was dropped; the last entry
    /// may then end early.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

impl ConsoleOutput {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && !self.truncated
    }
}

/// Per-entry cost charged in addition to its text, so a flood of empty calls
/// is bounded by the same budget as long ones.
pub const CONSOLE_ENTRY_OVERHEAD_BYTES: usize = 16;

/// Console output admitted against a byte budget.
///
/// The runner and the parent both account with this type, so the runner
/// stops sending exactly where the parent stops keeping.
#[derive(Debug)]
pub struct ConsoleCapture {
    output: ConsoleOutput,
    remaining: usize,
}

impl ConsoleCapture {
    pub fn new(budget_bytes: usize) -> Self {
        Self {
            output: ConsoleOutput::default(),
            remaining: budget_bytes,
        }
    }

    /// Record one call and return what was kept, or `None` once output has
    /// been truncated. An entry that does not fit is cut on a character
    /// boundary and ends the output.
    ///
    /// U+0000 becomes U+FFFD: console output is stored inside results, and
    /// the store's JSON type cannot hold U+0000 in a string.
    pub fn admit(&mut self, level: ConsoleLevel, text: &str) -> Option<&ConsoleEntry> {
        if self.output.truncated {
            return None;
        }
        let replaced;
        let text = if text.contains('\0') {
            replaced = text.replace('\0', "\u{fffd}");
            replaced.as_str()
        } else {
            text
        };
        let Some(room) = self.remaining.checked_sub(CONSOLE_ENTRY_OVERHEAD_BYTES) else {
            self.output.truncated = true;
            self.remaining = 0;
            return None;
        };
        let kept = if text.len() <= room {
            self.remaining = room - text.len();
            text
        } else {
            self.output.truncated = true;
            self.remaining = 0;
            let mut end = room;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            &text[..end]
        };
        self.output.entries.push(ConsoleEntry {
            level,
            text: kept.to_owned(),
        });
        self.output.entries.last()
    }

    pub fn is_truncated(&self) -> bool {
        self.output.truncated
    }

    /// Record that output was lost before it could be offered here.
    pub fn mark_truncated(&mut self) {
        self.output.truncated = true;
        self.remaining = 0;
    }

    pub fn into_output(self) -> ConsoleOutput {
        self.output
    }
}

pub fn encode_frame(frame: &impl Serialize) -> serde_json::Result<Vec<u8>> {
    let mut output = BoundedBuffer::new(limits().frame_bytes);
    serde_json::to_writer(&mut output, frame)?;
    Ok(output.into_inner())
}

pub fn encode_parent_frame(frame: &ParentFrame) -> serde_json::Result<Vec<u8>> {
    let limit = match frame {
        ParentFrame::Start { .. } => limits().parent_frame_bytes,
        ParentFrame::CallResult { .. } | ParentFrame::ArtifactResult { .. } => limits().frame_bytes,
    };
    let mut output = BoundedBuffer::new(limit);
    serde_json::to_writer(&mut output, frame)?;
    Ok(output.into_inner())
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8 * 1024)),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("Code Mode frame size overflow"))?;
        if next_len > self.limit {
            return Err(io::Error::other("Code Mode frame exceeds its limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_capture_keeps_output_within_its_budget() {
        let mut capture = ConsoleCapture::new(CONSOLE_ENTRY_OVERHEAD_BYTES * 2 + 6);
        assert!(capture.admit(ConsoleLevel::Log, "abc").is_some());
        // Two of the three remaining bytes fit; the cut never splits a character.
        let cut = capture
            .admit(ConsoleLevel::Warn, "aé✓")
            .expect("a shortened entry is kept")
            .clone();
        assert_eq!(cut.text, "aé");
        assert!(capture.admit(ConsoleLevel::Error, "dropped").is_none());
        let output = capture.into_output();
        assert!(output.truncated);
        assert_eq!(output.entries.len(), 2);
    }

    #[test]
    fn console_capture_never_keeps_nul() {
        let mut capture = ConsoleCapture::new(CONSOLE_ENTRY_OVERHEAD_BYTES * 2 + 8);
        let kept = capture
            .admit(ConsoleLevel::Log, "a\0b")
            .expect("entry fits")
            .clone();
        assert_eq!(kept.text, "a\u{fffd}b");
        let output = capture.into_output();
        assert!(!output.entries[0].text.contains('\0'));
    }

    #[test]
    fn console_capture_bounds_floods_of_empty_entries() {
        let mut capture = ConsoleCapture::new(CONSOLE_ENTRY_OVERHEAD_BYTES * 3);
        let kept = (0..100)
            .filter(|_| capture.admit(ConsoleLevel::Log, "").is_some())
            .count();
        assert_eq!(kept, 3);
        assert!(capture.into_output().truncated);
    }

    #[test]
    fn console_output_omits_the_flag_until_truncated() {
        let output = ConsoleOutput {
            entries: vec![ConsoleEntry {
                level: ConsoleLevel::Info,
                text: "ready".to_owned(),
            }],
            truncated: false,
        };
        assert_eq!(
            serde_json::to_value(&output).expect("serialize console output"),
            serde_json::json!({"entries": [{"level": "info", "text": "ready"}]})
        );
    }

    #[test]
    fn frame_encoder_refuses_oversized_values() {
        let oversized = ParentFrame::CallResult {
            id: 1,
            result: Ok(ConnectorCallResult::Inline {
                value: Value::String("x".repeat(limits().frame_bytes)),
            }),
        };

        assert!(encode_frame(&oversized).is_err());
    }

    #[test]
    fn start_frame_fits_independently_bounded_checkpoint_and_input() {
        let bounded_value = || Value::String("x".repeat(limits().checkpoint_bytes - 2));
        let mut start = ParentFrame::Start {
            source: "return execution.resume;".to_owned(),
            bindings: vec![RunnerBinding {
                connector: "email".to_owned(),
                operation: "read".to_owned(),
                call_id: String::new(),
            }],
            resume: None,
            input: Value::Null,
            artifacts_available: true,
            execution_limit_ms: default_execution_limit_ms(),
        };
        let base_size = serde_json::to_vec(&start).expect("encode base start").len();
        let ParentFrame::Start { bindings, .. } = &mut start else {
            unreachable!("test constructs a start frame")
        };
        bindings[0].call_id = "c".repeat(limits().frame_bytes - base_size);
        assert_eq!(
            encode_parent_frame(&start)
                .expect("maximal initial start frame")
                .len(),
            limits().frame_bytes
        );

        let ParentFrame::Start { resume, .. } = &mut start else {
            unreachable!("test constructs a start frame")
        };
        *resume = Some(RunnerResumeContext {
            checkpoint: bounded_value(),
            input: bounded_value(),
        });

        assert!(encode_parent_frame(&start).is_ok());
    }

    #[test]
    fn runner_failure_code_round_trips_as_a_stable_protocol_value() {
        let encoded = encode_frame(&RunnerFrame::Failed {
            code: RunnerFailureCode::ResultTooLarge,
            message: "bounded result required".to_owned(),
        })
        .expect("encode failure frame");
        let decoded: RunnerFrame = serde_json::from_slice(&encoded).expect("decode failure frame");

        assert!(matches!(
            decoded,
            RunnerFrame::Failed {
                code: RunnerFailureCode::ResultTooLarge,
                ..
            }
        ));
    }

    #[test]
    fn artifact_frames_round_trip_with_structured_content_and_reference() {
        let emitted = encode_frame(&RunnerFrame::Artifact {
            id: 7,
            value: serde_json::json!({"kind": "preview", "rows": [1, 2]}),
        })
        .expect("encode artifact frame");
        let emitted: RunnerFrame = serde_json::from_slice(&emitted).expect("decode artifact frame");
        assert!(matches!(
            emitted,
            RunnerFrame::Artifact {
                id: 7,
                value,
            } if value["kind"] == "preview"
        ));

        let stored = encode_parent_frame(&ParentFrame::ArtifactResult {
            id: 7,
            result: Ok(serde_json::json!({
                "execution_id": "01900000-0000-7000-8000-000000000001",
                "artifact_id": "01900000-0000-7000-8000-000000000002",
            })),
        })
        .expect("encode artifact result");
        let stored: ParentFrame = serde_json::from_slice(&stored).expect("decode artifact result");
        assert!(matches!(
            stored,
            ParentFrame::ArtifactResult {
                id: 7,
                result: Ok(reference),
            } if reference["artifact_id"]
                == "01900000-0000-7000-8000-000000000002"
        ));
    }
}
