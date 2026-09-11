use crate::codemode_limits::limits;
use std::io::{self, Write};

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
