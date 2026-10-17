use crate::codemode_limits::limits;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use rquickjs::{
    function::Func, CatchResultExt, CaughtError, CaughtResult, Context as JsContext, Ctx, Promise,
    Runtime, String as JsString,
};
use serde_json::Value;

use super::codemode_protocol::{
    bounded_failure_message, encode_frame, ConnectorCallResult, ParentFrame, RunnerBinding,
    RunnerFailureCode, RunnerFrame, RunnerResumeContext, CONFINEMENT_PROFILE, RUNNER_SPOOL_FLAG,
};

/// Budget applied when no parent frame has narrowed it. Sourced from the
/// protocol default so the parent and the runner cannot disagree about
/// what "unspecified" means.
const EXECUTION_LIMIT: Duration =
    Duration::from_millis(super::codemode_protocol::default_execution_limit_ms());
const RESULT_ENVELOPE_OVERHEAD_BYTES: usize = r#"{"result":}"#.len();
const CONNECTOR_MATERIALIZATION_FAILURE: &str =
    "gateway connector result exceeded runtime materialization capacity";
/// Closes the async function a program body runs in, then serializes the value
/// the program settled to with intrinsics captured before the program ran.
const PROGRAM_EPILOGUE: &str = r#"
  })();
  const gatewayResultEnvelope = gatewayObjectCreate(null);
  gatewayDefineProperty(gatewayResultEnvelope, "result", {
    value: gatewayProgramResult,
    enumerable: true
  });
  try {
    return gatewayJsonStringify(gatewayResultEnvelope);
  } catch {
    return "{}";
  }
})();
"#;
/// The name rquickjs gives every evaluated script while its `std` feature,
/// which would allow choosing one, is off.
const ENGINE_SCRIPT_NAME: &str = "eval_script";
/// The name failure positions use for the submitted program.
const PROGRAM_SCRIPT_NAME: &str = "program";

#[derive(Debug, PartialEq, Eq)]
struct RunnerExecutionFailure {
    code: RunnerFailureCode,
    message: String,
}

struct ExecutionCapabilities<F, P, A, W> {
    call: F,
    pause: P,
    artifact: A,
    wait: W,
    artifacts_available: bool,
}

impl RunnerExecutionFailure {
    fn new(code: RunnerFailureCode, message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            code,
            message: bounded_failure_message(&message),
        }
    }
}

pub fn run() -> anyhow::Result<()> {
    let spool = open_result_spool()?;
    let (runtime, deadline_reached, deadline) = create_runtime_armable()?;
    let context = JsContext::full(&runtime).context("create JavaScript context")?;
    apply_resource_limits()?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    // Rust initializes its process-wide stdio handles with a metadata syscall.
    // Establish them before confinement, then reuse only the inherited pipes.
    drop(stdin.lock());
    drop(stdout.lock());
    apply_confinement()?;
    write_runner_frame(
        &mut stdout.lock(),
        &RunnerFrame::Ready {
            confinement_profile: CONFINEMENT_PROFILE.to_owned(),
        },
    )?;

    let mut input = stdin.lock();
    let start = read_parent_frame(&mut input)?;
    let ParentFrame::Start {
        source,
        bindings,
        resume,
        input: program_input,
        artifacts_available,
        execution_limit_ms,
    } = start
    else {
        return Err(anyhow!("runner expected a start frame"));
    };

    // The parent has already bounded this against operator policy; the runner
    // applies it rather than deciding one.
    deadline.arm(execution_limit_ms);

    drop(input);
    let outcome = execute_in(
        &context,
        &source,
        &bindings,
        resume.as_ref(),
        &program_input,
        ExecutionCapabilities {
            call: runner_call(spool),
            pause: runner_pause(),
            artifact: runner_artifact(),
            wait: runner_wait(deadline.clone(), deadline_reached.clone()),
            artifacts_available,
        },
        &deadline_reached,
    );
    let mut output = stdout.lock();
    match outcome {
        Ok(result) => write_runner_frame(&mut output, &RunnerFrame::Complete { result }),
        Err(error) => write_runner_frame(
            &mut output,
            &RunnerFrame::Failed {
                code: error.code,
                message: error.message,
            },
        ),
    }
}

fn open_result_spool() -> anyhow::Result<File> {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    let mode = arguments.next();
    let spool_flag = arguments.next();
    let spool_path = arguments.next().map(PathBuf::from);
    let configured_limits = arguments.next();
    if mode.as_deref() != Some(std::ffi::OsStr::new(super::codemode_protocol::RUNNER_FLAG))
        || spool_flag.as_deref() != Some(std::ffi::OsStr::new(RUNNER_SPOOL_FLAG))
        || spool_path.is_none()
        || arguments.next().is_some()
    {
        return Err(anyhow!("runner requires exactly one result spool"));
    }
    if let Some(encoded) = configured_limits {
        crate::codemode_limits::install(serde_json::from_str(
            encoded.to_str().context("limits must be UTF-8")?,
        )?)?;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(spool_path.expect("checked above"))
        .context("open Code Mode result spool")
}

fn runner_pause() -> impl Fn(&str) -> rquickjs::Result<String> {
    move |checkpoint_json| {
        if checkpoint_json.len() > limits().checkpoint_bytes {
            return Err(rquickjs::Error::new_from_js_message(
                "checkpoint",
                "pause request",
                "checkpoint exceeds the protocol limit",
            ));
        }
        let checkpoint: Value = serde_json::from_str(checkpoint_json).map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "checkpoint",
                "pause request",
                "checkpoint must be JSON-compatible",
            )
        })?;
        let stdout = std::io::stdout();
        write_runner_frame(&mut stdout.lock(), &RunnerFrame::Pause { checkpoint }).map_err(
            |_| {
                rquickjs::Error::new_from_js_message(
                    "checkpoint",
                    "pause request",
                    "checkpoint transport failed",
                )
            },
        )?;

        // The parent durably records the checkpoint and closes this attempt.
        // Waiting on the inherited pipe prevents user code from advancing past
        // the boundary before the kill-on-drop parent tears down the runner.
        let stdin = std::io::stdin();
        let _ = read_parent_frame(&mut stdin.lock());
        Err(rquickjs::Error::new_from_js_message(
            "checkpoint",
            "pause request",
            "execution paused",
        ))
    }
}

fn runner_call(spool: File) -> impl Fn(&str) -> rquickjs::Result<String> {
    let next_id = AtomicU32::new(1);
    let spool = std::sync::Mutex::new(spool);
    move |request_json| {
        let request: Value = serde_json::from_str(request_json).map_err(|_| {
            rquickjs::Error::new_from_js_message("string", "request", "invalid connector request")
        })?;
        let call_id = request
            .get("call_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                rquickjs::Error::new_from_js_message(
                    "request",
                    "connector call",
                    "connector call id must be a string",
                )
            })?
            .to_owned();
        let arguments = request
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default()));
        if !arguments.is_object() {
            return Err(rquickjs::Error::new_from_js_message(
                "request",
                "connector call",
                "connector arguments must be an object",
            ));
        }
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let stdout = std::io::stdout();
        write_runner_frame(
            &mut stdout.lock(),
            &RunnerFrame::Call {
                id,
                call_id,
                arguments,
            },
        )
        .map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "request",
                "connector call",
                "connector transport failed",
            )
        })?;
        let stdin = std::io::stdin();
        match read_parent_frame(&mut stdin.lock()).map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "response",
                "connector call",
                "connector transport failed",
            )
        })? {
            ParentFrame::CallResult {
                id: response_id,
                result,
            } if response_id == id => {
                // Both arms reach the SDK as an envelope: the prelude throws
                // a structured Error (message plus a stable `code` split
                // from the broker's "code: message" contract) for the err
                // arm, so program code branches on `error.code` rather than
                // catching an opaque native exception.
                let envelope = match result {
                    Ok(ConnectorCallResult::Inline { value }) => {
                        serde_json::json!({ "ok": value })
                    }
                    Ok(ConnectorCallResult::Spool { bytes }) => {
                        let mut spool = spool.lock().map_err(|_| {
                            rquickjs::Error::new_from_js_message(
                                "response",
                                "connector call",
                                "connector spool lock failed",
                            )
                        })?;
                        let value =
                            crate::codemode_spool::read_value(&mut spool, bytes).map_err(|_| {
                                rquickjs::Error::new_from_js_message(
                                    "response",
                                    "connector call",
                                    "connector spool read failed",
                                )
                            })?;
                        serde_json::json!({ "ok": value })
                    }
                    Err(message) => serde_json::json!({ "err": message }),
                };
                Ok(envelope.to_string())
            }
            _ => Err(rquickjs::Error::new_from_js_message(
                "response",
                "connector call",
                "unexpected connector response",
            )),
        }
    }
}

fn runner_artifact() -> impl Fn(&str) -> rquickjs::Result<String> {
    let next_id = AtomicU32::new(1);
    move |artifact_json| {
        if artifact_json.len() > limits().artifact_bytes {
            let stdout = std::io::stdout();
            let _ = write_runner_frame(
                &mut stdout.lock(),
                &RunnerFrame::Failed {
                    code: RunnerFailureCode::ArtifactTooLarge,
                    message: "Code Mode artifact exceeded its size limit".to_owned(),
                },
            );
            return Err(rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "artifact exceeds the protocol limit",
            ));
        }
        let value: Value = serde_json::from_str(artifact_json).map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "artifact must be JSON-compatible",
            )
        })?;
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let stdout = std::io::stdout();
        write_runner_frame(&mut stdout.lock(), &RunnerFrame::Artifact { id, value }).map_err(
            |_| {
                rquickjs::Error::new_from_js_message(
                    "artifact",
                    "artifact emission",
                    "artifact transport failed",
                )
            },
        )?;
        let stdin = std::io::stdin();
        match read_parent_frame(&mut stdin.lock()).map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "artifact transport failed",
            )
        })? {
            ParentFrame::ArtifactResult {
                id: response_id,
                result,
            } if response_id == id => result.map(|value| value.to_string()).map_err(|message| {
                rquickjs::Error::new_from_js_message("artifact", "artifact emission", message)
            }),
            _ => Err(rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "unexpected artifact response",
            )),
        }
    }
}

#[cfg(test)]
fn execute_with<F>(
    source: &str,
    bindings: &[RunnerBinding],
    call: F,
) -> Result<Value, RunnerExecutionFailure>
where
    F: Fn(&str) -> rquickjs::Result<String> + 'static,
{
    execute_with_resume(source, bindings, ProgramData::default(), call, |_| {
        Err(rquickjs::Error::new_from_js_message(
            "checkpoint",
            "pause request",
            "pause is unavailable in this test",
        ))
    })
}

/// The two channels that hand a program its data: the checkpoint and input a
/// continuation resumes from, and the input its caller submitted. They travel
/// together everywhere a program starts, so they are named together here.
#[cfg(test)]
#[derive(Default, Clone, Copy)]
struct ProgramData<'a> {
    resume: Option<&'a RunnerResumeContext>,
    input: Option<&'a Value>,
}

#[cfg(test)]
fn execute_with_resume<F, P>(
    source: &str,
    bindings: &[RunnerBinding],
    data: ProgramData<'_>,
    call: F,
    pause: P,
) -> Result<Value, RunnerExecutionFailure>
where
    F: Fn(&str) -> rquickjs::Result<String> + 'static,
    P: Fn(&str) -> rquickjs::Result<String> + 'static,
{
    execute_with_capabilities(
        source,
        bindings,
        data,
        call,
        pause,
        |_| {
            Err(rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "artifacts are unavailable in this test",
            ))
        },
        false,
    )
}

#[cfg(test)]
fn execute_with_capabilities<F, P, A>(
    source: &str,
    bindings: &[RunnerBinding],
    data: ProgramData<'_>,
    call: F,
    pause: P,
    artifact: A,
    artifacts_available: bool,
) -> Result<Value, RunnerExecutionFailure>
where
    F: Fn(&str) -> rquickjs::Result<String> + 'static,
    P: Fn(&str) -> rquickjs::Result<String> + 'static,
    A: Fn(&str) -> rquickjs::Result<String> + 'static,
{
    let (runtime, deadline_reached, deadline) = create_runtime_armable().map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not initialize",
        )
    })?;
    deadline.arm(u64::try_from(EXECUTION_LIMIT.as_millis()).unwrap_or(u64::MAX));
    let context = JsContext::full(&runtime).map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not initialize",
        )
    })?;
    execute_in(
        &context,
        source,
        bindings,
        data.resume,
        data.input.unwrap_or(&Value::Null),
        ExecutionCapabilities {
            call,
            pause,
            artifact,
            wait: runner_wait(deadline, deadline_reached.clone()),
            artifacts_available,
        },
        &deadline_reached,
    )
}

/// Create a runtime whose deadline can be re-armed once the parent's start
/// frame arrives.
///
/// The runtime must exist before confinement is applied and before the frame
/// is read, so the budget cannot be known at creation time. It therefore
/// starts at the default and is narrowed or widened once, to the value the
/// parent computed under operator policy. Starting at the default rather than
/// unbounded means a runner that never receives a frame is still bounded.
fn create_runtime_armable() -> anyhow::Result<(Runtime, Arc<AtomicBool>, ArmableDeadline)> {
    let runtime = Runtime::new().context("create JavaScript runtime")?;
    runtime.set_memory_limit(limits().heap_bytes);
    runtime.set_max_stack_size(limits().stack_bytes);
    // Both the origin and the budget move when the parent's frame arrives, so
    // startup, confinement and frame I/O are not charged against a program's
    // grant. Until then the default applies from now, which keeps a runner
    // that never receives a frame bounded.
    let origin_ms = Arc::new(AtomicU64::new(0));
    let process_start = Instant::now();
    let budget_ms = Arc::new(AtomicU64::new(
        u64::try_from(EXECUTION_LIMIT.as_millis()).unwrap_or(u64::MAX),
    ));
    let deadline_reached = Arc::new(AtomicBool::new(false));
    let interrupt_deadline_reached = deadline_reached.clone();
    let interrupt_budget = budget_ms.clone();
    let interrupt_origin = origin_ms.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        let now_ms = u64::try_from(process_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let elapsed = now_ms.saturating_sub(interrupt_origin.load(Ordering::Relaxed));
        let reached = elapsed >= interrupt_budget.load(Ordering::Relaxed);
        if reached {
            interrupt_deadline_reached.store(true, Ordering::Relaxed);
        }
        reached
    })));
    Ok((
        runtime,
        deadline_reached,
        ArmableDeadline {
            budget_ms,
            origin_ms,
            process_start,
        },
    ))
}

/// Handle for narrowing or widening a live runtime's deadline exactly once,
/// when the parent's budget for this execution becomes known.
#[derive(Clone)]
struct ArmableDeadline {
    budget_ms: Arc<AtomicU64>,
    origin_ms: Arc<AtomicU64>,
    process_start: Instant,
}

impl ArmableDeadline {
    /// Start the granted budget now.
    ///
    /// Setting the origin as well as the duration is the point: a program's
    /// grant should measure its own execution, not the startup and frame I/O
    /// that preceded it.
    fn arm(&self, budget_ms: u64) {
        let now_ms = u64::try_from(self.process_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.origin_ms.store(now_ms, Ordering::Relaxed);
        self.budget_ms.store(budget_ms, Ordering::Relaxed);
    }

    /// Milliseconds left of the granted budget, from the same origin and by
    /// the same arithmetic the interrupt handler uses. Zero once spent.
    fn remaining_ms(&self) -> u64 {
        let now_ms = u64::try_from(self.process_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let elapsed = now_ms.saturating_sub(self.origin_ms.load(Ordering::Relaxed));
        self.budget_ms
            .load(Ordering::Relaxed)
            .saturating_sub(elapsed)
    }
}

/// Pace a program without spinning.
///
/// A poll loop has to let time pass, and the only way to do that in a runtime
/// with no timers is to burn a core. This sleeps instead, which the syscall
/// profile already permits: `nanosleep` and `clock_nanosleep` are on the
/// allow-list, so this adds a timer and not a route to anything else.
///
/// **Waiting spends the budget rather than pausing it.** The deadline's origin
/// does not move, so elapsed sleep counts exactly as elapsed computation does,
/// and a wait is clamped to what remains. That is what stops sleep being used
/// to outlive the operator's ceiling; the bound on a single wait is therefore
/// the remaining budget rather than a second limit to reason about.
///
/// **Running out of budget is not this primitive's failure to report.** A wait
/// that spends what remains marks the shared deadline and aborts evaluation,
/// so the runner reports the timeout reason it has always used. A final
/// deadline check after evaluation also prevents a program from catching the
/// native error and turning an exhausted budget into a successful result.
/// Refusing the duration as an ordinary program error would give the opposite
/// remedy: read the code rather than raise the limit.
fn runner_wait(
    deadline: ArmableDeadline,
    deadline_reached: Arc<AtomicBool>,
) -> impl Fn(f64) -> rquickjs::Result<String> {
    move |requested| {
        let refusal = |code: &str, message: &str| {
            Ok(serde_json::json!({"err": {"code": code, "message": message}}).to_string())
        };
        if !requested.is_finite() || requested < 0.0 {
            return refusal(
                "execution_wait_invalid",
                "wait expects a non-negative number of milliseconds",
            );
        }
        // Truncation is deliberate: sub-millisecond precision is not something
        // this can honour, and rounding up could exceed a checked remainder.
        let requested_ms = requested.trunc() as u64;
        let remaining_ms = deadline.remaining_ms();
        std::thread::sleep(Duration::from_millis(requested_ms.min(remaining_ms)));
        if requested_ms >= remaining_ms || deadline.remaining_ms() == 0 {
            deadline_reached.store(true, Ordering::Relaxed);
            return Err(rquickjs::Error::new_from_js_message(
                "wait",
                "execution deadline",
                "execution budget exhausted while waiting",
            ));
        }
        Ok(serde_json::json!({"ok": Value::Null}).to_string())
    }
}

/// Whether a program may still use host capabilities.
///
/// Every capability is refused once the shared execution deadline has fired.
/// QuickJS exceptions are deliberately catchable program errors. The runner's
/// final deadline check still selects the stable timeout result, while this
/// guard prevents code in a catch block from reaching a connector, publishing
/// an artifact, or checkpointing after the operator's budget is exhausted.
///
/// Every capability is also refused once the program's promise has settled.
/// Reporting a failure reads the thrown value's properties, and a getter or
/// proxy there runs program code; closing the capabilities first keeps that
/// code from causing any effect after the program has finished.
#[derive(Clone)]
struct HostGate {
    deadline_reached: Arc<AtomicBool>,
    settled: Arc<AtomicBool>,
}

impl HostGate {
    fn require_open(&self) -> rquickjs::Result<()> {
        if self.deadline_reached.load(Ordering::Relaxed) {
            return Err(rquickjs::Error::new_from_js_message(
                "execution",
                "host capability",
                "execution budget is exhausted",
            ));
        }
        if self.settled.load(Ordering::Relaxed) {
            return Err(rquickjs::Error::new_from_js_message(
                "execution",
                "host capability",
                "the program has finished",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
fn create_runtime_with_limit(
    execution_limit: Duration,
) -> anyhow::Result<(Runtime, Arc<AtomicBool>)> {
    let runtime = Runtime::new().context("create JavaScript runtime")?;
    runtime.set_memory_limit(limits().heap_bytes);
    runtime.set_max_stack_size(limits().stack_bytes);
    let deadline = Instant::now() + execution_limit;
    let deadline_reached = Arc::new(AtomicBool::new(false));
    let interrupt_deadline_reached = deadline_reached.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        let reached = Instant::now() >= deadline;
        if reached {
            interrupt_deadline_reached.store(true, Ordering::Relaxed);
        }
        reached
    })));
    Ok((runtime, deadline_reached))
}

#[cfg(target_os = "linux")]
fn apply_resource_limits() -> anyhow::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: limits().address_space_bytes as u64,
        rlim_max: limits().address_space_bytes as u64,
    };
    // The runner must establish its kernel-enforced address-space ceiling
    // before accepting source or installing callable host capabilities.
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } != 0 {
        return Err(std::io::Error::last_os_error()).context("limit runner address space");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_resource_limits() -> anyhow::Result<()> {
    Err(anyhow!(
        "Code Mode execution requires Linux process resource limits"
    ))
}

fn execute_in<F, P, A, W>(
    context: &JsContext,
    source: &str,
    bindings: &[RunnerBinding],
    resume: Option<&RunnerResumeContext>,
    input: &Value,
    capabilities: ExecutionCapabilities<F, P, A, W>,
    deadline_reached: &Arc<AtomicBool>,
) -> Result<Value, RunnerExecutionFailure>
where
    F: Fn(&str) -> rquickjs::Result<String> + 'static,
    P: Fn(&str) -> rquickjs::Result<String> + 'static,
    A: Fn(&str) -> rquickjs::Result<String> + 'static,
    W: Fn(f64) -> rquickjs::Result<String> + 'static,
{
    let bindings_json = serde_json::to_string(bindings).map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not install connector bindings",
        )
    })?;
    let resume_json = serde_json::to_string(&resume).map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not install resume context",
        )
    })?;
    // Serialized, handed to the sandbox as a string, and parsed there with the
    // captured `JSON.parse`. Caller-supplied input reaches the program as data
    // and is never evaluated as code.
    let input_json = serde_json::to_string(input).map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not install program input",
        )
    })?;
    let ExecutionCapabilities {
        call,
        pause,
        artifact,
        wait,
        artifacts_available,
    } = capabilities;
    context.with(|ctx| {
        // Set only after the parent has produced a valid encoded connector
        // envelope, before rquickjs converts the Rust String into a JS value.
        // It therefore covers both that allocation and JSON decoding, while a
        // native transport error never enters the materialization state.
        let connector_materialization_in_progress = Arc::new(AtomicBool::new(false));
        let gate = HostGate {
            deadline_reached: deadline_reached.clone(),
            settled: Arc::new(AtomicBool::new(false)),
        };
        let call_gate = gate.clone();
        let call_materialization = Arc::clone(&connector_materialization_in_progress);
        ctx.globals()
            .set(
                "__gateway_call",
                Func::from(move |request: JsString<'_>| -> rquickjs::Result<String> {
                    call_materialization.store(false, Ordering::Relaxed);
                    call_gate.require_open()?;
                    let request = request.to_cstring()?;
                    validate_connector_request(request.as_str(), limits().request_bytes)?;
                    let encoded = call(request.as_str())?;
                    call_materialization.store(true, Ordering::Relaxed);
                    Ok(encoded)
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install connector bindings",
                )
            })?;
        let queried_materialization = Arc::clone(&connector_materialization_in_progress);
        ctx.globals()
            .set(
                "__gateway_connector_materializing",
                Func::from(move || queried_materialization.load(Ordering::Relaxed)),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install connector bindings",
                )
            })?;
        let completed_materialization = Arc::clone(&connector_materialization_in_progress);
        ctx.globals()
            .set(
                "__gateway_connector_materialized",
                Func::from(move || {
                    completed_materialization.store(false, Ordering::Relaxed);
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install connector bindings",
                )
            })?;
        let pause_gate = gate.clone();
        ctx.globals()
            .set(
                "__gateway_pause",
                Func::from(move |checkpoint: JsString<'_>| {
                    pause_gate.require_open()?;
                    let checkpoint = checkpoint.to_cstring()?;
                    pause(checkpoint.as_str())
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install the pause boundary",
                )
            })?;
        let artifact_gate = gate.clone();
        ctx.globals()
            .set(
                "__gateway_artifact",
                Func::from(move |value: JsString<'_>| {
                    artifact_gate.require_open()?;
                    let value = value.to_cstring()?;
                    artifact(value.as_str())
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install artifact emission",
                )
            })?;
        let wait_gate = gate.clone();
        ctx.globals()
            .set(
                "__gateway_wait",
                Func::from(move |milliseconds: f64| {
                    wait_gate.require_open()?;
                    wait(milliseconds)
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install the wait primitive",
                )
            })?;
        ctx.globals()
            .set("__gateway_bindings_json", bindings_json)
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install connector bindings",
                )
            })?;
        ctx.globals()
            .set("__gateway_resume_json", resume_json)
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install resume context",
                )
            })?;
        ctx.globals()
            .set("__gateway_artifacts_available", artifacts_available)
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install artifact availability",
                )
            })?;
        ctx.globals()
            .set("__gateway_input_json", input_json)
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install program input",
                )
            })?;

        let prelude = format!(
            r#"
"use strict";
const gatewayJsonParse = JSON.parse;
const gatewayJsonStringify = JSON.stringify;
const gatewayObjectCreate = Object.create;
const gatewayDefineProperty = Object.defineProperty;
const GatewayError = Error;
const gatewayStringIndexOf = Function.prototype.call.bind(String.prototype.indexOf);
const gatewayStringSlice = Function.prototype.call.bind(String.prototype.slice);
const gatewayRegexTest = Function.prototype.call.bind(RegExp.prototype.test);
const gatewayHasOwn = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
const gatewayCodePattern = /^[a-z][a-z0-9_]*$/;
const connectors = (() => {{
  const gatewayCall = __gateway_call;
  const gatewayConnectorMaterializing = __gateway_connector_materializing;
  const gatewayConnectorMaterialized = __gateway_connector_materialized;
  const bindingSpecs = gatewayJsonParse(__gateway_bindings_json);
  delete globalThis.__gateway_call;
  delete globalThis.__gateway_connector_materializing;
  delete globalThis.__gateway_connector_materialized;
  delete globalThis.__gateway_bindings_json;
  const gatewayMaterializationError = () => {{
    const error = new GatewayError("{CONNECTOR_MATERIALIZATION_FAILURE}");
    gatewayDefineProperty(error, "code", {{
      value: "connector_result_too_large",
      enumerable: true
    }});
    gatewayConnectorMaterialized();
    return error;
  }};
  const generated = gatewayObjectCreate(null);
  for (const binding of bindingSpecs) {{
    let connector = generated[binding.connector];
    if (connector === undefined) {{
      connector = gatewayObjectCreate(null);
      gatewayDefineProperty(generated, binding.connector, {{
        value: connector,
        enumerable: true
      }});
    }}
    gatewayDefineProperty(connector, binding.operation, {{
      value: (args = {{}}) => {{
        const request = gatewayObjectCreate(null);
        gatewayDefineProperty(request, "call_id", {{
          value: binding.call_id,
          enumerable: true
        }});
        gatewayDefineProperty(request, "arguments", {{
          value: args,
          enumerable: true
        }});
        let encodedEnvelope;
        try {{
          encodedEnvelope = gatewayCall(gatewayJsonStringify(request));
        }} catch (cause) {{
          if (!gatewayConnectorMaterializing()) {{
            throw cause;
          }}
          throw gatewayMaterializationError();
        }}
        let envelope;
        try {{
          envelope = gatewayJsonParse(encodedEnvelope);
        }} catch {{
          throw gatewayMaterializationError();
        }}
        gatewayConnectorMaterialized();
        if (gatewayHasOwn(envelope, "err")) {{
          const separator = gatewayStringIndexOf(envelope.err, ": ");
          const candidate = separator > 0
            ? gatewayStringSlice(envelope.err, 0, separator)
            : "";
          const recognized = candidate !== ""
            && gatewayRegexTest(gatewayCodePattern, candidate);
          const error = new GatewayError(recognized
            ? gatewayStringSlice(envelope.err, separator + 2)
            : envelope.err);
          gatewayDefineProperty(error, "code", {{
            value: recognized ? candidate : "connector_failure",
            enumerable: true
          }});
          throw error;
        }}
        return envelope.ok;
      }},
      enumerable: true
    }});
  }}
  for (const connectorName of Object.keys(generated)) {{
    Object.freeze(generated[connectorName]);
  }}
  return Object.freeze(generated);
}})();
const execution = (() => {{
  const gatewayPause = __gateway_pause;
  const gatewayArtifact = __gateway_artifact;
  const gatewayWait = __gateway_wait;
  const resume = gatewayJsonParse(__gateway_resume_json);
  const input = gatewayJsonParse(__gateway_input_json);
  const artifactsAvailable = __gateway_artifacts_available;
  delete globalThis.__gateway_pause;
  delete globalThis.__gateway_artifact;
  delete globalThis.__gateway_wait;
  delete globalThis.__gateway_resume_json;
  delete globalThis.__gateway_input_json;
  delete globalThis.__gateway_artifacts_available;
  const generated = gatewayObjectCreate(null);
  gatewayDefineProperty(generated, "resume", {{
    value: resume,
    enumerable: true
  }});
  gatewayDefineProperty(generated, "input", {{
    value: input,
    enumerable: true
  }});
  gatewayDefineProperty(generated, "pause", {{
    value: (checkpoint = {{}}) =>
      gatewayPause(gatewayJsonStringify(checkpoint)),
    enumerable: true
  }});
  gatewayDefineProperty(generated, "artifactsAvailable", {{
    value: artifactsAvailable,
    enumerable: true
  }});
  gatewayDefineProperty(generated, "emitArtifact", {{
    value: (value) =>
      gatewayJsonParse(gatewayArtifact(gatewayJsonStringify(value))),
    enumerable: true
  }});
  gatewayDefineProperty(generated, "wait", {{
    value: (milliseconds) => {{
      const envelope = gatewayJsonParse(gatewayWait(milliseconds));
      if (gatewayHasOwn(envelope, "err")) {{
        const error = new GatewayError(envelope.err.message);
        gatewayDefineProperty(error, "code", {{
          value: envelope.err.code,
          enumerable: true
        }});
        throw error;
      }}
      return envelope.ok;
    }},
    enumerable: true
  }});
  return Object.freeze(generated);
}})();
(async () => {{
  const gatewayProgramResult = await (async () => {{
"#
        );
        let layout = ProgramLayout::new(&prelude, source);
        let wrapped = format!("{prelude}{source}{PROGRAM_EPILOGUE}");
        let evaluated = match ctx.eval::<Promise<'_>, _>(wrapped).catch(&ctx) {
            Ok(program) => settle_program(&ctx, &program, deadline_reached),
            Err(error) => ProgramSettlement::Settled(Err(error)),
        };
        gate.settled.store(true, Ordering::Relaxed);
        if deadline_reached.load(Ordering::Relaxed) {
            return Err(RunnerExecutionFailure::new(
                RunnerFailureCode::ExecutionTimeout,
                "Code Mode execution exceeded its time limit",
            ));
        }
        let ProgramSettlement::Settled(evaluated) = evaluated else {
            return Err(RunnerExecutionFailure::new(
                RunnerFailureCode::ProgramFailed,
                "Code Mode program never finished: it is waiting on a promise that nothing \
                 left to run can settle",
            ));
        };
        let result_json = evaluated.map_err(|error| {
            let is_stable_connector_error = match &error {
                CaughtError::Exception(exception) => {
                    exception
                        .as_object()
                        .get::<_, Option<String>>("code")
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some("connector_result_too_large")
                }
                CaughtError::Value(value) => value.as_object().is_some_and(|object| {
                    object
                        .get::<_, Option<String>>("code")
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some("connector_result_too_large")
                }),
                CaughtError::Error(_) => false,
            };
            if connector_materialization_in_progress.load(Ordering::Relaxed)
                || is_stable_connector_error
            {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::ConnectorResultTooLarge,
                    "Code Mode connector result exceeded runtime materialization capacity",
                )
            } else {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::ProgramFailed,
                    format!(
                        "Code Mode program evaluation failed: {}",
                        describe_program_error(&error, layout)
                    ),
                )
            }
        })?;
        let result_json = result_json.ok_or_else(|| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        let result_json = result_json.to_cstring().map_err(|_| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        if result_json.len() > limits().result_bytes + RESULT_ENVELOPE_OVERHEAD_BYTES {
            return Err(RunnerExecutionFailure::new(
                RunnerFailureCode::ResultTooLarge,
                "Code Mode execution result exceeded its size limit",
            ));
        }
        let envelope: Value = serde_json::from_str(result_json.as_str()).map_err(|_| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        let result = envelope.get("result").cloned().ok_or_else(|| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        let encoded_result = serde_json::to_vec(&result).map_err(|_| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        if encoded_result.len() > limits().result_bytes {
            return Err(RunnerExecutionFailure::new(
                RunnerFailureCode::ResultTooLarge,
                "Code Mode execution result exceeded its size limit",
            ));
        }
        Ok(result)
    })
}

enum ProgramSettlement<'js> {
    Settled(CaughtResult<'js, Option<JsString<'js>>>),
    /// The job queue emptied, or the deadline fired, while the program's
    /// promise was still pending.
    Unsettled,
}

/// Run queued promise jobs until the program's promise settles.
///
/// Connector calls, waits and pauses are synchronous host calls, so the only
/// jobs are the program's own promise reactions. A queue that empties while
/// the promise is pending can never settle it. The interrupt handler still
/// bounds every job, and the deadline is checked between jobs because a job
/// the interrupt aborted reports as executed.
fn settle_program<'js>(
    ctx: &Ctx<'js>,
    program: &Promise<'js>,
    deadline_reached: &AtomicBool,
) -> ProgramSettlement<'js> {
    loop {
        if let Some(outcome) = program.result::<Option<JsString<'js>>>() {
            return ProgramSettlement::Settled(outcome.catch(ctx));
        }
        if deadline_reached.load(Ordering::Relaxed) || !ctx.execute_pending_job() {
            return ProgramSettlement::Unsettled;
        }
    }
}

/// Where the submitted source sits inside the generated script.
///
/// The prelude ends with a line break, so the program's lines keep their
/// columns and only their line numbers are offset.
#[derive(Debug, Clone, Copy)]
struct ProgramLayout {
    first_line: usize,
    last_line: usize,
}

enum ScriptLocation {
    Program {
        line: usize,
        column: Option<usize>,
    },
    /// Past the program's last line: only a parser that ran out of program
    /// reports a position in the closing code that follows it.
    AfterProgram,
    Generated,
    Other,
}

impl ProgramLayout {
    fn new(prelude: &str, source: &str) -> Self {
        let first_line = prelude.matches('\n').count() + 1;
        Self {
            first_line,
            last_line: first_line + engine_line_breaks(source),
        }
    }

    fn locate(&self, location: &str) -> ScriptLocation {
        let Some(position) = location
            .strip_prefix(ENGINE_SCRIPT_NAME)
            .and_then(|position| position.strip_prefix(':'))
        else {
            return ScriptLocation::Other;
        };
        let (line, column) = match position.split_once(':') {
            Some((line, column)) => (line, Some(column)),
            None => (position, None),
        };
        let Ok(line) = line.parse::<usize>() else {
            return ScriptLocation::Other;
        };
        let column = match column.map(str::parse::<usize>) {
            Some(Ok(column)) => Some(column),
            Some(Err(_)) => return ScriptLocation::Other,
            None => None,
        };
        if line < self.first_line {
            ScriptLocation::Generated
        } else if line > self.last_line {
            ScriptLocation::AfterProgram
        } else {
            ScriptLocation::Program {
                line: line - self.first_line + 1,
                column,
            }
        }
    }

    /// Restate an engine stack trace in the submitted program's positions.
    ///
    /// Frames in the gateway's generated code are dropped because they are
    /// not the program's to act on; native frames are kept because they name
    /// the built-in that threw.
    fn program_stack(&self, stack: &str) -> String {
        stack
            .lines()
            .filter_map(|line| self.program_frame(line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn program_frame(&self, line: &str) -> Option<String> {
        let frame = line.trim_start();
        let indent = &line[..line.len() - frame.len()];
        let Some(frame) = frame.strip_prefix("at ") else {
            return Some(line.to_owned());
        };
        if let Some((function, location)) = frame
            .strip_suffix(')')
            .and_then(|frame| frame.rsplit_once(" ("))
        {
            return match self.locate(location) {
                ScriptLocation::Program { line, column } => Some(format!(
                    "{indent}at {function} ({})",
                    program_position(line, column)
                )),
                ScriptLocation::AfterProgram | ScriptLocation::Generated => None,
                ScriptLocation::Other => Some(line.to_owned()),
            };
        }
        // A frame without a function name is the parser's position. The
        // engine reports its scanner column rather than the offending token's,
        // so only the line is given.
        match self.locate(frame) {
            ScriptLocation::Program { line, .. } => {
                Some(format!("{indent}at {}", program_position(line, None)))
            }
            ScriptLocation::AfterProgram => Some(format!("{indent}at the end of the program")),
            ScriptLocation::Generated => None,
            ScriptLocation::Other => Some(line.to_owned()),
        }
    }
}

/// The JavaScript `typeof` name of a value, which agents recognize, rather than
/// the engine's tag name.
fn javascript_type(value: &rquickjs::Value<'_>) -> &'static str {
    match value.type_of() {
        rquickjs::Type::Uninitialized | rquickjs::Type::Undefined => "undefined",
        rquickjs::Type::Null => "null",
        rquickjs::Type::Bool => "boolean",
        rquickjs::Type::Int | rquickjs::Type::Float => "number",
        rquickjs::Type::String => "string",
        rquickjs::Type::Symbol => "symbol",
        rquickjs::Type::BigInt => "bigint",
        rquickjs::Type::Function | rquickjs::Type::Constructor => "function",
        _ => "object",
    }
}

/// Line breaks as the engine counts them between tokens: `\r\n`, a lone `\r`,
/// `\n`, U+2028 and U+2029 each end a line. Inside block comments and string
/// literals the engine counts fewer, so a program's last line computed from
/// this is an upper bound; the positions the engine reports are its own.
fn engine_line_breaks(source: &str) -> usize {
    let mut breaks = 0;
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                characters.next_if_eq(&'\n');
                breaks += 1;
            }
            '\n' | '\u{2028}' | '\u{2029}' => breaks += 1,
            _ => {}
        }
    }
    breaks
}

fn program_position(line: usize, column: Option<usize>) -> String {
    match column {
        Some(column) => format!("{PROGRAM_SCRIPT_NAME}:{line}:{column}"),
        None => format!("{PROGRAM_SCRIPT_NAME}:{line}"),
    }
}

/// Describe a program failure by its error name, message and the stack frames
/// that lie in the submitted program.
///
/// A thrown value that is not an `Error` is described without serializing it:
/// a primitive by its text, and an object only by its type, because turning an
/// object into text could call the program's own `toJSON` or `toString` after
/// evaluation has ended.
fn describe_program_error(error: &CaughtError<'_>, layout: ProgramLayout) -> String {
    let exception = match error {
        CaughtError::Exception(exception) => exception,
        CaughtError::Value(value) => {
            let kind = javascript_type(value);
            return match kind {
                "object" | "function" => {
                    format!("uncaught {kind}; throw an Error to report a message and position")
                }
                "null" | "undefined" => format!("uncaught {kind}"),
                _ => match value.get::<rquickjs::Coerced<String>>() {
                    Ok(text) => format!("uncaught {kind}: {}", text.0),
                    Err(_) => format!("uncaught {kind}"),
                },
            };
        }
        CaughtError::Error(error) => return error.to_string(),
    };
    let name = exception
        .as_object()
        .get::<_, Option<String>>("name")
        .ok()
        .flatten()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Error".to_owned());
    let mut description = match exception.message() {
        Some(message) if !message.is_empty() => format!("{name}: {message}"),
        _ => name,
    };
    if let Some(stack) = exception.stack() {
        let frames = layout.program_stack(&stack);
        if !frames.is_empty() {
            description.push('\n');
            description.push_str(&frames);
        }
    }
    description
}

/// Routing metadata has its own transport allowance; the public budget counts only arguments.
fn validate_connector_request(request: &str, argument_limit: usize) -> rquickjs::Result<()> {
    let invalid = || {
        rquickjs::Error::new_from_js_message(
            "request",
            "connector call",
            "connector request exceeds the protocol limit or is invalid",
        )
    };
    if request.len() > limits().frame_bytes {
        return Err(invalid());
    }
    let value: Value = serde_json::from_str(request).map_err(|_| invalid())?;
    let empty_arguments = Value::Object(Default::default());
    let arguments = value.get("arguments").unwrap_or(&empty_arguments);
    let bytes = serde_json::to_vec(arguments).map_err(|_| invalid())?;
    if bytes.len() > argument_limit {
        return Err(invalid());
    }
    Ok(())
}

fn read_parent_frame(input: &mut impl BufRead) -> anyhow::Result<ParentFrame> {
    let mut line = String::new();
    let bytes = std::io::Read::take(input, (limits().parent_frame_bytes + 1) as u64)
        .read_line(&mut line)
        .context("read parent frame")?;
    if bytes == 0 {
        return Err(anyhow!("parent closed the runner channel"));
    }
    if bytes > limits().parent_frame_bytes || !line.ends_with('\n') {
        return Err(anyhow!("parent frame exceeds the protocol limit"));
    }
    serde_json::from_str(&line).context("decode parent frame")
}

fn write_runner_frame(output: &mut impl Write, frame: &RunnerFrame) -> anyhow::Result<()> {
    let encoded = encode_frame(frame).context("encode runner frame")?;
    output.write_all(&encoded).context("write runner frame")?;
    output.write_all(b"\n").context("terminate runner frame")?;
    output.flush().context("flush runner frame")
}

#[cfg(target_os = "linux")]
fn apply_confinement() -> anyhow::Result<()> {
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

    let allowlist: BTreeMap<i64, Vec<_>> = allowed_syscalls()
        .into_iter()
        .map(|syscall| (syscall, Vec::new()))
        .collect();
    let filter: BpfProgram = SeccompFilter::new(
        allowlist,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .context("unsupported runner architecture")?,
    )
    .context("compile runner syscall policy")?
    .try_into()
    .context("assemble runner syscall policy")?;
    seccompiler::apply_filter(&filter).context("install runner syscall policy")
}

#[cfg(target_os = "linux")]
fn allowed_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_brk,
        libc::SYS_clock_getres,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_close,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_fcntl,
        libc::SYS_fstat,
        libc::SYS_futex,
        libc::SYS_getpid,
        libc::SYS_getrandom,
        libc::SYS_getrusage,
        libc::SYS_gettid,
        libc::SYS_ioctl,
        libc::SYS_lseek,
        libc::SYS_madvise,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_munmap,
        libc::SYS_nanosleep,
        libc::SYS_read,
        libc::SYS_readv,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sched_yield,
        libc::SYS_sigaltstack,
        libc::SYS_write,
        libc::SYS_writev,
    ]
}

#[cfg(not(target_os = "linux"))]
fn apply_confinement() -> anyhow::Result<()> {
    Err(anyhow!(
        "Code Mode execution requires Linux syscall confinement"
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::process_mode::codemode_protocol::MAX_FAILURE_MESSAGE_CHARS;

    fn bindings(names: &[(&str, &str)]) -> Vec<RunnerBinding> {
        names
            .iter()
            .map(|(connector, operation)| RunnerBinding {
                connector: (*connector).to_owned(),
                operation: (*operation).to_owned(),
                call_id: format!("{connector}:{operation}"),
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn syscall_policy_excludes_filesystem_and_cross_process_control() {
        let syscalls = allowed_syscalls();
        assert!(!syscalls.contains(&libc::SYS_prlimit64));
        assert!(!syscalls.contains(&libc::SYS_newfstatat));
    }

    #[test]
    fn program_composes_connector_results_with_javascript_control_flow() {
        let result = execute_with(
            r#"
const first = connectors.email.first({value: "seed"});
const second = connectors.email.second({value: first.result});
return second.result === "two" ? {combined: [first.result, second.result]} : null;
"#,
            &bindings(&[("email", "first"), ("email", "second")]),
            |request| {
                let request: Value = serde_json::from_str(request).expect("connector request");
                let result = match request["call_id"].as_str().expect("connector call id") {
                    "email:first" => "one",
                    "email:second" => "two",
                    other => panic!("unexpected connector {other}"),
                };
                Ok(serde_json::json!({"ok": {"result": result}}).to_string())
            },
        )
        .expect("program executes");

        assert_eq!(result, serde_json::json!({"combined": ["one", "two"]}));
    }

    #[test]
    fn fresh_attempt_receives_the_bound_checkpoint_and_resume_input() {
        let resume = RunnerResumeContext {
            checkpoint: serde_json::json!({
                "prompt": "Choose a region",
                "state": {"candidate_ids": [1, 2]},
            }),
            input: serde_json::json!({"region": "west"}),
        };
        let result = execute_with_resume(
            "return execution.resume;",
            &[],
            ProgramData {
                resume: Some(&resume),
                ..ProgramData::default()
            },
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
        )
        .expect("resumed program executes");

        assert_eq!(
            result,
            serde_json::json!({
                "checkpoint": {
                    "prompt": "Choose a region",
                    "state": {"candidate_ids": [1, 2]},
                },
                "input": {"region": "west"},
            })
        );
    }

    /// The point of the input channel: a program reads its arguments rather
    /// than having them edited into its text. This source is fixed and
    /// contains none of the values it returns.
    #[test]
    fn a_program_reads_its_arguments_from_the_input_channel() {
        let arguments = serde_json::json!({"owner": "bennight", "pr_number": 71});
        let result = execute_with_resume(
            "return {owner: execution.input.owner, pr: execution.input.pr_number};",
            &[],
            ProgramData {
                input: Some(&arguments),
                ..ProgramData::default()
            },
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
        )
        .expect("program executes");

        assert_eq!(result, serde_json::json!({"owner": "bennight", "pr": 71}));
    }

    /// Input crosses the boundary as data. A value that reads like source
    /// arrives as the string it is, never as something the sandbox ran.
    #[test]
    fn input_that_looks_like_source_arrives_as_data() {
        let arguments = serde_json::json!({"hostile": "globalThis.leaked = 1;"});
        let result = execute_with_resume(
            "return {kind: typeof execution.input.hostile, value: execution.input.hostile};",
            &[],
            ProgramData {
                input: Some(&arguments),
                ..ProgramData::default()
            },
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
        )
        .expect("program executes");

        assert_eq!(
            result,
            serde_json::json!({"kind": "string", "value": "globalThis.leaked = 1;"})
        );
    }

    #[test]
    fn pause_accepts_any_json_compatible_checkpoint_shape() {
        let observed = Arc::new(std::sync::Mutex::new(None));
        let observed_by_pause = observed.clone();
        let error = execute_with_resume(
            r#"execution.pause(["choose-region", {candidate_ids: [1, 2]}]);"#,
            &[],
            ProgramData::default(),
            |_| unreachable!("program makes no connector calls"),
            move |checkpoint| {
                *observed_by_pause.lock().expect("checkpoint lock") =
                    serde_json::from_str(checkpoint).ok();
                Err(rquickjs::Error::new_from_js_message(
                    "checkpoint",
                    "pause request",
                    "execution paused",
                ))
            },
        )
        .expect_err("test pause boundary stops evaluation");

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
        assert_eq!(
            *observed.lock().expect("checkpoint lock"),
            Some(serde_json::json!([
                "choose-region",
                {"candidate_ids": [1, 2]},
            ]))
        );
    }

    #[test]
    fn artifact_emission_returns_the_parent_reference_to_the_program() {
        let observed = Arc::new(std::sync::Mutex::new(None));
        let observed_by_artifact = observed.clone();
        let result = execute_with_capabilities(
            r#"
const reference = execution.emitArtifact({kind: "preview", rows: [1, 2]});
return {
  artifactsAvailable: execution.artifactsAvailable,
  reference
};
"#,
            &[],
            ProgramData::default(),
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
            move |value| {
                *observed_by_artifact.lock().expect("artifact lock") =
                    serde_json::from_str(value).ok();
                Ok(serde_json::json!({
                    "execution_id": "01900000-0000-7000-8000-000000000001",
                    "artifact_id": "01900000-0000-7000-8000-000000000002",
                })
                .to_string())
            },
            true,
        )
        .expect("program emits an artifact");

        assert_eq!(
            *observed.lock().expect("artifact lock"),
            Some(serde_json::json!({
                "kind": "preview",
                "rows": [1, 2],
            }))
        );
        assert_eq!(result["artifactsAvailable"], true);
        assert_eq!(
            result["reference"]["artifact_id"],
            "01900000-0000-7000-8000-000000000002"
        );
    }

    #[test]
    fn artifact_api_reports_availability_without_narrowing_the_sdk_shape() {
        let result = execute_with(
            "return {available: execution.artifactsAvailable, emit: typeof execution.emitArtifact};",
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("program observes artifact availability");

        assert_eq!(
            result,
            serde_json::json!({
                "available": false,
                "emit": "function",
            })
        );
    }

    #[test]
    fn runtime_exposes_no_common_ambient_authority_apis() {
        let result = execute_with(
            "return {process: typeof process, fetch: typeof fetch, require: typeof require};",
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("program executes");

        assert_eq!(
            result,
            serde_json::json!({
                "process": "undefined",
                "fetch": "undefined",
                "require": "undefined"
            })
        );
    }

    #[test]
    fn fresh_runtime_does_not_share_javascript_state() {
        execute_with(
            r#"
globalThis.crossExecutionMarker = "global";
Object.prototype.crossExecutionMarker = "prototype";
return true;
"#,
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("first runtime executes");

        let result = execute_with(
            r#"
return {
  globalMarker: typeof globalThis.crossExecutionMarker,
  prototypeMarker: ({}).crossExecutionMarker ?? null
};
"#,
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("second runtime executes");

        assert_eq!(
            result,
            serde_json::json!({
                "globalMarker": "undefined",
                "prototypeMarker": null
            })
        );
    }

    #[test]
    fn runtime_exposes_only_generated_bindings_and_hides_raw_host_functions() {
        let result = execute_with(
            r#"
return {
  connectors: Object.keys(connectors),
  email: Object.keys(connectors.email),
  missing: typeof connectors.email.send,
  rawCall: typeof __gateway_call,
  rawMaterializing: typeof __gateway_connector_materializing,
  rawMaterialized: typeof __gateway_connector_materialized,
  rawBindings: typeof __gateway_bindings_json
};
"#,
            &bindings(&[("email", "read")]),
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("program executes");

        assert_eq!(
            result,
            serde_json::json!({
                "connectors": ["email"],
                "email": ["read"],
                "missing": "undefined",
                "rawCall": "undefined",
                "rawMaterializing": "undefined",
                "rawMaterialized": "undefined",
                "rawBindings": "undefined"
            })
        );
    }

    #[test]
    fn unavailable_binding_never_crosses_the_native_call_boundary() {
        let called = Arc::new(AtomicBool::new(false));
        let called_by_connector = called.clone();
        let error = execute_with(
            "return connectors.email.send({value: \"message\"});",
            &bindings(&[("email", "read")]),
            move |_| {
                called_by_connector.store(true, Ordering::SeqCst);
                unreachable!("unavailable binding must not call the host")
            },
        )
        .expect_err("unavailable binding is absent");

        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    // The in-code error contract: a refused connector call throws an Error
    // whose stable `code` is split from the broker's "code: message"
    // string, so programs branch on codes, never message text. Prefixes
    // that are not lowercase snake_case (an upstream message that merely
    // contains a colon) fall back to `connector_failure` with the full
    // text, and the thrown value stays a real Error even when the program
    // has replaced the global Error and string intrinsics.
    #[test]
    fn connector_refusals_throw_structured_errors_with_stable_codes() {
        let result = execute_with(
            r#"
globalThis.Error = function FakeError() { return {tampered: true}; };
String.prototype.indexOf = () => -1;
String.prototype.slice = () => "tampered";
Object.prototype.err = "inherited poison";
const outcomes = [];
for (const args of [{value: "first"}, {value: "second"}, {value: "third"}]) {
  try {
    outcomes.push({caught: false, ok: connectors.email.send(args)});
  } catch (error) {
    outcomes.push({caught: true, code: error.code, message: error.message});
  }
}
return outcomes;
"#,
            &bindings(&[("email", "send")]),
            {
                let call_index = AtomicU32::new(0);
                move |_| {
                    Ok(match call_index.fetch_add(1, Ordering::SeqCst) {
                        0 => serde_json::json!({ "err": "forbidden: forbid policies: hide-tool" }),
                        1 => serde_json::json!({ "err": "HTTP 500: upstream exploded" }),
                        // A success envelope: a poisoned Object.prototype.err
                        // must not turn it into a thrown failure.
                        _ => serde_json::json!({ "ok": {"result": "delivered"} }),
                    }
                    .to_string())
                }
            },
        )
        .expect("program handles the refusals");

        assert_eq!(
            result,
            serde_json::json!([
                {
                    "caught": true,
                    "code": "forbidden",
                    "message": "forbid policies: hide-tool",
                },
                {
                    "caught": true,
                    "code": "connector_failure",
                    "message": "HTTP 500: upstream exploded",
                },
                {
                    "caught": false,
                    "ok": {"result": "delivered"},
                },
            ])
        );
    }

    #[test]
    fn generated_binding_identity_ignores_program_serialization_hooks() {
        let result = execute_with(
            r#"
Object.prototype.toJSON = () => "mutated";
JSON.stringify = () => '{"call_id":"email:send","arguments":{}}';
return connectors.email.read({value: "inbox"}).result;
"#,
            &bindings(&[("email", "read")]),
            |request| {
                let request: Value = serde_json::from_str(request).expect("connector request");
                assert_eq!(request["call_id"], "email:read");
                Ok(r#"{"ok":{"result":"ok"}}"#.to_owned())
            },
        )
        .expect("generated binding identity stays immutable");

        assert_eq!(result, serde_json::json!("ok"));
    }

    #[test]
    fn oversized_connector_request_never_crosses_the_native_call_boundary() {
        let called = Arc::new(AtomicBool::new(false));
        let called_by_connector = called.clone();
        let error = execute_with(
            &format!(
                "return connectors.email.read({{value: \"x\".repeat({})}});",
                limits().request_bytes
            ),
            &bindings(&[("email", "read")]),
            move |_| {
                called_by_connector.store(true, Ordering::SeqCst);
                unreachable!("oversized request must be refused first")
            },
        )
        .expect_err("oversized connector request is refused");

        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    #[test]
    fn connector_argument_limit_excludes_routing_metadata() {
        for call_id in ["c", "a-longer-connector-binding-identifier"] {
            let request = serde_json::json!({"call_id": call_id, "arguments": {}}).to_string();
            validate_connector_request(&request, 2).expect("empty object fits exactly");
            assert!(validate_connector_request(&request, 1).is_err());
        }
        let size = limits().request_bytes - "{\"body\":\"\"}".len();
        let result = execute_with(
            &format!("return connectors.email.read({{body: 'x'.repeat({size})}});"),
            &bindings(&[("email", "read")]),
            |request| {
                let value: Value = serde_json::from_str(request).expect("request");
                assert_eq!(
                    serde_json::to_vec(&value["arguments"]).unwrap().len(),
                    limits().request_bytes
                );
                Ok("{\"ok\":true}".to_owned())
            },
        )
        .expect("the full argument allowance dispatches");
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn oversized_program_result_is_refused() {
        let error = execute_with(
            &format!("return \"x\".repeat({});", limits().result_bytes + 1),
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect_err("oversized result is refused");

        assert_eq!(error.code, RunnerFailureCode::ResultTooLarge);
    }

    #[test]
    fn non_json_program_result_has_a_stable_failure_code() {
        for source in [
            "return undefined;",
            "return 1n;",
            "const value = {}; value.self = value; return value;",
        ] {
            let error = execute_with(source, &[], |_| {
                unreachable!("program makes no connector calls")
            })
            .expect_err("program result is not JSON-compatible");

            assert_eq!(error.code, RunnerFailureCode::ResultNotJson);
        }
    }

    /// Arming moves the origin as well as the budget, so a program is granted
    /// its own time rather than what startup left over.
    ///
    /// The delay here is deliberately longer than the budget that follows it.
    /// If arming set only the duration, the elapsed startup would already
    /// exceed the grant and the interrupt would fire on the program's first
    /// check, so a program that finishes proves the origin moved. An assertion
    /// that merely watched a long program die would pass either way and prove
    /// nothing.
    #[test]
    #[ignore = "wall-clock integration check; run explicitly on an idle host (docs/testing.md)"]
    fn arming_grants_a_program_its_own_time_not_what_startup_left() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");

        let startup = Duration::from_millis(400);
        let budget_ms = 200;
        assert!(
            startup > Duration::from_millis(budget_ms),
            "the delay must exceed the grant, or this cannot tell the two apart"
        );
        std::thread::sleep(startup);
        deadline.arm(budget_ms);

        let context = JsContext::full(&runtime).expect("create context");
        let result = execute_in(
            &context,
            "let n = 0; for (let i = 0; i < 20000; i++) { n += i; } return n;",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: |_: f64| -> rquickjs::Result<String> {
                    unreachable!("program does not wait")
                },
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect("a program armed after startup gets its full grant");
        assert!(result.is_number());
    }

    /// The armed budget is the one enforced, and its exhaustion is reported as
    /// a timeout rather than a program error.
    #[test]
    fn an_armed_budget_is_the_one_enforced() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");
        deadline.arm(20);

        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            "while (true) {}",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: |_: f64| -> rquickjs::Result<String> {
                    unreachable!("program does not wait")
                },
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect_err("the armed budget terminates the program");
        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
    }

    /// A program can pace itself without burning a core.
    ///
    /// The elapsed time is what makes this a wait rather than a no-op, and the
    /// program continuing afterwards is what makes it a wait rather than a
    /// termination.
    #[test]
    fn a_program_can_wait_and_then_continue() {
        let started = Instant::now();
        let result = execute_with("execution.wait(120); return \"resumed\";", &[], |_| {
            unreachable!("program makes no connector calls")
        })
        .expect("a paced program runs to completion");

        assert_eq!(result, Value::String("resumed".to_owned()));
        assert!(
            started.elapsed() >= Duration::from_millis(120),
            "the program must actually have waited"
        );
    }

    /// A wait far longer than the budget cannot outlive it, and ends as a
    /// timeout rather than as a program error.
    ///
    /// Those two reasons have opposite remedies — raise the limit, or read the
    /// code — so reporting the wrong one sends the reader in the wrong
    /// direction.
    #[test]
    #[ignore = "wall-clock wait latency; manual diagnostic only"]
    fn a_wait_longer_than_the_budget_is_clamped_and_reported_as_a_timeout() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");
        let budget = Duration::from_millis(200);
        deadline.arm(u64::try_from(budget.as_millis()).expect("budget fits"));

        let started = Instant::now();
        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            "try { execution.wait(60000); } catch {} return \"waited\";",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: runner_wait(deadline, deadline_reached.clone()),
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect_err("a wait cannot outlive the budget that grants it");

        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the wait must be clamped to the budget, not served in full"
        );
    }

    /// Catching an exhausted wait must not reopen any host capability.
    ///
    /// The final timeout result is not enough for side-effect safety: an
    /// admitted connector reached between the catch and that final check could
    /// already have changed external state.
    #[test]
    fn a_caught_exhausted_wait_cannot_reach_host_capabilities() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");
        deadline.arm(100);
        let connector_called = Arc::new(AtomicBool::new(false));
        let pause_called = Arc::new(AtomicBool::new(false));
        let artifact_called = Arc::new(AtomicBool::new(false));
        let connector_observed = connector_called.clone();
        let pause_observed = pause_called.clone();
        let artifact_observed = artifact_called.clone();

        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            r#"
try { execution.wait(60_000); } catch {}
try { connectors.test.effect({}); } catch {}
try { execution.emitArtifact({kind: "too-late"}); } catch {}
try { execution.pause({state: "too-late"}); } catch {}
return "too late";
"#,
            &bindings(&[("test", "effect")]),
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: move |_: &str| -> rquickjs::Result<String> {
                    connector_observed.store(true, Ordering::Relaxed);
                    Ok(serde_json::json!({"ok": Value::Null}).to_string())
                },
                pause: move |_: &str| -> rquickjs::Result<String> {
                    pause_observed.store(true, Ordering::Relaxed);
                    Ok("paused".to_owned())
                },
                artifact: move |_: &str| -> rquickjs::Result<String> {
                    artifact_observed.store(true, Ordering::Relaxed);
                    Ok(serde_json::json!({"artifact_id": "too-late"}).to_string())
                },
                wait: runner_wait(deadline, deadline_reached.clone()),
                artifacts_available: true,
            },
            &deadline_reached,
        )
        .expect_err("deadline exhaustion remains the terminal result");

        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
        assert!(!connector_called.load(Ordering::Relaxed));
        assert!(!pause_called.load(Ordering::Relaxed));
        assert!(!artifact_called.load(Ordering::Relaxed));
    }

    /// The budget the operator granted still ends a program that waits inside
    /// a loop, so pacing cannot be turned into an unbounded run.
    #[test]
    fn repeated_waiting_still_ends_at_the_granted_budget() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");
        deadline.arm(300);

        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            // Each wait is small enough to be granted, so the program is
            // stopped by the budget rather than by any single refusal.
            "while (true) { execution.wait(20); }",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: runner_wait(deadline, deadline_reached.clone()),
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect_err("a program that only waits is still bounded by its budget");

        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
    }

    /// A wait that is not a number of milliseconds is refused rather than
    /// coerced into some other duration.
    #[test]
    fn a_nonsensical_wait_is_refused() {
        for argument in ["-1", "NaN", "Infinity"] {
            let result = execute_with(
                &format!("try {{ execution.wait({argument}); return \"waited\"; }} catch (e) {{ return e.code; }}"),
                &[],
                |_| unreachable!("program makes no connector calls"),
            )
            .expect("the refusal reaches the program as a catchable error");
            assert_eq!(
                result,
                Value::String("execution_wait_invalid".to_owned()),
                "wait({argument}) must be refused"
            );
        }
    }

    #[test]
    fn infinite_loop_has_the_stable_timeout_code() {
        let (runtime, deadline_reached) =
            create_runtime_with_limit(Duration::from_millis(10)).expect("create runtime");
        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            "while (true) {}",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: |_: f64| -> rquickjs::Result<String> {
                    unreachable!("program does not wait")
                },
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect_err("interrupt deadline terminates the program");

        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
    }

    #[test]
    fn memory_pressure_terminates_with_a_stable_program_failure() {
        let error = execute_with(
            "const chunks = []; while (true) { chunks.push(new ArrayBuffer(1024 * 1024)); }",
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect_err("runtime memory limit terminates the program");

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    #[test]
    fn connector_object_graph_pressure_uses_the_connector_limit_failure() {
        let binding = RunnerBinding {
            connector: "mock".to_owned(),
            operation: "read".to_owned(),
            call_id: "call-1".to_owned(),
        };
        let expansive = format!(
            "{{\"ok\":[{}]}}",
            "{},".repeat(limits().heap_bytes / 32) + "{}"
        );

        let error = execute_with("return connectors.mock.read({});", &[binding], move |_| {
            Ok(expansive.clone())
        })
        .expect_err("connector object graph must hit the QuickJS heap boundary");

        assert_eq!(error.code, RunnerFailureCode::ConnectorResultTooLarge);
    }

    #[test]
    fn native_connector_failure_is_not_mislabeled_as_materialization_pressure() {
        let error = execute_with(
            "return connectors.mock.read({});",
            &[RunnerBinding {
                connector: "mock".to_owned(),
                operation: "read".to_owned(),
                call_id: "call-1".to_owned(),
            }],
            |_| {
                Err(rquickjs::Error::new_from_js_message(
                    "response",
                    "connector call",
                    "connector transport failed",
                ))
            },
        )
        .expect_err("native connector transport failure must stop evaluation");

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    #[test]
    fn matching_user_exception_message_is_not_a_connector_limit_failure() {
        let error = execute_with(
            &format!("throw new Error({CONNECTOR_MATERIALIZATION_FAILURE:?});"),
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect_err("user exception stops evaluation");

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    #[test]
    fn program_failure_message_is_bounded() {
        let error = RunnerExecutionFailure::new(
            RunnerFailureCode::ProgramFailed,
            "x".repeat(MAX_FAILURE_MESSAGE_CHARS * 2),
        );

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
        assert_eq!(error.message.chars().count(), MAX_FAILURE_MESSAGE_CHARS);
    }

    type HostCall = fn(&str) -> rquickjs::Result<String>;
    type HostWait = fn(f64) -> rquickjs::Result<String>;

    fn unused_capabilities() -> ExecutionCapabilities<HostCall, HostCall, HostCall, HostWait> {
        ExecutionCapabilities {
            call: |_: &str| -> rquickjs::Result<String> {
                unreachable!("program makes no connector calls")
            },
            pause: |_: &str| -> rquickjs::Result<String> { unreachable!("program does not pause") },
            artifact: |_: &str| -> rquickjs::Result<String> {
                unreachable!("program emits no artifacts")
            },
            wait: |_: f64| -> rquickjs::Result<String> { unreachable!("program does not wait") },
            artifacts_available: false,
        }
    }

    fn program_failure(source: &str) -> String {
        let error = execute_with(source, &[], |_| {
            unreachable!("program makes no connector calls")
        })
        .expect_err("program fails");
        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
        error.message
    }

    #[test]
    fn a_program_body_can_await_connector_results_and_promises() {
        let result = execute_with(
            r#"
const first = await connectors.email.first({});
const doubled = await Promise.resolve(first.result * 2);
return {first: first.result, doubled};
"#,
            &bindings(&[("email", "first")]),
            |_| Ok(serde_json::json!({"ok": {"result": 21}}).to_string()),
        )
        .expect("an awaiting program completes");

        assert_eq!(result, serde_json::json!({"first": 21, "doubled": 42}));
    }

    /// A promise the program returns is the result's value once settled, not
    /// the promise object, which serializes as an empty object.
    #[test]
    fn a_returned_promise_settles_to_its_value() {
        let result = execute_with("return (async () => ({answer: 5}))();", &[], |_| {
            unreachable!("program makes no connector calls")
        })
        .expect("the returned promise settles");

        assert_eq!(result, serde_json::json!({"answer": 5}));
    }

    #[test]
    fn an_awaited_connector_refusal_keeps_its_stable_code() {
        let refuse = |_: &str| Ok(serde_json::json!({"err": "forbidden: hidden"}).to_string());
        let caught = execute_with(
            r#"
try {
  await connectors.email.send({});
  return "sent";
} catch (error) {
  return error.code;
}
"#,
            &bindings(&[("email", "send")]),
            refuse,
        )
        .expect("the program handles the refusal");
        assert_eq!(caught, Value::String("forbidden".to_owned()));

        let error = execute_with(
            "await connectors.email.send({}); return \"sent\";",
            &bindings(&[("email", "send")]),
            refuse,
        )
        .expect_err("an unhandled refusal rejects the program");
        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
        assert!(error.message.contains("Error: hidden"), "{}", error.message);
    }

    #[test]
    fn a_promise_that_can_never_settle_fails_instead_of_returning() {
        for source in [
            "await new Promise(() => {}); return 1;",
            "return new Promise(() => {});",
        ] {
            let message = program_failure(source);
            assert!(message.contains("never finished"), "{source}: {message}");
        }
    }

    #[test]
    fn the_deadline_bounds_promise_jobs() {
        for source in [
            "await null; while (true) {}",
            "const spin = () => Promise.resolve().then(spin); spin(); \
             await new Promise(() => {});",
        ] {
            let (runtime, deadline_reached) =
                create_runtime_with_limit(Duration::from_millis(50)).expect("create runtime");
            let context = JsContext::full(&runtime).expect("create context");
            let error = execute_in(
                &context,
                source,
                &[],
                None,
                &Value::Null,
                unused_capabilities(),
                &deadline_reached,
            )
            .expect_err("the deadline ends promise jobs");

            assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout, "{source}");
        }
    }

    #[test]
    fn failures_report_positions_in_the_submitted_program() {
        assert_eq!(
            program_failure(
                "const a = 1;\nfunction decode() {\n  return new MissingDecoder().decode(a);\n}\n\
                 return decode();"
            ),
            "Code Mode program evaluation failed: ReferenceError: MissingDecoder is not defined\n    \
             at decode (program:3:14)\n    at <anonymous> (program:5:8)"
        );
        assert_eq!(
            program_failure("await null;\nnull.property;"),
            "Code Mode program evaluation failed: TypeError: cannot read property 'property' of \
             null\n    at <anonymous> (program:2:1)"
        );
        assert_eq!(
            program_failure("const first = 1;\nconst x = ;\nreturn x;"),
            "Code Mode program evaluation failed: SyntaxError: unexpected token in expression: \
             ';'\n    at program:2"
        );
        let unterminated = program_failure("return {\n  open: true,");
        assert!(
            unterminated.starts_with("Code Mode program evaluation failed: SyntaxError: ")
                && unterminated.ends_with("\n    at the end of the program"),
            "{unterminated}"
        );
    }

    #[test]
    fn connector_failures_point_at_the_calling_line_not_gateway_code() {
        let error = execute_with(
            "const unused = 1;\nreturn connectors.email.send({});",
            &bindings(&[("email", "send")]),
            |_| Ok(serde_json::json!({"err": "forbidden: hidden"}).to_string()),
        )
        .expect_err("the refusal fails the program");

        assert!(
            error.message.starts_with(
                "Code Mode program evaluation failed: Error: hidden\n    at <anonymous> (program:2:"
            ),
            "{}",
            error.message
        );
        assert!(
            !error.message.contains(ENGINE_SCRIPT_NAME),
            "{}",
            error.message
        );
    }

    /// A thrown value that is not an Error is described without running any of
    /// the program's code, even code the value itself supplies.
    #[test]
    fn thrown_non_error_values_are_described_without_running_program_code() {
        assert_eq!(
            program_failure("throw 'plain string';"),
            "Code Mode program evaluation failed: uncaught string: plain string"
        );
        assert_eq!(
            program_failure("throw 42;"),
            "Code Mode program evaluation failed: uncaught number: 42"
        );
        assert_eq!(
            program_failure("throw null;"),
            "Code Mode program evaluation failed: uncaught null"
        );
        let called = Arc::new(AtomicBool::new(false));
        let called_by_connector = called.clone();
        let error = execute_with(
            "throw {toString() { connectors.email.send({}); return 'shown'; }, \
             toJSON() { connectors.email.send({}); return 'shown'; }};",
            &bindings(&[("email", "send")]),
            move |_| {
                called_by_connector.store(true, Ordering::SeqCst);
                Ok(serde_json::json!({"ok": null}).to_string())
            },
        )
        .expect_err("the thrown object fails the program");

        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(
            error.message,
            "Code Mode program evaluation failed: uncaught object; throw an Error to report a \
             message and position"
        );
    }

    #[test]
    fn engine_stack_frames_are_restated_in_program_positions() {
        let layout = ProgramLayout {
            first_line: 10,
            last_line: 12,
        };
        assert_eq!(
            layout.program_stack(
                "    at f (eval_script:11:4)\n    at <anonymous> (eval_script:3:1)\n    at parse \
                 (native)\n    at <eval> (eval_script:14:2)"
            ),
            "    at f (program:2:4)\n    at parse (native)"
        );
        assert_eq!(
            layout.program_stack("    at eval_script:12:40"),
            "    at program:3"
        );
        assert_eq!(
            layout.program_stack("    at eval_script:13:9"),
            "    at the end of the program"
        );
    }

    #[test]
    fn line_breaks_are_counted_as_the_engine_counts_them() {
        assert_eq!(engine_line_breaks("a\nb\n"), 2);
        assert_eq!(engine_line_breaks("a\r\nb"), 1);
        assert_eq!(engine_line_breaks("a\rb"), 1);
        assert_eq!(engine_line_breaks("a\u{2028}b\u{2029}c"), 2);
        for separator in ["\n", "\r", "\r\n", "\u{2028}", "\u{2029}"] {
            let message = program_failure(&format!(
                "const a = 1;{separator}return new MissingDecoder(a);"
            ));
            assert!(
                message.ends_with("\n    at <anonymous> (program:2:12)"),
                "{separator:?}: {message}"
            );
        }
    }

    /// Reporting a failure reads the thrown value, and a getter or proxy can
    /// run program code during that read. None of it may reach a connector.
    #[test]
    fn reporting_a_failure_cannot_reach_host_capabilities() {
        for source in [
            "throw { get code() { connectors.email.send({}); return 'forbidden'; } };",
            "throw new Proxy({}, { get() { connectors.email.send({}); return undefined; } });",
            "const error = new Error('quiet');\nObject.defineProperty(error, 'message', \
             { get() { connectors.email.send({}); return 'loud'; } });\nthrow error;",
            "const error = new Error('quiet');\nObject.defineProperty(error, 'name', \
             { get() { connectors.email.send({}); return 'LoudError'; } });\nthrow error;",
        ] {
            let called = Arc::new(AtomicBool::new(false));
            let called_by_connector = called.clone();
            let error = execute_with(source, &bindings(&[("email", "send")]), move |_| {
                called_by_connector.store(true, Ordering::SeqCst);
                Ok(serde_json::json!({"ok": null}).to_string())
            })
            .expect_err("the thrown value fails the program");

            assert!(!called.load(Ordering::SeqCst), "{source}");
            assert_eq!(error.code, RunnerFailureCode::ProgramFailed, "{source}");
        }
    }

    /// The Code Mode reference lists the globals a program can rely on and the
    /// common Node.js and browser globals it cannot. Keep that list and this
    /// one in step.
    #[test]
    fn runtime_globals_match_the_documented_surface() {
        let result = execute_with(
            r#"
return {
  present: {
    connectors: typeof connectors,
    execution: typeof execution,
    atob: typeof atob,
    btoa: typeof btoa,
    queueMicrotask: typeof queueMicrotask,
    performanceNow: typeof performance.now,
    fromBase64: typeof Uint8Array.fromBase64,
    toBase64: typeof Uint8Array.prototype.toBase64,
    DOMException: typeof DOMException,
  },
  absent: {
    console: typeof console,
    TextEncoder: typeof TextEncoder,
    TextDecoder: typeof TextDecoder,
    URL: typeof URL,
    URLSearchParams: typeof URLSearchParams,
    crypto: typeof crypto,
    structuredClone: typeof structuredClone,
    Buffer: typeof Buffer,
    setTimeout: typeof setTimeout,
    setInterval: typeof setInterval,
    fetch: typeof fetch,
    require: typeof require,
    process: typeof process,
    Intl: typeof Intl,
  },
};
"#,
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("program executes");

        for (name, kind) in result["present"].as_object().expect("present globals") {
            assert_ne!(kind, "undefined", "{name} is documented as available");
        }
        for (name, kind) in result["absent"].as_object().expect("absent globals") {
            assert_eq!(kind, "undefined", "{name} is documented as absent");
        }
    }
}
