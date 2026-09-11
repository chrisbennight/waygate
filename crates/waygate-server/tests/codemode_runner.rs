#[cfg(target_os = "linux")]
use std::io::Write;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, ClientInfo, Implementation, JsonObject,
};
#[cfg(target_os = "linux")]
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
#[cfg(target_os = "linux")]
use rmcp::transport::StreamableHttpClientTransport;
#[cfg(target_os = "linux")]
use rmcp::{ServiceError, ServiceExt};
#[cfg(target_os = "linux")]
use serde_json::{json, Value};

#[test]
#[cfg(target_os = "linux")]
fn external_runner_composes_framed_connector_calls_without_ambient_apis() {
    let (mut child, mut input, mut output) = spawn_ready_runner();
    let thread_count = std::fs::read_dir(format!("/proc/{}/task", child.id()))
        .expect("read runner threads")
        .count();
    assert_eq!(
        thread_count, 1,
        "runner readiness requires every process thread to inherit confinement"
    );
    let limits = std::fs::read_to_string(format!("/proc/{}/limits", child.id()))
        .expect("read runner resource limits");
    let address_space = limits
        .lines()
        .find(|line| line.starts_with("Max address space"))
        .expect("address-space limit");
    assert!(
        address_space.contains("1145044992"),
        "runner address space is not bounded: {address_space}"
    );

    write_frame(
        &mut input,
        json!({
            "type": "start",
            "artifacts_available": false,
            "bindings": [
                {
                    "connector": "email",
                    "operation": "read",
                    "call_id": "5:email4:read"
                },
                {
                    "connector": "weather",
                    "operation": "current",
                    "call_id": "7:weather7:current"
                }
            ],
            "source": r#"
const first = connectors.email.read({value: "inbox"});
const second = connectors.weather.current({value: first.result});
return {
  combined: second.result,
  process: typeof process,
  fetch: typeof fetch,
  require: typeof require
};
"#
        }),
    );

    let first = read_frame(&mut output);
    assert_eq!(first["type"], "call");
    assert_eq!(first["id"], 1);
    assert_eq!(first["call_id"], "5:email4:read");
    assert_eq!(first["arguments"], json!({"value": "inbox"}));
    write_frame(
        &mut input,
        json!({
            "type": "call_result",
            "id": 1,
            "result": {"Ok": {"storage": "inline", "value": {"result": "message"}}}
        }),
    );

    let second = read_frame(&mut output);
    assert_eq!(second["type"], "call");
    assert_eq!(second["id"], 2);
    assert_eq!(second["call_id"], "7:weather7:current");
    assert_eq!(second["arguments"], json!({"value": "message"}));
    write_frame(
        &mut input,
        json!({
            "type": "call_result",
            "id": 2,
            "result": {"Ok": {"storage": "inline", "value": {"result": "sunny"}}}
        }),
    );

    let completed = read_frame(&mut output);
    assert_eq!(completed["type"], "complete");
    assert_eq!(
        completed["result"],
        json!({
            "combined": "sunny",
            "process": "undefined",
            "fetch": "undefined",
            "require": "undefined"
        })
    );
    drop(input);
    assert!(child.wait().expect("wait for runner").success());
}

#[test]
#[cfg(target_os = "linux")]
fn external_runner_materializes_a_large_completed_result_from_its_private_spool() {
    let (mut child, mut input, mut output, mut spool) = spawn_ready_runner_with_spool();
    write_frame(
        &mut input,
        json!({
            "type": "start",
            "artifacts_available": false,
            "bindings": [{
                "connector": "logs",
                "operation": "download",
                "call_id": "4:logs8:download"
            }],
            "source": r#"
const response = connectors.logs.download({});
return {
  bytes: response.data.length,
  tail: response.data.slice(-7)
};
"#
        }),
    );
    let call = read_frame(&mut output);
    assert_eq!(call["type"], "call");

    let value = json!({"data": format!("{}failure", "x".repeat(2 * 1024 * 1024))});
    spool
        .as_file_mut()
        .set_len(0)
        .expect("truncate runner spool");
    spool
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .expect("rewind runner spool");
    serde_json::to_writer(spool.as_file_mut(), &value).expect("write spooled result");
    spool.as_file_mut().flush().expect("flush spooled result");
    let bytes = spool.as_file().metadata().expect("spool metadata").len();
    write_frame(
        &mut input,
        json!({
            "type": "call_result",
            "id": call["id"],
            "result": {"Ok": {"storage": "spool", "bytes": bytes}}
        }),
    );

    let completed = read_frame(&mut output);
    assert_eq!(completed["type"], "complete");
    assert_eq!(completed["result"]["bytes"], 2 * 1024 * 1024 + 7);
    assert_eq!(completed["result"]["tail"], "failure");
    drop(input);
    assert!(child.wait().expect("wait for runner").success());
}

#[test]
#[cfg(target_os = "linux")]
fn external_runner_state_does_not_cross_execution_attempts() {
    let (mut first, mut first_input, mut first_output) = spawn_ready_runner();
    write_frame(
        &mut first_input,
        json!({
            "type": "start",
            "artifacts_available": false,
            "bindings": [],
            "source": r#"
globalThis.crossExecutionMarker = "global";
Object.prototype.crossExecutionMarker = "prototype";
return {contaminated: true};
"#
        }),
    );
    assert_eq!(read_frame(&mut first_output)["type"], "complete");
    drop(first_input);
    assert!(first.wait().expect("wait for first runner").success());

    let (mut second, mut second_input, mut second_output) = spawn_ready_runner();
    write_frame(
        &mut second_input,
        json!({
            "type": "start",
            "artifacts_available": false,
            "bindings": [],
            "source": r#"
return {
  globalMarker: typeof globalThis.crossExecutionMarker,
  prototypeMarker: ({}).crossExecutionMarker ?? null
};
"#
        }),
    );
    let completed = read_frame(&mut second_output);
    assert_eq!(completed["type"], "complete");
    assert_eq!(
        completed["result"],
        json!({
            "globalMarker": "undefined",
            "prototypeMarker": null
        })
    );
    drop(second_input);
    assert!(second.wait().expect("wait for second runner").success());
}

#[test]
#[cfg(target_os = "linux")]
fn external_runner_releases_at_a_checkpoint_and_accepts_resume_context() {
    let (mut paused, mut paused_input, mut paused_output) = spawn_ready_runner();
    write_frame(
        &mut paused_input,
        json!({
            "type": "start",
            "artifacts_available": false,
            "bindings": [],
            "resume": null,
            "source": r#"
execution.pause({
  prompt: "Choose a region",
  state: {candidate_ids: [1, 2]}
});
"#
        }),
    );
    let checkpoint = read_frame(&mut paused_output);
    assert_eq!(checkpoint["type"], "pause");
    assert_eq!(checkpoint["checkpoint"]["prompt"], "Choose a region");
    assert_eq!(
        checkpoint["checkpoint"]["state"]["candidate_ids"],
        json!([1, 2])
    );
    drop(paused_input);
    assert!(paused.wait().expect("wait for paused runner").success());

    let (mut resumed, mut resumed_input, mut resumed_output) = spawn_ready_runner();
    write_frame(
        &mut resumed_input,
        json!({
            "type": "start",
            "artifacts_available": false,
            "bindings": [],
            "resume": {
                "checkpoint": checkpoint["checkpoint"],
                "input": {"region": "west"}
            },
            "source": "return execution.resume;"
        }),
    );
    let completed = read_frame(&mut resumed_output);
    assert_eq!(completed["type"], "complete");
    assert_eq!(completed["result"]["input"]["region"], "west");
    assert_eq!(
        completed["result"]["checkpoint"]["state"]["candidate_ids"],
        json!([1, 2])
    );
    drop(resumed_input);
    assert!(resumed.wait().expect("wait for resumed runner").success());
}

#[test]
#[cfg(target_os = "linux")]
fn external_runner_reports_typed_resource_and_result_failures() {
    for (source, expected_code) in [
        ("return 1n;", "result_not_json"),
        (
            "return \"x\".repeat(8 * 1024 * 1024 + 1);",
            "result_too_large",
        ),
        (
            "const chunks = []; while (true) { chunks.push(new ArrayBuffer(1024 * 1024)); }",
            "program_failed",
        ),
        ("while (true) {}", "execution_timeout"),
    ] {
        let (mut child, mut input, mut output) = spawn_ready_runner();
        write_frame(
            &mut input,
            json!({
                "type": "start",
                "artifacts_available": false,
                "bindings": [],
                "source": source,
                "execution_limit_ms": 1000
            }),
        );

        let failure = read_frame(&mut output);
        assert_eq!(failure["type"], "failed");
        assert_eq!(failure["code"], expected_code);
        drop(input);
        assert!(child.wait().expect("wait for failed runner").success());
    }
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "wall-clock process scheduling diagnostic; manual execution only"]
fn external_runner_waits_under_confinement_and_reports_budget_exhaustion() {
    let (mut child, mut input, mut output) = spawn_ready_runner();
    let started = Instant::now();
    write_frame(
        &mut input,
        json!({
            "type": "start",
            "artifacts_available": false,
            "bindings": [],
            "execution_limit_ms": 200,
            "source": r#"
try {
  execution.wait(60_000);
} catch {
  return "caught";
}
return "waited";
"#
        }),
    );

    let failure = read_frame(&mut output);
    assert_eq!(failure["type"], "failed");
    assert_eq!(failure["code"], "execution_timeout");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the wait must be clamped to the granted budget"
    );
    drop(input);
    assert!(child.wait().expect("wait for timed-out runner").success());
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "wall-clock process scheduling diagnostic; manual execution only"]
fn external_runner_can_be_terminated_while_waiting() {
    let (mut child, mut input, mut output) = spawn_ready_runner();
    write_frame(
        &mut input,
        json!({
            "type": "start",
            "artifacts_available": false,
            "bindings": [{
                "connector": "test",
                "operation": "started",
                "call_id": "4:test7:started"
            }],
            "execution_limit_ms": 60_000,
            "source": r#"
connectors.test.started({});
execution.wait(60_000);
return "too late";
"#
        }),
    );

    let started_call = read_frame(&mut output);
    assert_eq!(started_call["type"], "call");
    assert_eq!(started_call["call_id"], "4:test7:started");
    write_frame(
        &mut input,
        json!({
            "type": "call_result",
            "id": started_call["id"],
            "result": {"Ok": {"storage": "inline", "value": null}}
        }),
    );
    std::thread::sleep(Duration::from_millis(50));

    let stopping = Instant::now();
    child.kill().expect("terminate waiting runner");
    let status = child.wait().expect("reap terminated runner");
    assert!(!status.success());
    assert!(
        stopping.elapsed() < Duration::from_secs(1),
        "a native wait must not wedge parent-driven runner teardown"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn external_runner_fails_closed_on_malformed_parent_frame() {
    let (mut child, mut input, _output) = spawn_ready_runner();
    input
        .write_all(b"{not-json}\n")
        .expect("write malformed parent frame");
    input.flush().expect("flush malformed parent frame");
    drop(input);

    assert!(!child.wait().expect("wait for malformed runner").success());
}

#[tokio::test]
#[cfg(target_os = "linux")]
#[ignore = "wall-clock integration check; run explicitly on an idle host (docs/testing.md)"]
async fn gateway_reports_runner_crash_and_recovers_for_the_next_execution() {
    let manifest_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/empty-servers");
    let policy_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../waygate-authz/tests/fixtures/policies");
    let mut gateway = tokio::process::Command::new(env!("CARGO_BIN_EXE_gateway-server"));
    gateway
        .env_clear()
        .env("GATEWAY_AUTH_MODE", "disabled")
        .env("GATEWAY_LISTEN_ADDR", "127.0.0.1:0")
        .env("GATEWAY_PUBLIC_URL", "http://127.0.0.1")
        .env("GATEWAY_MCP_ALLOWED_HOSTS", "")
        .env("GATEWAY_SERVERS_DIR", &manifest_dir)
        .env("GATEWAY_POLICIES_DIR", &policy_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut gateway = gateway.spawn().expect("start gateway");
    let gateway_pid = gateway.id().expect("gateway pid");
    let listen_addr = wait_for_gateway(gateway_pid, &mut gateway).await;
    let client = connect_gateway(listen_addr).await;

    let killer = tokio::spawn(kill_confined_runner_child(gateway_pid));
    let error = client
        .call_tool(execute_params("while (true) {}"))
        .await
        .expect_err("forced runner termination fails the execution");
    let killed_pid = killer.await.expect("runner killer task");
    match error {
        ServiceError::McpError(error) => {
            assert_eq!(
                error.data.as_ref().expect("structured runner crash")["error"],
                "runner_crashed"
            );
        }
        other => panic!("expected gateway MCP error after killing runner {killed_pid}: {other:?}"),
    }

    let recovered = client
        .call_tool(execute_params("return {ok: true};"))
        .await
        .expect("subsequent execution succeeds");
    assert_eq!(
        recovered
            .structured_content
            .as_ref()
            .expect("structured execute response")["result"]["ok"],
        true
    );

    client.cancel().await.expect("stop MCP client");
    gateway.start_kill().expect("stop gateway");
    gateway.wait().await.expect("reap gateway");
}

#[test]
#[cfg(not(target_os = "linux"))]
fn external_runner_fails_closed_without_linux_confinement() {
    let spool = tempfile::NamedTempFile::new().expect("create runner result spool");
    let mut child = Command::new(env!("CARGO_BIN_EXE_gateway-server"))
        .arg("--codemode-runner")
        .arg("--codemode-result-spool")
        .arg(spool.path())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start external runner");
    let output = child.stdout.take().expect("runner stdout");
    let mut output = BufReader::new(output);
    let mut line = String::new();

    assert_eq!(
        output.read_line(&mut line).expect("read runner output"),
        0,
        "unsupported hosts must not report confinement readiness"
    );
    assert!(!child.wait().expect("wait for runner").success());
}

#[cfg(target_os = "linux")]
fn spawn_ready_runner() -> (
    std::process::Child,
    std::process::ChildStdin,
    BufReader<std::process::ChildStdout>,
) {
    let (child, input, output, spool) = spawn_ready_runner_with_spool();
    drop(spool);
    (child, input, output)
}

#[cfg(target_os = "linux")]
fn spawn_ready_runner_with_spool() -> (
    std::process::Child,
    std::process::ChildStdin,
    BufReader<std::process::ChildStdout>,
    tempfile::NamedTempFile,
) {
    let spool = tempfile::NamedTempFile::new().expect("create runner result spool");
    let mut child = Command::new(env!("CARGO_BIN_EXE_gateway-server"))
        .arg("--codemode-runner")
        .arg("--codemode-result-spool")
        .arg(spool.path())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start external runner");
    let input = child.stdin.take().expect("runner stdin");
    let output = child.stdout.take().expect("runner stdout");
    let mut output = BufReader::new(output);
    let ready = read_frame(&mut output);
    assert_eq!(ready["type"], "ready");
    assert_eq!(ready["confinement_profile"], "linux-seccomp-v1");
    (child, input, output, spool)
}

#[cfg(target_os = "linux")]
async fn wait_for_gateway(
    gateway_pid: u32,
    gateway: &mut tokio::process::Child,
) -> std::net::SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(listen_addr) = gateway_listener_addr(gateway_pid).await {
            let ready_url = format!("http://{listen_addr}/readyz");
            if reqwest::get(&ready_url)
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                return listen_addr;
            }
        }
        if let Some(status) = gateway.try_wait().expect("inspect gateway process") {
            panic!("gateway exited before readiness: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "gateway did not bind and become ready"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(target_os = "linux")]
async fn gateway_listener_addr(gateway_pid: u32) -> Option<std::net::SocketAddr> {
    let mut socket_inodes = std::collections::BTreeSet::new();
    let mut descriptors = tokio::fs::read_dir(format!("/proc/{gateway_pid}/fd"))
        .await
        .ok()?;
    while let Some(descriptor) = descriptors.next_entry().await.ok()? {
        let target = tokio::fs::read_link(descriptor.path()).await.ok()?;
        let target = target.to_str()?;
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|target| target.strip_suffix(']'))
        {
            socket_inodes.insert(inode.to_owned());
        }
    }
    let sockets = tokio::fs::read_to_string(format!("/proc/{gateway_pid}/net/tcp"))
        .await
        .ok()?;
    for socket in sockets.lines().skip(1) {
        let fields = socket.split_whitespace().collect::<Vec<_>>();
        if fields.get(3) != Some(&"0A") || !socket_inodes.contains(*fields.get(9)?) {
            continue;
        }
        let (address, port) = fields.get(1)?.split_once(':')?;
        if address != "0100007F" {
            continue;
        }
        let port = u16::from_str_radix(port, 16).ok()?;
        return Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    }
    None
}

#[cfg(target_os = "linux")]
async fn connect_gateway(
    listen_addr: std::net::SocketAddr,
) -> rmcp::service::RunningService<rmcp::RoleClient, ClientInfo> {
    let uri: Arc<str> = Arc::from(format!("http://{listen_addr}/mcp"));
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(uri),
    );
    ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new("codemode-crash-recovery-test", env!("CARGO_PKG_VERSION")),
    )
    .serve(transport)
    .await
    .expect("initialize gateway MCP session")
}

#[cfg(target_os = "linux")]
fn execute_params(source: &str) -> CallToolRequestParams {
    CallToolRequestParams::new("codemode.execute").with_arguments(JsonObject::from_iter([(
        "source".to_owned(),
        Value::String(source.to_owned()),
    )]))
}

#[cfg(target_os = "linux")]
async fn kill_confined_runner_child(gateway_pid: u32) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let gateway_executable = tokio::fs::read_link(format!("/proc/{gateway_pid}/exe"))
        .await
        .expect("resolve gateway executable");
    loop {
        let mut task_dirs = tokio::fs::read_dir(format!("/proc/{gateway_pid}/task"))
            .await
            .expect("read gateway tasks");
        let mut child_pids = std::collections::BTreeSet::new();
        while let Some(task_dir) = task_dirs.next_entry().await.expect("read gateway task") {
            let children_path = task_dir.path().join("children");
            let children = match tokio::fs::read_to_string(children_path).await {
                Ok(children) => children,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("read gateway child processes: {error}"),
            };
            child_pids.extend(
                children
                    .split_whitespace()
                    .map(|raw_pid| raw_pid.parse::<u32>().expect("numeric child pid")),
            );
        }
        for pid in child_pids {
            let cmdline = tokio::fs::read(format!("/proc/{pid}/cmdline"))
                .await
                .unwrap_or_default();
            let argv = cmdline
                .split(|byte| *byte == 0)
                .filter(|argument| !argument.is_empty())
                .collect::<Vec<_>>();
            if argv.len() != 4
                || argv[0] != gateway_executable.as_os_str().as_bytes()
                || argv[1] != b"--codemode-runner"
                || argv[2] != b"--codemode-result-spool"
                || argv[3].is_empty()
            {
                continue;
            }
            let child_executable = tokio::fs::read_link(format!("/proc/{pid}/exe"))
                .await
                .expect("resolve runner executable");
            if child_executable != gateway_executable {
                continue;
            }
            let status = tokio::fs::read_to_string(format!("/proc/{pid}/status"))
                .await
                .expect("read runner status");
            if !status.lines().any(|line| line == "Seccomp:\t2") {
                continue;
            }
            wait_for_active_runner_execution(pid, deadline).await;
            let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            assert_eq!(result, 0, "kill confined Code Mode runner");
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "gateway did not spawn a confined Code Mode runner"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_active_runner_execution(pid: u32, deadline: Instant) {
    let clock_ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    assert!(
        clock_ticks_per_second > 0,
        "read Linux process clock tick rate"
    );
    let minimum_active_ticks = (clock_ticks_per_second as u64 / 20).max(1);
    let initial_ticks = process_cpu_ticks(pid).await;
    loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let current_ticks = process_cpu_ticks(pid).await;
        if current_ticks.saturating_sub(initial_ticks) >= minimum_active_ticks {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Code Mode runner did not enter sustained program execution"
        );
    }
}

#[cfg(target_os = "linux")]
async fn process_cpu_ticks(pid: u32) -> u64 {
    let stat = tokio::fs::read_to_string(format!("/proc/{pid}/stat"))
        .await
        .expect("read runner process statistics");
    let (_, fields) = stat
        .rsplit_once(") ")
        .expect("runner process statistics contain command");
    let mut fields = fields.split_whitespace();
    let user_ticks = fields
        .nth(11)
        .expect("runner statistics contain user CPU time")
        .parse::<u64>()
        .expect("runner user CPU time is numeric");
    let system_ticks = fields
        .next()
        .expect("runner statistics contain system CPU time")
        .parse::<u64>()
        .expect("runner system CPU time is numeric");
    user_ticks + system_ticks
}

#[cfg(target_os = "linux")]
fn write_frame(output: &mut impl Write, frame: Value) {
    serde_json::to_writer(&mut *output, &frame).expect("encode parent frame");
    output.write_all(b"\n").expect("terminate parent frame");
    output.flush().expect("flush parent frame");
}

#[cfg(target_os = "linux")]
fn read_frame(input: &mut impl BufRead) -> Value {
    let mut line = String::new();
    assert_ne!(input.read_line(&mut line).expect("read runner frame"), 0);
    serde_json::from_str(&line).expect("decode runner frame")
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn gateway_executes_large_source_and_reports_operator_limits() {
    let manifest_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/empty-servers");
    let policy_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../waygate-authz/tests/fixtures/policies");
    let mut gateway = tokio::process::Command::new(env!("CARGO_BIN_EXE_gateway-server"));
    gateway
        .env_clear()
        .env("GATEWAY_AUTH_MODE", "disabled")
        .env("GATEWAY_LISTEN_ADDR", "127.0.0.1:0")
        .env("GATEWAY_PUBLIC_URL", "http://127.0.0.1")
        .env("GATEWAY_MCP_ALLOWED_HOSTS", "")
        .env("GATEWAY_SERVERS_DIR", manifest_dir)
        .env("GATEWAY_POLICIES_DIR", policy_dir)
        .env("GATEWAY_CODEMODE_SOURCE_MAX_BYTES", "5242880")
        .env("GATEWAY_CODEMODE_RESULT_MAX_BYTES", "1024")
        .env("GATEWAY_CODEMODE_EXECUTION_LIMIT_SECONDS", "86400")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut gateway = gateway.spawn().expect("start isolated gateway");
    let address = wait_for_gateway(gateway.id().expect("gateway pid"), &mut gateway).await;
    let client = connect_gateway(address).await;
    let reported = client
        .call_tool(CallToolRequestParams::new("codemode.limits"))
        .await
        .expect("discover limits");
    let reported = reported.structured_content.expect("typed limits");
    assert_eq!(reported["resources"]["source_bytes"], 5 * 1024 * 1024);
    assert_eq!(reported["resources"]["heap_bytes"], 160 * 1024 * 1024);
    assert_eq!(reported["resources"]["execution_seconds"], 86_400);
    assert_eq!(
        reported["resources"]["retained_owner_bytes"],
        80 * 1024 * 1024
    );

    let source = format!("/*{}*/return {{ok:true}};", "x".repeat(4 * 1024 * 1024));
    let result = client
        .call_tool(execute_params(&source))
        .await
        .expect("multi-megabyte source executes");
    assert_eq!(
        result.structured_content.expect("execution result")["result"]["ok"],
        true
    );
    let oversized = "x".repeat(5 * 1024 * 1024 + 1);
    assert!(client.call_tool(execute_params(&oversized)).await.is_err());

    let mut params = execute_params("execution.wait(2000); return true;");
    params
        .arguments
        .as_mut()
        .expect("arguments")
        .insert("timeout_seconds".into(), json!(1));
    let error = client
        .call_tool(params)
        .await
        .expect_err("caller deadline enforced");
    let ServiceError::McpError(error) = error else {
        panic!("expected MCP timeout error");
    };
    assert_eq!(
        error.data.expect("timeout reason")["error"],
        "execution_timeout"
    );
    let error = client
        .call_tool(execute_params("return 'x'.repeat(1024);"))
        .await
        .expect_err("configured result budget enforced by runner");
    let ServiceError::McpError(error) = error else {
        panic!("expected MCP result limit error");
    };
    assert_eq!(
        error.data.expect("result limit reason")["error"],
        "execution_result_too_large"
    );
    let result = client
        .call_tool(execute_params("return true;"))
        .await
        .expect("gateway remains usable");
    assert_eq!(result.structured_content.expect("result")["result"], true);
    client.cancel().await.expect("stop client");
    gateway.start_kill().expect("stop gateway");
    gateway.wait().await.expect("reap gateway");
}

#[test]
fn gateway_refuses_invalid_resource_configuration_before_listening() {
    for (name, value) in [
        ("GATEWAY_CODEMODE_SOURCE_MAX_BYTES", "0"),
        ("GATEWAY_CODEMODE_SOURCE_MAX_BYTES", "18446744073709551615"),
        ("GATEWAY_CODEMODE_EXECUTION_LIMIT_SECONDS", "86401"),
        ("GATEWAY_CODEMODE_EXECUTION_MAX_SECONDS", "86401"),
        ("GATEWAY_CODEMODE_EXECUTION_MEMORY_BYTES", "1"),
        ("GATEWAY_CODEMODE_ARTIFACT_TOTAL_MAX_BYTES", "1"),
    ] {
        let status = Command::new(env!("CARGO_BIN_EXE_gateway-server"))
            .env_clear()
            .env("GATEWAY_AUTH_MODE", "disabled")
            .env("GATEWAY_LISTEN_ADDR", "127.0.0.1:0")
            .env("GATEWAY_PUBLIC_URL", "http://127.0.0.1")
            .env(name, value)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("start invalid configuration probe");
        assert!(!status.success(), "invalid {name} must refuse startup");
    }
}
