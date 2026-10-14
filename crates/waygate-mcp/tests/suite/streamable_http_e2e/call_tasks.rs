//! Gateway call tasks over the stateless wire: only a client that declared
//! the tasks extension, calling a tool the operator listed as long-running on
//! an upstream without native tasks, receives a gateway task handle, and the
//! lifecycle methods for that handle reach the call-task executor.
use super::*;

use rmcp::model::{DetailedTask, GetTaskResult, Task, TaskPayload, TaskStatus};
use waygate_mcp::call_tasks::{GatewayCallTasks, QualifiedCall};

fn handle() -> String {
    waygate_mcp::call_tasks::task_id(uuid::Uuid::from_u128(42))
}

#[derive(Default)]
struct RecordingCallTasks {
    starts: std::sync::Mutex<Vec<(String, QualifiedCall)>>,
    gets: std::sync::Mutex<Vec<String>>,
    cancels: std::sync::Mutex<Vec<String>>,
}

#[async_trait]
impl GatewayCallTasks for RecordingCallTasks {
    async fn start(
        &self,
        principal: &Principal,
        call: QualifiedCall,
    ) -> Result<Option<Task>, waygate_invocation::InvocationError> {
        self.starts
            .lock()
            .unwrap()
            .push((principal.sub.clone(), call));
        Ok(Some(Task::new(
            handle(),
            TaskStatus::Working,
            "2026-08-01T00:00:00Z",
            "2026-08-01T00:00:00Z",
        )))
    }

    async fn get(
        &self,
        _principal: &Principal,
        task_id: &str,
    ) -> Result<Option<GetTaskResult>, McpError> {
        self.gets.lock().unwrap().push(task_id.to_owned());
        if task_id != handle() {
            return Ok(None);
        }
        let result = json!({"content": [{"type": "text", "text": "done"}], "isError": false});
        Ok(Some(GetTaskResult::new(DetailedTask::new(
            Task::new(
                handle(),
                TaskStatus::Completed,
                "2026-08-01T00:00:00Z",
                "2026-08-01T00:00:01Z",
            ),
            TaskPayload::Completed {
                result: result.as_object().unwrap().clone(),
            },
        ))))
    }

    async fn cancel(&self, _principal: &Principal, task_id: &str) -> Result<bool, McpError> {
        self.cancels.lock().unwrap().push(task_id.to_owned());
        Ok(task_id == handle())
    }
}

/// A stateless 2026-07-28 request declaring `capabilities` for itself.
async fn post(
    client: &reqwest::Client,
    url: &str,
    id: u64,
    method: &str,
    mut params: Value,
    capabilities: Value,
) -> Value {
    params.as_object_mut().unwrap().insert(
        "_meta".into(),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": capabilities,
            "io.modelcontextprotocol/clientInfo": {"name": "call-task-probe", "version": "0.0.0"}
        }),
    );
    let mut request = client
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method);
    if let Some(name) = ["name", "taskId"]
        .into_iter()
        .find_map(|key| params.get(key).and_then(Value::as_str))
    {
        request = request.header("mcp-name", name.to_owned());
    }
    let response = request
        .json(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .send()
        .await
        .expect("stateless POST");
    stateless_response_json(response).await
}

fn tasks_capability() -> Value {
    json!({"extensions": {"io.modelcontextprotocol/tasks": {}}})
}

async fn spawn(catalog: DemoCatalog, call_tasks: Arc<RecordingCallTasks>) -> ServerHandle {
    let catalog: SharedCatalog = Arc::new(catalog);
    spawn_gateway_custom_with_principal(
        StreamableHttpServerConfig::default().with_allowed_hosts(vec![ALLOWED_HOST.to_string()]),
        move || GatewayServer::new(catalog.clone()).with_call_tasks(call_tasks.clone()),
        Some(wire_principal()),
    )
    .await
}

#[tokio::test]
async fn only_a_tasks_client_gets_a_gateway_task_for_a_long_running_tool() {
    let dispatches = Arc::new(AtomicUsize::new(0));
    let call_tasks = Arc::new(RecordingCallTasks::default());
    let server = spawn(
        DemoCatalog {
            dispatches: Some(dispatches.clone()),
            long_running_tools: vec!["echo".to_owned()],
            ..DemoCatalog::default()
        },
        call_tasks.clone(),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();
    let call = json!({"name": "demo.echo", "arguments": {"value": "x"}});

    let synchronous = post(&client, &url, 1, "tools/call", call.clone(), json!({})).await;
    assert_eq!(
        synchronous["result"]["content"][0]["text"], "called demo.echo",
        "a client without the tasks extension gets the ordinary result: {synchronous}"
    );
    assert!(call_tasks.starts.lock().unwrap().is_empty());
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);

    let created = post(&client, &url, 2, "tools/call", call, tasks_capability()).await;
    assert_eq!(created["result"]["resultType"], "task", "{created}");
    assert_eq!(created["result"]["taskId"], handle());
    {
        let starts = call_tasks.starts.lock().unwrap();
        assert_eq!(starts.len(), 1);
        assert_eq!(starts[0].0, wire_principal().sub);
        assert_eq!(
            (starts[0].1.server.as_str(), starts[0].1.tool.as_str()),
            ("demo", "echo")
        );
        assert_eq!(
            starts[0].1.arguments,
            json!({"value": "x"}).as_object().cloned()
        );
    }
    assert_eq!(
        dispatches.load(Ordering::SeqCst),
        1,
        "the executor owns dispatch of a task"
    );

    let fetched = post(
        &client,
        &url,
        3,
        "tasks/get",
        json!({"taskId": handle()}),
        tasks_capability(),
    )
    .await;
    assert_eq!(fetched["result"]["status"], "completed", "{fetched}");
    assert_eq!(fetched["result"]["result"]["content"][0]["text"], "done");

    let unknown = waygate_mcp::call_tasks::task_id(uuid::Uuid::from_u128(7));
    let missing = post(
        &client,
        &url,
        4,
        "tasks/get",
        json!({"taskId": unknown}),
        tasks_capability(),
    )
    .await;
    assert_eq!(missing["error"]["message"], "Task not found", "{missing}");

    let cancelled = post(
        &client,
        &url,
        5,
        "tasks/cancel",
        json!({"taskId": handle()}),
        tasks_capability(),
    )
    .await;
    assert!(cancelled.get("error").is_none(), "{cancelled}");
    assert_eq!(*call_tasks.gets.lock().unwrap(), [handle(), unknown]);
    assert_eq!(*call_tasks.cancels.lock().unwrap(), [handle()]);

    server.shutdown().await;
}

#[tokio::test]
async fn an_upstream_with_native_tasks_keeps_its_own_task_decision() {
    let dispatches = Arc::new(AtomicUsize::new(0));
    let call_tasks = Arc::new(RecordingCallTasks::default());
    let server = spawn(
        DemoCatalog {
            dispatches: Some(dispatches.clone()),
            long_running_tools: vec!["echo".to_owned()],
            task_binding: Some("native-task-binding".to_owned()),
            ..DemoCatalog::default()
        },
        call_tasks.clone(),
    )
    .await;
    let url = format!("http://{}/mcp", server.addr);
    let client = reqwest::Client::new();

    let response = post(
        &client,
        &url,
        1,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {}}),
        tasks_capability(),
    )
    .await;
    assert_eq!(
        response["result"]["content"][0]["text"], "called demo.echo",
        "{response}"
    );
    assert!(call_tasks.starts.lock().unwrap().is_empty());
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);

    server.shutdown().await;
}
