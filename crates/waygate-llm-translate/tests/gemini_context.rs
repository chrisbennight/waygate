use serde_json::{json, Value};
use waygate_llm_translate::*;

fn provider_response() -> Value {
    json!({"responseId":"response-1","modelVersion":"qualified-gemini",
        "candidates":[{"content":{"role":"model","parts":[{
            "functionCall":{"id":"provider-call-id","name":"weather","args":{"city":"Paris"}},
            "thoughtSignature":"opaque-context"
        }]},"finishReason":"STOP"}],
        "usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":3,"thoughtsTokenCount":1}})
}

fn assert_chat_echo(message: Value) {
    let request = parse_chat_completions(&json!({"model":"alias","messages":[message,
        {"role":"tool","tool_call_id":"provider-call-id","content":"sunny"}]}))
    .unwrap();
    assert_native_echo(&render_gemini(&request).unwrap());
    let other = render_openai_chat(&request, "other-model").unwrap();
    assert!(other["messages"][0]["tool_calls"][0]
        .get("extra_content")
        .is_none());
}

fn assert_responses_echo(output: Value) {
    let mut items = output.as_array().unwrap().clone();
    items
        .push(json!({"type":"function_call_output","call_id":"provider-call-id","output":"sunny"}));
    let request = parse_responses(&json!({"model":"alias","input":items})).unwrap();
    assert_native_echo(&render_gemini(&request).unwrap());
}

fn assert_native_echo(body: &Value) {
    let part = &body["contents"][0]["parts"][0];
    assert_eq!(part["functionCall"]["id"], "provider-call-id");
    assert_eq!(part["functionCall"]["args"], json!({"city":"Paris"}));
    assert_eq!(part["thoughtSignature"], "opaque-context");
    let result = &body["contents"][1]["parts"][0]["functionResponse"];
    assert_eq!(result["id"], "provider-call-id");
    assert_eq!(result["name"], "weather");
}

#[test]
fn unary_chat_and_responses_preserve_function_context_without_cross_provider_forwarding() {
    let response = provider_response();
    let legacy = gemini_response_to_openai_chat(&response);
    let canonical = gemini_to_canonical_response(&response);
    let chat = canonical_response_to_openai_chat(&canonical);
    assert_eq!(
        chat["choices"][0]["message"]["tool_calls"],
        legacy["choices"][0]["message"]["tool_calls"]
    );
    assert_chat_echo(chat["choices"][0]["message"].clone());
    assert_responses_echo(canonical_response_to_responses(&canonical)["output"].clone());
}

#[test]
fn streaming_chat_and_responses_preserve_the_same_function_context() {
    let record = InferenceRecord::new(
        LlmProvider::Google,
        "API",
        "alias",
        Surface::ChatCompletions,
        UpstreamProtocol::Gemini,
    );
    let mut translator = StreamTranslator::for_record(record);
    let step = translator.push(&provider_response().to_string());
    let mut call = step
        .chunks
        .iter()
        .find_map(|chunk| chunk.pointer("/choices/0/delta/tool_calls/0"))
        .unwrap()
        .clone();
    call.as_object_mut().unwrap().remove("index");
    assert_chat_echo(json!({"role":"assistant","content":null,"tool_calls":[call]}));
    let mut bridge = ChatStreamToResponses::new();
    let mut events = Vec::new();
    for chunk in step.chunks.iter().filter(|chunk| chunk.is_object()) {
        events.extend(bridge.push(chunk));
    }
    events.extend(bridge.finish(None));
    for (_, event) in events.iter().filter(|(name, _)| {
        matches!(
            name.as_str(),
            "response.output_item.added" | "response.output_item.done"
        )
    }) {
        assert_eq!(
            event.pointer("/item/extra_content/google/thought_signature"),
            Some(&json!("opaque-context"))
        );
    }
    let terminal = &events
        .iter()
        .find(|(name, _)| name == "response.completed")
        .unwrap()
        .1;
    assert_responses_echo(terminal["response"]["output"].clone());
}

#[test]
fn malformed_context_is_refused_without_echoing_the_opaque_value() {
    for extra in [
        json!({"google":{"thought_signature":7}}),
        json!({"google":{"thought_signature":"private-context","unexpected":true}}),
    ] {
        let request = json!({"model":"alias","messages":[{"role":"assistant","tool_calls":[{
            "id":"call","type":"function","function":{"name":"weather","arguments":"{}"},"extra_content":extra
        }]}]});
        let error = parse_chat_completions(&request).unwrap_err().to_string();
        assert!(error.contains("google.thought_signature"));
        assert!(!error.contains("private-context"));
    }
}

#[test]
fn repeated_call_ids_in_later_turns_do_not_relabel_earlier_function_results() {
    let messages = vec![
        json!({"role":"assistant","tool_calls":[{"id":"reused","type":"function","function":{"name":"first","arguments":"{}"}}]}),
        json!({"role":"tool","tool_call_id":"reused","content":"one"}),
        json!({"role":"assistant","tool_calls":[{"id":"reused","type":"function","function":{"name":"second","arguments":"{}"}}]}),
        json!({"role":"tool","tool_call_id":"reused","content":"two"}),
    ];
    let request = parse_chat_completions(&json!({"model":"alias","messages":messages})).unwrap();
    let body = render_gemini(&request).unwrap();
    assert_eq!(
        body["contents"][1]["parts"][0]["functionResponse"]["name"],
        "first"
    );
    assert_eq!(
        body["contents"][3]["parts"][0]["functionResponse"]["name"],
        "second"
    );
}
