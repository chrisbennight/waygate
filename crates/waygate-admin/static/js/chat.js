// LLM chat tester (streaming). Hand-rolled, no framework — matches the
// dashboard's vanilla-JS posture. The transcript is held client-side only;
// each turn POSTs the whole transcript to POST /chat/stream and reads the
// streamed text/event-stream body via fetch (EventSource is GET-only and we
// must POST the messages). Frames are the provider's OpenAI
// chat.completion.chunk JSON, terminated by `[DONE]`; an `event: error` frame
// carries a failure (and, for a step-up, the scope to re-authorize with).
(function () {
  "use strict";

  const root = document.querySelector("[data-chat]");
  if (!root) return;

  const streamUrl = root.getAttribute("data-stream-url");
  const csrf = root.getAttribute("data-csrf") || "";
  const loginUrl = root.getAttribute("data-login-url") || "/admin/login";

  const log = root.querySelector("[data-chat-log]");
  const form = root.querySelector("[data-chat-form]");
  const input = root.querySelector("[data-chat-input]");
  const sendBtn = root.querySelector("[data-chat-send]");
  const clearBtn = root.querySelector("[data-chat-clear]");
  const modelEl = root.querySelector("#chat-model");

  /** @type {{role:string, content:string}[]} */
  let transcript = [];
  let streaming = false;

  function dropEmptyState() {
    const empty = log.querySelector("[data-chat-empty]");
    if (empty) empty.remove();
  }

  function scrollToBottom() {
    log.scrollTop = log.scrollHeight;
  }

  // Append a message bubble; returns the element holding its text so a
  // streaming assistant reply can be grown in place.
  function addBubble(role) {
    dropEmptyState();
    const wrap = document.createElement("div");
    wrap.className = "chat-msg chat-msg--" + role;
    const who = document.createElement("div");
    who.className = "chat-msg__role";
    who.textContent = role;
    const body = document.createElement("div");
    body.className = "chat-msg__body";
    wrap.appendChild(who);
    wrap.appendChild(body);
    log.appendChild(wrap);
    scrollToBottom();
    return body;
  }

  function showError(message, stepUpScope) {
    dropEmptyState();
    const wrap = document.createElement("div");
    wrap.className = "chat-msg chat-msg--error";
    const body = document.createElement("div");
    body.className = "chat-msg__body";
    body.textContent = message || "request failed";
    wrap.appendChild(body);
    if (stepUpScope) {
      const next = window.location.pathname;
      const a = document.createElement("a");
      a.href =
        loginUrl +
        "?step_up_scope=" +
        encodeURIComponent(stepUpScope) +
        "&next=" +
        encodeURIComponent(next);
      a.textContent = "Re-authorize with " + stepUpScope;
      const p = document.createElement("p");
      p.style.marginTop = "6px";
      p.appendChild(a);
      wrap.appendChild(p);
    }
    log.appendChild(wrap);
    scrollToBottom();
  }

  function setStreaming(on) {
    streaming = on;
    if (sendBtn) sendBtn.disabled = on;
    if (input) input.disabled = on;
  }

  // Parse one SSE block ("event: x\ndata: y\ndata: z") into {event, data}.
  function parseFrame(block) {
    let event = "message";
    const dataLines = [];
    for (const raw of block.split("\n")) {
      const line = raw.replace(/\r$/, "");
      if (!line || line.startsWith(":")) continue; // blank / comment
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
    }
    return { event, data: dataLines.join("\n") };
  }

  // Apply one frame to the live assistant bubble. Returns true when the stream
  // is done (terminal sentinel or error).
  function applyFrame(frame, assistantBody, acc) {
    if (frame.event === "error") {
      let msg = "request failed",
        scope;
      try {
        const e = JSON.parse(frame.data).error || {};
        msg = e.message || msg;
        scope = e.step_up_scope;
      } catch (_) {}
      // Replace the (empty) assistant bubble with an error.
      const wrap = assistantBody.parentElement;
      if (wrap && !acc.text) wrap.remove();
      showError(msg, scope);
      return true;
    }
    if (frame.data === "[DONE]") return true;
    if (!frame.data) return false;
    try {
      const chunk = JSON.parse(frame.data);
      const delta =
        (chunk.choices && chunk.choices[0] && chunk.choices[0].delta && chunk.choices[0].delta.content) || "";
      if (delta) {
        acc.text += delta;
        assistantBody.textContent = acc.text;
        scrollToBottom();
      }
    } catch (_) {
      // Non-JSON data line — ignore (keep-alive / unknown).
    }
    return false;
  }

  async function send(text) {
    const model = modelEl ? (modelEl.value || "").trim() : "";
    if (!model) {
      showError("Pick or enter a model first.");
      return;
    }
    transcript.push({ role: "user", content: text });
    addBubble("user").textContent = text;

    const assistantBody = addBubble("assistant");
    assistantBody.textContent = "…";
    const acc = { text: "" };
    setStreaming(true);

    let resp;
    try {
      resp = await fetch(streamUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ csrf: csrf, model: model, messages: transcript }),
      });
    } catch (e) {
      assistantBody.parentElement.remove();
      showError("network error: " + e);
      setStreaming(false);
      return;
    }

    if (!resp.ok) {
      let msg = "HTTP " + resp.status;
      try {
        const j = await resp.json();
        if (j && j.error && j.error.message) msg = j.error.message;
      } catch (_) {}
      assistantBody.parentElement.remove();
      showError(msg);
      setStreaming(false);
      return;
    }

    // Read the streamed body and parse SSE frames as they arrive.
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let done = false;
    assistantBody.textContent = "";
    try {
      while (!done) {
        const { value, done: rdDone } = await reader.read();
        if (rdDone) break;
        buffer += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buffer.indexOf("\n\n")) !== -1) {
          const block = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          if (applyFrame(parseFrame(block), assistantBody, acc)) {
            done = true;
            break;
          }
        }
      }
    } catch (e) {
      showError("stream error: " + e);
    }

    if (acc.text) transcript.push({ role: "assistant", content: acc.text });
    else if (assistantBody.parentElement && assistantBody.textContent === "")
      assistantBody.parentElement.remove();
    setStreaming(false);
    if (input) input.focus();
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    if (streaming) return;
    const text = (input.value || "").trim();
    if (!text) return;
    input.value = "";
    send(text);
  });

  // Enter to send; Shift+Enter for a newline.
  input.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event("submit", { cancelable: true }));
    }
  });

  if (clearBtn) {
    clearBtn.addEventListener("click", function () {
      if (streaming) return;
      transcript = [];
      log.innerHTML =
        '<div class="empty-state" data-chat-empty>' +
        '<svg class="empty-state__icon" aria-hidden="true"><use href="/admin/static/lucide.svg#message-square"/></svg>' +
        '<p class="empty-state__title">No messages yet</p>' +
        '<p class="empty-state__body">Pick a model and send a message to test it. Replies stream in token by token.</p>' +
        "</div>";
    });
  }
})();
