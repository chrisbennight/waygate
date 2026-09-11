// Shared agent-chat client (Gateway-Agents / Contextual Assistant). Hand-rolled,
// no framework — matches the dashboard's vanilla-JS posture. Reused by both the
// immersive `/agent_chat` page and the docked assistant panel: both
// render the same `[data-agent-chat]` block and call `initAssistChat(root)`.
//
// Each turn POSTs {agent_id, message, conversation_id?} to the block's
// `data-stream-url` and reads the text/event-stream body. Frames are typed
// waygate-agent step events:
//   - default ("message") frames: an AgentEvent JSON ({event, ...}) — rendered
//     by its `event` tag (assistant_text / tool_call / tool_result /
//     approval_requested / approval_rejected).
//   - `event: session` — the chat-session id (carried into the next turn so the
//     thread persists, and used to correlate approve/reject decisions).
//   - `approval_requested` carries the call id; the UI shows Approve/Reject
//     buttons that POST to `…/approve` to resolve the parked call.
//   - `event: done` — terminal; carries {status, steps, tool_calls}.
//   - `event: error` — a pre/post-stream failure (with optional step_up_scope).
//
// A block is "hydrated" once it has a `data-stream-url`. The immersive page
// renders that server-side; the docked panel sets it client-side (after
// `/agent_chat/bootstrap`) before calling init. Un-hydrated blocks are skipped,
// so the panel's empty placeholder on every page is inert until opened.
(function () {
  "use strict";

  // `opts` (optional, used by the docked panel — the immersive page passes none):
  //   onConversation(id, agentName) — fired when a thread starts/continues/resumes
  //     so the caller can persist it (the panel stores it for cross-page resume).
  //   resume {id, agentName} — replay this owned thread on init (continuity across
  //     a full-page navigation).
  function initAssistChat(root, opts) {
    if (!root) return;
    opts = opts || {};
    const streamUrl = root.getAttribute("data-stream-url");
    if (!streamUrl) return; // not hydrated yet (e.g. the docked panel before open)
    if (root.dataset.assistChatInit === "1") return; // idempotent
    root.dataset.assistChatInit = "1";

    const approveUrl = streamUrl.replace(/\/stream$/, "/approve");
    const csrf = root.getAttribute("data-csrf") || "";
    const loginUrl = root.getAttribute("data-login-url") || "/admin/login";

    const log = root.querySelector("[data-chat-log]");
    const form = root.querySelector("[data-chat-form]");
    const input = root.querySelector("[data-chat-input]");
    const sendBtn = root.querySelector("[data-chat-send]");
    const clearBtn = root.querySelector("[data-chat-clear]");
    const agentEl = root.querySelector("[data-agent-select]");
    const modelChip = root.querySelector("[data-agent-model]");
    const historyToggle = root.querySelector("[data-history-toggle]");
    const historyPanel = root.querySelector("[data-history-panel]");
    const historyList = root.querySelector("[data-history-list]");
    const conversationsUrl = streamUrl.replace(/\/stream$/, "/conversations");

    let conversationId = null; // durable thread id (continuation)
    let sessionId = null; // per-turn id (approval correlation)
    let streaming = false;
    // Bumped on every user-initiated send / New. The async cross-page resume
    // captures it before its transcript fetch and re-checks after the await, so
    // a send/New that lands mid-fetch can't be clobbered by the late resume
    // write-back (read→await→write race).
    let interactionSeq = 0;

    // Egress indicator: reflect the selected agent's model in the chip. An LLM
    // turn leaves the gateway for this model's provider (governed + audited).
    function updateModelChip() {
      if (!modelChip || !agentEl) return;
      const opt = agentEl.options[agentEl.selectedIndex];
      const model = opt ? opt.getAttribute("data-model") || "" : "";
      modelChip.textContent = model ? "model: " + model : "";
    }
    function currentAgentName() {
      if (!agentEl) return null;
      const o = agentEl.options[agentEl.selectedIndex];
      return o ? o.textContent : null;
    }
    if (agentEl) {
      agentEl.addEventListener("change", updateModelChip);
      updateModelChip();
    }

    // Hand-off from the policy-review page: pre-fill the composer with a
    // finding so the operator can refine it here. Delivered via sessionStorage
    // (same-tab, same-origin) rather than a URL param, so sensitive finding text
    // never lands in browser history / access logs / referrers. Read
    // once on load, then clear it so a reload doesn't re-fill.
    (function applyPrefill() {
      if (!input) return;
      try {
        const prefill = sessionStorage.getItem("gw_agent_chat_prefill");
        if (prefill) {
          input.value = prefill;
          input.focus();
          sessionStorage.removeItem("gw_agent_chat_prefill");
        }
      } catch (_) {}
    })();

    function dropEmptyState() {
      const empty = log.querySelector("[data-chat-empty]");
      if (empty) empty.remove();
    }

    function scrollToBottom() {
      log.scrollTop = log.scrollHeight;
    }

    // Append a labelled bubble; returns the body element so streamed text can
    // grow it in place. `variant` styles the bubble (user/assistant/tool/error/
    // note).
    function addBubble(variant, label) {
      dropEmptyState();
      const wrap = document.createElement("div");
      wrap.className = "chat-msg chat-msg--" + variant;
      if (label) {
        const who = document.createElement("div");
        who.className = "chat-msg__role";
        who.textContent = label;
        wrap.appendChild(who);
      }
      const body = document.createElement("div");
      body.className = "chat-msg__body";
      wrap.appendChild(body);
      log.appendChild(wrap);
      scrollToBottom();
      return body;
    }

    function showError(message, stepUpScope) {
      const body = addBubble("error", null);
      body.textContent = message || "request failed";
      if (stepUpScope) {
        const a = document.createElement("a");
        a.href =
          loginUrl +
          "?step_up_scope=" +
          encodeURIComponent(stepUpScope) +
          "&next=" +
          encodeURIComponent(window.location.pathname);
        a.textContent = "Re-authorize with " + stepUpScope;
        const p = document.createElement("p");
        p.style.marginTop = "6px";
        p.appendChild(a);
        body.parentElement.appendChild(p);
      }
    }

    function setStreaming(on) {
      streaming = on;
      if (sendBtn) sendBtn.disabled = on;
      if (input) input.disabled = on;
    }

    // Parse one SSE block ("event: x\ndata: y") into {event, data}.
    function parseFrame(block) {
      let event = "message";
      const dataLines = [];
      for (const raw of block.split("\n")) {
        const line = raw.replace(/\r$/, "");
        if (!line || line.startsWith(":")) continue;
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
      }
      return { event, data: dataLines.join("\n") };
    }

    // Render one AgentEvent (a default "message" frame's parsed JSON). `ctx`
    // holds the live assistant bubble so consecutive assistant_text events grow
    // it.
    function renderAgentEvent(ev, ctx) {
      switch (ev.event) {
        case "assistant_text": {
          if (!ctx.assistant) ctx.assistant = addBubble("assistant", "assistant");
          ctx.assistant.textContent += ev.text || "";
          scrollToBottom();
          break;
        }
        case "tool_call": {
          ctx.assistant = null; // a later assistant_text starts a fresh bubble
          const body = addBubble("tool", "↳ tool call: " + (ev.name || ""));
          body.textContent = ev.arguments || "";
          break;
        }
        case "tool_result": {
          const body = addBubble(ev.is_error ? "error" : "tool", "tool result: " + (ev.name || ""));
          body.textContent = ev.content || "";
          break;
        }
        case "approval_requested": {
          const body = addBubble("note", "approval needed: " + (ev.name || ""));
          const pre = document.createElement("div");
          pre.textContent = ev.arguments || "";
          body.appendChild(pre);
          const actions = document.createElement("div");
          actions.style.marginTop = "6px";
          const mk = (label, decision, primary) => {
            const b = document.createElement("button");
            b.type = "button";
            b.className = "btn btn--sm" + (primary ? " btn-primary" : "");
            b.textContent = label;
            b.addEventListener("click", () => decide(ev.id, decision, actions, body));
            return b;
          };
          const ok = mk("Approve", "approve", true);
          const no = mk("Reject", "reject", false);
          no.style.marginLeft = "6px";
          actions.appendChild(ok);
          actions.appendChild(no);
          body.appendChild(actions);
          break;
        }
        case "approval_rejected": {
          const body = addBubble("note", "declined: " + (ev.name || ""));
          body.textContent = ev.reason || "";
          break;
        }
        default:
          break;
      }
    }

    // POST an approve/reject decision for a parked side-effecting call. The
    // loop's gate is blocked on this; resolving it unblocks the turn (which
    // keeps streaming on the open SSE connection).
    async function decide(callId, decision, actionsEl, bodyEl) {
      for (const b of actionsEl.querySelectorAll("button")) b.disabled = true;
      try {
        const resp = await fetch(approveUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: JSON.stringify({
            csrf: csrf,
            session_id: sessionId,
            call_id: callId,
            decision: decision,
          }),
        });
        if (!resp.ok) {
          const note = document.createElement("div");
          note.style.marginTop = "4px";
          note.textContent = "decision failed (HTTP " + resp.status + ") — try again";
          bodyEl.appendChild(note);
          for (const b of actionsEl.querySelectorAll("button")) b.disabled = false;
          return;
        }
        const note = document.createElement("div");
        note.style.marginTop = "4px";
        note.textContent = decision === "approve" ? "✓ approved" : "✗ rejected";
        actionsEl.replaceWith(note);
      } catch (e) {
        for (const b of actionsEl.querySelectorAll("button")) b.disabled = false;
      }
    }

    // Apply one parsed frame. Returns true when the stream is terminal.
    function applyFrame(frame, ctx) {
      if (frame.event === "session") {
        try {
          sessionId = JSON.parse(frame.data).id || sessionId;
        } catch (_) {}
        return false;
      }
      if (frame.event === "conversation") {
        try {
          conversationId = JSON.parse(frame.data).id || conversationId;
        } catch (_) {}
        if (opts.onConversation) opts.onConversation(conversationId, currentAgentName());
        return false;
      }
      if (frame.event === "error") {
        let msg = "request failed",
          scope;
        try {
          const e = JSON.parse(frame.data).error || {};
          msg = e.message || msg;
          scope = e.step_up_scope;
        } catch (_) {}
        showError(msg, scope);
        return true;
      }
      if (frame.event === "done") return true;
      if (!frame.data) return false;
      try {
        renderAgentEvent(JSON.parse(frame.data), ctx);
      } catch (_) {
        // Non-JSON keep-alive / unknown — ignore.
      }
      return false;
    }

    async function send(text) {
      interactionSeq++; // invalidate any in-flight cross-page resume
      const agentId = agentEl ? (agentEl.value || "").trim() : "";
      if (!agentId) {
        showError("Pick an agent first.");
        return;
      }
      addBubble("user", "you").textContent = text;
      const ctx = { assistant: null };
      setStreaming(true);

      let resp;
      try {
        resp = await fetch(streamUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: JSON.stringify({
            csrf: csrf,
            agent_id: agentId,
            message: text,
            conversation_id: conversationId,
            // The docked panel sets data-page so the agent is grounded in the
            // operator's current page; omitted (undefined) for the immersive
            // page, which has no page context.
            page: root.getAttribute("data-page") || undefined,
          }),
        });
      } catch (e) {
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
        showError(msg);
        setStreaming(false);
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let done = false;
      try {
        while (!done) {
          const { value, done: rdDone } = await reader.read();
          if (rdDone) break;
          buffer += decoder.decode(value, { stream: true });
          let idx;
          while ((idx = buffer.indexOf("\n\n")) !== -1) {
            const block = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 2);
            if (applyFrame(parseFrame(block), ctx)) {
              done = true;
              break;
            }
          }
        }
      } catch (e) {
        showError("stream error: " + e);
      }

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

    input.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" && !ev.shiftKey) {
        ev.preventDefault();
        form.requestSubmit
          ? form.requestSubmit()
          : form.dispatchEvent(new Event("submit", { cancelable: true }));
      }
    });

    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        if (streaming) return;
        interactionSeq++; // invalidate any in-flight cross-page resume
        conversationId = null;
        sessionId = null;
        // Let the caller forget the persisted thread too, so "New" can't be
        // undone by a later cross-page resume.
        if (opts.onClear) opts.onClear();
        log.innerHTML =
          '<div class="empty-state" data-chat-empty>' +
          '<svg class="empty-state__icon" aria-hidden="true"><use href="/admin/static/lucide.svg#message-square"/></svg>' +
          '<p class="empty-state__title">No messages yet</p>' +
          '<p class="empty-state__body">Pick an agent and send a message. The agent can call its allowlisted tools; tool calls and results stream in as it works.</p>' +
          "</div>";
      });
    }

    // --- Recent conversations (resume) -------------------------------------

    async function loadHistory() {
      if (!historyList) return;
      historyList.textContent = "Loading…";
      let items = [];
      try {
        const resp = await fetch(conversationsUrl, { headers: { Accept: "application/json" } });
        if (resp.ok) items = (await resp.json()).conversations || [];
      } catch (_) {}
      historyList.innerHTML = "";
      if (!items.length) {
        historyList.textContent = "No past conversations.";
        return;
      }
      for (const c of items) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "chat-history__item";
        b.textContent = (c.title || "(untitled)") + " · " + (c.agent_name || "");
        // Where the thread began (origin_page), when recorded. The value is
        // a server-sanitized nav suffix; textContent keeps it inert regardless.
        if (c.origin_page) {
          const origin = document.createElement("span");
          origin.className = "chat-history__origin";
          origin.textContent = " · from " + c.origin_page;
          b.appendChild(origin);
        }
        b.addEventListener("click", () => resumeConversation(c.id, c.agent_name));
        historyList.appendChild(b);
      }
    }

    // Re-select the conversation's original agent in the picker (match by name).
    // Returns true if found — a resumed thread stays bound to its agent (the
    // server also enforces this; this keeps the UI honest). Returns false if
    // that agent is no longer enabled/listed, so the caller can warn.
    function selectAgentByName(name) {
      if (!agentEl || !name) return false;
      for (const opt of agentEl.options) {
        if (opt.textContent === name) {
          agentEl.value = opt.value;
          updateModelChip();
          return true;
        }
      }
      return false;
    }

    // Load an owned conversation's transcript into the log (display-only) and
    // set it as the active thread so the next message continues it.
    async function resumeConversation(id, agentName) {
      if (streaming) return;
      const seq = interactionSeq; // snapshot before the await
      let msgs = [];
      try {
        const resp = await fetch(conversationsUrl + "/" + encodeURIComponent(id), {
          headers: { Accept: "application/json" },
        });
        if (resp.ok) msgs = (await resp.json()).messages || [];
      } catch (_) {
        showError("could not load that conversation");
        return;
      }
      // Re-check after the await: if the operator sent a message, clicked New,
      // or a turn started streaming while the transcript was loading, abandon
      // the resume rather than clobbering the live thread.
      if (streaming || interactionSeq !== seq) return;
      log.innerHTML = "";
      for (const m of msgs) {
        const variant = m.role === "user" ? "user" : m.role === "tool" ? "tool" : "assistant";
        addBubble(variant, m.role).textContent = m.text || "";
      }
      conversationId = id;
      sessionId = null;
      if (opts.onConversation) opts.onConversation(conversationId, agentName);
      // Bind the picker to the thread's original agent so the next turn
      // continues with it (the server rejects a mismatch regardless).
      const matched = selectAgentByName(agentName);
      if (!matched && agentName) {
        addBubble("note", "note").textContent =
          'the agent "' + agentName + '" for this conversation is no longer available; ' +
          "pick an agent to continue.";
      }
      if (historyPanel) historyPanel.hidden = true;
      if (input) input.focus();
    }

    if (historyToggle && historyPanel) {
      historyToggle.addEventListener("click", function () {
        historyPanel.hidden = !historyPanel.hidden;
        if (!historyPanel.hidden) loadHistory();
      });
    }

    // Let an external caller (the docked panel) mark a user interaction so an
    // in-flight cross-page resume won't clobber content the caller just rendered
    // into the log — e.g. one-shot review findings. Bumps the same
    // generation guard the resume re-checks after its await.
    root.assistNoteInteraction = function () {
      interactionSeq += 1;
    };

    // Cross-page continuity (docked panel): replay the last thread so the
    // assistant "follows" the operator across a full-page navigation. The server
    // still owner-scopes and agent-binds the resume.
    if (opts.resume && opts.resume.id) {
      resumeConversation(opts.resume.id, opts.resume.agentName);
    }
  }

  // Expose for the docked panel, which hydrates a block then inits it.
  window.initAssistChat = initAssistChat;

  // Auto-init any server-rendered (already-hydrated) block, e.g. the immersive
  // /agent_chat page. Loaded with `defer`, so the DOM is parsed.
  document.querySelectorAll("[data-agent-chat]").forEach(initAssistChat);
})();
