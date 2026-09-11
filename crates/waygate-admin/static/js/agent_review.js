// Task-agent review UI — shared by Policy Review and
// Classification Audit. Runs the selected review agent via the card's
// data-run-url POST and renders its structured findings. Each finding offers a
// "Refine in chat" handoff that stashes the finding in sessionStorage (same-tab,
// never in the URL) and opens the interactive chat, which reads + clears it on
// load. Hand-rolled vanilla JS, matching the dashboard's posture.
(function () {
  "use strict";

  const root = document.querySelector("[data-agent-review]");
  if (!root) return;

  const runUrl = root.getAttribute("data-run-url");
  const chatUrl = root.getAttribute("data-chat-url");
  const csrf = root.getAttribute("data-csrf") || "";

  // sessionStorage key for the refine-in-chat handoff (must match assist_chat.js).
  const PREFILL_KEY = "gw_agent_chat_prefill";

  const agentEl = root.querySelector("[data-review-agent]");
  const runBtn = root.querySelector("[data-review-run]");
  const statusEl = root.querySelector("[data-review-status]");
  const findingsEl = root.querySelector("[data-review-findings]");

  // Map a model-supplied severity onto a chip modifier (default = neutral).
  function severityChip(sev) {
    const s = (sev || "").toLowerCase();
    if (s === "critical") return "chip chip--bad";
    if (s === "warn" || s === "warning") return "chip chip--warn";
    return "chip";
  }

  // Compose the chat hand-off text for a finding.
  function prefillFor(f) {
    const lines = [];
    const where = f.policy_id ? "`" + f.policy_id + "`" : "the reviewed set";
    lines.push("Regarding " + where + " — " + (f.title || "a review finding") + ".");
    if (f.detail) lines.push(f.detail);
    if (f.recommendation) lines.push("Suggested fix: " + f.recommendation);
    lines.push("Help me decide whether and how to address this.");
    return lines.join("\n");
  }

  function renderFindings(findings) {
    findingsEl.innerHTML = "";
    if (!findings.length) {
      const ok = document.createElement("p");
      ok.className = "review-empty";
      ok.textContent = "No findings — the reviewer flagged nothing.";
      findingsEl.appendChild(ok);
      return;
    }
    for (const f of findings) {
      const card = document.createElement("div");
      card.className = "review-finding";

      const head = document.createElement("div");
      head.className = "review-finding__head";
      const chip = document.createElement("span");
      chip.className = severityChip(f.severity);
      chip.textContent = f.severity || "info";
      head.appendChild(chip);
      const title = document.createElement("span");
      title.className = "review-finding__title";
      title.textContent = f.title || "(untitled finding)";
      head.appendChild(title);
      if (f.policy_id) {
        const pid = document.createElement("span");
        pid.className = "review-finding__policy";
        pid.textContent = f.policy_id;
        head.appendChild(pid);
      }
      card.appendChild(head);

      if (f.detail) {
        const d = document.createElement("p");
        d.className = "review-finding__detail";
        d.textContent = f.detail;
        card.appendChild(d);
      }
      if (f.recommendation) {
        const r = document.createElement("p");
        r.className = "review-finding__rec";
        r.textContent = "Recommendation: " + f.recommendation;
        card.appendChild(r);
      }

      // Refine-in-chat handoff: stash the finding in sessionStorage (same-tab,
      // same-origin — never in the URL, so it can't leak into browser history,
      // access logs, or referrers) and navigate to the chat, which
      // reads + clears it on load. href stays the plain chat URL so open-in-new-
      // tab still works (it just won't pre-fill — sessionStorage is per-tab).
      const a = document.createElement("a");
      a.className = "btn btn--sm";
      a.href = chatUrl;
      a.textContent = "Refine in chat →";
      a.addEventListener("click", () => {
        try {
          sessionStorage.setItem(PREFILL_KEY, prefillFor(f));
        } catch (_) {}
      });
      card.appendChild(a);

      findingsEl.appendChild(card);
    }
  }

  async function run() {
    const agentId = agentEl ? (agentEl.value || "").trim() : "";
    if (!agentId) {
      statusEl.textContent = "Pick an agent first.";
      return;
    }
    runBtn.disabled = true;
    findingsEl.innerHTML = "";
    statusEl.textContent = "Running the review… (one model call)";
    try {
      const resp = await fetch(runUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ csrf: csrf, agent_id: agentId }),
      });
      if (!resp.ok) {
        let msg = "HTTP " + resp.status;
        try {
          const j = await resp.json();
          if (j && j.error && j.error.message) msg = j.error.message;
        } catch (_) {}
        statusEl.textContent = "Review failed: " + msg;
        return;
      }
      const body = await resp.json();
      const findings = body.findings || [];
      statusEl.textContent =
        findings.length + (findings.length === 1 ? " finding" : " findings") +
        (body.agent ? " · " + body.agent : "");
      renderFindings(findings);
    } catch (e) {
      statusEl.textContent = "Network error: " + e;
    } finally {
      runBtn.disabled = false;
    }
  }

  if (runBtn) runBtn.addEventListener("click", run);
})();
