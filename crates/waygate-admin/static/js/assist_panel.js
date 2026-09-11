// Docked Contextual Assistant panel. One drawer mounted in layout.html,
// on EVERY page, for any authenticated dashboard user. This file owns the shell:
// toggling, the Ctrl/Cmd-J shortcut, and persistence of open/closed state + the
// active conversation across full-page navigation (sessionStorage). The chat
// itself is the shared assist_chat.js client, hydrated on first open from
// GET /agent_chat/bootstrap (agents + session CSRF + tenant-correct stream URL).
(function () {
  "use strict";

  const panel = document.getElementById("gw-assist-panel");
  const toggle = document.querySelector("[data-assist-toggle]");
  if (!panel || !toggle) return; // not an authenticated dashboard page

  // The immersive /agent_chat page already shows the chat full-width; don't offer
  // a redundant docked copy there.
  if (location.pathname.replace(/\/+$/, "").endsWith("/agent_chat")) {
    toggle.hidden = true;
    return;
  }

  const OPEN_KEY = "gw_assist_open";
  const CONVO_KEY = "gw_assist_convo";
  const chatRoot = panel.querySelector("[data-agent-chat]");
  const closeBtn = panel.querySelector("[data-assist-close]");
  let hydrated = false;
  // The current page's anchor scheme (from /assist/context), so a finding can
  // point back at its row on the page. null ⇒ no anchoring for this page.
  let pageAnchor = null;

  function readConvo() {
    try {
      return JSON.parse(sessionStorage.getItem(CONVO_KEY) || "null");
    } catch (_) {
      return null;
    }
  }
  function storeConvo(id, agentName) {
    try {
      sessionStorage.setItem(CONVO_KEY, JSON.stringify({ id: id, agentName: agentName }));
    } catch (_) {}
  }
  function forgetConvo() {
    try {
      sessionStorage.removeItem(CONVO_KEY);
    } catch (_) {}
  }

  // Tenant-aware admin base: the body carries `data-tenant-slug` on tenant-scoped
  // URLs (set in layout.html); fall back to the legacy un-prefixed mount.
  function adminBase() {
    const slug = document.body.dataset.tenantSlug;
    return slug ? "/admin/t/" + slug : "/admin";
  }

  // The nav suffix of the current page (e.g. "/policies"), used to ground the
  // agent in the operator's page (and the /assist/context lookup).
  function pageSuffix() {
    const base = adminBase();
    let p = location.pathname;
    if (p.startsWith(base)) p = p.slice(base.length);
    return p || "/";
  }

  function setUnavailable(msg) {
    const title = chatRoot.querySelector("[data-assist-empty-title]");
    const body = chatRoot.querySelector("[data-assist-empty-body]");
    if (title) title.textContent = "Assistant unavailable";
    if (body) body.textContent = msg;
    const form = chatRoot.querySelector("[data-chat-form]");
    if (form) form.querySelectorAll("textarea, button").forEach((e) => (e.disabled = true));
  }

  async function hydrate() {
    if (hydrated) return;
    hydrated = true;
    let cfg = null;
    try {
      const resp = await fetch(adminBase() + "/agent_chat/bootstrap", {
        headers: { Accept: "application/json" },
      });
      if (resp.ok) cfg = await resp.json();
    } catch (_) {}

    if (!cfg) return setUnavailable("The assistant is unavailable right now.");
    if (!cfg.configured) return setUnavailable("No agents are configured on this gateway.");
    if (!cfg.inference_ready) return setUnavailable("Inference is not configured on this gateway.");
    if (!cfg.agents || !cfg.agents.length) {
      return setUnavailable("No enabled chat agents. Create one on the Agents tab.");
    }

    const sel = chatRoot.querySelector("[data-agent-select]");
    sel.innerHTML = "";
    for (const a of cfg.agents) {
      const o = document.createElement("option");
      o.value = a.id;
      o.textContent = a.name;
      o.setAttribute("data-model", a.model || "");
      sel.appendChild(o);
    }
    // Recent (resume) is only meaningful when a conversation store is wired.
    const recent = chatRoot.querySelector("[data-history-toggle]");
    if (recent && cfg.history_enabled) recent.hidden = false;

    chatRoot.setAttribute("data-page", pageSuffix());
    chatRoot.setAttribute("data-stream-url", cfg.stream_url);
    chatRoot.setAttribute("data-csrf", cfg.csrf || "");
    if (window.initAssistChat) {
      window.initAssistChat(chatRoot, {
        onConversation: storeConvo,
        onClear: forgetConvo,
        resume: readConvo(),
      });
    }
    // The composer shipped disabled (no native-submit before the handler was
    // installed); enable it now that init wired the submit path.
    const input = chatRoot.querySelector("[data-chat-input]");
    const send = chatRoot.querySelector("[data-chat-send]");
    if (input) {
      input.disabled = false;
      input.focus();
    }
    if (send) send.disabled = false;

    loadChips();
  }

  // Per-page suggested-action chips: fetch the current page's context
  // and render clickable chips above the transcript. A OneShotReview chip with a
  // resolved agent runs the governed review driver and renders structured
  // findings in the panel; any other chip seeds the composer.
  async function loadChips() {
    const wrap = chatRoot.querySelector("[data-assist-chips]");
    const input = chatRoot.querySelector("[data-chat-input]");
    if (!wrap) return;
    let ctx = null;
    try {
      const resp = await fetch(adminBase() + "/assist/context?page=" + encodeURIComponent(pageSuffix()), {
        headers: { Accept: "application/json" },
      });
      if (resp.ok) ctx = await resp.json();
    } catch (_) {}
    pageAnchor = (ctx && ctx.anchor) || null;
    if (!ctx || !Array.isArray(ctx.actions) || !ctx.actions.length) return;
    wrap.innerHTML = "";
    for (const a of ctx.actions) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "assist-chip";
      chip.textContent = a.label || a.id;
      chip.addEventListener("click", () => {
        if (a.action === "one_shot_review" && a.agent_id) {
          runReview(a.agent_kind, a.agent_id, chip);
        } else if (input) {
          input.value = a.action === "seed_prompt" && a.text ? a.text : a.label || "";
          input.focus();
        }
      });
      wrap.appendChild(chip);
    }
    wrap.hidden = false;
  }

  function reviewDriverUrl(kind) {
    if (kind === "policy_review") return adminBase() + "/agent_review/policy";
    if (kind === "classification") return adminBase() + "/classification_audit/run";
    return null;
  }

  function severityChipClass(sev) {
    const s = (sev || "").toLowerCase();
    if (s === "critical") return "chip chip--bad";
    if (s === "warn" || s === "warning") return "chip chip--warn";
    return "chip";
  }

  // The chat hand-off text for a finding's "Refine in chat" (mirrors the
  // standalone review page's prefill, but seeds THIS panel's composer).
  function prefillForFinding(f) {
    const lines = [];
    const where = f.policy_id ? "`" + f.policy_id + "`" : "the reviewed set";
    lines.push("Regarding " + where + " — " + (f.title || "a review finding") + ".");
    if (f.detail) lines.push(f.detail);
    if (f.recommendation) lines.push("Suggested fix: " + f.recommendation);
    lines.push("Help me decide whether and how to address this.");
    return lines.join("\n");
  }

  // Map a finding to its DOM element on the current page using the page's anchor
  // scheme. Returns null when the page has no scheme, the finding has no
  // id, the element isn't in the DOM (e.g. a different sub-tab is showing), or
  // the row is present but not actually visible — filtered out via [hidden] or
  // inside a collapsed accordion. In all those cases the caller
  // omits the "Show on page" affordance rather than offer a no-op scroll.
  function anchorElementFor(f) {
    if (!pageAnchor || !f || !f.policy_id) return null;
    let elId = null;
    if (pageAnchor === "policy_id") {
      elId = "policy-" + f.policy_id;
    } else if (pageAnchor === "tool_fq_name") {
      // policy_id is the canonical "server.tool"; the row id is "tool-" + that
      // verbatim (no split), so a dotted server name stays unambiguous — the
      // template builds the same id. getElementById handles dotted ids fine.
      elId = "tool-" + f.policy_id;
    }
    const el = elId ? document.getElementById(elId) : null;
    // offsetParent is null for display:none elements and any descendant of one
    // (the `[hidden]` filter and collapsed accordion both use display:none).
    return el && el.offsetParent !== null ? el : null;
  }

  function flashElement(el) {
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.add("assist-anchor-flash");
    setTimeout(() => el.classList.remove("assist-anchor-flash"), 1600);
  }

  function logBubble(log, variant, role) {
    const empty = log.querySelector("[data-chat-empty]");
    if (empty) empty.remove();
    const wrap = document.createElement("div");
    wrap.className = "chat-msg chat-msg--" + variant;
    if (role) {
      const who = document.createElement("div");
      who.className = "chat-msg__role";
      who.textContent = role;
      wrap.appendChild(who);
    }
    const body = document.createElement("div");
    body.className = "chat-msg__body";
    wrap.appendChild(body);
    log.appendChild(wrap);
    return body;
  }

  // Run a one-shot review driver (governed, admin-gated server-side) and render
  // its structured findings into the transcript. Each finding offers a
  // "Refine in chat" that seeds THIS composer — no navigation, same thread.
  async function runReview(kind, agentId, chip) {
    const url = reviewDriverUrl(kind);
    if (!url) return;
    // Cancel any in-flight cross-page resume so it can't erase the findings we
    // are about to render into the log.
    if (chatRoot.assistNoteInteraction) chatRoot.assistNoteInteraction();
    const log = chatRoot.querySelector("[data-chat-log]");
    const input = chatRoot.querySelector("[data-chat-input]");
    const csrf = chatRoot.getAttribute("data-csrf") || "";
    if (chip) chip.disabled = true;
    const status = logBubble(log, "note", "review");
    status.textContent = "Running the review… (one governed model call)";
    log.scrollTop = log.scrollHeight;

    let body = null;
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ csrf: csrf, agent_id: agentId }),
      });
      if (resp.ok) {
        body = await resp.json();
      } else {
        let msg = "HTTP " + resp.status;
        try {
          const j = await resp.json();
          if (j && j.error && j.error.message) msg = j.error.message;
        } catch (_) {}
        status.textContent = "Review failed: " + msg;
        if (chip) chip.disabled = false;
        return;
      }
    } catch (e) {
      status.textContent = "Review failed: " + e;
      if (chip) chip.disabled = false;
      return;
    }

    const findings = (body && body.findings) || [];
    status.textContent = findings.length
      ? findings.length +
        (findings.length === 1 ? " finding" : " findings") +
        " from " + (body.agent || "the reviewer") + ":"
      : "No findings — the reviewer flagged nothing.";

    for (const f of findings) {
      const card = document.createElement("div");
      card.className = "review-finding";
      const head = document.createElement("div");
      head.className = "review-finding__head";
      const sev = document.createElement("span");
      sev.className = severityChipClass(f.severity);
      sev.textContent = f.severity || "info";
      head.appendChild(sev);
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
      // Point back at the offending row on the page, when it's anchorable.
      const target = anchorElementFor(f);
      if (target) {
        const show = document.createElement("button");
        show.type = "button";
        show.className = "btn btn--sm";
        show.style.marginRight = "6px";
        show.textContent = "Show on page →";
        show.addEventListener("click", () => flashElement(target));
        card.appendChild(show);
      }
      const refine = document.createElement("button");
      refine.type = "button";
      refine.className = "btn btn--sm";
      refine.textContent = "Refine in chat →";
      refine.addEventListener("click", () => {
        if (input) {
          input.value = prefillForFinding(f);
          input.focus();
        }
      });
      card.appendChild(refine);
      log.appendChild(card);
    }
    log.scrollTop = log.scrollHeight;
    if (chip) chip.disabled = false;
  }

  function isOpen() {
    return panel.getAttribute("data-open") === "true";
  }

  function setOpen(open) {
    panel.setAttribute("data-open", open ? "true" : "false");
    panel.setAttribute("aria-hidden", open ? "false" : "true");
    // `inert` when closed keeps the (visually hidden) controls out of the tab
    // order and the a11y tree on every page.
    if (open) panel.removeAttribute("inert");
    else panel.setAttribute("inert", "");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    try {
      sessionStorage.setItem(OPEN_KEY, open ? "1" : "0");
    } catch (_) {}
    if (open) {
      hydrate();
      const input = chatRoot.querySelector("[data-chat-input]");
      if (input && !input.disabled) input.focus();
    }
  }

  toggle.addEventListener("click", () => setOpen(!isOpen()));
  if (closeBtn) closeBtn.addEventListener("click", () => setOpen(false));

  // On-object trigger hook: an on-page affordance (e.g. a header button on
  // a curated page) can open the docked assistant so its contextual chips are
  // right there. Also drives the [data-assist-open] buttons wired below.
  window.gwAssistOpen = () => setOpen(true);
  document
    .querySelectorAll("[data-assist-open]")
    .forEach((b) => b.addEventListener("click", () => setOpen(true)));

  document.addEventListener("keydown", (ev) => {
    if ((ev.ctrlKey || ev.metaKey) && (ev.key === "j" || ev.key === "J")) {
      ev.preventDefault();
      setOpen(!isOpen());
    } else if (ev.key === "Escape" && isOpen()) {
      setOpen(false);
    }
  });

  // Restore the open state across full-page navigation so the assistant "stays
  // with" the operator as they move between pages.
  try {
    if (sessionStorage.getItem(OPEN_KEY) === "1") setOpen(true);
  } catch (_) {}
})();
