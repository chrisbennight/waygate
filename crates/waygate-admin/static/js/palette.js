/* Cmd-K command palette.
 *
 * Vanilla JS (no Alpine / no framework). Opens on Cmd-K / Ctrl-K,
 * fetches results from a server-side `/admin[/t/<tenant>]/search?q=...`
 * endpoint that returns `{ query, items: [...], truncated }`. Selecting a
 * row navigates `window.location.href` to the row's `href`.
 *
 * Lives in `static/js/palette.js`; the overlay markup is in
 * `templates/layout.html`. The layout writes the active tenant slug into
 * `<body data-tenant-slug="...">` so this script can build the right
 * search URL without parsing `window.location`.
 *
 * Keyboard contract:
 *   - Cmd-K / Ctrl-K       — toggle open
 *   - Esc                  — close
 *   - ArrowDown / ArrowUp  — move selection
 *   - Enter                — navigate to selected
 *   - Click / Tap          — same as Enter on hovered row
 *
 * The fetch is debounced ~120ms so a fast typist doesn't generate one
 * round-trip per keystroke. The previous in-flight request is aborted
 * via `AbortController` so a slow earlier response can't overwrite a
 * fast later one (the classic "stale render" bug). */
(function () {
  "use strict";

  const overlay = document.getElementById("palette-overlay");
  if (!overlay) {
    // Layout wasn't rendered (e.g. login page); palette is dashboard-only.
    return;
  }
  const input = overlay.querySelector("[data-palette-input]");
  const list = overlay.querySelector("[data-palette-results]");
  const empty = overlay.querySelector("[data-palette-empty]");
  const truncated = overlay.querySelector("[data-palette-truncated]");
  if (!input || !list || !empty || !truncated) {
    // Defensive: layout drift would break the palette silently
    // otherwise. Log + bail so the page still works.
    console.error("palette: layout missing required elements");
    return;
  }

  // Derive the search endpoint from the body's tenant data attribute
  // (server-rendered) so it matches the mount the page itself was
  // served from. Falls back to legacy `/admin/search` when absent.
  function searchUrl(q) {
    const slug = document.body.dataset.tenantSlug;
    const base = slug ? `/admin/t/${encodeURIComponent(slug)}/search` : "/admin/search";
    return `${base}?q=${encodeURIComponent(q)}`;
  }

  let selectedIndex = 0;
  let items = [];
  let inflight = null; // AbortController for the current fetch
  let debounceTimer = null;

  function open() {
    overlay.hidden = false;
    overlay.dataset.open = "true";
    input.value = "";
    selectedIndex = 0;
    items = [];
    render({ items: [], truncated: false }, "");
    // Defer focus so the overlay is in the DOM render tree.
    requestAnimationFrame(() => input.focus());
    // Kick off an empty-query fetch so the catalogue is visible
    // immediately — operators don't need to type to see what's there.
    runQuery("");
  }

  function close() {
    overlay.dataset.open = "false";
    overlay.hidden = true;
    if (inflight) {
      inflight.abort();
      inflight = null;
    }
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
  }

  function toggle() {
    if (overlay.dataset.open === "true") {
      close();
    } else {
      open();
    }
  }

  // Cmd-K (Mac) / Ctrl-K (other) — toggle. Esc closes. The capture
  // phase ensures the palette intercepts the shortcut even when a
  // form input on the page has focus.
  document.addEventListener(
    "keydown",
    function (e) {
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        toggle();
        return;
      }
      if (e.key === "Escape" && overlay.dataset.open === "true") {
        e.preventDefault();
        close();
        return;
      }
      if (overlay.dataset.open !== "true") {
        return;
      }
      if (e.key === "ArrowDown") {
        e.preventDefault();
        selectedIndex = Math.min(items.length - 1, selectedIndex + 1);
        renderSelection();
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        selectedIndex = Math.max(0, selectedIndex - 1);
        renderSelection();
      } else if (e.key === "Enter") {
        e.preventDefault();
        const item = items[selectedIndex];
        if (item) {
          window.location.href = item.href;
        }
      }
    },
    true,
  );

  // Backdrop click closes (but not clicks inside the card).
  overlay.addEventListener("click", function (e) {
    if (e.target === overlay) {
      close();
    }
  });

  input.addEventListener("input", function () {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(function () {
      runQuery(input.value);
    }, 120);
  });

  function runQuery(q) {
    if (inflight) {
      inflight.abort();
    }
    inflight = new AbortController();
    fetch(searchUrl(q), {
      credentials: "same-origin",
      signal: inflight.signal,
      headers: { Accept: "application/json" },
    })
      .then((r) => r.json())
      .then((body) => {
        render(body, q);
      })
      .catch((err) => {
        // AbortError fires on every keystroke that supersedes an
        // in-flight fetch; that's expected, not a real error.
        if (err.name !== "AbortError") {
          console.error("palette: search failed", err);
        }
      });
  }

  function render(body, query) {
    items = body.items || [];
    selectedIndex = 0;
    truncated.hidden = !body.truncated;
    list.innerHTML = "";
    if (items.length === 0) {
      empty.hidden = false;
      empty.textContent = query
        ? `No matches for “${query}”.`
        : "Type to search pages and tenants.";
      return;
    }
    empty.hidden = true;
    for (let i = 0; i < items.length; i++) {
      list.appendChild(renderRow(items[i], i));
    }
    renderSelection();
  }

  function renderRow(item, i) {
    const li = document.createElement("li");
    li.className = "palette__row";
    li.dataset.index = String(i);
    li.setAttribute("role", "option");
    li.innerHTML =
      '<svg class="palette__icon" aria-hidden="true"><use href="/admin/static/lucide.svg#' +
      escapeHtmlAttr(item.icon || "search") +
      '"/></svg>' +
      '<span class="palette__label">' +
      escapeHtml(item.label) +
      "</span>" +
      (item.hint
        ? '<span class="palette__hint">' + escapeHtml(item.hint) + "</span>"
        : "") +
      '<span class="palette__category">' +
      escapeHtml(item.category || "") +
      "</span>";
    li.addEventListener("click", function () {
      window.location.href = item.href;
    });
    li.addEventListener("mouseenter", function () {
      selectedIndex = i;
      renderSelection();
    });
    return li;
  }

  function renderSelection() {
    const rows = list.querySelectorAll(".palette__row");
    rows.forEach((row, i) => {
      if (i === selectedIndex) {
        row.classList.add("palette__row--selected");
        row.setAttribute("aria-selected", "true");
        // Keep the selected row in view as keyboard nav moves
        // through the list.
        row.scrollIntoView({ block: "nearest" });
      } else {
        row.classList.remove("palette__row--selected");
        row.removeAttribute("aria-selected");
      }
    });
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;");
  }

  function escapeHtmlAttr(s) {
    // Same as escapeHtml — separate function name keeps intent
    // grep-able if we ever need a stricter attribute encoding (e.g.
    // SVG fragment identifier safe-list).
    return escapeHtml(s);
  }
})();
