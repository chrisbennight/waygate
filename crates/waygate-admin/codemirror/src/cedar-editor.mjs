// Cedar editor — the vendored CodeMirror 6 entry point.
//
// Built into../static/js/codemirror.bundle.js by build.sh (esbuild, IIFE,
// global `CedarEditor`). Progressive enhancement over the existing
// `<textarea name="content">`: the textarea stays the form field, CM6 mounts
// over it and syncs every edit back to it, so htmx form posts and no-JS both
// keep working. Syntax colors come from CSS classes themed in components.css
// against design tokens — NO color literals here.

import { EditorState } from "@codemirror/state";
import {
  EditorView,
  keymap,
  lineNumbers,
  highlightActiveLine,
  highlightActiveLineGutter,
  drawSelection,
} from "@codemirror/view";
import {
  defaultKeymap,
  history,
  historyKeymap,
  indentWithTab,
} from "@codemirror/commands";
import {
  StreamLanguage,
  syntaxHighlighting,
  HighlightStyle,
  bracketMatching,
  indentOnInput,
} from "@codemirror/language";
import { linter, lintGutter } from "@codemirror/lint";
import { tags as t } from "@lezer/highlight";

// Cedar keywords (cedar-policy grammar). Annotations (`@id`, `@layer`, …) and
// types (capitalized: `Action`, `Tool`, namespaces) are handled separately.
const KEYWORDS = new Set([
  "permit",
  "forbid",
  "when",
  "unless",
  "principal",
  "action",
  "resource",
  "context",
  "in",
  "has",
  "like",
  "is",
  "if",
  "then",
  "else",
  "true",
  "false",
]);

// A small hand-written Cedar tokenizer (no external grammar dep keeps the
// bundle lean). It only classifies tokens for coloring — the authoritative
// parse + validation is server-side (waygate-authz). Strings and `//` comments
// are consumed wholesale so a `;`/`@id`/keyword inside them isn't mis-colored,
// matching the server segmenter's lexical model.
const cedar = StreamLanguage.define({
  token(stream) {
    if (stream.eatSpace()) return null;
    if (stream.match("//")) {
      stream.skipToEnd();
      return "comment";
    }
    if (stream.match(/@[A-Za-z_]\w*/)) return "meta"; // @id, @layer, @description…
    if (stream.peek() === '"') {
      stream.next();
      let escaped = false;
      while (!stream.eol()) {
        const ch = stream.next();
        if (ch === '"' && !escaped) break;
        escaped = ch === "\\" && !escaped;
      }
      return "string";
    }
    if (stream.match(/\d+/)) return "number";
    const word = stream.match(/[A-Za-z_]\w*/);
    if (word) {
      if (KEYWORDS.has(word[0])) return "keyword";
      if (/^[A-Z]/.test(word[0])) return "typeName";
      return "variableName";
    }
    if (stream.match(/==|!=|<=|>=|&&|\|\||::/)) return "operator";
    stream.next();
    return null;
  },
  languageData: { commentTokens: { line: "//" } },
});

// Map highlight tags to CLASS names only — colors are assigned in
// components.css from design tokens, so the editor follows the Day/Night
// ledger theme and adds no color literals to a JS asset.
const cedarHighlight = HighlightStyle.define([
  { tag: t.comment, class: "cm-cedar-comment" },
  { tag: t.string, class: "cm-cedar-string" },
  { tag: t.keyword, class: "cm-cedar-keyword" },
  { tag: t.meta, class: "cm-cedar-annotation" },
  { tag: t.number, class: "cm-cedar-number" },
  { tag: t.typeName, class: "cm-cedar-type" },
  { tag: t.variableName, class: "cm-cedar-var" },
  { tag: t.operator, class: "cm-cedar-operator" },
]);

// Find the 1-based line of the policy whose `@id("<id>")` annotation appears,
// so the editor can scroll to a deep-linked policy (the `?focus=` jump).
function findFocusLine(doc, id) {
  const needle = '@id("' + id + '")';
  for (let i = 1; i <= doc.lines; i++) {
    if (doc.line(i).text.includes(needle)) return i;
  }
  return null;
}

// Convert a server 1-based (line, col) to a CM6 absolute document position,
// clamped into the document / line so a stale diagnostic can't throw.
function lineColToPos(doc, line, col) {
  const ln = Math.max(1, Math.min(line || 1, doc.lines));
  const lineObj = doc.line(ln);
  const pos = lineObj.from + Math.max(0, (col || 1) - 1);
  return Math.min(pos, lineObj.to);
}

// As-you-type Cedar validation: a debounced linter that POSTs the
// document to the server's stateless diagnostics endpoint — the SAME parser
// production enforces — and maps {line,col,…,message} to gutter markers. On any
// network/server error it yields no markers (never blocks editing). The CSRF
// token is required because the endpoint is an admin POST.
function cedarLinter(lintUrl, csrf) {
  return linter(
    async (view) => {
      const body = new URLSearchParams();
      body.set("csrf", csrf || "");
      body.set("content", view.state.doc.toString());
      let data;
      try {
        const resp = await fetch(lintUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: body.toString(),
          credentials: "same-origin",
        });
        if (!resp.ok) return [];
        data = await resp.json();
      } catch (e) {
        return [];
      }
      const doc = view.state.doc;
      return ((data && data.diagnostics) || []).map((d) => {
        const from = lineColToPos(doc, d.line, d.col);
        let to = lineColToPos(doc, d.end_line, d.end_col);
        if (to <= from) to = Math.min(from + 1, doc.length); // ensure a visible range
        return { from, to, severity: "error", message: d.message };
      });
    },
    { delay: 400 },
  );
}

/**
 * Mount CM6 over a textarea as progressive enhancement.
 *
 * @param {HTMLTextAreaElement} textarea the form field (stays the source of truth for posts)
 * @param {{focus?: string, lintUrl?: string, csrf?: string}} [opts]
 *   focus: scroll to the policy with this @id;
 *   lintUrl + csrf: enable as-you-type validation against that endpoint.
 * @returns {{view: EditorView, focusedLine: number|null}|null}
 */
export function init(textarea, opts = {}) {
  if (!textarea || textarea.dataset.cmMounted === "1") return null;
  textarea.dataset.cmMounted = "1";

  const syncToTextarea = EditorView.updateListener.of((u) => {
    if (u.docChanged) {
      textarea.value = u.state.doc.toString();
      // Let any listeners (e.g. the debounced validator) react to edits.
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });

  const extensions = [
    lineNumbers(),
    highlightActiveLine(),
    highlightActiveLineGutter(),
    drawSelection(),
    history(),
    indentOnInput(),
    bracketMatching(),
    cedar,
    syntaxHighlighting(cedarHighlight),
    EditorView.lineWrapping,
    keymap.of([indentWithTab, ...defaultKeymap, ...historyKeymap]),
    syncToTextarea,
  ];
  // As-you-type validation: only when a lint endpoint is supplied.
  if (opts.lintUrl) {
    extensions.push(lintGutter(), cedarLinter(opts.lintUrl, opts.csrf));
  }

  const view = new EditorView({
    state: EditorState.create({ doc: textarea.value, extensions }),
  });

  // Keep the textarea in the form (CM6 writes through to it) but hide it.
  textarea.style.display = "none";
  textarea.setAttribute("aria-hidden", "true");
  textarea.parentNode.insertBefore(view.dom, textarea.nextSibling);
  view.dom.classList.add("cm-cedar");

  let focusedLine = null;
  if (opts.focus) {
    focusedLine = findFocusLine(view.state.doc, opts.focus);
    if (focusedLine != null) {
      const pos = view.state.doc.line(focusedLine).from;
      view.dispatch({
        selection: { anchor: pos },
        scrollIntoView: true,
      });
      view.focus();
    }
  }
  return { view, focusedLine };
}
