/* Governed "Try this tool" form enhancement.
 *
 * Vanilla JS (no framework), same house style as palette.js. The tool
 * drawer (`templates/tools_drawer.html`) ships:
 *   - a <script type="application/json" id="try-schema"> with the tool's
 *     JSON-Schema `inputSchema`,
 *   - a <form data-try-tool> carrying hidden csrf/server/tool fields, a
 *     raw-JSON <textarea name="arguments"> (the no-JS fallback + the value
 *     carrier), and an empty `#try-inputs` container.
 *
 * This script progressively enhances the form: it reads the schema and
 * renders one typed input per top-level property (text / number /
 * checkbox / <select> for enums, and a per-field JSON textarea for
 * nested object/array properties). On submit it assembles the values
 * into a single JSON object, writes it into the `arguments` textarea,
 * and lets htmx POST the form to `/tools/try`. If the schema is missing
 * or unparseable, the raw-JSON textarea stays visible and nothing is
 * enhanced — the operator just types JSON.
 *
 * The drawer is loaded as an htmx fragment, so we (re)initialise on
 * `htmx:afterSwap` as well as initial DOMContentLoaded, guarding each
 * form with a `data-try-init` flag so we never wire one twice.
 *
 * Security note: this is pure UX. Authorisation, the high-risk confirm
 * guard, argument validation, and audit all happen server-side in
 * `tools_try`; a tampered-with form can at most produce a different JSON
 * body, which the governed invocation pipeline validates exactly as it
 * would a real MCP client's call. */
(function () {
  "use strict";

  function firstType(spec) {
    var t = spec && spec.type;
    if (Array.isArray(t)) {
      for (var i = 0; i < t.length; i++) {
        if (t[i] && t[i] !== "null") return t[i];
      }
      return t[0] || "string";
    }
    return t || "string";
  }

  function labelFor(name, spec, required) {
    var label = document.createElement("label");
    label.className = "try-field";
    var span = document.createElement("span");
    span.className = "try-field__name";
    span.textContent = name + (required ? " *" : "");
    label.appendChild(span);
    if (spec && spec.description) {
      label.title = spec.description;
    }
    return label;
  }

  function buildField(name, spec, required) {
    var ty = firstType(spec);
    var label = labelFor(name, spec, required);
    var input;
    if (spec && Array.isArray(spec.enum)) {
      input = document.createElement("select");
      if (!required) {
        var blank = document.createElement("option");
        blank.value = "";
        blank.textContent = "—";
        input.appendChild(blank);
      }
      spec.enum.forEach(function (v) {
        var opt = document.createElement("option");
        opt.value = String(v);
        opt.textContent = String(v);
        input.appendChild(opt);
      });
    } else if (ty === "boolean") {
      input = document.createElement("input");
      input.type = "checkbox";
    } else if (ty === "number" || ty === "integer") {
      input = document.createElement("input");
      input.type = "number";
      if (ty === "integer") input.step = "1";
    } else if (ty === "object" || ty === "array") {
      input = document.createElement("textarea");
      input.rows = 3;
      input.className = "mono";
      input.placeholder = ty === "array" ? "[ ... ]" : "{ ... }";
      input.dataset.json = "true";
    } else {
      input = document.createElement("input");
      input.type = "text";
    }
    input.dataset.field = name;
    input.dataset.ty = ty;
    label.appendChild(input);
    return label;
  }

  // Read one rendered field back into a JS value. Returns
  // { include: bool, value: any } or throws on invalid JSON.
  function readField(input) {
    var ty = input.dataset.ty;
    if (ty === "boolean") {
      return { include: true, value: input.checked };
    }
    var raw = input.value.trim();
    if (raw === "") return { include: false };
    if (input.dataset.json === "true") {
      return { include: true, value: JSON.parse(raw) };
    }
    if (ty === "number" || ty === "integer") {
      var n = Number(raw);
      if (Number.isNaN(n)) throw new Error(input.dataset.field + ": not a number");
      return { include: true, value: n };
    }
    return { include: true, value: raw };
  }

  function init(form) {
    if (!form || form.dataset.tryInit === "1") return;
    var schemaEl = form.parentNode.querySelector("#try-schema");
    var inputsEl = form.querySelector("#try-inputs");
    var textarea = form.querySelector("#try-arguments");
    var errEl = form.querySelector("#try-error");
    if (!schemaEl || !inputsEl || !textarea) return;

    var schema;
    try {
      schema = JSON.parse(schemaEl.textContent || "{}");
    } catch (e) {
      // Unparseable schema: leave the raw-JSON textarea as the input.
      return;
    }
    var props = (schema && schema.properties) || {};
    var names = Object.keys(props);
    var required = (schema && schema.required) || [];

    // Mark initialised up front so a second afterSwap doesn't double-wire.
    form.dataset.tryInit = "1";

    // No properties ⇒ argument-less tool. Hide the textarea; an empty
    // `arguments` posts as a no-arg call.
    if (names.length === 0) {
      textarea.hidden = true;
      return;
    }

    names.forEach(function (name) {
      inputsEl.appendChild(buildField(name, props[name], required.indexOf(name) !== -1));
    });
    inputsEl.hidden = false;
    // The typed inputs are now the source of truth; hide the raw textarea
    // (it still carries the assembled value to the server on submit).
    textarea.hidden = true;

    form.addEventListener("submit", function () {
      // Assemble on submit. htmx fires its POST after our handler runs, so
      // writing textarea.value here lands in the request body. On a JSON
      // parse error we surface it and cancel the submit (htmx included).
      if (errEl) errEl.textContent = "";
      var obj = {};
      var fields = inputsEl.querySelectorAll("[data-field]");
      try {
        for (var i = 0; i < fields.length; i++) {
          var r = readField(fields[i]);
          if (r.include) obj[fields[i].dataset.field] = r.value;
        }
      } catch (e) {
        if (errEl) errEl.textContent = String(e.message || e);
        // Cancel both the native submit and htmx's.
        arguments[0].preventDefault();
        arguments[0].stopImmediatePropagation();
        return;
      }
      textarea.value = JSON.stringify(obj);
    });
  }

  function initAll(root) {
    var scope = root && root.querySelectorAll ? root : document;
    var forms = scope.querySelectorAll("form[data-try-tool]");
    for (var i = 0; i < forms.length; i++) init(forms[i]);
    // htmx swaps can target the form itself; handle that case too.
    if (root && root.matches && root.matches("form[data-try-tool]")) init(root);
  }

  document.addEventListener("DOMContentLoaded", function () {
    initAll(document);
  });
  document.body.addEventListener("htmx:afterSwap", function (e) {
    initAll(e.target);
  });
})();
