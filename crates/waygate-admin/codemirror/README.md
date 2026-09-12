# Cedar editor — vendored CodeMirror 6 bundle

This directory is **build tooling**, not a shipped asset. It produces the single
committed artifact

    ../static/js/codemirror.bundle.js

which is the only file that reaches the runtime / Docker image (the Dockerfile
copies `crates/waygate-admin/static/`, not this directory). The repo stays
build-step-free at deploy time — exactly the same posture as
`static/js/htmx.min.js`: a pre-built, vendored bundle committed to git.

## Why vendored + pre-built

The dashboard stack is askama + htmx + vanilla JS with **no bundler, no CDN, no
CSP, no npm at deploy time** (see `docs/agents/dashboard-ui.md`). CodeMirror 6 is
the one place a real editor is justified, so we build it once locally with
esbuild and commit the output, mirroring how htmx is vendored.

## What's in the bundle

- CodeMirror 6 core: `@codemirror/state`, `@codemirror/view`,
  `@codemirror/commands`, `@codemirror/language` (line numbers, history,
  bracket matching, active-line highlight, default keymap).
- A hand-written Cedar `StreamLanguage` mode (`src/cedar-editor.mjs`) —
  keywords, `@id`/`@layer`/… annotations, strings, `//` comments, numbers,
  types, operators. No external grammar dependency.
- A `HighlightStyle` that assigns **CSS classes** (`cm-cedar-*`), never colors —
  the palette lives in `static/css/components.css` against `tokens.css` design
  tokens, so the editor follows the selected dashboard theme.
- `@codemirror/lint` — the as-you-type validation gutter. A
  debounced linter POSTs the document to the server's stateless diagnostics
  endpoint (`POST /policy_bundles/diagnostics` → `waygate_authz::validate_diagnostics`,
  the same Cedar parser publish enforces, incl. duplicate-`@id` rejection) and
  maps the returned `{line, col, …, message}` to gutter markers. Network/server
  errors yield no markers (never block editing). The error squiggle + tooltip
  border are themed via `--deny` in `components.css`.

The vendored CodeMirror core carries its own compiled-in default theme colors
(cursor, selection, bracket matching, …) inside the bundle. The Cedar mode and
highlight we author add no color literals, and `components.css` overrides CM6's
**visible** chrome — editor surface, gutters, cursor, selection, active line,
and bracket match/mismatch — to the `--syntax-*` / ledger tokens, so what the
operator sees routes through the theme. (`static/js/*` isn't covered by the
`style_tokens` discipline test; the CSS that themes the editor is.)

It exposes a single global, `CedarEditor.init(textarea, opts)`, which mounts CM6
over an existing `<textarea>` as progressive enhancement (the textarea stays the
form field and CM6 syncs every edit back to it, so htmx posts and no-JS both keep
working). `opts`:

- `focus` — scroll to the policy whose `@id("…")` matches (the `?focus=` deep-link jump).
- `lintUrl` + `csrf` — enable the as-you-type lint gutter against that diagnostics
  endpoint (omit to mount without validation).

Both the whole-bundle editor (`/policy_bundles`) and the inline per-policy editors
on the Policies pane (`/policies`) call `init` over their textareas.

## Rebuild

Versions are pinned in `package.json` + `package-lock.json`, so the build is
reproducible:

    cd crates/waygate-admin/codemirror
    npm ci          # or: npm install
    ./build.sh      # esbuild → ../static/js/codemirror.bundle.js

`node_modules/` is git-ignored; `package-lock.json` is committed. Bump a
CodeMirror version by editing `package.json`, re-running `npm install` (updates
the lockfile), then `./build.sh`, and commit the new lockfile + bundle together.
