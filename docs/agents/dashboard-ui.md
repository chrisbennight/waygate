# Admin dashboard

How to add or change pages in the operator-facing dashboard at `/admin`.

Load this when touching anything under `crates/waygate-admin/templates/`,
`crates/waygate-admin/static/`, or page handlers in `crates/waygate-admin/src/`.

## Stack

- **Server-rendered HTML** via [askama](https://github.com/rinja-rs/askama) 0.16
  (compile-time-checked templates, struct-as-context).
- **htmx** for in-page partial swaps (table refresh after a mutation, infinite-
  scroll, drawer panels). The library is local at
  `static/js/htmx.min.js` — no CDN.
- **Vanilla JS** for the Cmd-K palette (~250 LoC including HTML escape +
  debounce + AbortController machinery) and sidebar collapse persistence
  (~75 LoC). Both are self-contained, no framework, no build step.
- **No SPA framework**, **no Alpine** as a default, **no bundler**. The
  asset surface stays grep-able and the build stays "cargo build."

Rationale: every dashboard interaction is one of (a) a full-page render, (b) an
htmx fragment swap of a small region, (c) a tiny client-side state machine
(palette toggle, collapse). None of these justify the bundle/runtime cost of a
framework. The cutoff lines for reaching for more JS live below.

## Design system

Follow the canonical [Waygate design language](../design.md) for identity,
typography, surfaces, icons, and accessibility. Apply it through the shared
`static/css/tokens.css`, `fonts.css`, `base.css`, and `components.css` rather than
creating page-specific visual rules.

- Define color and font literals only in `tokens.css` and `fonts.css`. Templates
  use CSS variables and shared classes, with no `<style>` blocks. The
  `style_tokens` tests enforce this for every template.
- Preserve `--font-display`, `--font-ui`, and `--font-mono` roles, self-hosted
  fonts, and numeric readability when updating the visual treatment.
- Keep decision states, cross-tenant warnings, focus, active navigation,
  unavailable data, and validation messages explicit. A brand accent is not an
  authorization result. Break-glass warnings must remain prominent.
- Review changed pages in both themes and at narrow widths, including keyboard
  use, reduced motion, and stable htmx updates. Current implementation values
  live in the stylesheets, not a duplicate table in this guide.

One layout footgun worth calling out: **`.card--table` sets `padding: 0`** so a
`<table>` (whose cells supply their own gutter) sits flush to the card edge.
Only put a table — or table-like flush content — in a `card--table`. A **form**
or other padded content nested in one renders flush to the card edge (inputs
lose their left gutter), which looks broken next to every normal `.card`
(`16px 20px` inset). The convention across the management pages
(rbac / federation / break-glass / api-key-profiles) is: the listing table goes
in a `card--table`, and the create/edit form goes in its **own** sibling
`<div class="card">`. Don't nest the form in the table-card.

## URL structure

Every dashboard page mounts at TWO paths:

- `/admin/<page>` — unprefixed paths.
- `/admin/t/<tenant>/<page>` — canonical, tenant-scoped. Sidebar nav, post-login
  redirect, and palette items all use this shape.

The same handler set serves both. The `tenant_scope_middleware` runs on the
prefixed mount only — it injects an `Extension<TenantContext>` into request
extensions. Page handlers extract `Option<Extension<TenantContext>>` and pass
it through to their template struct.

### Composing URLs

Use the helpers in `crate::tenant_ctx`:

- **In a Rust handler** (e.g. an auth redirect target): call
  `tenant_ctx::nav_url(ctx, "/foo")` — returns `/admin/t/<slug>/foo` when
  `ctx` is `Some`, else `/admin/foo`.
- **In an Askama template**: every layout-extending page struct embeds
  `chrome: PageChrome`, which carries
  `tenant_ctx` and exposes the single `nav_url`. Templates call
  `{{ self.chrome.nav_url("/foo") }}`. Pages that `{% include %}` a shared
  partial ALSO keep a one-line `fn nav_url` delegate forwarding to
  `self.chrome.nav_url` (the partial's `self.nav_url` must resolve on both
  the page and the standalone fragment struct).
- **In a fragment template** (e.g. `activity_rows.html`): the fragment struct
  carries `tenant_ctx` + a one-line `nav_url` delegate to
  `crate::tenant_ctx::nav_url`, populated by the fragment-rendering handler
  from `Option<Extension<TenantContext>>`. Fragments do NOT embed
  `PageChrome` — they render no layout. `scripts/check-page-chrome.sh`
  enforces that every `nav_url` outside `chrome.rs`/`tenant_ctx.rs` is a
  pure delegate.

What stays un-prefixed by design:

- `/admin/static/*` — assets are cross-tenant.
- `/admin/login`, `/admin/logout`, `/admin/auth/callback` — auth flow.
- `/admin/tenant-switch?tenant_slug=…` — the server-side endpoint that
  validates and 303s into the tenant home. Used by the sidebar selector
  form and the palette tenant-switch entries.

## Tenant selector + cross-tenant banner

The sidebar renders a tenant `<select>` on tenant-prefixed pages only (hidden
entirely on legacy `/admin/...`). Form action is `/admin/tenant-switch` — works
without JS via the `<noscript>` Switch button; JS users get a no-click
`onchange` submit. The selector list comes from `state.identity.tenants.list()` capped
at 50; if the active slug sorts past the cap, the loader displaces the last
visible row so the active option is always present.

The red cross-tenant banner appears when `url_tenant != principal.tenant`.
Gateway-admin operators acting on another tenant's data always see it; tenant
operators viewing their own scope never see it. The banner includes a "Back to
my tenant" link.

## Cmd-K command palette

The palette is the primary navigation primitive once the dashboard expands
beyond ~7-8 items. The sidebar destinations + in-page tab bars are the
secondary structure for operators who prefer mouse navigation.

- Backend: `crate::palette::router()` mounts `GET /search?q=<q>` inside
  `page_routes()` so it inherits both legacy and tenant-prefixed mounts. The
  handler returns `SearchResponse { query, items: [SearchItem...], truncated }`.
- Frontend: `static/js/palette.js` is a self-contained vanilla-JS module loaded
  by every layout-extending page. Cmd-K / Ctrl-K toggles; ESC closes;
  arrow-key + Enter navigates; click selects. 120ms debounce on input.
- Tenant awareness: the `<body data-tenant-slug="…">` attribute (server-
  rendered when `TenantContext` is `Some`) tells the JS which mount to fetch
  from, so search results' page hrefs come back already-prefixed.

### Adding palette items for a new page

Append to the producer list in `crate::palette::collect_items`:

- **Pages**: add a tuple to the `PAGES` const. Each item gets a hint string
  rendered as a second line.
- **Per-page navigations** (e.g. "Open Identities for alice-deploy",
  "Jump to API key alice-deploy"): query the relevant
  store and emit `SearchItem { category: "action", ... }` rows with
  `href` pointing at a server-side endpoint. Keep the endpoint **a
  read-only GET that navigates** — render a detail page, or 303 to one.
  Selecting a palette row triggers `window.location.href = href`, which
  is a top-level GET; CSRF protection isn't possible on that shape.

  **Palette rows MUST NOT mutate state.** "Revoke alice-deploy" doesn't
  belong in the palette; "Open alice-deploy (where you can revoke)"
  does. Any mutation continues to happen via the existing
  CSRF-protected `POST` from the destination page's form (see
  [Auth + CSRF](#auth--csrf)). If a future UX absolutely requires
  one-click action from the palette, it has to be a confirmation-page
  navigation (palette → confirm page → POST form), never a direct
  mutating GET — Lakera's playground is the closest precedent: palette
  navigates to a pre-filled state, then the operator clicks Submit.

## Sidebar destinations + tab bars

The sidebar groups its task destinations into three labeled sections:

- **Common** (cross-cutting governance for both backends): Overview /
  Activity / Access / Policy / Decisions.
- **MCP Gateway** (MCP-specific resources): Servers / Tools / Federation /
  Connect.
- **LLM Gateway** (provider-facing resources): Models / Credentials.

Settings stays section Common but is pinned to the foot. Each destination
has a distinct Lucide icon, and second-level pages render as an in-page
underline tab bar at the top of `<main>` — page URLs are unchanged, only
the chrome moved.

- Destinations + their tabs are declared in `DESTINATIONS` in
  `dashboard.rs` as `(section, label, default_suffix, icon, tabs)`. The
  consts are grouped in render order; add a page as a tab of the right
  destination, or a new single-page destination under the right section.
- `nav()` sets `NavGroup::section_header` to `Some(label)` on the FIRST
  destination of each section (in render order) and `None` on the rest, so
  the layout prints one muted header row per section. The row is a
  `role="heading" aria-level="2"` `<li>` (not `aria-hidden`) so assistive
  tech announces the grouping instead of seeing a flat link list. The
  bottom-pinned Settings entry is section Common but not the first Common
  destination, so it gets `None` and never re-prints the "Common" header at
  the foot.
- The active destination carries `aria-current="page"` on its sidebar
  link, and the active tab carries `aria-current="page"` in the tab bar.
- The Decisions entry carries the nav's one badge: `static/js/badge.js`
  fetches the pending count (change requests + pending skill reviews + active break-glass) from
  `GET /badge/decisions`, which caches per tenant for 30s server-side and
  degrades to "0" for non-admin sessions / absent stores / errors.
- The Decisions destination lands on the **merged Queue**
  (`dashboard_decisions`, `/decisions`): pending change requests, pending skill
  reviews, and active break-glass in one inbox. Change requests and break-glass
  have inline approve / deny / revoke forms that
  POST to queue-owned routes (`/decisions/changes/{id}/{approve,deny}`,
  `/decisions/break_glass/{id}/revoke`). Those routes are thin
  auth+CSRF+parse wrappers that reuse the SAME mutation cores as the
  per-surface pages (`change_requests::approve_and_execute_core`,
  `deny_core`, `break_glass::revoke_token_core`) and PRG back to
  `/decisions` — no mutation logic is duplicated. **The queue's sources
  are exactly the badge's** (pending CRs + pending skill reviews + active break-glass).
  Pending skill rows link to the exact content review on `/skills/review`.
  The inbox
  renders at most eight pending changes because it shows every captured param
  in full; when saturated it links to the paginated Change requests queue.
  Already-decided HITL approval grants stay on the Approvals tab — they aren't
  pending operator decisions.
- Add new Lucide icons by appending a `<symbol>` to `static/lucide.svg`.

The sidebar retains named destinations and a readable tenant selector on wide
screens. At phone widths it becomes a horizontally scrollable row of named
destinations below the tenant selector. The shared CSS owns the exact
breakpoints and spacing.

## Skills review

The Skills destination (`/skills`) is a searchable tenant-scoped review catalog.
`/skills/review` compares the candidate and approved contents and inventories
all supporting files. Source text is always escaped plain text. The comparison
layout stacks on narrow screens and uses the shared theme tokens. Decisions
reuse `skill_reviews::decide_core`, the same core registered by the control-plane
skill action executors. Decision history is committed with the review state;
the admin mutation recorder additionally emits the required evidence event.
See [distribution review](../skill-distribution-review.md).

## When to reach for more JS

| Pattern | Approach | Notes |
|---|---|---|
| CRUD table with inline edit | Pure htmx + askama | The happy path. |
| Server-paginated list with filters | Pure htmx | Use `hx-get` with `hx-trigger="change, search"`. |
| Drawer / detail panel | Pure htmx | `hx-target` on a fixed element; `hx-swap="innerHTML"`. |
| Cedar policy editor | **CodeMirror island** | Vendored CM6 bundle (`static/js/codemirror.bundle.js`, built from `crates/waygate-admin/codemirror/`) mounts over the editor textarea — Cedar syntax + line numbers, themed via `--syntax-*` tokens — with an **as-you-type lint gutter** (`POST /policy_bundles/diagnostics` → `waygate_authz::validate_diagnostics`, the same parser publish enforces). Editing is **per-policy**: `waygate_authz::segment` splits a bundle by `@id` so one policy can be edited/added/removed (`/policy_bundles/policy/*`), and the **Policies pane (`/policies`) hosts an inline editor per policy** (edit in place → Save creates a draft → land in the bundle editor's Publish / Preview impact). The one place a real editor is justified. See `crates/waygate-admin/codemirror/README.md` for the bundle. |

The default is "no JS until a feature needs it." Three existing vanilla-JS
modules (`palette.js`, `badge.js`, `try_tool.js`) are the precedent
— small, self-contained, no framework. `try_tool.js` is the "one
justified island": it builds typed inputs from a tool's JSON-Schema in the
detail drawer and assembles the `arguments` JSON for the governed
`POST /tools/try` call. It re-initialises on `htmx:afterSwap` (the drawer is
an htmx fragment) and is pure UX — every security check (admin scope, CSRF,
the high-risk confirm guard, argument validation, audit) is enforced
server-side in `dashboard::tools_try`, which routes through the same
`SharedInvocation` pipeline a real MCP client hits.

## SSE conventions (operational)

The HITL approval WebSocket is the only
WS connection in the dashboard. Use SSE for additional one-way event streams.

Rationale: HTTP/1.1 enforces a 6-connections-per-origin limit in browsers
("won't fix" in Chrome/Firefox), so every long-lived WS permanently consumes
one slot. SSE over HTTP/2 — which the production reverse proxy negotiates —
multiplexes ~100 streams per connection. SSE is simpler infra (just a
`text/event-stream` response), survives proxies that strip WS upgrade
headers, and auto-reconnects with exponential backoff in browsers.

**Operational gotcha**: intermediate proxies buffer responses by default,
which turns an SSE stream into "nothing, nothing, nothing, 4KB chunk." Set
`X-Accel-Buffering: no` (nginx) or the equivalent for your reverse proxy on
every SSE response. Add it via a response header at the handler level — don't
rely on proxy config.

## Page handler shape

Every layout-extending page handler follows this pattern:

```rust
async fn my_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    // …page-specific extractors (Query / Form / Path)…
) -> Response {
    // …fetch view-model from state, page-specific…
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    render(&MyPage {
        title: "My Page",
        env: "dev",
        user: user.map(|Extension(p)| user_display(&p)),
        theme: theme_from_cookie(&headers),
        nav: nav("/my-page", tenant_ctx.as_ref()),
        tenant_ctx,
        // …page-specific fields…
    })
}
```

The template struct mirrors that by embedding `chrome: PageChrome`,
whose builder takes the `TenantContext` (see [Composing
URLs](#composing-urls)).

## Auth + CSRF

There are three top-level mount points; each uses a different auth model:

- **`/admin/*`** uses session cookie + PKCE login (`crate::auth`). Read
  `Extension<Principal>` for caller identity; `Extension<CsrfToken>` for the
  per-session CSRF nonce.
- **`/api/v1/*`** uses bearer + `mcp:*` scope checks (`mcp:admin`,
  `mcp:read`). Dashboard page handlers DON'T re-use this surface — they
  talk to `AdminState` directly to skip the JSON round-trip.
- **`/scim/v2/*`** uses bearer + `scim:*` scope checks (`scim:read`,
  `scim:write`). Mounted separately because SCIM clients (Okta, Authentik,
  Entra) probe the well-known `/scim/v2/ServiceProviderConfig` path — see
  `crate::scim_router` and the comment in `lib.rs`. Same `BearerLayer`,
  different prefix.

CSRF discipline on the dashboard:

- **Every mutating form on a *page* carries `<input type="hidden" name="csrf"
  value="{{ csrf_token }}">`**. Handlers verify via `require_csrf(...)` — see
  the established pattern in `api_keys::mint`. The CSRF token comes from the
  session cookie and is stamped into the page when the layout renders, so the
  same token round-trips with every form on the page.
- **htmx-driven POST endpoints** need the same CSRF token in the form body;
  htmx serializes hidden inputs by default.
- **Exception: `POST /admin/logout`** — no CSRF input, no `require_csrf`
  check. Logout is idempotent (it only clears the session cookie) and a
  forged logout would just nudge the operator to log in again — no
  exfiltration / mutation surface to protect. Future logout-side state
  changes (e.g. a "revoke all my OAuth sessions on logout" option) would
  flip this; until then, the bare form in `layout.html` is intentional.

## Audit evidence — categories and reliability

Two orthogonal decisions per mutation handler: (1) which
`EvidenceCategory` the event belongs to, (2) whether to use
`record_required` (fail-closed), `record_chained_best_effort` (chain-covered
without failing the request), or `record_best_effort` (unchained and
non-failing).

### Pick the right category

Use the category defined for the operation in the
[telemetry reference](telemetry.md#event-categories). Dashboard and API
paths for the same operation must use the same category and shared recording
helper. Read-only handlers do not need mutation events.

### Pick the right reliability

Choose the recording method from the
[telemetry delivery contract](telemetry.md#evidencerecorder). For new
security-impacting admin mutations, use `record_required` and the shared
admin mutation recorder. An audit failure must be surfaced to the operator;
it cannot roll back a store write that already committed. Review operation
ordering before changing an existing handler's failure behavior.

All three methods take the same `AuditEvent` shape; chain coverage, outbox
delivery, and failure propagation differ. Always populate
`with_category(...)`, `with_principal(actor)`, and `with_reason(...)`
(sanitized identifiers, not raw input).

## Adding a new page — checklist

1. New module under `crates/waygate-admin/src/<area>.rs` with the page handler
   + template struct + `router()` function.
2. Add `pub mod <area>;` in `lib.rs`.
3. Merge `<area>::router()` into `dashboard::page_routes` so it gets mounted
   at both legacy and tenant-prefixed paths.
4. Add the page as a `(label, suffix)` tab of the right destination in
   `dashboard::DESTINATIONS` (or add a new destination under the right
   section — Common / MCP Gateway / LLM Gateway — if it is genuinely a new
   task area; prefer adding a tab to an existing destination so each
   section stays scannable rather than growing the destination count).
5. Add the same page to `palette::PAGES` so it's discoverable via Cmd-K.
6. New template under `templates/<area>.html` that `{% extends "layout.html" %}`.
   Embed `chrome: PageChrome` on the struct (built via `PageChrome::build`
   at the top of the handler) — never redeclare title/env/user/theme/nav/
   tenant_ctx/csrf fields (`check-page-chrome.sh` fails CI on copies).
7. Use `{{ self.chrome.nav_url("/...") }}` for every internal `href`, htmx URL
   attribute (`hx-get`, `hx-post`, `hx-put`, `hx-delete`), and form
   `action`. `hx-target` is a DOM selector (e.g. `#keys-table`), not a
   URL — don't run it through `nav_url`.
8. Add tests to the matching module under `tests/dashboard_render/`
   covering: page renders at the
   tenant-prefixed mount, sidebar nav active marker, any tenant-prefixed
   in-page URL.
9. If the page emits durable events on mutation, pick the right category +
   reliability per [Audit evidence — categories and reliability](#audit-evidence--categories-and-reliability).
   For NEW `AdminMutation` surfaces, default to `record_required(event).
   await?`. When the
   surface already has a domain-specific category (e.g. `ApiKeyLifecycle`,
   `OAuthEvent`), follow the established producer's reliability choice
   rather than flipping it inline.

## Test patterns

Integration tests live under `crates/waygate-admin/tests/dashboard_render/`
(one module per page family; shared builders in `common.rs`, the pg
preamble/mocks/state core in `waygate-test-support`).
Use the existing helpers:

- `empty_state()` — `AdminState` with no audit / no api-keys / no tenants
  registry. Enough for "page renders" smoke.
- `state_with_audit()` — for testing audit-aware rendering branches
  (activity page, overview's notable-events tile).
- `state_with_cedar()` — for the policies simulator.
- `body_of(app, "/path")` — fires a GET and returns `(StatusCode, String)`.
- `dashboard_router(state, DashboardAuth::Disabled)` — synthesizes a
  `dev@local` admin principal so handlers run without a session cookie.

For the tenant-prefixed `/admin/t/<slug>/` canonical URL, the production stack
applies `NormalizePathLayer::trim_trailing_slash()` at the outer level.
Integration tests use the no-trailing-slash form (e.g. `/t/default`) directly
to avoid the wrapper, OR call out the dependency via the existing
`tenant_prefix_trailing_slash_requires_normalize_layer` test pattern.

## File layout

```
crates/waygate-admin/
├── src/
│   ├── lib.rs                  — pub mod declarations + router composition
│   ├── dashboard.rs            — chrome (nav(), render, theme), router/page_routes;
│   │                             pages live in dashboard_*.rs siblings
│   ├── tenant_ctx.rs           — TenantContext, middleware, nav_url
│   ├── palette.rs              — Cmd-K search endpoint
│   ├── api_keys.rs             — Identities page (API keys + OAuth sessions)
│   ├── oauth_clients.rs        — OAuth-sessions section / refresh handler
│   ├── auth.rs                 — PKCE flow + session middleware
│   ├── state.rs                — AdminState (every wired-in store)
│   └── …per-area REST modules (audit, catalog, rbac, …)
├── templates/
│   ├── layout.html             — base; tenant selector, banner, palette,
│   │                             sidebar destinations + tab bar
│   ├── overview.html           — Overview page
│   ├── activity.html           — Activity page + htmx-loaded rows
│   ├── policies.html           — Policies + simulator
│   ├── api_keys.html           — Identities page
│   ├── *_table.html            — htmx fragments
│   ├── *_section.html          — composed sections (e.g. oauth_clients)
│   └── *_drawer.html           — drawer fragments
└── static/
    ├── css/
    │   ├── tokens.css          — color + spacing tokens
    │   └── base.css            — layout + components
    ├── js/
    │   ├── theme.js            — light/dark toggle (localStorage)
    │   ├── palette.js          — Cmd-K palette
    │   ├── badge.js            — Decisions nav badge fetch
    │   ├── try_tool.js         — governed "Try this tool" form
    │   └── htmx.min.js         — htmx core
    └── lucide.svg              — icon spritesheet
```

## See also

- [`README.md`](../../README.md) — admin URL (`/admin/`) and OpenAPI URL
  (`/api/v1/openapi.json`).
- [`docs/agents/identity.md`](identity.md) — auth flow + scopes (the
  `Principal` extensions the dashboard reads).
- [`docs/agents/telemetry.md`](telemetry.md) — categorical evidence events
  that admin mutations emit.
- [`docs/agents/federation.md`](federation.md) — Tier-C peer admin.
- [`docs/agents/break-glass.md`](break-glass.md) — emergency-access flow
