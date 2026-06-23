# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`PDS-Pro` is a small Go web app that fronts `goat pds admin` with operator-level OAuth so SGC operators can manage Bluesky PDS instances without sharing the `PDS_ADMIN_PASSWORD`. One admin instance manages multiple PDS instances.

It's a **sibling project** to:
- `~/sgc/apps/pds/` — the SGC fork of `bluesky-social/pds` (multi-domain deployment work)
- `~/sgc/ansible/roles/pds-ar/` — the ansible role that deploys each PDS instance
- `~/sgc/ansible/roles/pds-pro-ar/` (planned) — the ansible role that deploys this admin app

The PDS admin password never reaches the browser. The auth boundary is *this app* — it authenticates the human via OAuth, decides if they're allowed (allowlist for now, claim-based later), then runs `goat pds admin` server-side with the shared admin secret on their behalf, writing an audit log entry per action.

## Stack

- **Go**, no SPA, server-rendered HTML using `html/template`'s `{{block "content" .}}` pattern + htmx via CDN
- **chi** for routing
- **goth** + **gorilla/sessions** for OAuth + cookie sessions
- **goat** invoked as a subprocess (the binary is bundled in the container at `/usr/local/bin/goat`)
- **YAML** config (single file, loaded at startup)
- **JSON-lines audit log** to a local file (will move to SQLite in Phase 6)

## Layout

```
cmd/pds-pro/    # entrypoint
internal/
  audit/              # JSON-lines audit logger (sync.Mutex-guarded file append)
  auth/
    allowlist.go      # subject/email/email_domain matching, role helpers
    oauth.go          # goth provider registration (Okta now; Google/MS/FB/X planned)
    session.go        # gorilla/sessions cookie store, RequireAuth middleware
  config/             # YAML config schema + loader; ReadSecretFile helper
  goat/               # subprocess wrapper that injects --admin-password and --pds-host
  handlers/           # chi routes + handlers; render() uses Templates map
web/templates/
  layout.html         # base chrome with {{block "content" .}} placeholder
  *.html              # each page redefines content; loaded via ParseFiles(layout, page)
config.example.yaml   # canonical reference for every config field
Dockerfile            # multi-stage: builds the app + builds goat from source pinned via GOAT_VERSION ARG
```

## Phase plan (high-level)

| Phase | Scope |
|---|---|
| 2 (current) | Okta OAuth, allowlist auth, account list/create/takedown |
| 3 | reset-password, delete, invites, account info/update, blob status/purge, request-crawl |
| 4 | Add Google + Microsoft providers |
| 5 | Add Facebook + X providers |
| 6 | SQLite audit log + CSV export, role management UI, instance picker |
| 7 | `pds-pro-ar` ansible role + wire into SGC playbook |

## Auth model

Three layers:

1. **Authentication**: `goth` initiates an OAuth/OIDC flow per provider; on success the callback handler builds a `subject` of the form `<provider>|<provider-user-id>` (e.g. `okta|00uXXXXX`). This namespacing keeps the subject unambiguous as we add providers.
2. **Authorization**: `auth.Authorize` walks `config.allowlist` in order; first match wins. An entry can match by `subject`, exact `email`, or `email_domain`. Role list comes from the matching entry. This will be replaced by claim-based mapping later (e.g. Okta group `pds-admins` → `super-admin`).
3. **Session**: Signed cookie (`gorilla/sessions`), 1-day default lifetime. The session secret is loaded from `session.secret_file` and auto-created (random 32 bytes, hex-encoded) if missing — persist this file across restarts.

Routes under `/login`, `/auth/{provider}`, `/auth/{provider}/callback`, `/logout` are public. Everything else goes through `sessions.Middleware`, which redirects unauthenticated requests to `/login`.

## Goat invocation

`internal/goat.Client` shells out to `goat pds admin <args>` and injects `--admin-password <pw>` and `--pds-host <url>` from the per-instance config. We deliberately avoid relying on goat's `/pds/pds.env` lookup (or our planned `PDS_ENV_FILE` env var) because the admin password lives in a per-instance secret file, and we want explicit per-request scoping.

If you add a new goat command:
1. Add a method on `Client` that builds the args list and calls `c.run(ctx, "pds", "admin", ...)`.
2. The `run` helper enforces that args start with `"pds", "admin"` and inserts `--admin-password` / `--pds-host` between `admin` and the subcommand.

## Templates

Each page is a separate `*template.Template` made from `ParseFiles(layout.html, <page>.html)`. The handler's `render(name, data)` looks up by page filename (e.g. `accounts.html`) and executes `layout.html` against it. **Don't try to load all pages into one set** — they all redefine `{{define "content"}}` and would clobber each other.

Data passed to every page should include the `User` field (so the layout can render the logout button). Helpers in `handlers.go` already do this.

## Audit log

`audit.Logger.Log(audit.Entry)` writes one JSON object per line. Fields: `ts, subject, email, provider, instance, action, args, result, http_status, error`.

Log on every state-changing action (create, takedown, etc.) AND on login attempts (both `login` and `login.denied`). Read-only operations like `account.list` are logged too — this is an audit log, not a change log.

## Adding a new OAuth provider

1. Add a `<Provider>` struct under `config.OAuthConfig` (mirror `OktaProvider`).
2. In `auth/oauth.go`'s `RegisterProviders`, instantiate the goth provider when the config block is present, append to `enabled`.
3. The login template will render a button per enabled provider automatically.
4. The callback route `/auth/{provider}/callback` is generic — no per-provider handler needed.

## Adding a new admin operation

1. New method on `internal/goat.Client` (mirror `AccountTakedown`).
2. New handler in `internal/handlers/handlers.go` calling that method, gated on `auth.HasRole` for the appropriate role.
3. Route registration in `Server.Routes()`.
4. New template page in `web/templates/` if user-facing output.
5. Always emit an `audit.Log` entry — never skip auditing.

## Don't

- Don't store the PDS admin password anywhere except the per-instance secret file. Never put it in env vars on the running app, never write it to logs, never include it in audit `args`.
- Don't bypass the `RequireAuth` middleware for state-changing routes.
- Don't `gob.Register` new types in handlers — register in `auth/session.go`'s `init()` so it's all in one place.
- Don't add features for hypothetical future providers/operations. Phase plan above is the source of truth for what to build next.

## Cross-auth federation (atproto ↔ Authentik) — the "session-broker" model

Beyond per-instance operator admin, pds-pro is the **management plane** for the
Discord → Authentik → Stoked-chat + Bluesky cross-auth on cooey.club. Goal: one
identity — sign in with Discord (a source on the cooey Authentik brand), become a
durable Authentik user, and be associated with both a Stoked chat user and a
`<handle>.cooey.club` atproto account. Canonical design + decisions: pds-pro
project memory `crossauth-atproto-federation.md`.

**Why session-broker (not PDS-OAuth federation):** atproto's
`@atproto/oauth-provider` (the PDS login) has no external-IdP hook, and patching
it is a deep, fragile change to a weekly-bumped dep. Instead pds-pro creates each
account with a **managed password it can re-derive** —
`HMAC(secret, "atproto:session:"+sub)` — so it can mint atproto sessions /
app-passwords on the user's behalf ("one Authentik login → bsky") without
touching the PDS.

**Config:** optional `authentik` + `ntfy` + `atproto` blocks (see
config.example.yaml). `atproto.instance` must be a configured PDS instance;
`atproto.claim` is the end-user OIDC client. Federation is off unless `atproto`
is set; `config.Load` validates the dependent blocks when it is.

**Two auth audiences in one app:**
- **Operators** — `/` + `/instances/*`, OIDC + allowlist (existing).
- **End users** — the `/claim` flow: a SEPARATE goth provider `claim` pointed at
  the cooey brand (`auth.cooey.club`), **not allowlist-gated**, so any cooey user
  can claim. Flow: `GET /claim` (form) → `POST /claim` (stash localpart in a
  10-min `pds-pro-claim` cookie) → `GET /claim/auth` (gothic begin) → Authentik →
  `GET /claim/callback` (gothic complete → `linkage.ProvisionAndLink`). The
  `/claim/*` paths deliberately avoid the operator `/auth/{provider}` routes;
  `claim.callback_url` MUST be `<base_url>/claim/callback`. The `claim` provider
  is registered with goth but never added to the operator login buttons.

**Provisioning + linkage (`internal/linkage`, `internal/authentik`):**
`ProvisionAndLink` creates `<localpart>.<handle_domain>` via goat, then PATCHes
`attributes.atproto = {did,handle,status:"active"}` onto the Authentik user
(read-modify-write so other attributes survive). **Failure is non-blocking:**
flag `status:"error"` (carrying the OIDC sub + any did), ntfy the eagledrive-admin
topic, audit — never block the user. A 10-minute `reconcileLoop`
(cmd/pds-pro/main.go) retries flagged users quietly (relink if a did is present,
else re-create).

**Authentik side** (`apps/authentik/scripts/sgc/`):
`provision-atproto-claims.py` (the `atproto` OIDC scope → atproto_did/handle/status
claims, attached to `stoked`, for chat to read) + `provision-atproto-writer-token.py`
(the writer service account + token). A provision script for the `pds-pro-claim`
OIDC client is a Phase-5 TODO.

**Session broker (built, `internal/atproto` + `linkage`):** `IssueAppPassword`
and `BrokerSession` re-derive the managed password and call
`com.atproto.server.createSession` / `createAppPassword` against the instance's
PDS host. The claim callback mints + shows a `cooey` app-password on success (for
external Bluesky apps); `BrokerSession` is ready for chat to embed bsky via a
brokered session.

**Naming — drop the service prefix:** the PDS host carries a prefix
(`pds.<domain>`, or `bsky.<domain>` colloquially), but everything user-facing is
the BARE `<user>.cooey.club` — never `<user>.pds.cooey.club`. `atproto.handle_domain`
is the explicit bare domain (separate from the prefixed `pds_host`), so handles +
emails already drop the prefix. **Stoked:** the chat username is just `<user>` (the localpart = the Authentik
`preferred_username`); `<user>.cooey.club` is ONLY the bsky handle format. So no
chat-username construction is needed — the claim's handle localpart IS that same
`<user>` (chat `<user>` ↔ bsky `<user>.cooey.club`, one shared identity).

**Still TODO:** Stoked — read the `atproto_*` claims onto the chat profile to
surface the bsky handle (Phase 4; the username already = `<user>`, no change); a
standalone app-password page for already-claimed users; deploy wiring (Phase 5:
add the `cooey` instance + the secrets + the `pds-pro-claim` Authentik client,
run the Authentik scripts).
