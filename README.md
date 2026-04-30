# PDS-Pro

A small web admin UX that wraps `goat pds admin` with operator-level OAuth, so SGC operators can manage one or more Bluesky PDS instances without ever touching the shared `PDS_ADMIN_PASSWORD` directly.

- One admin app fronts **multiple PDS instances**.
- OAuth via [`goth`](https://github.com/markbates/goth). Okta is wired up first; Google, Microsoft, Facebook, and X are planned (one config flag each).
- **Allowlist-based authorization** to start (matches by OAuth `subject`, exact email, or email domain). Claim-based mapping later.
- **Per-action audit log** keyed on the OAuth subject (JSON-lines).
- Server-rendered HTML + htmx. No SPA build.
- `goat` is shelled out per request; the admin password is loaded from a per-instance secret file and passed via `--admin-password` so we never touch the hardcoded `/pds/pds.env` lookup.

This is part of the SGC PDS work — see [`P3X-118/pds`](https://github.com/P3X-118/pds) for the PDS distribution fork and [`pds-pro-ar`](https://github.com/P3X-118/pds-pro-ar) for the ansible role that deploys this app.

## Phase 2 scope (this commit)

- OAuth login via Okta; allowlist auth; session middleware
- Account list / create / takedown (and reverse) for each configured instance
- Audit log for every action and every login attempt

Future phases add `account info/update/reset-password/delete`, `blob status/purge`, `request-crawl`, additional OAuth providers, role UI, and SQLite-backed audit log with CSV export.

## Layout

```
cmd/pds-pro/      # entrypoint
internal/
  audit/                # JSON-lines audit log
  auth/                 # goth OAuth, gorilla/sessions, allowlist
  config/               # YAML config loader
  goat/                 # subprocess wrapper for `goat pds admin`
  handlers/             # HTTP handlers and routes (chi)
web/templates/          # html/template pages (layout.html + per-page block)
config.example.yaml
Dockerfile              # multi-stage; bundles goat alongside the binary
```

## Configure

Copy `config.example.yaml` to `config.yaml` and fill in your Okta client ID, secret-file paths, allowlist entries, and PDS instance list. The example is the canonical reference for every field.

Secrets live in files (per the SGC pattern, derived from `sgc_pgsk` in the deployment role):

- `session.secret_file` — 32+ byte hex secret, used to sign session cookies. Auto-generated on first run if missing.
- `oauth.okta.client_secret_file` — Okta client secret, single line.
- `instances[].admin_password_file` — `PDS_ADMIN_PASSWORD` for the corresponding PDS.

## Run locally

```bash
go run ./cmd/pds-pro --config ./config.yaml --templates ./web/templates
```

## Build the container

```bash
docker build -t pds-pro:dev .
docker run --rm -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/pds-pro/config.yaml:ro \
  -v $(pwd)/secrets:/run/secrets/pds-pro:ro \
  pds-pro:dev
```

The runtime image bundles `goat` so the admin app can shell out to `/usr/local/bin/goat` directly. Pin the goat version with `--build-arg GOAT_VERSION=vX.Y.Z`.

## Audit log

Every action writes one JSON object per line to `audit.log_path` (or stdout if unset). Fields: `ts, subject, email, provider, instance, action, args, result, error`.

`subject` is namespaced as `<provider>|<provider-user-id>` so it stays unambiguous when more providers are wired up.
