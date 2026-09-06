# authnz

A standalone authentication + authorization gateway written in Rust
([actix-web](https://actix.rs/)). It sits in front of an upstream application,
handles everything related to *who the caller is* and *what they're allowed
to do*, and reverse-proxies already-authenticated requests through to that
upstream — injecting trusted identity headers along the way.

- **authn** — registration, password login, passwordless (magic link / one-time
  code) login, optional WebAuthn/passkey login, sessions, JWT issuance/refresh,
  password resets, and a small admin API over users and sessions.
- **authz** — a bitmask-based permission/role system (`grants`) plus an admin
  API for granting and revoking individual permission bits.
- **proxy** — once a request has an authenticated session, any route not
  claimed by authn/authz is forwarded to an `UPSTREAM` service with
  `X-User-Id`, `X-User-Email`, and `X-User-Name` headers set from the session
  (stripping any client-supplied copies of those headers first).

## Table of contents

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Database setup](#database-setup)
- [Running](#running)
- [Permissions model](#permissions-model)
- [API reference](#api-reference)
- [Project layout](#project-layout)

## Architecture

```
                      ┌───────────────────────────────────────────┐
                      │                 actix-web                 │
 client ── request ──▶│  /authn/*   (public + session-protected)  │
                      │  /authz/*   (permission-gated admin API)  │
                      │  /*         (Permissions + SessionMiddle- │
                      │             ware) ──▶ Proxy ──▶ UPSTREAM  │
                      └───────────────────────────────────────────┘
                                     │
                                 PostgreSQL
```

- **Sessions** are opaque UUIDs stored server-side (Postgres, cached with
  [moka](https://docs.rs/moka)) and handed to the client as an
  `HttpOnly` / `Secure` / `SameSite=Strict` cookie named `session`. Session
  rows denormalize `username`, `email`, and `role` so the session store can
  answer identity + authorization checks without a join.
- **JWTs** (`/authn/jwt`, `/authn/me/jwt`) are available as a stateless
  alternative/complement to cookie sessions, with refresh-token rotation
  handled by `JwtService`.
- **Authorization** is a 128-bit permission bitmask per user (`grants.role`,
  stored as a UUID and reinterpreted as `u128`). Route-level permission
  requirements are declared once in [`permissions.json`](./permissions.json)
  and enforced by the `Permissions<User>` middleware from `actixutils`.
- **Everything outside `/authn` and `/authz`** falls through to
  `default_service`, which is the `Proxy` — so this binary can be dropped in
  front of an existing app to add auth without touching that app's code.

## Requirements

- Rust (2024 edition toolchain — see `Cargo.toml`)
- PostgreSQL
- The `viewset` and `actixutils` crates, referenced as a local path
  dependency (`../viewset`) and a versioned crate respectively — make sure
  `viewset` is checked out as a sibling directory if building from source.
- `sqlx-cli` for running migrations (`cargo install sqlx-cli --no-default-features --features postgres`)

## Configuration

The service reads configuration from environment variables (a `.env` file in
the working directory is loaded automatically via `dotenv`).

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | yes | Postgres connection string, e.g. `postgres://user:pass@localhost/authnz` |
| `signer.secret` | yes | HMAC secret used to sign JWTs (HS256) |
| `signer.aud` | yes | `aud` claim embedded in issued JWTs |
| `UPSTREAM` | yes | Base URL the proxy forwards unmatched requests to, e.g. `http://localhost:3000` |
| `ADMIN` | yes, for authz "claim admin" | UUID of the user allowed to self-promote to a full-permission role via `POST /authz/admin/claim` |
| `PROXIES` | no | Comma-separated list of trusted proxy CIDRs, used by the passwordless rate limiter to resolve real client IPs |
| `RUST_LOG` | no | `tracing-subscriber` env filter (defaults to `info`) |

The server binds to `127.0.0.1:8080`.

## Database setup

Migrations live under [`migrations/`](./migrations) and are plain SQL,
managed with `sqlx-cli`:

```bash
export DATABASE_URL=postgres://user:pass@localhost/authnz
sqlx database create
sqlx migrate run
```

This creates:

- `users` — credentials and profile fields (`username`, `email`,
  `password_hash`, `email_confirmed`, timestamps)
- `refresh_tokens` — hashed refresh tokens for the JWT flow
- `password_resets` — hashed, single-use password reset tokens
- `passkey_credentials` — registered WebAuthn credentials (only used when
  built with the `passkey` feature)
- `sessions` — server-side session records (denormalized user info + issuing
  IP + expiry)
- `grants` — one row per user mapping `to_id → role` (the permission bitmask)

## Running

```bash
# core build (password + passwordless auth, no WebAuthn)
cargo run

# with WebAuthn/passkey support
cargo run --features passkey
```

On startup the service also loads [`permissions.json`](./permissions.json)
and will refuse to start if it's missing or invalid.

## Permissions model

Authorization is a single `u128` bitmask per user, persisted as a UUID in
`grants.role`. Each protected admin route is mapped to a bit position in
`permissions.json`:

```json
{ "method": "GET", "url": "/authn/me/admin/users", "bit_id": 100 }
```

- `POST /authz/admin/grant` sets bit `permission` for `target` (OR).
- `POST /authz/admin/deny` clears bit `permission` for `target` (AND NOT) and
  revokes all of that user's active sessions, so a denied permission takes
  effect immediately rather than waiting for the session to expire.
- `POST /authz/admin/claim` lets exactly one bootstrap user — the UUID in the
  `ADMIN` env var — grant themselves the all-ones role (`u128::MAX`) once,
  to get the system off the ground.

`grant`/`deny` themselves are **not** gated by the `Permissions` middleware in
this codebase (they sit above `/authz`'s permission-gated `admin/*` scope) —
treat access to them as a deployment-level concern (network policy, mutual
TLS, etc.) rather than an in-app one.

## API reference

All request/response bodies are JSON unless noted. Routes under `/me` require
a valid `session` cookie; routes under `/me/admin` and `/authz/admin/grants`
additionally require the caller's role to have the relevant permission bit
set (see [`permissions.json`](./permissions.json)).

### Password authentication — `/authn/auth`

| Method | Path | Description |
|---|---|---|
| POST | `/register` | Create a user. Body: `{ username, email, password }` |
| POST | `/login/email` | Log in with email + password. Body: `{ identifier, password }`. Sets the `session` cookie |
| POST | `/login/username` | Log in with username + password |
| POST | `/request_password_reset` | Body: `{ email }`. Always returns 200; emits an event carrying the reset token for an out-of-band mailer to consume |
| POST | `/confirm_password_reset` | Body: `{ token, new_password }`. Revokes all existing sessions and refresh tokens for that user |

These routes are wrapped in a `ResponseEqualizer` that normalizes response
timing, to reduce the ability to distinguish "wrong password" from
"no such user" via timing side-channels.

### Session-protected account routes — `/authn/me`

| Method | Path | Description |
|---|---|---|
| POST | `/jwt` | Exchange the current session for a JWT access/refresh pair |
| POST | `/logout` | Destroy the current session |
| GET | `/account` | Echoes the authenticated user's ID (sanity-check endpoint) |
| POST | `/change_password` | Body: `{ current_password, new_password }`. Revokes all sessions and refresh tokens, then issues a fresh session for the calling device |
| GET | `/sessions` | List the caller's own active sessions |
| DELETE | `/delete_session/{id}` | Delete one of the caller's own sessions (403 if it belongs to someone else) |

### JWT lifecycle — `/authn/jwt`

| Method | Path | Description |
|---|---|---|
| POST | `/refresh` | Rotate a refresh token for a new access/refresh pair |
| POST | `/logout` | Revoke a specific refresh token |

### Passwordless login — `/authn/passwordless`

Rate-limited (100 requests/min per client IP, trusting `PROXIES` for IP
resolution).

| Method | Path | Description |
|---|---|---|
| POST | `/challenge/email` | Body: `{ email }`. Emits an event with a magic-link token for an out-of-band mailer |
| GET | `/challenge/username/{username}` | Same, keyed by username |
| GET | `/confirm_link/{link}` | Confirm via magic link, marks the email confirmed, and starts a session |
| POST | `/confirm_token` | Body: `{ token, nonce }` — confirm via a short numeric code + nonce instead of a link |

### Passkeys — `/authn/passkey` (feature `passkey`)

| Method | Path | Description |
|---|---|---|
| POST | `/register/start` | Begin WebAuthn credential registration (session required) |
| POST | `/register/finish` | Complete registration |
| GET | `/register` | List the caller's registered credentials |
| DELETE | `/register/{id}` | Remove a credential |
| POST | `/login/start` | Begin WebAuthn login (public — no session yet) |
| POST | `/login/finish` | Complete WebAuthn login and start a session |

### Admin — users & sessions — `/authn/me/admin`

Standard CRUD `ViewSet`s, permission-gated per method/route as declared in
`permissions.json`:

- `/users`, `/users/{id}` — manage user records
- `/sessions`, `/sessions/{id}` — manage any user's sessions

### Authorization admin — `/authz`

| Method | Path | Description |
|---|---|---|
| POST | `/admin/claim` | Bootstrap: the `ADMIN`-configured user grants themselves full permissions |
| POST | `/admin/grant` | Body: `{ target, permission, .. }`. Sets a permission bit for `target` |
| POST | `/admin/deny` | Clears a permission bit for `target` and revokes their sessions |
| GET/POST/GET/DELETE/PATCH | `/admin/grants[/{id}]` | `ViewSet` over raw grant rows |

### Everything else

Any request that doesn't match a route above passes through
`SessionMiddleware` + `Permissions<User>` and is proxied to `UPSTREAM`, with
`X-User-Id` / `X-User-Email` / `X-User-Name` set from the session.

## Project layout

```
src/
├── main.rs             # wiring: DB pool, session store, module composition, HTTP server
├── proxy.rs             # reverse proxy to UPSTREAM with identity header injection
├── models.rs            # the app-wide `User` (session/authz-facing) type
├── authn/
│   ├── config.rs         # route composition for the authn module
│   ├── handlers.rs       # register/login/logout/password reset/JWT handlers
│   ├── middleware.rs     # SessionMiddleware
│   ├── session.rs        # Session<T> extractor
│   ├── admin.rs          # ViewSets for admin user/session management
│   ├── domain/           # user service, JWT service, session service
│   ├── passwdless/       # magic-link / one-time-code login
│   └── passkey/          # WebAuthn registration & login (feature-gated)
└── authz/
    ├── config.rs         # route composition for the authz module
    ├── handlers.rs       # grant/deny/claim admin endpoints
    ├── services.rs        # bitmask grant/deny logic
    └── admin.rs           # ViewSet over raw grant rows

migrations/               # sqlx migrations (users, sessions, tokens, grants, passkeys)
permissions.json          # method+URL → permission-bit map, loaded at startup
```
