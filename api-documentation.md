# Authnz Service — API Documentation

An Actix Web authentication/authorization service providing password, passwordless
(magic-link/OTP), and passkey (WebAuthn) login, server-side session management,
JWT access/refresh token issuance, bitmask RBAC, and a reverse proxy that forwards
authenticated requests upstream with asserted identity headers.

Two sibling modules are mounted into one `App`:

- **`authn`** — registration, login, sessions, JWT, passwordless, passkeys, account admin.
- **`authz`** — bitmask permission grants/denials and a raw grants admin viewset.

Everything not matched by `authn`/`authz` falls through to a **reverse proxy**
(`default_service`) that forwards the request upstream, provided the caller has a
valid session.

---

## 1. Base URL & Mounting

The router is assembled in `main.rs`:

```
/authn/...                      → authn module (public + session-protected routes)
/  (everything else)            → wrapped in Permissions + SessionMiddleware,
                                   then authz module, then proxy fallback
```

`authn`'s own routes are namespaced under whatever prefix is passed to
`AuthModule::config` (`"authn"` in `main.rs`), so in practice:

| Path prefix | Handled by |
|---|---|
| `/authn/auth/*` | public auth (register/login/reset) |
| `/authn/jwt/*` | JWT refresh/logout |
| `/authn/me/*` | session-protected account routes |
| `/authn/me/admin/*` | admin viewsets (users, sessions) — permission-gated |
| `/authn/passwordless/*` | magic-link / OTP login |
| `/authn/passkey/*` | WebAuthn passkeys (only if the `passkey` feature is enabled) |
| `/authn/user_id/username/{username}` | username → user id lookup |
| `/authz/*` | permission grant/deny/claim + `/authz/admin/grants` viewset |
| everything else | reverse-proxied upstream (requires a valid session) |

---

## 2. Authentication Mechanisms

The service supports two parallel credential types, issued from the same login flows:

### 2.1 Session cookie (server-side session)

- Cookie name: **`session`** (UUID v4 session id).
- Attributes: `Path=/`, `HttpOnly`, `Secure`, `SameSite=Strict`.
- Enforced by `SessionMiddleware`, which resolves the cookie against a session
  store (Postgres + in-memory cache) and rejects the request with
  **401 Unauthorized** if the cookie is missing, not a valid UUID, not found in
  the store, or expired (sessions expire **30 minutes** after issuance).
- Routes protected by this middleware expose a `Session<User>` extractor to
  handlers, giving read/write access to `{ sub, username, email, role, expires_at }`.
- This is what gates the reverse proxy and the `/me/*` and `/authz/*` routes.

### 2.2 JWT access/refresh pair

- Obtained via `POST /authn/me/jwt` (while holding a valid session) or through the
  passwordless/passkey flows.
- `access_token` is an HS256-signed token (audience-scoped); `refresh_token` is a
  single-use, rotating opaque token stored server-side only as a SHA-256 hash
  (the raw value is returned to the client exactly once and never persisted).
- Refresh tokens expire after **30 days** and rotate on every use — reusing an
  already-rotated (deleted) refresh token fails as "not found."
- **Access token expiry discrepancy:** every JWT response reports
  `"expires_in": 600` (hardcoded), but the access token itself is signed via
  `actixutils`' `Identity` claims, which set `exp` to **500 seconds** after
  issuance (`HS256Signer`/`Identity::new`, not configurable per call). A
  client that trusts the reported `expires_in` will treat the token as valid
  for 100 seconds after it has actually expired server-side — worth fixing
  in either `JwtResult` or `Identity::new`, but documented here as-is.
- Intended for callers that can't hold cookies (native/mobile clients, service-to-service).

### 2.3 RBAC (bitmask permissions)

- A user's `role` is a `u128` bitmask. Each bit (0–127) represents one permission.
- Grants are stored per-user in a `grants` table (`to_id`, `role`) and are folded
  into the session's `User.role` at login time.
- `Permissions::<User>` middleware wraps the outer scope (proxy + `authz`) and the
  `/me/admin` scope, checking the caller's bitmask against a `permissions.json`
  policy file loaded at startup. The file has the shape:
  ```json
  { "permissions": [ { "method": "GET", "url": "/authz/admin/grants", "bit_id": 3 } ] }
  ```
  `url` is matched as an **exact Actix route pattern** (e.g. `/users/{id}`, not a
  live path like `/users/42`) against `(method, path)` for every request that
  passes through the middleware.
- **The policy is default-deny, at two levels:**
  - No `(method, url)` entry matches → **403 Forbidden**, even for an
    authenticated caller with a fully-permissive role.
  - A match exists but there's no principal in request extensions (i.e. the
    session middleware didn't run first, or found no session) → **401 Unauthorized**.
  - A match exists and a principal is present, but its role bit is unset →
    **403 Forbidden**.
  - Only when the matching permission's bit *is* set does the request reach
    the handler. In other words, every route under a `Permissions`-wrapped
    scope needs an explicit entry in `permissions.json`, including ones that
    "should" be open to any authenticated user.
- A special **super-admin claim** flow (`POST /authz/admin/claim`) lets one
  pre-designated account (env var `ADMIN`, a UUID matched against the caller's
  `sub`) set its own in-memory session role to `u128::MAX` (all permissions).
  This mutates only the live session object (and, since `write()` marks it
  dirty, gets persisted back to the session store after the request) — it does
  **not** write a `grants` row, so it doesn't survive a session revocation/logout.

---

## 3. Common Response Envelope

Most `authn` JSON responses use:

```json
{
  "success": true,
  "message": "human-readable message",
  "data": { }
}
```

`data` is `null`/omitted for endpoints with no payload. Some legacy/simple
endpoints (login, passkey, passwordless, proxy) instead return a bare body,
an empty `200`, or a raw error string — these are called out per-endpoint below.

### Standard error shapes

| Style | Shape | Used by |
|---|---|---|
| Enveloped | `{ "success": false, "message": "..." }` | most `authn` "auth" errors |
| `ErrorResponse` | `{ "error": "..." }` | passkey endpoints |
| `viewset::ApiError` | `{ "error": "..." }` (5xx bodies are genericized — see §7) | all viewset-backed CRUD (§7, §11) |
| Plain text body | raw string | passwordless errors, some validation errors |
| Empty body | status code only | JWT endpoints, `Permissions` 401/403, some proxy/internal errors |

### Status codes used by the shared `viewset` crate

Every viewset-backed endpoint (§7, §11) maps its internal `ApiError` to HTTP
the same way:

| `ApiError` variant | Status | Notes |
|---|---|---|
| `NotFound` / `Database(sqlx::Error::RowNotFound)` | `404 Not Found` | |
| `Validation(_)` | `422 Unprocessable Entity` | bad id format, DTO field fails to coerce to its column type, or a `before_create`/`before_update` hook rejects the request |
| `Forbidden` | `403 Forbidden` | |
| `Unauthorized` | `401 Unauthorized` | |
| `Conflict(_)` / `StaleVersion` | `409 Conflict` | |
| `Database(_)` (other) / `Internal(_)` | `500 Internal Server Error` | body is genericized to `{"error":"internal server error"}` — the real error is only `tracing::error!`-logged server-side, never leaked to the client |

---

## 4. Auth — Registration & Password Login

Base path: `/authn/auth`. Wrapped in a `ResponseEqualizer` (normalizes response
timing to ~200ms) to reduce timing side-channels on login/registration.

### `POST /authn/auth/register`
Create a new account.

**Body**
```json
{
  "username": "string, 3–30 chars",
  "email": "string, valid email",
  "password": "string, min 8 chars"
}
```

**Responses**
- `201 Created` — `ApiResponse<...>` envelope, `"User registered successfully"`.
- `400 Bad Request` — validation failure, or `MissingCredentials` / `PasswordTooShort`.
- `409 Conflict` — `UserAlreadyExists`.
- `500 Internal Server Error` — DB/hashing failure.

### `POST /authn/auth/login/email`
Password login using an email identifier.

**Body**
```json
{ "identifier": "email address", "password": "string" }
```

**Responses**
- `200 OK`, `Set-Cookie: session=<uuid>` (HttpOnly/Secure/Strict), empty body.
- `400/401` — invalid credentials / missing fields (via `auth_error_to_response`).
- `500` — DB/hashing/role-lookup failure.

### `POST /authn/auth/login/username`
Identical to `login/email`, but the identifier is matched as a username.

### `POST /authn/auth/request_password_reset`
**Body:** `{ "email": "string" }`
Always returns `200 OK` with a success envelope
(`"If the account exists, a reset link has been sent"`), regardless of whether
the address exists, to avoid account enumeration. On success internally, a
password-reset event (carrying the raw reset token) is published to the event
bus for a subscriber (e.g. an email service) to deliver — the token is never
returned in the HTTP response or logged.

### `POST /authn/auth/confirm_password_reset`
**Body**
```json
{ "token": "string (from the reset email/link)", "new_password": "string" }
```
**Responses**
- `200 OK`, empty body — on success, **all** of the user's sessions and refresh
  tokens are revoked (a reset invalidates every existing login, including any
  attacker-held session).
- `400/401` — invalid/expired token (via `auth_error_to_response`).

---

## 5. JWT Endpoints

Base path: `/authn/jwt` (public — used by clients holding a refresh token, no
session cookie required).

### `POST /authn/jwt/refresh`
**Body:** `{ "refresh_token": "string" }`

Rotates the refresh token: the old one is deleted and a new pair issued in a
single DB transaction (so a failure before commit leaves the old token replayable).

**Responses**
- `200 OK` — `ApiResponse<JwtResult>`:
  ```json
  {
    "success": true,
    "message": "Refresh successful",
    "data": {
      "access_token": "string",
      "refresh_token": "string",
      "expires_in": 600
    }
  }
  ```
- `500 Internal Server Error` — missing/invalid/expired/not-found token, or DB error
  (all JWT errors currently collapse to 500; no 4xx distinction is made here).

### `POST /authn/jwt/logout`
**Body:** `{ "refresh_token": "string" }`
Revokes (soft-deletes) the given refresh token. Idempotent — revoking an
already-revoked/unknown token still succeeds.

**Responses**
- `200 OK` — `ApiResponse<()>`, `"Logged out successfully"`.
- `500 Internal Server Error` — DB error.

---

## 6. Session-Protected Account Routes (`/authn/me`)

All routes in this section require a valid `session` cookie
(`SessionMiddleware`) and expose the caller's identity via the `Session<User>`
extractor.

### `POST /authn/me/jwt`
Mint a fresh JWT access/refresh pair for the currently-logged-in session
(issuer tag: `"session"`).

**Response:** `200 OK` — raw `JwtResult` (not wrapped in `ApiResponse`):
```json
{ "access_token": "string", "refresh_token": "string", "expires_in": 600 }
```

### `POST /authn/me/logout`
Logs out the current session (deletes it from the store using the `session` cookie).

**Response:** `200 OK` — `ApiResponse<()>`, `"Logged out successfully"`.

### `GET /authn/me/account`
Returns the caller's identity — a simple "am I authenticated" probe.

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "Protected data retrieved successfully",
  "data": { "user_id": "uuid", "message": "Access granted to protected route" }
}
```

### `POST /authn/me/change_password`
**Body**
```json
{ "current_password": "string", "new_password": "string" }
```

Verifies the current password, sets the new one, then:
1. Revokes **all** of the user's sessions.
2. Issues a **new** session for the calling device (so it isn't logged out by its own request) and sets a fresh `session` cookie.
3. Revokes **all** of the user's refresh tokens.

**Responses**
- `200 OK`, `Set-Cookie: session=<new uuid>` — `ApiResponse<()>`, `"Password changed successfully"`.
- `400/401` — wrong current password / validation error.
- `500` — DB/hashing/role-lookup failure.

### `GET /authn/me/sessions`
List the caller's own active sessions (server-side filter forces
`sub == caller`, so a query-string `sub=` override is redundant but harmless).
Accepts the same `?field=value` / `?search=` / `?sort=` query params described
in §7 below (any of `Session`'s filterable/sortable columns).

**Note:** unlike the admin viewsets in §7, this handler calls
`Repository::list()` **directly** rather than going through a `ViewSet` —
so the response is the repository's raw `(Vec<Entity>, total_count)` tuple,
which `serde_json` renders as a **2-element array**, not the `Page<T>` object
used everywhere else:

```json
[
  [
    {
      "id": "uuid",
      "created_at": "timestamp",
      "sub": "uuid",
      "username": "string",
      "email": "string",
      "role": "uuid (u128 packed into a UUID)",
      "expires_at": "timestamp",
      "ip_address": "string"
    }
  ],
  1
]
```
The first element is the array of session rows; the second is the total
matching count (ignoring pagination). There is no pagination applied to the
returned array itself — `page`/`page_size` in the query string only affect
`LIMIT`/`OFFSET` in the underlying SQL.

**Response:** `200 OK` on success, `500 Internal Server Error` on a list failure.

### `DELETE /authn/me/delete_session/{id}`
Revoke one of the caller's own sessions by session id.

**Responses**
- `200 OK` — deleted.
- `403 Forbidden` — the session belongs to a different user.
- `500 Internal Server Error` — lookup/delete failure.

---

## 7. Admin Routes (`/authn/me/admin`)

Nested under `/me` (so a valid session is required) **and** additionally wrapped
in `Permissions::<User>` — the caller's role bitmask must satisfy the policy
configured in `permissions.json` for these paths.

Both sub-resources are exposed as standard CRUD **viewsets** (list/get/create/put/patch/delete
generated by the shared `viewset` crate's `DefaultViewSet::configure`, from the
`#[derive(Entity)]` structs). Exact routes:

| Method | Path | Effect | Success status |
|---|---|---|---|
| `GET` | `/{resource}` | list, paginated | `200 OK` — `Page<ResponseDto>` |
| `POST` | `/{resource}` | create | `201 Created` — `ResponseDto` |
| `GET` | `/{resource}/{id}` | retrieve one | `200 OK` — `ResponseDto` |
| `PUT` | `/{resource}/{id}` | update | `200 OK` — `ResponseDto` |
| `PATCH` | `/{resource}/{id}` | update | `200 OK` — `ResponseDto` |
| `DELETE` | `/{resource}/{id}` | delete | `204 No Content` |

`{id}` is parsed as the entity's declared id type (a `Uuid` for both resources
below) — a malformed id returns `422 Unprocessable Entity`. Errors otherwise
follow the `ApiError` table in §3.

**`PUT` and `PATCH` are functionally identical** here — both route to the same
`update` handler and both deserialize into the same `UpdateDto`, whose fields
are all `Option<T>` with `skip_serializing_if = "Option::is_none"`. There is no
"full replace" semantic: an omitted field in either verb leaves that column
untouched. Send only the fields you want to change, regardless of which of
the two methods you use.

**List query parameters** (`GET /{resource}`), read by the underlying
`Repository::list`:

| Param | Effect |
|---|---|
| `page` | 1-based page number (default `1`) |
| `page_size` | rows per page (default `25`, clamped to `1..=200`) |
| `sort` | comma-separated column list; prefix a column with `-` for `DESC` (e.g. `sort=-created_at,username`). Only columns declared `#[entity(sortable)]` are honored — others are silently dropped. |
| `search` | ILIKE `%value%` match, OR'd across every `#[entity(searchable)]` column. No-op if the entity declares no searchable columns. |
| any other `field=value` | exact-match filter — only applied if `field` is declared `#[entity(filterable)]`; unknown/non-filterable keys are silently ignored (not an error). |

**List response shape** (`Page<T>`):
```json
{
  "items": [ /* ResponseDto */ ],
  "page": 1,
  "page_size": 25,
  "total": 42,
  "total_pages": 2
}
```

### `/authn/me/admin/users`
Backed by the `User` entity (`id`, `username` [searchable/sortable/filterable],
`email` [sortable/filterable], `created_at` [sortable], `password_hash`, `updated_at`).
Responses are shaped as `UserDto { id, username, email }` (password hash never serialized out).

- `POST` (create) is explicitly disabled via a `before_create` hook — returns
  `422 Unprocessable Entity`, `{"error": "manual create not allowed, use registration endpoint"}`.
- `PUT`/`PATCH` accept a partial `{ username?, email? }` body (`UpdateUser`).

### `/authn/me/admin/sessions`
Backed by the `Session` entity (columns as shown under §6 "List sessions"), but
**not** scoped to the caller — an admin can list/get/delete *any* user's
sessions, and (unlike `/me/sessions`) this route does go through the full
viewset, so `GET /authn/me/admin/sessions` returns the paginated `Page<Session>`
envelope described above, not the `[items, total]` tuple from §6.

- `POST` (create) is disabled via `before_create` — `422 Unprocessable Entity`,
  `{"error": "manual create not allowed, use login endpoint"}`. Sessions can
  only be created by logging in.
- `PUT`/`PATCH` accept an `ActiveUser` (`crate::models::User`) body per the
  entity's `create = "ActiveUser"` attribute — in practice there's little
  reason to hand-edit a session this way; prefer `DELETE` to revoke one.

---

## 8. Passwordless Login (`/authn/passwordless`)

Public routes. Rate-limited (100 requests / 60s per client IP, via
`RateLimiter<ClientIp>`) and behind `ClientIpMiddleware` (trusts `PROXIES` env
var for real-IP resolution behind reverse proxies).

Challenges are dual-purpose: a **magic link** and a **6-digit OTP** are issued
together for the same login attempt; either one confirms it.

### `POST /authn/passwordless/challenge/email`
**Body:** `{ "email": "string" }`
Issues a link+OTP challenge for the account with this email and publishes it to
the event bus (e.g. for an email-delivery subscriber — the raw link/token are
never returned in the response).

**Responses**
- `201 Created` — empty body.
- `400` — bad token state / `404` — user not found / `500` — DB error
  (via `translate_error`; body is a plain error string, not JSON).

### `GET /authn/passwordless/challenge/username/{username}`
Same as above, by username instead of email.

### `GET /authn/passwordless/confirm_link/{link}`
Confirm via the magic-link token from the URL. On success, logs the user in
exactly like password login: issues a session and sets the `session` cookie.

**Responses**
- `200 OK`, `Set-Cookie: session=<uuid>` — empty body.
- `400 Bad Request` — invalid/expired token.
- `404 Not Found` — user not found.
- `500` — DB error / role lookup / session issuance failure.

### `POST /authn/passwordless/confirm_token`
**Body:** `{ "token": <6-digit number>, "nonce": "string" }`
Confirm via the OTP. Same success/failure semantics and side effects as `confirm_link`.

---

## 9. Passkeys / WebAuthn (`/authn/passkey`)

Only mounted when the crate's `passkey` feature is enabled. Registration and
credential management require an existing session (passkeys are *added* to an
account, never used to create one); login/start and login/finish are public
(no session exists yet at that point).

All error responses use the `{ "error": "string" }` shape.

### `POST /authn/passkey/register/start`  *(session required)*
Begins WebAuthn registration ceremony for the caller's account. Excludes any
authenticators already registered to the account (`exclude_credentials`).

**Response:** `200 OK` — WebAuthn `CreationChallengeResponse` (standard WebAuthn JSON, passed straight to `navigator.credentials.create()`).

### `POST /authn/passkey/register/finish?label=<optional>`  *(session required)*
**Body:** WebAuthn `RegisterPublicKeyCredential` (the browser's `create()` result).
Verifies and persists the new credential. `label` is a purely cosmetic name
shown back via the list endpoint.

**Responses**
- `200 OK` — `{ "status": "success", "message": "Passkey registered" }`.
- `400 Bad Request` — no registration in progress / expired / WebAuthn verification failure.
- `500 Internal Server Error` — persistence failure.

### `GET /authn/passkey/register`  *(session required)*
List the caller's registered passkeys (metadata only — for an account-settings view).

**Response:** `200 OK` — JSON array of credential metadata rows.

### `DELETE /authn/passkey/register/{id}`  *(session required)*
Remove one of the caller's passkeys by its row id (from the list endpoint).

**Responses**
- `200 OK` — `{ "status": "success" }`.
- `404 Not Found` — passkey not found (or belongs to a different user).
- `500` — deletion failure.

### `POST /authn/passkey/login/start`  *(public)*
**Body:** `{ "username": "string" }`
Begins a passkey login ceremony. Returns the same generic error whether the
account doesn't exist or simply has no passkeys, to avoid username enumeration.

**Responses**
- `200 OK` — WebAuthn `RequestChallengeResponse`.
- `400 Bad Request` — empty username / no passkeys registered / WebAuthn error.

### `POST /authn/passkey/login/finish?username=<name>`  *(public)*
**Body:** WebAuthn `PublicKeyCredential` (the browser's `get()` result).
Verifies the assertion, updates the stored authenticator's signature counter
(clone detection), and — on success — issues a session exactly like any other
login method.

**Responses**
- `200 OK`, `Set-Cookie: session=<uuid>` — empty body.
- `400 Bad Request` — no authentication in progress / expired / verification failure.
- `500 Internal Server Error` — role lookup / session issuance failure.

---

## 10. Username Lookup

### `GET /authn/user_id/username/{username}`
**Response:** `200 OK` — the user's UUID as a raw text body (not JSON).
`404 Not Found` if the username doesn't exist or the query fails.

---

## 11. Authorization Service (`/authz`)

Mounted at the top level (outer scope), behind the global
`Permissions::<User>` + `SessionMiddleware` wrap in `main.rs` — i.e. **every**
route below requires a valid session, and (except `claim`, which checks
identity directly) is additionally gated by the global permission policy.

### `POST /authz/admin/grant`
**Body:** `{ "permission": 0-127, "target": "uuid" }`
Sets bit `permission` in `target`'s role bitmask (OR).

**Responses**
- `200 OK` — `{ "success": true, "new_role": <u128> }`.
- `400 Bad Request` — `{ "success": false, "error": "invalid operation" }` (permission > 127).
- `500 Internal Server Error` — DB error.

### `POST /authz/admin/deny`
**Body:** `{ "permission": 0-127, "target": "uuid" }`
Clears bit `permission` in `target`'s role bitmask (AND NOT), then revokes
**all** of the target user's active sessions (so the change takes effect immediately).

**Responses**
- `200 OK` — `{ "success": true, "new_role": <u128> }`.
- `406 Not Acceptable` — plain text: permission wasn't previously granted / operation failed.
- `500 Internal Server Error` — DB error.

### `POST /authz/admin/claim`  *(session required)*
No body. Lets one specific pre-designated account (its id set via the `ADMIN`
env var) elevate its **current session's** in-memory role to `u128::MAX`
(all permissions). This only affects the live session object, not the
persisted `grants` row.

**Responses**
- `200 OK` — success.
- `404 Not Found` — `ADMIN` env var missing/invalid.
- `406 Not Acceptable` — caller is not the designated admin account.

### `/authz/admin/grants` (viewset)
Raw CRUD access to the `grants` table (`Absolute { to_id (pk), role }`) via the
same generic viewset pattern described in §7 — full `GET`/`POST`/`GET {id}`/
`PUT {id}`/`PATCH {id}`/`DELETE {id}` on `to_id` as the id. `GET` (list/retrieve)
and `DELETE` work as expected. Neither `to_id` nor `role` is declared
searchable/sortable/filterable on `Absolute`, so `?search=`, `?sort=`, and
`?field=value` on the list endpoint have no effect here — only `?page`/`?page_size` do.

**`POST`/`PUT`/`PATCH` are effectively non-functional as written.** Unlike
`/me/admin/users` and `/me/admin/sessions`, create/update aren't explicitly
disabled here — but the entity is declared `#[entity(create = "PermissionReq",
update = "PermissionReq")]`, and column binding works by **matching the DTO's
serialized JSON key names against the entity's column names** (§7's SQL-typing
note). `PermissionReq`'s fields are `permission`/`target`; `Absolute`'s columns
are `to_id`/`role`. None of those names match, so `insert_columns`/
`update_columns` resolve to an **empty column list** for every request
regardless of body content — the request will either fail at the database
(missing required columns) or silently write nothing, depending on the
generated SQL's handling of a zero-column insert/update. In practice, granting
and revoking permissions should go through `POST /authz/admin/grant` /
`POST /authz/admin/deny` (§11 above), which apply the correct bitwise
semantics directly — not through this viewset's write routes.

---

## 12. Reverse Proxy (fallback route)

Any request that doesn't match `authn` or `authz` falls through to
`default_service`, which requires a valid session (`Session<User>` extractor)
and forwards the request to the `UPSTREAM` base URL, preserving path, query
string, method, and body.

**Identity assertion:** the proxy strips any client-supplied
`X-User-Id` / `X-User-Email` / `X-User-Name` headers (so a caller can never
spoof another identity) and re-adds them itself from the authenticated
session before forwarding — these three headers are the trusted identity
contract between this service and whatever it proxies to.

**Responses:** the upstream's status code, headers, and body are passed
through unchanged. `502 Bad Gateway` if the upstream request or its response
body fails.

---

## 13. Environment Variables Referenced

| Variable | Used by | Purpose |
|---|---|---|
| `DATABASE_URL` | startup | Postgres connection string |
| `signer.secret`, `signer.aud` | `AuthModule::new` | HS256 signing key + audience for access tokens |
| `AUD` | `JwtService::new` | comma-separated list of valid token audiences |
| `PROXIES` | passwordless `config` | trusted proxy CIDRs for real client-IP resolution |
| `ADMIN` | `authz::claim_admin` | UUID of the account allowed to self-elevate to full permissions |
| `UPSTREAM` | `Proxy::new` | base URL the fallback proxy forwards to |
| `permissions.json` (file, not env) | startup | RBAC policy consumed by `Permissions::<User>` middleware |

---

## 14. Notes on Coverage

This documentation is generated from the `authnz` service source plus its two
first-party dependencies, `viewset` and `actixutils` (all three provided as
source). Every route, status code, and query-parameter behavior above —
including §7/§11's CRUD tables, the `Permissions` default-deny policy, the
`ResponseEqualizer`/`RateLimiter` semantics, and the JWT expiry discrepancy in
§2.2 — is verified directly against those crates' implementations, not
inferred from call sites. `typed-eventbus` (used for the password-reset and
passwordless challenge events) is not included in either archive; its
publish/subscribe wire format is out of scope here since it's internal to the
service and never touches the HTTP API.

### Known quirks worth a maintainer's attention

- **`POST /authn/jwt/refresh`** collapses every failure mode (missing/expired/
  revoked/not-found token, DB error) to a flat `500`, unlike the rest of the
  service's error handling.
- **JWT `expires_in` is wrong** — reports `600` but the token actually expires
  in `500` seconds (§2.2).
- **`GET /authn/me/sessions`** returns a bare `[items, total]` tuple, not the
  `Page<T>` envelope every other list endpoint uses (§6) — inconsistent with
  its near-identical admin counterpart at `/authn/me/admin/sessions`.
- **`/authz/admin/grants`' write routes (`POST`/`PUT`/`PATCH`) don't work** —
  the `PermissionReq` DTO's field names don't match the `Absolute` entity's
  column names, so no columns ever get bound (§11).
