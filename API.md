---

# authnz API Reference

**Version:** 0.1.3 · **Framework:** actix-web 4 · **Base URL:** `/{namespace}` (the module is mounted under a configurable namespace by the host application)

An authentication/authorization service providing password, passwordless (email OTP / magic link), and WebAuthn passkey flows, cookie-based sessions, and JWT access/refresh token pairs.

---

## 1. Conventions

### Authentication

| Mechanism | Where used |
| --- | --- |
| `session` cookie (UUID) | All `/me/**` routes. Issued by every successful login flow. |
| JWT access token | Bearer workflows; issued via `POST /me/jwt`, refreshed via `/jwt/refresh`. |

**Session cookie attributes:** `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`. Sessions are stored server-side (cache-backed) and expire **30 minutes** after issuance.

### Standard envelope

Most endpoints return a JSON envelope:

```json
{ "success": true, "message": "...", "data": { } }
```

Errors use the same shape with `success: false` and `data: null`.

> ⚠️ **Inconsistency note:** passkey endpoints return `{"error": "..."}` and passwordless endpoints return **plain-text** error bodies. See each section.

### Error status codes

| Code | Meaning |
| --- | --- |
| 400 | Validation failure, invalid/expired token, malformed WebAuthn payload |
| 401 | Invalid credentials, invalid token, user not found |
| 403 | Session does not belong to the authenticated user |
| 404 | Resource (session, passkey, user) not found |
| 409 | Username/email already registered |
| 500 | Database, bcrypt, cache, or outbox failure |

---

## 2. Authentication — Password Flow

### Register
`POST /auth/register`

| Field | Type | Rules |
| --- | --- | --- |
| `username` | string | 3–30 chars |
| `email` | string | valid email format |
| `password` | string | min 8 chars (strength additionally checked server-side) |

**201 Created**

```json
{ "success": true, "message": "User registered successfully", "data": { "id": "…", "username": "…", "email": "…", "created_at": "…", "updated_at": "…", "email_confirmed": false } }
```

Errors: `400` validation · `409` user already exists.

### Login (by email)
`POST /auth/login/email`

```json
{ "identifier": "user@example.com", "password": "secret" }
```

**200 OK** — no JSON body; sets the `session` cookie. Errors: `400`, `401`.

### Login (by username)
`POST /auth/login/username` — same body/behavior, but `identifier` is the username.

### Request password reset
`POST /auth/request_password_reset`

```json
{ "email": "user@example.com" }
```

**200 OK** — *always*, whether or not the email exists (anti-enumeration). A reset token is issued out-of-band (published via the transactional outbox as `PasswordResetRequested`).

### Confirm password reset
`POST /auth/confirm_password_reset`

```json
{ "token": "<reset-token>", "new_password": "<new password>" }
```

**200 OK** (empty body). On success **all sessions and refresh tokens for the user are revoked**. Errors: `400`, `401` (invalid token).

> The `/auth/**` scope is wrapped in a `ResponseEqualizer` (~200 ms minimum response time) to blunt timing-based user-enumeration on the login endpoints.

---

## 3. Session Management — `/me` (requires session cookie)

### Get current account
`GET /me/account` → **200**

```json
{ "success": true, "message": "Protected data retrieved successfully",
  "data": { "user_id": "uuid", "username": "…", "email": "…" } }
```

### Logout
`POST /me/logout` — destroys the server-side session and clears the cookie. **200** `{ "success": true, "message": "Logged out successfully" }`. Idempotent (missing/unknown cookie still returns 200).

### Change password
`POST /me/change_password`

```json
{ "current_password": "…", "new_password": "…" }
```

**200 OK** + fresh `session` cookie. Side effects: **all other sessions and all refresh tokens are revoked**; the current device gets a new session so it isn't logged out by its own request. Errors: `400`, `401`.

### List my sessions
`GET /me/sessions` → **200** with a **flat JSON array** (not the paginated envelope):

```json
[ { "id": "uuid", "sub": "uuid", "expires_at": "…", "ip_address": "…", "user_agent": "…" }, … ]
```

(Fields beyond `id` follow the viewset `Session` entity.) Sessions are filtered to the authenticated user.

### Delete a session
`DELETE /me/delete_session/{id}` — owner-only.
**200** deleted · **403** session belongs to another user · **404** not found.

---

## 4. JWT

### Issue token pair
`POST /me/jwt` *(session required)* → **200**

```json
{ "success": true, "message": "JWT issued successfully",
  "data": { "access_token": "…", "refresh_token": "…", "expires_in": 1800 } }
```

Access token is HS256-signed (audience/secret from `signer.aud` / `signer.secret`). Refresh tokens are stored SHA-256-hashed; the raw token is never persisted.

### Refresh
`POST /jwt/logout`… *correction:* `POST /jwt/refresh` *(public)*

```json
{ "refresh_token": "…" }
```

→ **200** with a new `JwtResult` object (same shape as above). Errors: `401` invalid/revoked token, `500`.

### Revoke (JWT logout)
`POST /jwt/logout` *(public)*

```json
{ "refresh_token": "…" }
```

→ **200** `{ "success": true, "message": "Logged out successfully" }`.

---

## 5. Passwordless — `/passwordless` (OTP + magic link)

All four endpoints are **rate-limited to 2 requests / 60 s per client IP** (in-memory sliding window). Trusted proxy CIDRs are read from the `PROXIES` env var for correct client-IP resolution. Challenge material (OTP + link + nonce) is valid for **120 seconds** and is single-use.

### Request challenge by email
`POST /passwordless/challenge/email`

```json
{ "email": "user@example.com" }
```

**201 Created** (empty). Publishes a `ChallengeRequested` event through the transactional outbox; the OTP/link are delivered out-of-band by an email consumer. **404** `User not found` if the email isn't registered.

### Request challenge by username
`GET /passwordless/challenge/username/{username}` → **201 Created** / **404**.

### Confirm with magic link
`GET /passwordless/confirm_link/{link}`

Consumes the link, marks the email confirmed, and issues a session. **200** + `session` cookie. Errors: **400** `Invalid or expired token` · **404** user not found.

### Confirm with OTP
`POST /passwordless/confirm_token`

```json
{ "token": 482913, "nonce": "<nonce from the challenge>" }
```

**200** + `session` cookie (also marks email confirmed). Errors: **400** `Invalid or expired token` · **404** user not found.

> Error bodies in this section are **plain text**, not JSON.

---

## 6. Passkeys (WebAuthn) — `/passkey` — *feature-gated (`passkey` cargo feature)*

Configured via `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_ORIGIN`, optional `WEBAUTHN_RP_NAME`. Ceremony state (challenges) is cached with a **5-minute TTL** and is single-use.

### Start registration — 🔐 auth required
`POST /passkey/register/start` → **200** with WebAuthn `PublicKeyCredentialCreationOptions` JSON. Existing credentials for the account are excluded (no duplicate authenticators). Stores in-progress state keyed by user ID.

### Finish registration — 🔐 auth required
`POST /passkey/register/finish?label=MacBook%20Touch%20ID`

Body: `RegisterPublicKeyCredential` (from `navigator.credentials.create()`).

**200**

```json
{ "status": "success", "message": "Passkey registered" }
```

**400** `{"error": "…"}` — e.g. *"No registration in progress for this account, or it expired."*

### List my passkeys — 🔐 auth required
`GET /passkey/register` → **200**, array of:

```json
[ { "id": "uuid", "label": "YubiKey 5C", "created_at": "…", "last_used_at": "…" } ]
```

### Remove a passkey — 🔐 auth required
`DELETE /passkey/register/{id}` → **200** `{"status":"success"}` · **404** `{"error":"Passkey not found"}`.

### Start login — public
`POST /passkey/login/start`

```json
{ "username": "alice" }
```

→ **200** with WebAuthn `PublicKeyCredentialRequestOptions`. Returns the same error whether the account is missing or has no passkeys (anti-enumeration).

### Finish login — public
`POST /passkey/login/finish?username=alice`

Body: `PublicKeyCredential` (from `navigator.credentials.get()`).

**200** + `session` cookie. On success the per-credential signature counter is updated (clone detection). Errors: **400** (`{"error": "…"}`) — expired/missing ceremony, verification failure.

---

## 7. Admin Viewsets — `/me/admin` (session required)

Generic CRUD viewsets over internal entities. **Create is explicitly disabled** on both (`"manual create not allowed"` — use the registration/login endpoints).

### `/me/admin/users`
Standard viewset operations: list / retrieve / update (`PATCH`) / delete.
- Responses use the safe `UserResponse` shape: `id, username, email, created_at, updated_at, email_confirmed` — **password hashes are never exposed**.
- Update payload (`UpdateUser`): `{ "username"?: string, "email_confirmed"?: bool }`
- `username` is searchable/sortable/filterable; `email` is filterable/sortable (per entity metadata).

### `/me/admin/sessions`
List / retrieve / update / delete over all sessions (audit/support use). Create blocked.

---

## 8. Utility

### Username → user ID
`GET /username2userid/{username}` — resolves a username to its user ID. *(Mounted at the module root; exact response shape is a simple ID payload.)*

---

## 9. Configuration Reference

| Env var | Required | Purpose |
| --- | --- | --- |
| `signer.secret` | ✅ | HS256 JWT signing secret |
| `signer.aud` | ✅ | JWT audience claim |
| `WEBAUTHN_RP_ID` | ✅ *(passkey feature)* | Relying-party ID (e.g. `example.com`) |
| `WEBAUTHN_RP_ORIGIN` | ✅ *(passkey feature)* | RP origin URL (must be a valid URL) |
| `WEBAUTHN_RP_NAME` | ➖ | Display name (defaults to RP ID) |
| `PROXIES` | ➖ | Comma-separated trusted proxy CIDRs for client-IP rate limiting |

---

## 10. Security Notes

- All cookies: `HttpOnly; Secure; SameSite=Strict`.
- Passwords: bcrypt-hashed; min length 8; strength estimated with zxcvbn.
- Refresh tokens stored only as SHA-256 hashes; revocable per-token or per-user.
- Password change/reset triggers **global revocation** of sessions + refresh tokens.
- Passwordless challenges: single-use, 120 s TTL, rate-limited.
- Login timing equalized (200 ms) to reduce user-enumeration via response timing.
- Login/reset endpoints never reveal whether an account exists (generic responses).
- Passkey ceremonies: single-use challenges, 5 min TTL, signature-counter clone detection.

---

