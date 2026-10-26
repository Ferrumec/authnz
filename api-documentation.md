**AuthNZ API Documentation** (v0.1.2)

This is a Rust (Actix-web) authentication & session library providing:

- Password-based registration / login
- Cookie-based sessions
- JWT access + refresh tokens
- Password reset
- Passwordless (email/OTP / magic-link) authentication
- Optional WebAuthn / Passkey support (`passkey` feature)
- Session management and basic admin viewsets

All routes are mounted under a configurable **namespace** (passed to `AuthModule::configure`). In the examples below the namespace is shown as `{ns}`.

**Common response envelope**

```json
{
  "success": true|false,
  "message": "string",
  "data": <T> | null
}
```

Many endpoints return this shape. Some (especially successful logins) return only a `Set-Cookie` header or a raw body.

**Authentication**

- **Session cookie**: `session=<uuid>` (HttpOnly, Secure, SameSite=Strict). Required for `/me/*` routes.
- **JWT**: Issued via `POST {ns}/me/jwt`. Use as Bearer token where the host application expects it.
- Protected routes use `SessionMiddleware` (or the passkey handlers’ own extractors).

---

### Public Authentication Routes

#### Register

`POST {ns}/auth/register`

**Request body**
```json
{
  "username": "string (3–30 chars)",
  "email": "valid email",
  "password": "string (min 8 chars)"
}
```

**Responses**
- `201 Created` – `{ success, message, data }` (user created)
- `400 Bad Request` – validation error
- `409 Conflict` – username already exists

#### Login (email identifier)

`POST {ns}/auth/login/email`

**Request body**
```json
{
  "identifier": "email or username",
  "password": "string"
}
```

**Response**
- `200 OK` + `Set-Cookie: session=<uuid>`
- `401 Unauthorized` – invalid credentials

#### Login (username)

`POST {ns}/auth/login/username`

Same body and responses as the email login endpoint (uses username lookup).

#### Request Password Reset

`POST {ns}/auth/request_password_reset`

**Request body**
```json
{
  "email": "user@example.com"
}
```

**Response**
- Always `200 OK` with message `"If the account exists, a reset link has been sent"` (no user enumeration).

#### Confirm Password Reset

`POST {ns}/auth/confirm_password_reset`

**Request body**
```json
{
  "token": "reset-token-from-email",
  "new_password": "string"
}
```

**Responses**
- `200 OK` (empty body) – password changed; all sessions & refresh tokens revoked
- `401` / `400` – invalid/expired token or weak password

#### Username → User ID lookup

`GET {ns}/user_id/username/{username}`

**Response**
- `200 OK` – plain text UUID
- `404 Not Found`

---

### JWT Routes

#### Logout (revoke refresh token)

`POST {ns}/jwt/logout`

**Request body**
```json
{
  "refresh_token": "string"
}
```

**Response**
- `200 OK` – `{ success: true, message: "Logged out successfully", data: null }`

#### Refresh access token

`POST {ns}/jwt/refresh`

**Request body**
```json
{
  "refresh_token": "string"
}
```

**Response**
- `200 OK`
```json
{
  "success": true,
  "message": "Refresh successful",
  "data": {
    "access_token": "...",
    "refresh_token": "...",
    "expires_in": 3600
  }
}
```

---

### Protected Routes (`/me/*`)

All require a valid `session` cookie (via `SessionMiddleware`).

#### Issue JWT pair

`POST {ns}/me/jwt`

**Response**
```json
{
  "success": true,
  "message": "JWT issued successfully",
  "data": {
    "access_token": "...",
    "refresh_token": "...",
    "expires_in": <seconds>
  }
}
```

#### Logout (session)

`POST {ns}/me/logout`

Clears the session cookie and destroys the server-side session.

**Response**
```json
{
  "success": true,
  "message": "Logged out successfully",
  "data": null
}
```

#### Account info (protected probe)

`GET {ns}/me/account`

**Response**
```json
{
  "success": true,
  "message": "Protected data retrieved successfully",
  "data": {
    "user_id": "uuid",
    "message": "Access granted to protected route"
  }
}
```

#### Change password

`POST {ns}/me/change_password`

**Request body**
```json
{
  "current_password": "string",
  "new_password": "string"
}
```

**Behaviour**
- Validates current password
- Updates password
- Revokes **all** existing sessions and refresh tokens for the user
- Issues a **new** session cookie for the current device

**Response**
- `200 OK` + new `session` cookie + success envelope

#### List own sessions

`GET {ns}/me/sessions`

**Response** – flat JSON array of session objects (each containing at least an `id` field).

#### Delete a session

`DELETE {ns}/me/delete_session/{id}`

- Only the owner can delete their own session.
- `200 OK` on success / already deleted
- `403 Forbidden` if the session belongs to another user
- `404 Not Found`

---

### Passwordless Authentication

Mounted at `{ns}/passwordless`. Rate-limited (2 requests / 60 s per client IP) and protected by client-IP middleware.

#### Challenge by email

`POST {ns}/passwordless/challenge/email`

**Request body**
```json
{
  "email": "user@example.com"
}
```

**Response**
- `201 Created` (empty) – challenge issued (email / outbox event)
- Error statuses for DB / not-found cases

#### Challenge by username

`GET {ns}/passwordless/challenge/username/{username}`

Same behaviour as the email challenge.

#### Confirm via magic link

`GET {ns}/passwordless/confirm_link/{link}`

- Validates the one-time link
- Marks email as confirmed
- Issues a session cookie

**Response**
- `200 OK` + `Set-Cookie: session=<uuid>`

#### Confirm via OTP + nonce

`POST {ns}/passwordless/confirm_token`

**Request body**
```json
{
  "token": 123456,   // 6-digit OTP
  "nonce": "string"
}
```

**Response**
- `200 OK` + session cookie (same as link confirm)

Tokens/links are short-lived (≈ 120 s) and single-use.

---

### Passkey / WebAuthn (feature = `"passkey"`)

Mounted at `{ns}/passkey`. Registration endpoints require an authenticated session; login endpoints are public.

#### Start registration

`POST {ns}/passkey/register/start`

Requires session. Returns WebAuthn `PublicKeyCredentialCreationOptions`.

#### Finish registration

`POST {ns}/passkey/register/finish?label=OptionalDeviceName`

**Body**: WebAuthn `RegisterPublicKeyCredential` JSON.

Persists the credential against the current user.

#### List registered passkeys

`GET {ns}/passkey/register`

Returns the list of credentials for the authenticated user.

#### Remove a passkey

`DELETE {ns}/passkey/register/{id}`

#### Start login

`POST {ns}/passkey/login/start`

**Request body**
```json
{
  "username": "string"
}
```

Returns WebAuthn authentication options.

#### Finish login

`POST {ns}/passkey/login/finish?username=...`

**Body**: WebAuthn `PublicKeyCredential` assertion.

On success issues a session cookie (same pattern as password login).

---

### Admin Viewsets (under `/me/admin`)

Protected by the same session middleware.

- `{ns}/me/admin/users` – CRUD-style viewset for users (powered by `viewset`)
- `{ns}/me/admin/sessions` – session management viewset

These follow the standard `viewset` conventions (list/filter/sort, retrieve, update, delete, etc.).

---

### Error Mapping (AuthError → HTTP)

| Error                        | Status          |
|-----------------------------|-----------------|
| MissingCredentials / PasswordTooShort | 400 Bad Request |
| InvalidCredentials / InvalidToken / UserNotFound | 401 Unauthorized |
| UserAlreadyExists           | 409 Conflict    |
| Database / Bcrypt / Cache   | 500 Internal Server Error |

Passwordless-specific errors map to 400 / 404 / 500 as appropriate.

---

### Notes for Integrators

- The library is designed to be mounted into a larger Actix-web application via `ferrumec::Module`.
- Environment variables required: `signer.secret`, `signer.aud`.  
  Passkey feature additionally needs `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN`.
- Sessions have sliding expiration (default ~1 h on issue; middleware extends on use).
- Password changes and resets revoke **all** sessions and refresh tokens for the user.
- Passwordless challenges publish events via a transactional outbox (email delivery is external).
- Rate limiting and response-time equalization are applied on sensitive public endpoints.

This documentation is derived directly from the handlers, models, and routing configuration present in the `authnz` crate.
