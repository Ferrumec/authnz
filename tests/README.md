# authnz end-to-end test suite

Black-box tests that talk to a **running** authnz instance purely over real
HTTP — the same way a browser, mobile app, or any other real client would.
Nothing here imports the Rust source, mocks the service, or touches its
database directly.

## What it covers

- **Registration** — success, duplicate username/email, weak password,
  invalid email/username validation.
- **Login** — email login, username login, wrong password, unknown user
  (no enumeration), session cookie flags (`HttpOnly`, `Secure`,
  `SameSite=Strict`), and the `/auth` scope's timing-attack mitigation
  (response-time floor).
- **Protected routes / sessions** — cookie required, garbage cookie
  rejected, `/me/account` identity, logout, listing sessions, deleting
  your own session vs. someone else's (must be `403`).
- **JWT** — issuing a pair from a session, refresh, revoking on
  `/jwt/logout`, rejecting garbage refresh tokens.
- **Password management** — change password (+ old password stops
  working, other devices get logged out, the changing device doesn't),
  wrong current password, password-reset request never leaking whether
  an account exists.
- **Passwordless** — request-side behavior for email/username challenges
  and rejection of bad tokens/links.
- **Authorization** — ordinary users are denied admin-only routes on both
  the authn and authz sides.
- **The proxy/gateway** — the core security property of the whole
  service: unauthenticated requests to the proxied backend are rejected,
  authenticated requests are forwarded with the *real* identity headers
  (`X-User-Id`/`-Email`/`-Name`), and any client-supplied copies of those
  headers are stripped and overwritten rather than trusted.

See the module docstring in `test_authnz_e2e.py` for what's deliberately
**out of scope** (full passkey ceremonies, and the tail end of the
password-reset flow, since the reset token is only ever handed to an
event bus, never returned over HTTP).

## Running it

1. Have a real instance of the service up, with a real, migrated Postgres
   database behind it (run the SQL files under `migrations/`), reachable
   at the URL you'll pass as `AUTHNZ_BASE_URL`.
2. `pip install -r requirements.txt`
3. Run:

   ```bash
   AUTHNZ_BASE_URL=http://127.0.0.1:8080 pytest -v
   ```

By default the suite also binds a tiny local HTTP server on
`127.0.0.1:8000` (matching `UPSTREAM` in the checked-in `.env`) to stand
in for the real backend the gateway proxies to, purely so the proxy tests
can inspect what the backend received. If your real upstream already owns
that port, set `AUTHNZ_MANAGE_UPSTREAM=0` to skip those tests instead of
fighting over the port, or point `AUTHNZ_UPSTREAM_HOST`/`AUTHNZ_UPSTREAM_PORT`
at a free one and repoint the service's `UPSTREAM` env at it for the test
run.

See the docstring at the top of `conftest.py` for the full list of
environment variables.

## Notes on some deliberate choices

- **Cookies over plain HTTP in local dev.** The service marks its session
  cookie `Secure`. If you're testing against a plain-`http://` instance
  (typical for local/dev), a strictly-correct HTTP client won't replay
  that cookie on later requests — a real browser wouldn't either, over
  plain HTTP. The suite works around this deliberately (see
  `set_session_cookie` in `conftest.py`) so the rest of the flow can be
  exercised locally; it does not indicate a way to bypass `Secure` when
  actually talking over HTTPS.
- **The proxy tests' permission assumption** is documented inline in
  `TestProxyIdentityAssertion` — they assume the permission ACL only
  restricts the specific routes listed in `permissions.json` and
  otherwise lets an authenticated request through. If that's wrong for
  your deployment, that test will fail with a `403` and is worth treating
  as a real finding, not a flaky test.
