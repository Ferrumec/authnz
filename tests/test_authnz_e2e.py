"""
End-to-end tests for the authnz service.

Scope and philosophy
---------------------
These tests treat authnz as a real client would: everything goes over
real HTTP to a running instance (`AUTHNZ_BASE_URL`, default
http://127.0.0.1:8080), backed by its real Postgres database. There is
no mocking of authnz itself, no importing its Rust internals, and no
poking at the database directly.

The one thing that *is* simulated is the "real backend" that authnz's
gateway/proxy forwards unmatched requests to (`UPSTREAM` in authnz's
own .env) — see `upstream` fixture in conftest.py. That's a legitimate
end of the system under test: authnz's job there is to sit in front of
some other service and assert the caller's identity to it, and the only
way to observe that behavior is to look at what the backend received.

What's intentionally out of scope
----------------------------------
* Passkey / WebAuthn flows require a real authenticator ceremony
  (attestation, signature over a challenge) that can't be faithfully
  produced by a plain HTTP client. `test_passkey_routes_reachable`
  only checks the routes are wired up; a full passkey e2e test belongs
  in a suite that drives a virtual authenticator.
* Password reset / passwordless email flows hand the raw token to an
  event bus (e.g. for an email service to deliver) rather than
  returning it over HTTP — by design, so a network observer or curious
  client can't fish it out. These tests verify the request side
  (correct status codes, no user-enumeration) but can't complete the
  loop without a way to observe what was published, which is
  deployment-specific. If your environment exposes one (e.g. a test
  subscriber), wire it into `capture_published_token` and un-skip
  `test_password_reset_full_round_trip`.
"""
from __future__ import annotations

import time
import uuid

import pytest
import requests

from conftest import (
    BASE_URL,
    DEFAULT_PASSWORD,
    TestUser,
    api,
    authz_api,
    set_session_cookie,
)


# ==========================================================================
# Registration
# ==========================================================================

class TestRegistration:
    def test_register_new_user_succeeds(self, client, unique_user):
        resp = client.post(
            api("/auth/register"),
            json={
                "username": unique_user.username,
                "email": unique_user.email,
                "password": unique_user.password,
            },
            timeout=5,
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["success"] is True

    def test_duplicate_username_is_rejected(self, client, registered_user):
        resp = client.post(
            api("/auth/register"),
            json={
                "username": registered_user.username,
                "email": f"different_{uuid.uuid4().hex[:8]}@example.test",
                "password": DEFAULT_PASSWORD,
            },
            timeout=5,
        )
        assert resp.status_code == 409, resp.text

    def test_weak_password_is_rejected(self, client, unique_user):
        resp = client.post(
            api("/auth/register"),
            json={
                "username": unique_user.username,
                "email": unique_user.email,
                "password": "password",  # short + low entropy
            },
            timeout=5,
        )
        assert resp.status_code == 400, resp.text

    def test_invalid_email_is_rejected(self, client, unique_user):
        resp = client.post(
            api("/auth/register"),
            json={
                "username": unique_user.username,
                "email": "not-an-email",
                "password": DEFAULT_PASSWORD,
            },
            timeout=5,
        )
        assert resp.status_code == 400, resp.text

    def test_username_too_short_is_rejected(self, client, unique_user):
        resp = client.post(
            api("/auth/register"),
            json={"username": "ab", "email": unique_user.email, "password": DEFAULT_PASSWORD},
            timeout=5,
        )
        assert resp.status_code == 400, resp.text


# ==========================================================================
# Login
# ==========================================================================

class TestLogin:
    def test_login_with_email_sets_session_cookie(self, client, registered_user):
        resp = client.post(
            api("/auth/login/email"),
            json={"identifier": registered_user.email, "password": registered_user.password},
            timeout=5,
        )
        assert resp.status_code == 200, resp.text
        raw_cookie_header = resp.headers.get("set-cookie", "")
        assert "session=" in raw_cookie_header
        assert "HttpOnly" in raw_cookie_header
        assert "Secure" in raw_cookie_header
        assert "SameSite=Strict" in raw_cookie_header

    def test_login_with_username(self, client, registered_user):
        resp = client.post(
            api("/auth/login/username"),
            json={"identifier": registered_user.username, "password": registered_user.password},
            timeout=5,
        )
        assert resp.status_code == 200, resp.text
        assert "session=" in resp.headers.get("set-cookie", "")

    def test_login_wrong_password_is_rejected(self, client, registered_user):
        resp = client.post(
            api("/auth/login/email"),
            json={"identifier": registered_user.email, "password": "definitely-wrong-1"},
            timeout=5,
        )
        assert resp.status_code == 401, resp.text
        assert "session" not in resp.headers.get("set-cookie", "")

    def test_login_unknown_user_is_rejected_not_leaked(self, client):
        """An unknown identifier should fail the same way as a wrong
        password — never a distinct error that lets a caller enumerate
        which emails/usernames exist."""
        resp = client.post(
            api("/auth/login/email"),
            json={"identifier": f"ghost_{uuid.uuid4().hex}@example.test", "password": "whatever1"},
            timeout=5,
        )
        assert resp.status_code == 401, resp.text

    def test_auth_scope_has_response_time_floor(self, client, registered_user):
        """`/auth` is wrapped in a ResponseEqualizer(200ms) precisely so a
        network observer can't distinguish a fast failure (bad username)
        from a slow one (bcrypt verify on a real hash) by timing alone.
        Confirm the floor is actually applied."""
        start = time.monotonic()
        client.post(
            api("/auth/login/email"),
            json={"identifier": "nobody-such-user@example.test", "password": "x" * 12},
            timeout=5,
        )
        elapsed = time.monotonic() - start
        assert elapsed >= 0.18, (
            f"expected the auth scope's response-time floor (~200ms) to apply, "
            f"got {elapsed * 1000:.0f}ms"
        )


# ==========================================================================
# Protected routes / sessions
# ==========================================================================

class TestProtectedRoutes:
    def test_account_requires_session(self, client):
        resp = client.get(api("/me/account"), timeout=5)
        assert resp.status_code == 401, resp.text

    def test_garbage_cookie_is_rejected(self, client):
        client.cookies.set("session", "not-a-uuid")
        resp = client.get(api("/me/account"), timeout=5)
        assert resp.status_code == 401, resp.text

    def test_account_returns_the_logged_in_user(self, logged_in):
        client, user = logged_in
        resp = client.get(api("/me/account"), timeout=5)
        assert resp.status_code == 200, resp.text
        assert resp.json()["data"]["user_id"] == user.user_id

    def test_logout_invalidates_the_session(self, logged_in):
        client, _ = logged_in
        resp = client.post(api("/me/logout"), timeout=5)
        assert resp.status_code == 200, resp.text

        after = client.get(api("/me/account"), timeout=5)
        assert after.status_code == 401, after.text

    def test_list_sessions_contains_current_session(self, logged_in):
        client, _ = logged_in
        resp = client.get(api("/me/sessions"), timeout=5)
        assert resp.status_code == 200, resp.text
        sessions = resp.json()
        assert isinstance(sessions, list)
        assert len(sessions) >= 1

    def test_cannot_delete_another_users_session(self, logged_in):
        """The delete-session endpoint must scope by owner, not just by
        session id existing."""
        owner_client, _owner = logged_in

        # A second, independent logged-in user with its own HTTP session —
        # deliberately not the `client` fixture, so it can't accidentally
        # share state with `owner_client`.
        intruder = requests.Session()
        second_user = TestUser(
            username=f"e2e_{uuid.uuid4().hex[:12]}",
            email=f"e2e_{uuid.uuid4().hex[:12]}@example.test",
        )
        intruder.post(
            api("/auth/register"),
            json={
                "username": second_user.username,
                "email": second_user.email,
                "password": second_user.password,
            },
            timeout=5,
        )
        login = intruder.post(
            api("/auth/login/email"),
            json={"identifier": second_user.email, "password": second_user.password},
            timeout=5,
        )
        set_session_cookie(intruder, login)

        owner_sessions = owner_client.get(api("/me/sessions"), timeout=5).json()
        assert owner_sessions, "expected the owner to have at least one session"
        target_id = owner_sessions[0]["id"]

        resp = intruder.delete(api(f"/me/delete_session/{target_id}"), timeout=5)
        assert resp.status_code == 403, resp.text

    def test_own_session_can_be_deleted(self, logged_in):
        client, _ = logged_in
        sessions = client.get(api("/me/sessions"), timeout=5).json()
        target_id = sessions[0]["id"]

        resp = client.delete(api(f"/me/delete_session/{target_id}"), timeout=5)
        assert resp.status_code == 200, resp.text


# ==========================================================================
# JWT issuance / refresh / logout
# ==========================================================================

class TestJwt:
    def test_issue_jwt_from_session(self, logged_in):
        client, _ = logged_in
        resp = client.post(api("/me/jwt"), timeout=5)
        assert resp.status_code == 200, resp.text
        body = resp.json()["data"]
        assert body["access_token"]
        assert body["refresh_token"]
        assert body["expires_in"] > 0

    def test_jwt_requires_a_session(self, client):
        resp = client.post(api("/me/jwt"), timeout=5)
        assert resp.status_code == 401, resp.text

    def test_refresh_returns_a_new_pair(self, logged_in):
        client, _ = logged_in
        issued = client.post(api("/me/jwt"), timeout=5).json()["data"]

        resp = client.post(
            api("/jwt/refresh"),
            json={"refresh_token": issued["refresh_token"]},
            timeout=5,
        )
        assert resp.status_code == 200, resp.text
        refreshed = resp.json()["data"]
        assert refreshed["access_token"]
        assert refreshed["refresh_token"]

    def test_refresh_with_garbage_token_fails(self, client):
        resp = client.post(
            api("/jwt/refresh"),
            json={"refresh_token": "not-a-real-token"},
            timeout=5,
        )
        assert resp.status_code >= 400

    def test_jwt_logout_revokes_refresh_token(self, logged_in):
        client, _ = logged_in
        issued = client.post(api("/me/jwt"), timeout=5).json()["data"]

        logout = client.post(
            api("/jwt/logout"),
            json={"refresh_token": issued["refresh_token"]},
            timeout=5,
        )
        assert logout.status_code == 200, logout.text

        # A revoked refresh token must not mint further tokens.
        again = client.post(
            api("/jwt/refresh"),
            json={"refresh_token": issued["refresh_token"]},
            timeout=5,
        )
        assert again.status_code >= 400, again.text


# ==========================================================================
# Change password / reset password
# ==========================================================================

class TestPasswordManagement:
    def test_change_password_then_login_with_new_password(self, logged_in):
        client, user = logged_in
        new_password = "Qw7!another-strong-one#9"

        resp = client.post(
            api("/me/change_password"),
            json={"current_password": user.password, "new_password": new_password},
            timeout=5,
        )
        assert resp.status_code == 200, resp.text
        # The handler issues a fresh session cookie so the calling device
        # isn't logged out by its own request.
        set_session_cookie(client, resp)

        # Old password must no longer work.
        fresh = requests.Session()
        old_login = fresh.post(
            api("/auth/login/email"),
            json={"identifier": user.email, "password": user.password},
            timeout=5,
        )
        assert old_login.status_code == 401, old_login.text

        # New password does work.
        new_login = fresh.post(
            api("/auth/login/email"),
            json={"identifier": user.email, "password": new_password},
            timeout=5,
        )
        assert new_login.status_code == 200, new_login.text

    def test_change_password_wrong_current_password_rejected(self, logged_in):
        client, _ = logged_in
        resp = client.post(
            api("/me/change_password"),
            json={"current_password": "totally-wrong-1", "new_password": "Zx9!brand-new-pass#1"},
            timeout=5,
        )
        assert resp.status_code == 401, resp.text

    def test_change_password_revokes_other_sessions(self, registered_user):
        """Changing a password from one device must log every *other*
        device out, while the device that made the change stays logged in
        (via the fresh cookie it's issued)."""
        device_a = requests.Session()
        device_b = requests.Session()

        for dev in (device_a, device_b):
            login = dev.post(
                api("/auth/login/email"),
                json={"identifier": registered_user.email, "password": registered_user.password},
                timeout=5,
            )
            set_session_cookie(dev, login)

        new_password = "Zx9!revoke-check-pass#7"
        change = device_a.post(
            api("/me/change_password"),
            json={"current_password": registered_user.password, "new_password": new_password},
            timeout=5,
        )
        assert change.status_code == 200, change.text
        set_session_cookie(device_a, change)

        assert device_a.get(api("/me/account"), timeout=5).status_code == 200
        assert device_b.get(api("/me/account"), timeout=5).status_code == 401

    def test_request_password_reset_always_returns_ok(self, client, registered_user):
        """Must return the same 200 whether or not the email exists, so a
        caller can't use this endpoint to enumerate accounts."""
        real = client.post(
            api("/auth/request_password_reset"),
            json={"email": registered_user.email},
            timeout=5,
        )
        fake = client.post(
            api("/auth/request_password_reset"),
            json={"email": f"nobody_{uuid.uuid4().hex}@example.test"},
            timeout=5,
        )
        assert real.status_code == 200, real.text
        assert fake.status_code == 200, fake.text

    def test_confirm_password_reset_rejects_bad_token(self, client):
        resp = client.post(
            api("/auth/confirm_password_reset"),
            json={"token": "not-a-real-token", "new_password": "Zx9!whatever-pass#3"},
            timeout=5,
        )
        assert resp.status_code >= 400

    @pytest.mark.skip(
        reason=(
            "Requires observing the reset token authnz hands to the event "
            "bus (by design, it is never returned over HTTP). Wire up a "
            "way to capture it for your deployment and remove this skip."
        )
    )
    def test_password_reset_full_round_trip(self, client, registered_user):
        client.post(
            api("/auth/request_password_reset"),
            json={"email": registered_user.email},
            timeout=5,
        )
        token = ...  # capture_published_token(registered_user.email)
        new_password = "Zx9!post-reset-pass#8"
        confirm = client.post(
            api("/auth/confirm_password_reset"),
            json={"token": token, "new_password": new_password},
            timeout=5,
        )
        assert confirm.status_code == 200, confirm.text

        login = client.post(
            api("/auth/login/email"),
            json={"identifier": registered_user.email, "password": new_password},
            timeout=5,
        )
        assert login.status_code == 200


# ==========================================================================
# Passwordless (request side only — see module docstring)
# ==========================================================================

class TestPasswordless:
    def test_email_challenge_for_real_user_is_accepted(self, client, registered_user):
        resp = client.post(
            api("/passwordless/challenge/email"),
            json={"email": registered_user.email},
            timeout=5,
        )
        assert resp.status_code == 201, resp.text

    def test_confirm_token_rejects_garbage(self, client):
        resp = client.post(
            api("/passwordless/confirm_token"),
            json={"token": 111111, "nonce": "not-a-real-nonce"},
            timeout=5,
        )
        assert resp.status_code == 400, resp.text

    def test_confirm_link_rejects_garbage(self, client):
        resp = client.get(api("/passwordless/confirm_link/not-a-real-link"), timeout=5)
        assert resp.status_code == 400, resp.text


# ==========================================================================
# Passkey (routes present, full ceremony out of scope — see module docstring)
# ==========================================================================

class TestPasskeyRoutesReachable:
    def test_passkey_login_start_is_reachable_if_feature_enabled(self, client):
        resp = client.post(api("/passkey/login/start"), json={"username": "nobody"}, timeout=5)
        if resp.status_code == 404:
            pytest.skip("service was built without the `passkey` feature")
        assert resp.status_code < 500, resp.text


# ==========================================================================
# Authorization: admin-only endpoints must actually be gated
# ==========================================================================

class TestAuthorization:
    def test_ordinary_user_cannot_list_admin_users(self, logged_in):
        client, _ = logged_in
        resp = client.get(api("/me/admin/users"), timeout=5)
        assert resp.status_code == 403, resp.text

    def test_ordinary_user_cannot_grant_permissions(self, logged_in):
        client, user = logged_in
        resp = client.post(
            authz_api("/admin/grant"),
            json={"target": user.user_id, "bit_id": 100},
            timeout=5,
        )
        assert resp.status_code in (401, 403), resp.text

    def test_ordinary_user_cannot_claim_admin_without_matching_id(self, logged_in):
        client, _ = logged_in
        resp = client.post(authz_api("/admin/claim"), timeout=5)
        # 404 (no ADMIN configured) or 406 (id doesn't match) — either way,
        # not success.
        assert resp.status_code in (404, 406), resp.text

    @pytest.mark.skip(
        reason=(
            "Needs real credentials for the account matching AUTHNZ_ADMIN_ID "
            "in your deployment. Fill in a login step for that account, then "
            "assert GET /authn/me/admin/users returns 200 and POST "
            "/authz/admin/grant succeeds against a target user."
        )
    )
    def test_configured_admin_can_list_admin_users(self, client):
        pass


# ==========================================================================
# The proxy/gateway: identity headers must be asserted, never trusted
# ==========================================================================

class TestProxyIdentityAssertion:
    """authnz's default_service forwards anything that doesn't match an
    authn/authz route to UPSTREAM, after requiring a valid session and
    stamping X-User-Id/-Email/-Name. This is the core security property
    of the whole gateway: a client must never be able to forge those
    headers, and every proxied request must require a real session."""

    # NOTE: these tests assume that the role/permission ACL (from
    # permissions.json) only *restricts* the specific admin-ish routes it
    # lists, and otherwise lets an authenticated request through to the
    # proxy — which is the only reading consistent with the proxy's
    # purpose (letting ordinary logged-in users reach the real backend at
    # all). If your deployment's permission model instead default-denies
    # unlisted routes, `test_proxy_forwards_authenticated_request_with_correct_identity`
    # will need a permission grant fixture first.

    def test_proxied_request_requires_a_session(self, client, upstream):
        resp = client.get(f"{BASE_URL}/some/backend/route", timeout=5)
        assert resp.status_code == 401, resp.text
        assert not upstream.captured, "upstream should never have been called"

    def test_proxy_forwards_authenticated_request_with_correct_identity(self, logged_in, upstream):
        client, user = logged_in
        resp = client.get(
            f"{BASE_URL}/some/backend/route?x=1",
            timeout=5,
        )
        assert resp.status_code == 200, resp.text

        seen = upstream.last()
        assert seen.method == "GET"
        assert seen.path == "/some/backend/route?x=1"
        assert seen.headers.get("x-user-id") == user.user_id
        assert seen.headers.get("x-user-email") == user.email
        assert seen.headers.get("x-user-name") == user.username

    def test_proxy_strips_client_supplied_identity_headers(self, logged_in, upstream):
        """A caller must not be able to impersonate another user by simply
        setting X-User-Id themselves — the gateway must overwrite it with
        the identity from the real session, unconditionally."""
        client, user = logged_in
        spoofed_id = str(uuid.uuid4())
        resp = client.get(
            f"{BASE_URL}/some/backend/route",
            headers={
                "X-User-Id": spoofed_id,
                "X-User-Email": "attacker@example.test",
                "X-User-Name": "attacker",
            },
            timeout=5,
        )
        assert resp.status_code == 200, resp.text

        seen = upstream.last()
        assert seen.headers.get("x-user-id") == user.user_id
        assert seen.headers.get("x-user-id") != spoofed_id
        assert seen.headers.get("x-user-email") == user.email
        assert seen.headers.get("x-user-name") == user.username

    def test_proxy_forwards_method_and_body(self, logged_in, upstream):
        client, _ = logged_in
        payload = {"hello": "world", "n": 42}
        resp = client.post(
            f"{BASE_URL}/some/backend/create",
            json=payload,
            timeout=5,
        )
        assert resp.status_code == 200, resp.text

        seen = upstream.last()
        assert seen.method == "POST"
        assert seen.path == "/some/backend/create"
        import json as _json

        assert _json.loads(seen.body) == payload
