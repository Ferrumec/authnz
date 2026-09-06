"""
Shared fixtures for the authnz end-to-end test suite.

These tests are black-box: they only ever talk to the service over real
HTTP, the same way a real client would. Nothing here reaches into the
database, imports Rust code, or mocks any part of the service itself.

Configuration (all optional, sensible defaults for local dev):

    AUTHNZ_BASE_URL        Base URL of the running authnz service.
                           Default: http://127.0.0.1:8080

    AUTHNZ_UPSTREAM_HOST   Host/port the test double for the proxied
    AUTHNZ_UPSTREAM_PORT   "real backend" (UPSTREAM in authnz's .env)
                           binds to, so proxy tests can inspect what
                           the backend actually received.
                           Default: 127.0.0.1 / 8000 (matches the
                           checked-in .env: UPSTREAM=http://localhost:8000)

    AUTHNZ_MANAGE_UPSTREAM Set to "0" if something else already owns
                           the upstream port (e.g. the real backend is
                           running there) and proxy tests should be
                           skipped instead of binding it themselves.
                           Default: "1"

    AUTHNZ_ADMIN_ID        UUID of a user pre-provisioned as the
                           bootstrap admin (matches the service's
                           ADMIN env var). Optional — admin-only tests
                           are skipped if not set.

Run with the service (and its real Postgres database, migrated) already
up and reachable at AUTHNZ_BASE_URL.
"""
from __future__ import annotations

import os
import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

import pytest
import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

BASE_URL = os.environ.get("AUTHNZ_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
UPSTREAM_HOST = os.environ.get("AUTHNZ_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("AUTHNZ_UPSTREAM_PORT", "8000"))
MANAGE_UPSTREAM = os.environ.get("AUTHNZ_MANAGE_UPSTREAM", "1") != "0"
ADMIN_ID = os.environ.get("AUTHNZ_ADMIN_ID")

# A password that comfortably clears the service's zxcvbn score>=3
# requirement (mixed case, digits, symbols, decent length).
DEFAULT_PASSWORD = "Zx9!correct-horse-battery#42"


def _make_client() -> requests.Session:
    s = requests.Session()
    # Real clients don't get to skip cert/host checks etc.; we just don't
    # want stale cookies leaking between fixtures.
    s.trust_env = False
    return s


@pytest.fixture(scope="session", autouse=True)
def _service_is_up():
    """Fail fast with a clear message if the service isn't reachable,
    rather than letting every test time out individually."""
    try:
        requests.get(f"{BASE_URL}/authn/me/account", timeout=3)
    except requests.exceptions.ConnectionError as e:
        pytest.exit(
            f"authnz service is not reachable at {BASE_URL} "
            f"(is it running, with a migrated Postgres DB behind it?): {e}"
        )


@pytest.fixture
def client() -> requests.Session:
    return _make_client()


def api(path: str) -> str:
    """Build a full URL for an authn-scoped path, e.g. api('/auth/register')."""
    return f"{BASE_URL}/authn{path}"


def authz_api(path: str) -> str:
    return f"{BASE_URL}/authz{path}"


def set_session_cookie(client: requests.Session, response: requests.Response) -> str:
    """Pull the `session` cookie value out of a login/register response and
    attach it to `client` for subsequent requests.

    The service marks this cookie `Secure`, which means Python's stdlib
    cookiejar (used internally by requests.Session) will correctly refuse
    to replay it over a plain-http connection, per RFC 6265 — exactly as a
    real browser would over TLS. Local/dev runs of the service are
    typically plain HTTP, so we extract the value ourselves and attach it
    without the Secure flag, purely so the test client can keep talking
    to the same plain-http endpoint the rest of the suite uses.
    """
    raw = response.cookies.get("session")
    assert raw, f"expected a 'session' cookie in response, got: {response.headers}"
    client.cookies.set("session", raw, domain=response.url.split("/")[2].split(":")[0])
    return raw


@dataclass
class TestUser:
    username: str
    email: str
    password: str = DEFAULT_PASSWORD
    user_id: Optional[str] = None


@pytest.fixture
def unique_user() -> TestUser:
    tag = uuid.uuid4().hex[:12]
    return TestUser(username=f"e2e_{tag}", email=f"e2e_{tag}@example.test")


@pytest.fixture
def registered_user(client: requests.Session, unique_user: TestUser) -> TestUser:
    """A user that has successfully completed POST /auth/register."""
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
    return unique_user


@pytest.fixture
def logged_in(client: requests.Session, registered_user: TestUser):
    """A fresh requests.Session already holding a valid `session` cookie
    for `registered_user`, obtained via the real login endpoint."""
    resp = client.post(
        api("/auth/login/email"),
        json={"identifier": registered_user.email, "password": registered_user.password},
        timeout=5,
    )
    assert resp.status_code == 200, resp.text
    set_session_cookie(client, resp)

    who = client.get(api("/me/account"), timeout=5)
    assert who.status_code == 200, who.text
    registered_user.user_id = who.json()["data"]["user_id"]
    return client, registered_user


# --------------------------------------------------------------------------
# Mock upstream ("the real backend behind the proxy")
# --------------------------------------------------------------------------

@dataclass
class CapturedRequest:
    method: str
    path: str
    headers: dict
    body: bytes


@dataclass
class UpstreamDouble:
    server: HTTPServer
    thread: threading.Thread
    captured: list = field(default_factory=list)
    response_body: bytes = b'{"ok": true}'
    response_status: int = 200

    def last(self) -> CapturedRequest:
        assert self.captured, "upstream never received a request"
        return self.captured[-1]

    def shutdown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)


def _build_upstream(double_ref: list) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _handle(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            double_ref[0].captured.append(
                CapturedRequest(
                    method=self.command,
                    path=self.path,
                    headers={k.lower(): v for k, v in self.headers.items()},
                    body=body,
                )
            )
            self.send_response(double_ref[0].response_status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(double_ref[0].response_body)

        def log_message(self, *args):  # silence
            pass

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle

    return HTTPServer((UPSTREAM_HOST, UPSTREAM_PORT), Handler)


@pytest.fixture
def upstream():
    """Starts a throwaway HTTP server standing in for the real backend that
    authnz's default_service proxies unmatched requests to (UPSTREAM in the
    service's .env). Lets proxy tests assert on exactly what the backend
    received — in particular, the identity headers authnz is responsible
    for asserting/stripping.

    Skips (rather than fails) if something else already owns that port,
    since in that case the *real* upstream is presumably already running
    there and shouldn't be stolen out from under it.
    """
    if not MANAGE_UPSTREAM:
        pytest.skip("AUTHNZ_MANAGE_UPSTREAM=0: not managing the upstream port")

    double_ref = [UpstreamDouble(server=None, thread=None)]  # type: ignore
    try:
        server = _build_upstream(double_ref)
    except OSError as e:
        pytest.skip(f"could not bind upstream double on {UPSTREAM_HOST}:{UPSTREAM_PORT}: {e}")
        return

    double_ref[0].server = server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    double_ref[0].thread = thread
    thread.start()
    try:
        yield double_ref[0]
    finally:
        double_ref[0].shutdown()
