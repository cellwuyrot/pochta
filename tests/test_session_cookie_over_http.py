"""Regression: the default install must be able to log in.

``cookie_secure`` defaults to True, so the session cookie carries ``Secure``.
Browsers silently discard a Secure cookie delivered over plain http:// to an IP
address — and ``setup.sh`` advertises exactly that (http://SERVER_IP:PORT/admin)
while generating a .env with no COOKIE_SECURE line. Result: login redirects back
to the login page with no error shown.
"""
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import async_session
from app.models import User, hash_password

PASSWORD = "login-test-password"


@pytest.fixture
def client():
    from app.config import settings

    settings.smtp_port = 0  # controller is not started by TestClient here
    from app.main import app

    return TestClient(app)


async def _make_admin():
    async with async_session() as db:
        existing = (await db.execute(select(User).where(User.username == "admin"))).scalar_one_or_none()
        if existing:
            return
        pw_hash, pw_salt = hash_password(PASSWORD)
        db.add(User(username="admin", password_hash=pw_hash, password_salt=pw_salt, role="admin"))
        await db.commit()


@pytest.mark.asyncio
async def test_cookie_has_no_secure_flag_when_cookie_secure_disabled(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "cookie_secure", False)
    await _make_admin()

    response = client.post(
        "/admin/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', client.get("/admin/login").text).group(1)},
        follow_redirects=False,
    )

    assert response.status_code == 302
    cookie = response.headers.get("set-cookie", "")
    assert "admin_session=" in cookie
    assert "secure" not in cookie.lower(), "Secure must be off when COOKIE_SECURE=false"
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower()


@pytest.mark.asyncio
async def test_cookie_keeps_secure_flag_when_enabled(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "cookie_secure", True)
    await _make_admin()

    response = client.post(
        "/admin/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', client.get("/admin/login").text).group(1)},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "secure" in response.headers.get("set-cookie", "").lower()


@pytest.mark.asyncio
async def test_empty_password_field_is_rejected_not_crashed(client):
    """An empty password field must be a clean auth failure, not a 422."""
    await _make_admin()

    response = client.post(
        "/admin/login",
        data={"username": "admin", "password": "", "csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', client.get("/admin/login").text).group(1)},
        follow_redirects=False,
    )

    assert response.status_code == 200, "expected the login page re-rendered with an error"
    assert "admin_session" not in response.headers.get("set-cookie", "")


def test_setup_script_pins_cookie_secure(repo_root):
    """setup.sh must not generate a .env that silently breaks login over http."""
    setup = (repo_root / "setup.sh").read_text(encoding="utf-8")

    heredoc = re.search(r"cat > \.env <<\s*EOF(.*?)^EOF", setup, re.DOTALL | re.MULTILINE)
    assert heredoc, "could not find the .env heredoc in setup.sh"

    assert "COOKIE_SECURE=" in heredoc.group(1), (
        "setup.sh generates a .env without COOKIE_SECURE, so it defaults to true, "
        "so the browser drops the session cookie over the http:// URL setup.sh prints"
    )


def test_setup_script_does_not_advertise_disabled_swagger(repo_root):
    """API_DOCS_ENABLED defaults to false, so printing a Swagger URL is a 404.

    Only ``echo`` lines count — mentioning /api/docs in a comment is fine.
    """
    setup = (repo_root / "setup.sh").read_text(encoding="utf-8")
    if "API_DOCS_ENABLED=true" in setup:
        return  # docs deliberately switched on — advertising them is fine

    advertised = [
        line.strip()
        for line in setup.splitlines()
        if line.strip().startswith("echo") and "/api/docs" in line
    ]
    assert not advertised, (
        "setup.sh prints a Swagger URL while API_DOCS_ENABLED is off — that link 404s: "
        f"{advertised}"
    )
