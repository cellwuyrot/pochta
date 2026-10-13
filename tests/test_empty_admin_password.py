"""Regression: an unset ADMIN_PASSWORD must never yield a usable account.

With ``admin_password`` defaulting to "", ``seed_admin_user()`` used to bcrypt
the empty string and store it. ``verify_password("", stored_hash)`` then returned
True. The web login form happened to reject a literally empty field with 422, but
``SmtpAuthenticator`` calls ``verify_password`` directly — and an authenticated
SMTP session is granted relay to *any* domain, i.e. an open relay.
"""
import asyncio

import pytest
from aiosmtpd.smtp import LoginPassword
from sqlalchemy import select

from app.database import async_session, seed_admin_user
from app.models import User, hash_password, verify_password


def test_verify_password_rejects_empty_password():
    """An empty password must never validate, whatever is stored."""
    pw_hash, pw_salt = hash_password("")
    assert verify_password("", pw_hash, pw_salt) is False


def test_verify_password_rejects_empty_against_real_password():
    pw_hash, pw_salt = hash_password("a-real-password")
    assert verify_password("", pw_hash, pw_salt) is False
    assert verify_password("a-real-password", pw_hash, pw_salt) is True


def test_verify_password_rejects_empty_for_legacy_sha256_records():
    """Legacy salted-SHA256 rows must get the same treatment."""
    import hashlib

    salt = "legacysalt"
    legacy_hash = hashlib.sha256(f"{salt}".encode()).hexdigest()  # hash of salt + ""
    assert verify_password("", legacy_hash, salt) is False


@pytest.mark.asyncio
async def test_seeding_refuses_empty_admin_password(monkeypatch):
    """Startup must fail loudly rather than create a passwordless admin."""
    from app.config import settings

    monkeypatch.setattr(settings, "admin_password", "")

    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
        await seed_admin_user()

    async with async_session() as db:
        users = (await db.execute(select(User))).scalars().all()
    assert users == [], "no user may be created when ADMIN_PASSWORD is empty"


@pytest.mark.asyncio
async def test_seeding_works_with_a_real_password(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "admin_password", "s3cret-password")
    monkeypatch.setattr(settings, "admin_username", "admin")

    await seed_admin_user()

    async with async_session() as db:
        user = (await db.execute(select(User).where(User.username == "admin"))).scalar_one()
    assert verify_password("s3cret-password", user.password_hash, user.password_salt) is True
    assert verify_password("", user.password_hash, user.password_salt) is False


@pytest.mark.asyncio
async def test_smtp_auth_rejects_empty_password():
    """The SMTP AUTH path is the one that would become an open relay."""
    from app.smtp_server import SmtpAuthenticator

    async with async_session() as db:
        pw_hash, pw_salt = hash_password("")  # worst case: an empty-password hash on disk
        db.add(User(username="admin", password_hash=pw_hash, password_salt=pw_salt, role="admin"))
        await db.commit()

    authenticator = SmtpAuthenticator()

    class FakeSession:
        authenticated = False

    session = FakeSession()
    # aiosmtpd invokes the authenticator synchronously from inside the thread that
    # runs the event loop. Calling it directly here reproduces that exactly; running
    # it in an executor instead would make it fail for the wrong reason (no current
    # event loop) and the test would pass without proving anything.
    assert asyncio.get_running_loop().is_running()
    result = authenticator(
        server=None,
        session=session,
        envelope=None,
        mechanism="LOGIN",
        auth_data=LoginPassword(login=b"admin", password=b""),
    )

    assert result.success is False, "empty password authenticated over SMTP AUTH — open relay"
    assert session.authenticated is False


@pytest.mark.asyncio
async def test_smtp_auth_accepts_a_real_password():
    """Guard against 'fixed' by breaking auth entirely."""
    from app.smtp_server import SmtpAuthenticator

    async with async_session() as db:
        pw_hash, pw_salt = hash_password("correct-horse")
        db.add(User(username="relay", password_hash=pw_hash, password_salt=pw_salt, role="user"))
        await db.commit()

    class FakeSession:
        authenticated = False

    session = FakeSession()
    result = SmtpAuthenticator()(
        server=None,
        session=session,
        envelope=None,
        mechanism="LOGIN",
        auth_data=LoginPassword(login=b"relay", password=b"correct-horse"),
    )

    assert result.success is True
    assert session.authenticated is True
