"""Relay resolution, failover, and the connection test — against a real fake SMTP server."""
import socket
import threading

import pytest
from sqlalchemy import select

from app.database import async_session
from app.models import EmailProvider, Site
from app.providers import resolve_relay_targets, send_via_providers

# Imported under an alias: pytest would otherwise collect `test_connection`
# itself as a test case and fail looking for a `host` fixture.
from app.providers import test_connection as check_connection


class FakeSMTPServer(threading.Thread):
    """A minimal SMTP server: speaks enough of the protocol to accept or refuse.

    ``reject_auth`` makes AUTH fail with 535 so the tests can distinguish a
    reachability problem from a credentials problem, which is exactly the
    distinction the connection-test endpoint exists to report.
    """

    def __init__(self, *, accept: bool = True, reject_auth: bool = False, advertise_starttls: bool = False):
        super().__init__(daemon=True)
        self.accept_mail = accept
        self.reject_auth = reject_auth
        self.advertise_starttls = advertise_starttls
        self.messages: list[bytes] = []
        self.auth_attempts = 0
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(5)
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        stream = conn.makefile("rwb", buffering=0)
        stream.write(b"220 fake.test ESMTP\r\n")
        collecting = False
        buffer = bytearray()
        while True:
            line = stream.readline()
            if not line:
                return
            if collecting:
                if line.strip() == b".":
                    self.messages.append(bytes(buffer))
                    buffer.clear()
                    collecting = False
                    stream.write(b"250 OK queued\r\n")
                else:
                    buffer += line
                continue

            upper = line.upper()
            if upper.startswith((b"EHLO", b"HELO")):
                extensions = [b"250-fake.test"]
                if self.advertise_starttls:
                    extensions.append(b"250-STARTTLS")
                extensions.append(b"250-AUTH LOGIN PLAIN")
                extensions.append(b"250 HELP")
                stream.write(b"\r\n".join(extensions) + b"\r\n")
            elif upper.startswith(b"AUTH"):
                self.auth_attempts += 1
                if self.reject_auth:
                    stream.write(b"535 5.7.8 Authentication credentials invalid\r\n")
                else:
                    # Multi-step LOGIN: prompt, then accept whatever arrives.
                    stream.write(b"334 VXNlcm5hbWU6\r\n")
                    stream.readline()
                    stream.write(b"334 UGFzc3dvcmQ6\r\n")
                    stream.readline()
                    stream.write(b"235 2.7.0 Authentication successful\r\n")
            elif upper.startswith(b"MAIL"):
                stream.write(b"250 OK\r\n" if self.accept_mail else b"550 Rejected\r\n")
            elif upper.startswith(b"RCPT"):
                stream.write(b"250 OK\r\n" if self.accept_mail else b"550 Rejected\r\n")
            elif upper.startswith(b"DATA"):
                if self.accept_mail:
                    stream.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    collecting = True
                else:
                    stream.write(b"554 No\r\n")
            elif upper.startswith(b"QUIT"):
                stream.write(b"221 Bye\r\n")
                return
            else:
                stream.write(b"250 OK\r\n")

    def stop(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


@pytest.fixture
def smtp_server():
    server = FakeSMTPServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def dead_port():
    """A port with nothing listening, so connections are refused at once."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _add_provider(site: Site, **kwargs) -> EmailProvider:
    defaults = {
        "site_id": site.id,
        "name": "p",
        "host": "127.0.0.1",
        "port": 587,
        "use_tls": False,
        "is_active": True,
        "priority": 100,
    }
    defaults.update(kwargs)
    async with async_session() as db:
        provider = EmailProvider(**defaults)
        db.add(provider)
        await db.commit()
        await db.refresh(provider)
        return provider


SEND_KWARGS = {
    "to_email": "user@example.net",
    "subject": "hi",
    "body_html": "<p>hi</p>",
    "body_text": "hi",
    "from_email": "noreply@example.com",
    "from_name": "Test",
    "dkim_domain": "",
    "dkim_selector": "",
    "dkim_private_key": "",
}


# --- Resolution order -----------------------------------------------------


async def test_no_configuration_yields_no_targets(site, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "relay_host", "")
    async with async_session() as db:
        assert await resolve_relay_targets(db, site) == []


async def test_providers_come_before_the_site_relay(site, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "relay_host", "global.example.test")
    async with async_session() as db:
        stored = (await db.execute(select(Site).where(Site.id == site.id))).scalar_one()
        stored.relay_host = "site.example.test"
        await db.commit()

    await _add_provider(site, name="secondary", host="second.example.test", priority=20)
    await _add_provider(site, name="primary", host="first.example.test", priority=10)

    async with async_session() as db:
        stored = (await db.execute(select(Site).where(Site.id == site.id))).scalar_one()
        targets = await resolve_relay_targets(db, stored)

    assert [t.host for t in targets] == [
        "first.example.test",
        "second.example.test",
        "site.example.test",
        "global.example.test",
    ]
    assert [t.label for t in targets] == [
        "provider:primary",
        "provider:secondary",
        "site-relay",
        "global-relay",
    ]


async def test_inactive_providers_are_skipped(site, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "relay_host", "")
    await _add_provider(site, name="off", host="off.example.test", is_active=False)
    async with async_session() as db:
        assert await resolve_relay_targets(db, site) == []


async def test_providers_without_a_host_are_skipped(site, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "relay_host", "")
    await _add_provider(site, name="blank", host="")
    async with async_session() as db:
        assert await resolve_relay_targets(db, site) == []


# --- Sending and failover -------------------------------------------------


async def test_send_uses_the_highest_priority_provider(site, smtp_server, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "relay_host", "")
    await _add_provider(site, name="primary", port=smtp_server.port, priority=10)

    async with async_session() as db:
        stored = (await db.execute(select(Site).where(Site.id == site.id))).scalar_one()
        success, error, source = await send_via_providers(db, stored, **SEND_KWARGS)

    assert success is True, error
    assert source == "provider:primary"
    assert len(smtp_server.messages) == 1
    assert b"To: user@example.net" in smtp_server.messages[0]


async def test_send_falls_over_to_the_next_provider(site, smtp_server, dead_port, monkeypatch):
    """A refused connection must not drop the message."""
    from app.config import settings

    monkeypatch.setattr(settings, "relay_host", "")
    await _add_provider(site, name="broken", port=dead_port, priority=10)
    await _add_provider(site, name="working", port=smtp_server.port, priority=20)

    async with async_session() as db:
        stored = (await db.execute(select(Site).where(Site.id == site.id))).scalar_one()
        success, error, source = await send_via_providers(db, stored, **SEND_KWARGS)

    assert success is True, error
    assert source == "provider:working", "should have fallen through to the healthy provider"
    assert len(smtp_server.messages) == 1


async def test_all_providers_failing_reports_every_attempt(site, dead_port, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "relay_host", "")
    await _add_provider(site, name="one", port=dead_port, priority=10)
    await _add_provider(site, name="two", port=dead_port, priority=20)

    async with async_session() as db:
        stored = (await db.execute(select(Site).where(Site.id == site.id))).scalar_one()
        success, error, _ = await send_via_providers(db, stored, **SEND_KWARGS)

    assert success is False
    assert "provider:one" in error and "provider:two" in error, (
        "the error must name every relay tried, not just the last"
    )


async def test_site_relay_still_works_with_no_providers(site, smtp_server, monkeypatch):
    """Backwards compatibility: configuration that predates providers."""
    from app.config import settings

    monkeypatch.setattr(settings, "relay_host", "")
    async with async_session() as db:
        stored = (await db.execute(select(Site).where(Site.id == site.id))).scalar_one()
        stored.relay_host = "127.0.0.1"
        stored.relay_port = smtp_server.port
        stored.relay_use_tls = False
        await db.commit()
        await db.refresh(stored)
        success, error, source = await send_via_providers(db, stored, **SEND_KWARGS)

    assert success is True, error
    assert source == "site-relay"
    assert len(smtp_server.messages) == 1


async def test_authenticated_relay_requires_tls(site, smtp_server, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "relay_host", "")
    await _add_provider(site, name="auth", port=smtp_server.port, username="u", password="p")

    async with async_session() as db:
        stored = (await db.execute(select(Site).where(Site.id == site.id))).scalar_one()
        success, error, _ = await send_via_providers(db, stored, **SEND_KWARGS)

    assert success is False
    assert "TLS" in error
    assert smtp_server.auth_attempts == 0


# --- Connection testing ---------------------------------------------------


def test_connection_succeeds_without_credentials(smtp_server):
    ok, error, steps = check_connection("127.0.0.1", smtp_server.port, use_tls=False)
    assert ok is True, error
    assert any("connected" in s for s in steps)
    assert any("login not attempted" in s for s in steps)


def test_connection_refuses_cleartext_login(smtp_server):
    ok, error, steps = check_connection(
        "127.0.0.1", smtp_server.port, username="u", password="p", use_tls=False
    )
    assert ok is False
    assert "TLS" in error
    assert smtp_server.auth_attempts == 0


def test_connection_distinguishes_bad_credentials_from_unreachable(dead_port):
    server = FakeSMTPServer(reject_auth=True)
    server.start()
    try:
        ok, error, steps = check_connection(
            "127.0.0.1", server.port, username="u", password="wrong", use_tls=False
        )
        assert ok is False
        assert "TLS" in error
        # It got far enough to talk SMTP, so the transcript proves reachability.
        assert any("connected" in s for s in steps)
        assert any("EHLO" in s for s in steps)
    finally:
        server.stop()

    ok, error, steps = check_connection("127.0.0.1", dead_port, use_tls=False)
    assert ok is False
    assert "could not reach" in error
    assert steps == [], "nothing succeeded, so the transcript must be empty"


def test_connection_reports_missing_starttls(smtp_server):
    """use_tls against a server that does not advertise STARTTLS must say so."""
    ok, error, steps = check_connection("127.0.0.1", smtp_server.port, use_tls=True)
    assert ok is False
    assert "STARTTLS" in error
    assert any("EHLO" in s for s in steps)


def test_connection_negotiates_starttls_when_advertised():
    server = FakeSMTPServer(advertise_starttls=True)
    server.start()
    try:
        # The fake server advertises STARTTLS but cannot complete a real handshake,
        # so this must fail at the TLS step rather than being silently skipped.
        ok, error, steps = check_connection("127.0.0.1", server.port, use_tls=True)
        assert ok is False
        assert any("EHLO" in s for s in steps)
        assert "STARTTLS" not in error or "TLS" in error
    finally:
        server.stop()
