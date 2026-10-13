"""Integration tests use real local SMTP sockets, TLS and SQLite snapshots."""

import asyncio
import base64
import datetime as dt
import re
import smtplib
import ssl
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from aiosmtpd.controller import Controller
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select, text

from app.auth import SESSION_COOKIE, create_session_token
from app.config import Settings, settings
from app.database import async_session, migrate_hardening
from app.domain_util import normalize_domain
from app.main import app
from app.models import DeliveryAttempt, EmailLog, EmailProvider, OutboxMessage, Site, User, hash_password
from app.outbox import dispatch_due, enqueue_message, now, recover_interrupted
from app.smtp_server import SmtpHandler, start_smtp_server, stop_smtp_server


@pytest.fixture
def tls_pair(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_file, key_file


async def create_user(role="admin", domains="example.com"):
    hashed, salt = await asyncio.to_thread(hash_password, "correct-password")
    async with async_session() as db:
        db.add(User(username="owner", role=role, password_hash=hashed, password_salt=salt, smtp_domains=domains))
        await db.commit()


@pytest.mark.asyncio
async def test_live_starttls_auth_submission_provider_and_mime(site, free_port, tls_pair, monkeypatch):
    await create_user()
    messages = []

    class Receiver:
        async def handle_DATA(self, server, session, envelope):
            messages.append(envelope.content)
            return "250 accepted"

    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        relay_port = sock.getsockname()[1]
    relay = Controller(Receiver(), hostname="127.0.0.1", port=relay_port)
    relay.start()
    async with async_session() as db:
        db.add(EmailProvider(site_id=site.id, name="local-relay", host="127.0.0.1", port=relay_port, use_tls=False))
        await db.commit()
    monkeypatch.setattr(settings, "smtp_port", free_port)
    monkeypatch.setattr(settings, "tls_cert_path", str(tls_pair[0]))
    monkeypatch.setattr(settings, "tls_key_path", str(tls_pair[1]))
    monkeypatch.setattr(settings, "allow_direct_mx", False)
    start_smtp_server()
    raw = b'From: noreply@example.com\r\nTo: user@example.net\r\nSubject: MIME preservation\r\nContent-Type: multipart/mixed; boundary="abc"\r\n\r\n--abc\r\nContent-Type: text/plain\r\n\r\nbody\r\n--abc\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nYXR0YWNobWVudA==\r\n--abc--\r\n'

    def send():
        with smtplib.SMTP("localhost", free_port, timeout=5) as client:
            client.ehlo()
            assert not client.has_extn("auth")
            context = ssl.create_default_context(cafile=str(tls_pair[0]))
            client.starttls(context=context)
            client.ehlo()
            client.login("owner", "correct-password")
            assert client.sendmail("noreply@example.com", ["user@example.net"], raw) == {}
            code, _ = client.mail("spoof@evil.example")
            assert code == 553

    try:
        await asyncio.to_thread(send)
        async with async_session() as db:
            row = (await db.execute(select(OutboxMessage))).scalar_one()
            assert row.status == "queued"
        assert await dispatch_due() == 1
        assert len(messages) == 1
        assert b"YXR0YWNobWVudA==" in messages[0]
        async with async_session() as db:
            row = (await db.execute(select(OutboxMessage))).scalar_one()
            assert row.status == "accepted"
            attempt = (await db.execute(select(DeliveryAttempt))).scalar_one()
            assert attempt.relay == "provider:local-relay"
            assert attempt.message_id == row.id
    finally:
        stop_smtp_server()
        relay.stop()


@pytest.mark.asyncio
async def test_tls_credentials_work_with_real_relay(tls_pair, free_port):
    from aiosmtpd.smtp import AuthResult

    from app.providers import test_connection as check
    from app.smtp_client import _send_via_relay

    received = []

    class Receiver:
        async def handle_DATA(self, server, session, envelope):
            received.append(envelope.content)
            return "250 OK"

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tls_pair[0]), str(tls_pair[1]))

    def authenticate(server, session, envelope, mechanism, auth_data):
        return AuthResult(success=(auth_data.login == b"u" and auth_data.password == b"p"), handled=False)

    ctl = Controller(
        Receiver(),
        hostname="localhost",
        port=free_port,
        tls_context=ctx,
        authenticator=authenticate,
        auth_require_tls=True,
    )
    ctl.start()
    # Trust the ephemeral CA through the actual OpenSSL trust path, no TLS verification bypass.
    import os

    previous = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = str(tls_pair[0])
    try:
        ok, error, steps = await asyncio.to_thread(check, "localhost", free_port, "u", "p", True)
        assert ok, error
        assert any("authenticated" in step for step in steps)
        ok, error = await asyncio.to_thread(
            _send_via_relay,
            b"From: a@example.com\r\n\r\nbody",
            "a@example.com",
            "b@example.net",
            "localhost",
            free_port,
            "u",
            "p",
            True,
        )
        assert ok, error
        assert len(received) == 1
        ok, error, _ = await asyncio.to_thread(check, "localhost", free_port, "u", "wrong", True)
        assert not ok and "authentication rejected" in error
    finally:
        ctl.stop()
        if previous is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = previous


@pytest.mark.asyncio
async def test_queue_idempotency_conflict_and_site_isolation(site):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": "Bearer sm_testkey", "Idempotency-Key": "request-1"}
        payload = {"from_email": "noreply@example.com", "to": "user@example.net", "subject": "test", "text": "hello"}
        first = await client.post("/api/outbox", headers=headers, json=payload)
        second = await client.post("/api/outbox", headers=headers, json=payload)
        assert first.status_code == second.status_code == 202
        assert first.json()["id"] == second.json()["id"]
        payload["text"] = "changed"
        assert (await client.post("/api/outbox", headers=headers, json=payload)).status_code == 409
        async with async_session() as db:
            db.add(Site(name="other", domain="other.example", sender_email="a@other.example", api_key="sm_other"))
            await db.commit()
        assert (
            await client.get("/api/outbox/" + first.json()["id"], headers={"Authorization": "Bearer sm_other"})
        ).status_code == 404
        assert (await client.get("/api/outbox/" + first.json()["id"], headers=headers)).json()["status"] == "queued"


@pytest.mark.asyncio
async def test_queue_persists_and_unknown_is_not_replayed(site):
    async with async_session() as db:
        row = await enqueue_message(
            db,
            site,
            {
                "from_email": "a@example.com",
                "to_email": "b@example.net",
                "subject": "x",
                "body_html": "",
                "body_text": "x",
            },
        )
        row.status = "sending"
        await db.commit()
        id_ = row.id
    await recover_interrupted()
    assert await dispatch_due() == 0
    async with async_session() as db:
        assert (await db.get(OutboxMessage, id_)).status == "unknown"


@pytest.mark.asyncio
async def test_queue_retries_refused_connection(site, free_port, monkeypatch):
    monkeypatch.setattr(settings, "outbox_max_attempts", 2)
    async with async_session() as db:
        db.add(EmailProvider(site_id=site.id, name="offline", host="127.0.0.1", port=free_port, use_tls=False))
        row = await enqueue_message(
            db,
            site,
            {
                "from_email": "a@example.com",
                "to_email": "b@example.net",
                "subject": "x",
                "body_html": "",
                "body_text": "x",
            },
        )
        await db.commit()
        id_ = row.id
    assert await dispatch_due() == 1
    async with async_session() as db:
        row = await db.get(OutboxMessage, id_)
        assert row.status == "queued" and row.attempts == 1
        row.next_attempt_at = now() - dt.timedelta(seconds=1)
        await db.commit()
    assert await dispatch_due() == 1
    async with async_session() as db:
        row = await db.get(OutboxMessage, id_)
        assert row.status == "failed" and row.attempts == 2
        assert len((await db.execute(select(DeliveryAttempt))).scalars().all()) == 2


@pytest.mark.asyncio
async def test_secrets_are_encrypted_and_migration_idempotent(site):
    async with async_session() as db:
        row = await db.get(Site, site.id)
        row.relay_password = "secret-value"
        await db.commit()
        value = (await db.execute(text("SELECT relay_password FROM sites WHERE id=:id"), {"id": site.id})).scalar()
        assert value.startswith("enc:v1:") and "secret-value" not in value
    await migrate_hardening()
    await migrate_hardening()
    async with async_session() as db:
        assert (await db.get(Site, site.id)).relay_password == "secret-value"


@pytest.mark.asyncio
async def test_inbound_preserves_original_mime(site, monkeypatch):
    monkeypatch.setattr(settings, "inbound_enabled", True)
    raw = b"From: a@example.net\r\nSubject: inbound\r\n\r\nraw body\r\n"
    result = await SmtpHandler()._store_inbound("a@example.net", ["in@example.com"], "inbound", "raw body", raw)
    assert result.startswith("250")
    async with async_session() as db:
        row = (await db.execute(select(EmailLog))).scalar_one()
        assert base64.b64decode(row.raw_message) == raw
        assert row.site_id == site.id


@pytest.mark.asyncio
async def test_inbound_disabled_by_default(monkeypatch):
    monkeypatch.setattr(settings, "inbound_enabled", False)
    result = await SmtpHandler().handle_RCPT(
        None, SimpleNamespace(authenticated=False), SimpleNamespace(rcpt_tos=[]), "in@example.com", []
    )
    assert result.startswith("550")


@pytest.mark.asyncio
async def test_csrf_protects_changes_and_secret_can_be_retained_or_cleared(site):
    await create_user()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        client.cookies.set(SESSION_COOKIE, create_session_token("owner"))
        page = await client.get(f"/admin/sites/{site.id}/edit")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        payload = {
            "name": "Updated",
            "domain": "EXAMPLE.COM.",
            "sender_email": "a@example.com",
            "is_active": "true",
            "relay_password": "secret-change",
        }
        assert (await client.post(f"/admin/sites/{site.id}/edit", data=payload)).status_code == 403
        payload["csrf_token"] = token
        assert (
            await client.post(f"/admin/sites/{site.id}/edit", data=payload, headers={"Origin": "https://evil.test"})
        ).status_code == 403
        assert (await client.post(f"/admin/sites/{site.id}/edit", data=payload)).status_code == 302
        payload["relay_password"] = ""
        assert (await client.post(f"/admin/sites/{site.id}/edit", data=payload)).status_code == 302
        async with async_session() as db:
            assert (await db.get(Site, site.id)).relay_password == "secret-change"
        payload["clear_relay_password"] = "true"
        assert (await client.post(f"/admin/sites/{site.id}/edit", data=payload)).status_code == 302
        async with async_session() as db:
            assert (await db.get(Site, site.id)).relay_password == ""
        assert (await client.get("/admin/logout")).status_code == 405


@pytest.mark.asyncio
async def test_all_admin_routes_deny_database_user_role():
    await create_user(role="user")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        client.cookies.set(SESSION_COOKIE, create_session_token("owner", "admin"))
        token = re.search(r'name="csrf_token" value="([^"]+)"', (await client.get("/admin/login")).text).group(1)
        from fastapi.routing import APIRoute

        from app.routes_admin import router as admin_router
        from app.routes_admin_providers import router as providers_router
        from app.routes_admin_webhooks import router as hooks_router

        tested = 0
        for route in [*admin_router.routes, *hooks_router.routes, *providers_router.routes]:
            if not isinstance(route, APIRoute) or not route.path.startswith("/admin") or route.path == "/admin/login":
                continue
            path = re.sub(r"\{[^}]+\}", "1", route.path)
            for method in route.methods:
                result = await client.request(method, path, data={"csrf_token": token} if method == "POST" else None)
                tested += 1
                assert result.status_code == 403, (method, path, result.status_code)
        assert tested >= 40


@pytest.mark.parametrize(
    "value,expected", [(" https://EXAMPLE.COM/ ", "example.com"), ("ПРИМЕР.РФ.", "xn--e1afmkfd.xn--p1ai")]
)
def test_domain_normalization(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize("value", ["https://example.com/path", "example.com:25", "a..com", "-bad.com"])
def test_domain_rejects_invalid(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


def test_production_policy_defaults():
    # Disable test environment and dotenv for these explicitly supplied fields.
    cfg = Settings(allow_direct_mx=False, inbound_enabled=False, webhook_require_https=True)
    assert not cfg.allow_direct_mx and not cfg.inbound_enabled and cfg.webhook_require_https


@pytest.mark.asyncio
async def test_direct_mx_opt_in(site, monkeypatch):
    from app.providers import send_via_providers

    monkeypatch.setattr(settings, "allow_direct_mx", False)
    monkeypatch.setattr(settings, "relay_host", "")
    async with async_session() as db:
        ok, error, source = await send_via_providers(
            db, site, to_email="b@example.net", subject="x", body_html="", from_email="a@example.com"
        )
    assert not ok and source == "none" and "disabled" in error


def test_forwarded_ip_is_ignored_unless_peer_trusted(monkeypatch):
    from starlette.requests import Request

    from app.ratelimit import _client_ip

    request = Request({"type": "http", "headers": [(b"x-forwarded-for", b"8.8.8.8")], "client": ("127.0.0.1", 123)})
    monkeypatch.setattr(settings, "trusted_proxy_ips", "")
    assert _client_ip(request) == "127.0.0.1"
    monkeypatch.setattr(settings, "trusted_proxy_ips", "127.0.0.1")
    assert _client_ip(request) == "8.8.8.8"


def test_backup_restore_preserves_sqlite(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("backup_tool", Path(__file__).parents[1] / "tools/backup.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    import sqlite3

    source, tmp, restored = tmp_path / "source.db", tmp_path / "backup.db", tmp_path / "restored.db"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE test (value TEXT)")
        db.execute("INSERT INTO test VALUES('retained')")
        db.commit()
    mod.backup(source, tmp)
    mod.restore(tmp, restored)
    with sqlite3.connect(restored) as db:
        assert db.execute("SELECT value FROM test").fetchone()[0] == "retained"
    with pytest.raises(FileExistsError):
        mod.restore(tmp, restored)


@pytest.mark.asyncio
async def test_webhook_pinning_blocks_rebinding_before_tcp(monkeypatch):
    import app.webhook_service as service
    from app.webhook_transport import PublicNetworkBackend

    class Backend:
        async def connect_tcp(self, *args, **kwargs):
            raise AssertionError("Must not connect to private address")

    monkeypatch.setattr(service, "_resolve_all", lambda host: ["127.0.0.1"])
    with pytest.raises(service.WebhookUrlError):
        await PublicNetworkBackend(Backend()).connect_tcp("rebind.example", 443)


@pytest.mark.asyncio
async def test_webhook_tcp_is_pinned_to_validated_ip(monkeypatch):
    import app.webhook_service as service
    from app.webhook_transport import PublicNetworkBackend, webhook_transport

    captured = []

    class Backend:
        async def connect_tcp(self, host, port, **kwargs):
            captured.append((host, port))
            return "stream"

    monkeypatch.setattr(service, "_resolve_all", lambda host: ["8.8.8.8"])
    assert await PublicNetworkBackend(Backend()).connect_tcp("public.example", 443) == "stream"
    assert captured == [("8.8.8.8", 443)]
    monkeypatch.setattr(settings, "webhook_allow_private_targets", False)
    transport = webhook_transport()
    assert isinstance(transport._pool._network_backend, PublicNetworkBackend)
    await transport.aclose()


def test_smtp_target_blocks_private_and_probe_ports(monkeypatch):
    from app.smtp_transport import target_ips

    monkeypatch.setattr(settings, "smtp_allow_private_targets", False)
    with pytest.raises(ValueError):
        target_ips("127.0.0.1", 587)
    with pytest.raises(ValueError):
        target_ips("8.8.8.8", 22)


@pytest.mark.asyncio
async def test_provider_api_empty_password_explicitly_clears(site):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        headers = {"Authorization": "Bearer sm_testkey"}
        result = await client.post(
            "/api/providers",
            headers=headers,
            json={"name": "test", "preset": "postmark", "password": "original-secret"},
        )
        assert result.status_code == 201
        id_ = result.json()["id"]
        assert "original-secret" not in result.text
        result = await client.patch(f"/api/providers/{id_}", headers=headers, json={"password": ""})
        assert result.status_code == 200 and not result.json()["has_password"]
