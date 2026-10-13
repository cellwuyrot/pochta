"""Regressions from the supplied audit; see reports/security-before.txt."""
import asyncio
import smtplib

import httpx
import pytest

from app.auth import SESSION_COOKIE, create_session_token
from app.config import settings
from app.database import async_session
from app.main import app
from app.models import Site, User, hash_password
from app.smtp_server import SmtpHandler, start_smtp_server, stop_smtp_server


@pytest.mark.asyncio
async def test_auth_is_not_advertised_or_accepted_without_tls(monkeypatch, free_port):
    monkeypatch.setattr(settings, 'smtp_port', free_port)
    monkeypatch.setattr(settings, 'tls_cert_path', '')
    monkeypatch.setattr(settings, 'tls_key_path', '')
    start_smtp_server()
    def probe():
        with smtplib.SMTP('127.0.0.1', free_port, timeout=3) as client:
            client.ehlo()
            advertised = client.has_extn('auth')
            code, _ = client.docmd('AUTH', 'PLAIN AGFkbWluAHBhc3M=')
            return advertised, code
    try:
        advertised, code = await asyncio.to_thread(probe)
        assert not advertised
        assert code in (538, 530)
    finally:
        stop_smtp_server()


@pytest.mark.asyncio
@pytest.mark.parametrize('path', ['/admin', '/admin/sites', '/admin/templates', '/admin/logs', '/admin/webhooks', '/admin/guide'])
async def test_user_cannot_read_admin_groups(path):
    hashed, salt = hash_password('test-pass')
    async with async_session() as db:
        db.add(User(username='reader', password_hash=hashed, password_salt=salt, role='user'))
        await db.commit()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        client.cookies.set(SESSION_COOKIE, create_session_token('reader', 'admin'))
        result = await client.get(path)
    assert result.status_code == 403  # DB role, not signed cookie role, is authoritative


@pytest.mark.asyncio
async def test_saved_relay_password_never_in_html(site):
    hashed, salt = hash_password('test-pass')
    async with async_session() as db:
        db.add(User(username='owner', password_hash=hashed, password_salt=salt, role='admin'))
        row = await db.get(Site, site.id)
        row.relay_password = 'never-echo-this-relay-secret'
        await db.commit()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        client.cookies.set(SESSION_COOKIE, create_session_token('owner'))
        result = await client.get(f'/admin/sites/{site.id}/edit')
    assert result.status_code == 200
    assert 'never-echo-this-relay-secret' not in result.text


@pytest.mark.asyncio
async def test_inbound_storage_failure_returns_temporary_failure(monkeypatch):
    import app.smtp_server as smtp
    class BrokenSession:
        async def __aenter__(self):
            raise OSError('disk unavailable')
        async def __aexit__(self, *args):
            pass
    monkeypatch.setattr(smtp, 'async_session', BrokenSession)
    result = await SmtpHandler()._store_inbound('sender@example.net', ['inbox@example.com'], 'subject', 'body')
    assert result.startswith('451')
