"""Beget mailbox identities, isolation, encryption, migration and cabinet workflows."""

import base64
import json
import re
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text

from app.auth import SESSION_COOKIE, create_session_token
from app.config import settings
from app.database import async_session, engine, migrate_hardening
from app.mailboxes import validate_sender
from app.main import app
from app.models import Mailbox, OutboxMessage, Site, User
from app.outbox import dispatch_due, enqueue_message
from app.providers import send_via_providers
from app.smtp_server import SmtpHandler


async def account(site, email="info@example.com", password="secret-account-one", **fields):
    async with async_session() as db:
        project = await db.get(Site, site.id)
        project.mailbox_mode = True
        project.sender_email = email
        row = Mailbox(site_id=site.id, email=email, password=password, **fields)
        db.add(row)
        await db.commit()
        return row


@pytest_asyncio.fixture
async def cabinet_client():
    async with async_session() as db:
        db.add(User(username="owner", password_hash="unused", password_salt="", role="admin"))
        await db.commit()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        client.cookies.set(SESSION_COOKIE, create_session_token("owner"))
        yield client


async def csrf(client, path):
    page = await client.get(path)
    assert page.status_code == 200, page.text
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text)[1]


def message(sender="info@example.com"):
    return {"from_email": sender, "to_email": "recipient@example.net", "subject": "hello", "body_html": "", "body_text": "test"}


@pytest.mark.asyncio
async def test_each_mailbox_uses_its_own_credentials(site, monkeypatch):
    await account(site, "info@example.com", "secret-info")
    await account(site, "sales@example.com", "secret-sales")
    calls = []
    def fake(**kwargs):
        calls.append(kwargs)
        return True, ""
    monkeypatch.setattr("app.providers.send_email", fake)
    async with async_session() as db:
        project = await db.get(Site, site.id)
        for sender in ["info@example.com", "sales@example.com"]:
            ok, error, source = await send_via_providers(db, project, **message(sender), dkim_private_key="project-key")
            assert ok and source == f"mailbox:{sender}"
    assert [c["relay_username"] for c in calls] == ["info@example.com", "sales@example.com"]
    assert [c["relay_password"] for c in calls] == ["secret-info", "secret-sales"]
    assert all(c["relay_host"] == "smtp.beget.com" and c["relay_port"] == 465 for c in calls)
    assert all(c["dkim_private_key"] == "" for c in calls)


@pytest.mark.asyncio
async def test_no_fallback_to_other_mailbox_global_relay_or_direct_mx(site, monkeypatch):
    await account(site)
    await account(site, "sales@example.com")
    monkeypatch.setattr(settings, "relay_host", "fallback.example.net")
    monkeypatch.setattr(settings, "allow_direct_mx", True)
    calls = []
    def fake(**kwargs):
        calls.append(kwargs)
        return False, "authentication rejected"
    monkeypatch.setattr("app.providers.send_email", fake)
    async with async_session() as db:
        project = await db.get(Site, site.id)
        ok, error, source = await send_via_providers(db, project, **message())
    assert not ok and source == "mailbox:info@example.com"
    assert len(calls) == 1 and calls[0]["relay_username"] == "info@example.com"


@pytest.mark.asyncio
@pytest.mark.parametrize("sender", ["not-added@example.com", "someone@foreign.ru"])
async def test_unregistered_sender_fails_closed(site, sender, monkeypatch):
    await account(site)
    def must_not_send(**kwargs):
        pytest.fail("unregistered sender dialled SMTP")
    monkeypatch.setattr("app.providers.send_email", must_not_send)
    async with async_session() as db:
        ok, error, _ = await send_via_providers(db, await db.get(Site, site.id), **message(sender))
    assert not ok and error.startswith("permanent:")


@pytest.mark.asyncio
async def test_secret_encrypted_at_rest(site):
    row = await account(site, password="private-password-at-rest")
    async with engine.connect() as conn:
        raw = (await conn.execute(text("SELECT password FROM mailboxes WHERE id=:id"), {"id": row.id})).scalar()
    assert raw.startswith("enc:v1:") and "private-password-at-rest" not in raw
    async with async_session() as db:
        assert (await db.get(Mailbox, row.id)).password == "private-password-at-rest"


@pytest.mark.asyncio
async def test_cabinet_and_edit_never_echo_password(site, cabinet_client):
    row = await account(site, password="never-render-this-password")
    for path in [f"/admin/sites/{site.id}", f"/admin/sites/{site.id}/mailboxes/{row.id}/edit"]:
        result = await cabinet_client.get(path)
        assert result.status_code == 200
        assert "never-render-this-password" not in result.text
    result = await cabinet_client.get("/api/mailboxes", headers={"Authorization": "Bearer sm_testkey"})
    assert result.status_code == 200
    assert "never-render-this-password" not in result.text and "password" not in result.text


@pytest.mark.asyncio
async def test_add_multiple_mailboxes_normalize_duplicates_and_defaults(site, cabinet_client):
    path = f"/admin/sites/{site.id}/mailboxes/new"
    for email in ["INFO@EXAMPLE.COM", "sales@example.com"]:
        token = await csrf(cabinet_client, path)
        result = await cabinet_client.post(path, data={"csrf_token": token, "email": email,
            "display_name": "Team", "password": "mailbox-pass", "is_active": "true"})
        assert result.status_code == 303
    async with async_session() as db:
        rows = (await db.execute(select(Mailbox).where(Mailbox.site_id == site.id).order_by(Mailbox.id))).scalars().all()
        assert [r.email for r in rows] == ["info@example.com", "sales@example.com"]
        project = await db.get(Site, site.id)
        assert project.mailbox_mode and project.sender_email == "info@example.com"
    token = await csrf(cabinet_client, path)
    result = await cabinet_client.post(path, data={"csrf_token": token, "email": "INFO@example.com", "password": "secret"})
    assert result.status_code == 422


@pytest.mark.asyncio
async def test_blank_edit_password_preserves_existing_secret(site, cabinet_client):
    row = await account(site)
    path = f"/admin/sites/{site.id}/mailboxes/{row.id}/edit"
    result = await cabinet_client.post(path, data={"csrf_token": await csrf(cabinet_client, path),
        "email": row.email, "display_name": "New name", "password": "", "is_active": "true"})
    assert result.status_code == 303
    async with async_session() as db:
        updated = await db.get(Mailbox, row.id)
        assert updated.password == "secret-account-one" and updated.display_name == "New name"


@pytest.mark.asyncio
async def test_choose_default_disable_and_delete_keep_fail_closed(site, cabinet_client):
    one = await account(site)
    two = await account(site, "sales@example.com")
    root = f"/admin/sites/{site.id}"
    token = await csrf(cabinet_client, root)
    assert (await cabinet_client.post(f"{root}/mailboxes/{one.id}/default", data={"csrf_token": token})).status_code == 303
    async with async_session() as db:
        assert (await db.get(Site, site.id)).sender_email == one.email
    assert (await cabinet_client.post(f"{root}/mailboxes/{one.id}/toggle", data={"csrf_token": token})).status_code == 303
    async with async_session() as db:
        assert (await db.get(Site, site.id)).sender_email == two.email
    for row in [one, two]:
        assert (await cabinet_client.post(f"{root}/mailboxes/{row.id}/delete", data={"csrf_token": token})).status_code == 303
    async with async_session() as db:
        project = await db.get(Site, site.id)
        assert project.mailbox_mode and project.sender_email == ""
        with pytest.raises(ValueError):
            await validate_sender(db, project, "info@example.com")


@pytest.mark.asyncio
async def test_project_scoped_catalogue_and_cross_project_address(site, cabinet_client):
    await account(site, "info@trioz.ru")
    async with async_session() as db:
        other = Site(name="Business", domain="buisness.trioz.ru", sender_email="sales@trioz.ru",
                     mailbox_mode=True, api_key="sm_business")
        db.add(other)
        await db.flush()
        db.add(Mailbox(site_id=other.id, email="sales@trioz.ru", password="secret-business"))
        await db.commit()
    headers = {"Authorization": "Bearer sm_testkey"}
    result = await cabinet_client.get("/api/mailboxes", headers=headers)
    assert [r["email"] for r in result.json()["mailboxes"]] == ["info@trioz.ru"]
    assert "sales@trioz.ru" not in result.text
    assert (await cabinet_client.get("/api/mailboxes?site_domain=buisness.trioz.ru", headers=headers)).status_code == 403
    result = await cabinet_client.post("/api/outbox", headers=headers, json={
        "from_email": "sales@trioz.ru", "to": "a@example.net", "subject": "test"})
    assert result.status_code == 403
    result = await cabinet_client.post("/api/outbox", headers={"Authorization": "Bearer sm_business"}, json={
        "from_email": "sales@trioz.ru", "to": "a@example.net", "subject": "test"})
    assert result.status_code == 202


@pytest.mark.asyncio
async def test_sync_api_accepts_registered_cross_domain_sender(site, cabinet_client, monkeypatch):
    await account(site, "info@trioz.ru")
    calls = []
    def fake(**kwargs):
        calls.append(kwargs)
        return True, ""
    monkeypatch.setattr("app.providers.send_email", fake)
    result = await cabinet_client.post("/api/emails", headers={"Authorization": "Bearer sm_testkey"}, json={
        "from_email": "info@trioz.ru", "to": "a@example.net", "subject": "test"})
    assert result.status_code == 200 and calls[0]["relay_username"] == "info@trioz.ru"
    result = await cabinet_client.post("/api/emails", headers={"Authorization": "Bearer sm_testkey"}, json={
        "from_email": "unknown@trioz.ru", "to": "a@example.net", "subject": "test"})
    assert result.status_code == 403


@pytest.mark.asyncio
async def test_global_shared_mailbox_requires_project_selection(site, cabinet_client, monkeypatch):
    await account(site, "shared@trioz.ru")
    async with async_session() as db:
        other = Site(name="Other", domain="buisness.trioz.ru", sender_email="shared@trioz.ru",
                     mailbox_mode=True, api_key="sm_other")
        db.add(other)
        await db.flush()
        db.add(Mailbox(site_id=other.id, email="shared@trioz.ru", password="other"))
        await db.commit()
    monkeypatch.setattr(settings, "api_key", "global-secret")
    monkeypatch.setattr("app.providers.send_email", lambda **kw: (True, ""))
    payload = {"from_email": "shared@trioz.ru", "to": "a@example.net", "subject": "test"}
    headers = {"Authorization": "Bearer global-secret"}
    assert (await cabinet_client.post("/api/emails", headers=headers, json=payload)).status_code == 400
    assert (await cabinet_client.post("/api/emails?site_domain=buisness.trioz.ru", headers=headers, json=payload)).status_code == 200


@pytest.mark.asyncio
async def test_disabled_mailbox_blocks_queued_message_before_delivery(site, monkeypatch):
    row = await account(site)
    async with async_session() as db:
        project = await db.get(Site, site.id)
        job = await enqueue_message(db, project, message())
        (await db.get(Mailbox, row.id)).is_active = False
        await db.commit()
    def no_send(**kw):
        pytest.fail("Disabled account attempted delivery")
    monkeypatch.setattr("app.providers.send_email", no_send)
    assert await dispatch_due() == 1
    async with async_session() as db:
        updated = await db.get(OutboxMessage, job.id)
        assert updated.status == "failed" and updated.error.startswith("permanent:")


@pytest.mark.asyncio
async def test_cabinet_sending_queues_selected_mailbox(site, cabinet_client):
    await account(site)
    await account(site, "sales@example.com")
    path = f"/admin/sites/{site.id}"
    result = await cabinet_client.post(path+"/send", data={"csrf_token": await csrf(cabinet_client, path),
        "from_email": "info@example.com", "to": "a@example.net", "subject": "from cabinet", "text": "hello"})
    assert result.status_code == 303 and result.headers["location"].startswith("/admin/messages/")
    async with async_session() as db:
        jobs = (await db.execute(select(OutboxMessage))).scalars().all()
        assert len(jobs) == 1 and json.loads(jobs[0].payload)["from_email"] == "info@example.com"


@pytest.mark.asyncio
async def test_csrf_origin_and_roles_still_enforced(site, cabinet_client):
    path = f"/admin/sites/{site.id}/mailboxes/new"
    data = {"email": "a@example.com", "password": "secret", "is_active": "true"}
    assert (await cabinet_client.post(path, data=data)).status_code == 403
    token = await csrf(cabinet_client, path)
    assert (await cabinet_client.post(path, data={**data, "csrf_token": token}, headers={"Origin": "https://evil.example"})).status_code == 403
    async with async_session() as db:
        db.add(User(username="reader", password_hash="unused", password_salt="", role="user"))
        await db.commit()
    cabinet_client.cookies.set(SESSION_COOKIE, create_session_token("reader", "admin"))
    assert (await cabinet_client.get(path)).status_code == 403


@pytest.mark.asyncio
async def test_mailbox_id_cannot_be_used_under_another_project(site, cabinet_client):
    row = await account(site)
    async with async_session() as db:
        other = Site(name="Other", domain="other.ru", sender_email="a@other.ru", api_key="sm_other")
        db.add(other)
        await db.commit()
    path = f"/admin/sites/{other.id}"
    token = await csrf(cabinet_client, path)
    assert (await cabinet_client.get(f"{path}/mailboxes/{row.id}/edit")).status_code == 404
    assert (await cabinet_client.post(f"{path}/mailboxes/{row.id}/delete", data={"csrf_token": token})).status_code == 404


@pytest.mark.asyncio
async def test_connection_test_redacts_password_before_db_and_html(site, cabinet_client, monkeypatch):
    row = await account(site)
    encoded = base64.b64encode(row.password.encode()).decode()
    monkeypatch.setattr("app.routes_mailboxes.test_connection", lambda *args: (False, f"error {row.password} {encoded}", []))
    path = f"/admin/sites/{site.id}"
    result = await cabinet_client.post(f"{path}/mailboxes/{row.id}/test", data={"csrf_token": await csrf(cabinet_client, path)})
    assert result.status_code == 303
    async with async_session() as db:
        saved = await db.get(Mailbox, row.id)
        assert saved.last_test_ok is False
        assert row.password not in saved.last_test_error and encoded not in saved.last_test_error
    page = await cabinet_client.get(path)
    assert row.password not in page.text and encoded not in page.text


@pytest.mark.asyncio
async def test_send_error_redacts_plain_and_encoded_auth(site, monkeypatch):
    row = await account(site)
    encoded = base64.b64encode(f"\0{row.email}\0{row.password}".encode()).decode()
    monkeypatch.setattr("app.providers.send_email", lambda **kw: (False, f"refused {row.password} {encoded}"))
    async with async_session() as db:
        ok, error, _ = await send_via_providers(db, await db.get(Site, site.id), **message())
    assert not ok and row.password not in error and encoded not in error


@pytest.mark.asyncio
async def test_dns_screen_does_not_recommend_replacing_beget_mx(site, cabinet_client):
    await account(site)
    page = await cabinet_client.get(f"/admin/sites/{site.id}/dns")
    assert page.status_code == 200 and "Оставьте MX" in page.text
    result = await cabinet_client.get("/api/domains/example.com/dns", headers={"Authorization": "Bearer sm_testkey"})
    assert result.status_code == 200 and result.json()["records"] == []
    assert result.json()["managed_by"] == "beget"


@pytest.mark.asyncio
async def test_old_schema_migration_preserves_sites_and_encrypted_accounts(site):
    row = await account(site)
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE sites DROP COLUMN mailbox_mode"))
    await migrate_hardening()
    async with async_session() as db:
        project = await db.get(Site, site.id)
        assert project.domain == "example.com" and project.api_key == "sm_testkey"
        assert (await db.get(Mailbox, row.id)).password == "secret-account-one"
        assert project.mailbox_mode is False  # legacy rows default to compatibility mode


@pytest.mark.asyncio
async def test_deleting_site_cascades_mailbox_secrets(site, cabinet_client):
    row = await account(site)
    async with async_session() as db:
        await enqueue_message(db, await db.get(Site, site.id), message())
        await db.commit()
    path = f"/admin/sites/{site.id}"
    result = await cabinet_client.post(path+"/delete", data={"csrf_token": await csrf(cabinet_client, path)})
    assert result.status_code == 302
    async with async_session() as db:
        assert await db.get(Mailbox, row.id) is None
        assert not (await db.execute(select(OutboxMessage))).scalars().all()


@pytest.mark.asyncio
async def test_smtp_scope_uses_project_domain_for_cross_domain_mailbox(site):
    await account(site, "info@trioz.ru")
    async with async_session() as db:
        db.add(User(username="submitter", password_hash="unused", password_salt="", role="user", smtp_domains="example.com"))
        await db.commit()
    session = SimpleNamespace(authenticated=True, ssl=True, smtp_username="submitter")
    envelope = SimpleNamespace(mail_from="", mail_options=[])
    result = await SmtpHandler().handle_MAIL(None, session, envelope, "info@trioz.ru", [])
    assert result.startswith("250") and session.smtp_site_id == site.id
    result = await SmtpHandler().handle_MAIL(None, session, envelope, "unknown@trioz.ru", [])
    assert result.startswith("553")


@pytest.mark.asyncio
async def test_smtp_from_header_cannot_switch_to_another_mailbox(site):
    await account(site)
    await account(site, "sales@example.com")
    raw = b"From: sales@example.com\r\nTo: a@example.net\r\nSubject: hello\r\n\r\nbody"
    result = await SmtpHandler()._relay_outbound("info@example.com", ["a@example.net"], raw, "hello", "body", site_id=site.id)
    assert result.startswith("553")


@pytest.mark.asyncio
async def test_template_send_selects_specific_mailbox(site, cabinet_client, monkeypatch):
    from app.models import EmailTemplate
    await account(site)
    await account(site, "sales@example.com")
    async with async_session() as db:
        db.add(EmailTemplate(site_id=site.id, name="Hello", slug="hello", subject="Welcome",
                             body_html="<p>Hello</p>", body_text="Hello"))
        await db.commit()
    calls = []
    def fake(**kw):
        calls.append(kw)
        return True, ""
    monkeypatch.setattr("app.providers.send_email", fake)
    result = await cabinet_client.post("/api/send", headers={"Authorization": "Bearer sm_testkey"}, json={
        "site_domain": "example.com", "template_slug": "hello", "to_email": "a@example.net",
        "from_email": "info@example.com"})
    assert result.status_code == 200 and calls[0]["relay_username"] == "info@example.com"


def test_transport_redacts_secrets_before_logging(monkeypatch, caplog):
    import smtplib

    from app.smtp_client import _send_via_relay
    secret = "do-not-log-this"
    encoded = base64.b64encode(secret.encode()).decode()
    def failing(*args, **kw):
        raise smtplib.SMTPAuthenticationError(535, f"bad auth {secret} {encoded}".encode())
    monkeypatch.setattr("app.smtp_client.SafeSMTP_SSL", failing)
    ok, error = _send_via_relay(b"From: info@example.com\r\n\r\nTest", "info@example.com",
                               "a@example.net", "smtp.beget.com", 465, "info@example.com", secret, True)
    assert not ok
    assert secret not in error and encoded not in error
    assert secret not in caplog.text and encoded not in caplog.text


@pytest.mark.asyncio
async def test_unknown_delivery_is_not_replayed(site, monkeypatch):
    await account(site)
    calls = []
    def fake(**kw):
        calls.append(kw)
        return False, "uncertain: connection interrupted after DATA"
    monkeypatch.setattr("app.providers.send_email", fake)
    async with async_session() as db:
        job = await enqueue_message(db, await db.get(Site, site.id), message())
        await db.commit()
    await dispatch_due()
    await dispatch_due()
    async with async_session() as db:
        assert (await db.get(OutboxMessage, job.id)).status == "unknown"
    assert len(calls) == 1
