"""REST API for webhook management, including cross-site isolation."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import async_session
from app.models import Site, Webhook

# An IP literal, so the guard runs but no DNS lookup is involved: CI sandboxes
# (this one included) often resolve every hostname into private space, which the
# SSRF guard would legitimately reject.
HOOK_URL = "https://93.184.216.34/smtp"


@pytest.fixture
def client(monkeypatch):
    from app.config import settings

    settings.smtp_port = 0
    from app.main import app

    return TestClient(app)


@pytest.fixture
def auth(site):
    return {"Authorization": f"Bearer {site.api_key}"}


async def _second_site() -> Site:
    async with async_session() as db:
        other = Site(
            name="Other", domain="other.test", sender_email="n@other.test", api_key="sm_otherkey"
        )
        db.add(other)
        await db.commit()
        await db.refresh(other)
        return other


# --- Auth -----------------------------------------------------------------


def test_listing_requires_a_key(client):
    assert client.get("/api/webhooks").status_code == 401


def test_listing_rejects_an_unknown_key(client):
    response = client.get("/api/webhooks", headers={"Authorization": "Bearer sm_nope"})
    assert response.status_code == 401


def test_event_catalogue_is_public_but_documented(client):
    response = client.get("/api/webhooks/events")
    assert response.status_code == 200
    names = [e["name"] for e in response.json()["events"]]
    assert names == ["email.sent", "email.failed", "email.received"]


# --- CRUD -----------------------------------------------------------------


def test_create_returns_a_signing_secret(client, auth):
    response = client.post(
        "/api/webhooks",
        headers=auth,
        json={"url": HOOK_URL, "events": ["email.sent"], "description": "prod"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["url"] == HOOK_URL
    assert body["events"] == ["email.sent"]
    assert body["secret"].startswith("whsec_")
    assert body["is_active"] is True
    assert body["site_domain"] == "example.com"


def test_create_defaults_to_all_events(client, auth):
    response = client.post("/api/webhooks", headers=auth, json={"url": HOOK_URL})
    assert response.status_code == 201
    assert response.json()["events"] == ["email.sent", "email.failed", "email.received"]


def test_create_rejects_unknown_events(client, auth):
    response = client.post(
        "/api/webhooks", headers=auth, json={"url": HOOK_URL, "events": ["email.exploded"]}
    )
    assert response.status_code == 422
    assert "email.exploded" in response.text


def test_create_rejects_empty_event_list(client, auth):
    response = client.post("/api/webhooks", headers=auth, json={"url": HOOK_URL, "events": []})
    assert response.status_code == 422


def test_create_rejects_private_urls(client, auth, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "webhook_allow_private_targets", False)
    response = client.post(
        "/api/webhooks", headers=auth, json={"url": "http://169.254.169.254/latest/"}
    )
    assert response.status_code == 422
    assert "private" in response.text.lower()


def test_create_rejects_non_http_schemes(client, auth):
    response = client.post("/api/webhooks", headers=auth, json={"url": "file:///etc/passwd"})
    assert response.status_code == 422


def test_list_get_patch_delete_roundtrip(client, auth):
    created = client.post(
        "/api/webhooks", headers=auth, json={"url": HOOK_URL, "events": ["email.sent"]}
    ).json()
    hook_id = created["id"]

    listed = client.get("/api/webhooks", headers=auth).json()
    assert [h["id"] for h in listed] == [hook_id]

    fetched = client.get(f"/api/webhooks/{hook_id}", headers=auth).json()
    assert fetched["url"] == HOOK_URL

    patched = client.patch(
        f"/api/webhooks/{hook_id}",
        headers=auth,
        json={"events": ["email.failed", "email.received"], "is_active": False},
    ).json()
    assert patched["events"] == ["email.failed", "email.received"]
    assert patched["is_active"] is False
    assert patched["url"] == HOOK_URL, "untouched fields must be preserved"

    assert client.delete(f"/api/webhooks/{hook_id}", headers=auth).status_code == 204
    assert client.get(f"/api/webhooks/{hook_id}", headers=auth).status_code == 404


def test_rotate_secret_changes_it(client, auth):
    created = client.post("/api/webhooks", headers=auth, json={"url": HOOK_URL}).json()
    rotated = client.post(f"/api/webhooks/{created['id']}/rotate-secret", headers=auth).json()
    assert rotated["secret"] != created["secret"]
    assert rotated["secret"].startswith("whsec_")


def test_stats_reports_zero_for_a_fresh_webhook(client, auth):
    created = client.post("/api/webhooks", headers=auth, json={"url": HOOK_URL}).json()
    stats = client.get(f"/api/webhooks/{created['id']}/stats", headers=auth).json()
    assert stats == {
        "webhook_id": created["id"],
        "pending": 0,
        "success": 0,
        "failed": 0,
        "total": 0,
    }


# --- Isolation between sites ---------------------------------------------


@pytest.mark.asyncio
async def test_a_site_key_cannot_read_another_sites_webhook(client, site):
    other = await _second_site()
    async with async_session() as db:
        db.add(Webhook(site_id=other.id, url=HOOK_URL, events="email.sent", secret="whsec_x"))
        await db.commit()
        foreign_id = (
            await db.execute(select(Webhook.id).where(Webhook.site_id == other.id))
        ).scalar_one()

    auth = {"Authorization": f"Bearer {site.api_key}"}
    assert client.get("/api/webhooks", headers=auth).json() == []
    assert client.get(f"/api/webhooks/{foreign_id}", headers=auth).status_code == 404
    assert client.delete(f"/api/webhooks/{foreign_id}", headers=auth).status_code == 404
    assert (
        client.patch(f"/api/webhooks/{foreign_id}", headers=auth, json={"is_active": False}).status_code
        == 404
    )


@pytest.mark.asyncio
async def test_site_key_cannot_impersonate_another_site_via_query(client, site):
    await _second_site()
    auth = {"Authorization": f"Bearer {site.api_key}"}
    response = client.get("/api/webhooks?site_domain=other.test", headers=auth)
    assert response.status_code == 403
    assert "scoped" in response.text


# --- Global admin key -----------------------------------------------------


@pytest.mark.asyncio
async def test_global_key_must_name_a_site(client, site, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "api_key", "global-admin-key")
    auth = {"Authorization": "Bearer global-admin-key"}

    missing = client.get("/api/webhooks", headers=auth)
    assert missing.status_code == 400
    assert "site_domain" in missing.text

    scoped = client.get(f"/api/webhooks?site_domain={site.domain}", headers=auth)
    assert scoped.status_code == 200


@pytest.mark.asyncio
async def test_global_key_gets_404_for_an_unknown_site(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "api_key", "global-admin-key")
    response = client.get(
        "/api/webhooks?site_domain=nope.test", headers={"Authorization": "Bearer global-admin-key"}
    )
    assert response.status_code == 404
