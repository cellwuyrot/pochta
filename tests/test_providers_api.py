"""Provider CRUD, presets, and credential handling over REST."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import async_session
from app.models import EmailProvider, Site
from app.providers import PRESETS


@pytest.fixture
def client():
    from app.config import settings

    settings.smtp_port = 0
    from app.main import app

    return TestClient(app)


@pytest.fixture
def auth(site):
    return {"Authorization": f"Bearer {site.api_key}"}


# --- Presets --------------------------------------------------------------


def test_preset_catalogue_is_served(client):
    response = client.get("/api/providers/presets")
    assert response.status_code == 200
    presets = {p["name"]: p for p in response.json()["presets"]}
    assert {"postmark", "sendgrid", "mailgun", "ses", "yandex", "gmail", "custom"} <= presets.keys()
    assert presets["postmark"]["host"] == "smtp.postmarkapp.com"
    assert presets["yandex"]["implicit_tls"] is True, "port 465 must be flagged as implicit TLS"
    assert presets["sendgrid"]["port"] == 587
    assert presets["ses"]["needs_attention"] == ["host"], "SES host is region-specific"


def test_presets_route_is_not_shadowed_by_the_id_route(client, auth):
    """`/presets` must not be parsed as a provider id."""
    assert client.get("/api/providers/presets").status_code == 200
    assert client.get("/api/providers/999", headers=auth).status_code == 404


# --- Creation -------------------------------------------------------------


def test_preset_fills_in_host_and_port(client, auth):
    response = client.post(
        "/api/providers", headers=auth, json={"name": "Postmark prod", "preset": "postmark"}
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["host"] == "smtp.postmarkapp.com"
    assert body["port"] == 587
    assert body["use_tls"] is True
    assert body["implicit_tls"] is False


def test_yandex_preset_is_flagged_as_implicit_tls(client, auth):
    body = client.post("/api/providers", headers=auth, json={"name": "Y", "preset": "yandex"}).json()
    assert body["port"] == 465
    assert body["implicit_tls"] is True


def test_explicit_values_override_the_preset(client, auth):
    body = client.post(
        "/api/providers",
        headers=auth,
        json={"name": "SES eu", "preset": "ses", "host": "email-smtp.eu-west-1.amazonaws.com", "port": 2587},
    ).json()
    assert body["host"] == "email-smtp.eu-west-1.amazonaws.com"
    assert body["port"] == 2587


def test_custom_preset_requires_a_host(client, auth):
    response = client.post("/api/providers", headers=auth, json={"name": "Mine", "preset": "custom"})
    assert response.status_code == 422
    assert "host is required" in response.text


def test_unknown_preset_is_rejected(client, auth):
    response = client.post(
        "/api/providers", headers=auth, json={"name": "X", "preset": "sendblue"}
    )
    assert response.status_code == 422
    assert "sendblue" in response.text


def test_creation_requires_a_key(client):
    assert client.post("/api/providers", json={"name": "X", "preset": "postmark"}).status_code == 401


# --- Passwords are write-only --------------------------------------------


def test_password_is_never_returned(client, auth):
    created = client.post(
        "/api/providers",
        headers=auth,
        json={"name": "P", "preset": "postmark", "username": "token", "password": "s3cret-token"},
    ).json()

    assert "password" not in created
    assert created["has_password"] is True

    fetched = client.get(f"/api/providers/{created['id']}", headers=auth).json()
    assert "password" not in fetched

    listed = client.get("/api/providers", headers=auth).json()
    assert all("password" not in p for p in listed)

    # And it is genuinely absent from the serialised body, not merely renamed.
    assert "s3cret-token" not in client.get("/api/providers", headers=auth).text


@pytest.mark.asyncio
async def test_password_is_stored_even_though_it_is_not_returned(client, auth):
    created = client.post(
        "/api/providers",
        headers=auth,
        json={"name": "P", "preset": "postmark", "password": "s3cret-token"},
    ).json()
    async with async_session() as db:
        provider = (
            await db.execute(select(EmailProvider).where(EmailProvider.id == created["id"]))
        ).scalar_one()
    assert provider.password == "s3cret-token"


@pytest.mark.asyncio
async def test_omitting_password_on_patch_keeps_the_existing_one(client, auth):
    created = client.post(
        "/api/providers",
        headers=auth,
        json={"name": "P", "preset": "postmark", "password": "original"},
    ).json()

    patched = client.patch(
        f"/api/providers/{created['id']}", headers=auth, json={"name": "Renamed"}
    ).json()
    assert patched["name"] == "Renamed"
    assert patched["has_password"] is True

    async with async_session() as db:
        provider = (
            await db.execute(select(EmailProvider).where(EmailProvider.id == created["id"]))
        ).scalar_one()
    assert provider.password == "original", "a name change must not wipe the credentials"


@pytest.mark.asyncio
async def test_changing_the_password_invalidates_the_previous_test_result(client, auth):
    created = client.post(
        "/api/providers",
        headers=auth,
        json={"name": "P", "preset": "postmark", "password": "original"},
    ).json()

    async with async_session() as db:
        provider = (
            await db.execute(select(EmailProvider).where(EmailProvider.id == created["id"]))
        ).scalar_one()
        provider.last_test_ok = True
        provider.last_test_error = ""
        await db.commit()

    patched = client.patch(
        f"/api/providers/{created['id']}", headers=auth, json={"password": "rotated"}
    ).json()
    assert patched["last_test_ok"] is None, (
        "a stored 'it worked' must not survive a credential change"
    )


# --- CRUD and isolation ---------------------------------------------------


def test_list_is_ordered_by_priority(client, auth):
    client.post("/api/providers", headers=auth, json={"name": "backup", "preset": "mailgun", "priority": 50})
    client.post("/api/providers", headers=auth, json={"name": "primary", "preset": "postmark", "priority": 10})
    names = [p["name"] for p in client.get("/api/providers", headers=auth).json()]
    assert names == ["primary", "backup"]


def test_delete_removes_the_provider(client, auth):
    created = client.post("/api/providers", headers=auth, json={"name": "P", "preset": "postmark"}).json()
    assert client.delete(f"/api/providers/{created['id']}", headers=auth).status_code == 204
    assert client.get(f"/api/providers/{created['id']}", headers=auth).status_code == 404


@pytest.mark.asyncio
async def test_a_site_key_cannot_touch_another_sites_provider(client, site):
    async with async_session() as db:
        other = Site(name="O", domain="other.test", sender_email="n@other.test", api_key="sm_o")
        db.add(other)
        await db.commit()
        await db.refresh(other)
        db.add(EmailProvider(site_id=other.id, name="theirs", host="smtp.other.test"))
        await db.commit()
        foreign_id = (
            await db.execute(select(EmailProvider.id).where(EmailProvider.site_id == other.id))
        ).scalar_one()

    auth = {"Authorization": f"Bearer {site.api_key}"}
    assert client.get("/api/providers", headers=auth).json() == []
    assert client.get(f"/api/providers/{foreign_id}", headers=auth).status_code == 404
    assert client.delete(f"/api/providers/{foreign_id}", headers=auth).status_code == 404
    assert client.post(f"/api/providers/{foreign_id}/test", headers=auth).status_code == 404


def test_every_preset_can_be_created(client, auth):
    """Catch a preset whose defaults are not actually usable."""
    for name in PRESETS:
        payload = {"name": name, "preset": name}
        if name == "custom":
            payload["host"] = "smtp.example.test"
        response = client.post("/api/providers", headers=auth, json=payload)
        assert response.status_code == 201, f"preset {name} failed: {response.text}"
