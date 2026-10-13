"""Key validation (`GET /api/me`) and tenant isolation on the domain endpoints.

Two defects motivated these tests:

1. ``verify_api_key`` only checked that a bearer token was *non-empty*; the actual
   comparison against a real key happened later, "once the target site is known".
   For ``/api/domains`` and ``/api/domains/{domain}/dns`` that moment never came,
   so any ``Authorization: Bearer anything`` was accepted.
2. ``/api/domains`` returned every configured site regardless of which key asked,
   leaking other tenants' domains, sender addresses, names and relay status.

There was also no way at all for a client to validate a key and discover what it
grants, which is what an integration's "Connect" screen needs.
"""
import pytest
from fastapi.testclient import TestClient

from app.database import async_session
from app.models import Site

GARBAGE = {"Authorization": "Bearer sm_this_key_does_not_exist"}
GLOBAL_KEY = "global-admin-key"


@pytest.fixture
def client():
    from app.config import settings

    settings.smtp_port = 0
    from app.main import app

    return TestClient(app)


@pytest.fixture
def use_global_key(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "api_key", GLOBAL_KEY)
    return {"Authorization": f"Bearer {GLOBAL_KEY}"}


async def _make_site(domain: str, key: str, *, active: bool = True, **overrides) -> Site:
    fields = {
        "name": f"Site {domain}",
        "domain": domain,
        "sender_email": f"noreply@{domain}",
        "api_key": key,
        "is_active": active,
        "dkim_private_key": "",
    }
    fields.update(overrides)
    async with async_session() as db:
        s = Site(**fields)
        db.add(s)
        await db.commit()
        await db.refresh(s)
        return s


# --- Hole 1: unvalidated tokens ------------------------------------------


@pytest.mark.asyncio
async def test_domains_rejects_an_unknown_token(client):
    """Any non-empty bearer used to be accepted here."""
    await _make_site("alpha.ru", "sm_alpha")
    response = client.get("/api/domains", headers=GARBAGE)
    assert response.status_code == 401, (
        f"unknown key was accepted: {response.status_code} {response.text[:200]}"
    )


@pytest.mark.asyncio
async def test_domain_dns_rejects_an_unknown_token(client):
    await _make_site("alpha.ru", "sm_alpha")
    response = client.get("/api/domains/alpha.ru/dns", headers=GARBAGE)
    assert response.status_code == 401


def test_domains_rejects_a_missing_token(client):
    assert client.get("/api/domains").status_code == 401


@pytest.mark.asyncio
async def test_domains_rejects_the_key_of_a_deactivated_site(client):
    """Switching a site off must revoke its key everywhere."""
    await _make_site("off.ru", "sm_off", active=False)
    assert client.get("/api/domains", headers={"Authorization": "Bearer sm_off"}).status_code == 401


@pytest.mark.asyncio
async def test_domains_accepts_a_valid_site_key(client):
    await _make_site("alpha.ru", "sm_alpha")
    response = client.get("/api/domains", headers={"Authorization": "Bearer sm_alpha"})
    assert response.status_code == 200


# --- Hole 2: cross-tenant leak -------------------------------------------


@pytest.mark.asyncio
async def test_site_key_sees_only_its_own_domain(client):
    await _make_site("alpha.ru", "sm_alpha", relay_host="smtp.yandex.ru")
    await _make_site("beta.ru", "sm_beta", relay_host="smtp.postmarkapp.com")

    body = client.get("/api/domains", headers={"Authorization": "Bearer sm_alpha"}).json()

    assert [row["domain"] for row in body] == ["alpha.ru"]
    serialised = str(body)
    assert "beta.ru" not in serialised, "another tenant's domain leaked"
    assert "postmarkapp" not in serialised, "another tenant's relay leaked"


@pytest.mark.asyncio
async def test_site_key_cannot_read_another_domains_dns(client):
    await _make_site("alpha.ru", "sm_alpha")
    await _make_site("beta.ru", "sm_beta")

    own = client.get("/api/domains/alpha.ru/dns", headers={"Authorization": "Bearer sm_alpha"})
    assert own.status_code == 200

    foreign = client.get("/api/domains/beta.ru/dns", headers={"Authorization": "Bearer sm_alpha"})
    assert foreign.status_code == 404, "a site key must not read another domain's DNS setup"


@pytest.mark.asyncio
async def test_global_key_still_sees_every_domain(client, use_global_key):
    """The admin-scoped key keeps its fleet-wide view."""
    await _make_site("alpha.ru", "sm_alpha")
    await _make_site("beta.ru", "sm_beta")

    body = client.get("/api/domains", headers=use_global_key).json()
    assert sorted(row["domain"] for row in body) == ["alpha.ru", "beta.ru"]


@pytest.mark.asyncio
async def test_global_key_can_read_any_domains_dns(client, use_global_key):
    await _make_site("beta.ru", "sm_beta")
    assert client.get("/api/domains/beta.ru/dns", headers=use_global_key).status_code == 200


@pytest.mark.asyncio
async def test_domains_never_exposes_relay_credentials(client, use_global_key):
    await _make_site(
        "alpha.ru", "sm_alpha",
        relay_host="smtp.yandex.ru", relay_username="me@ya.ru", relay_password="super-secret",
    )
    text = client.get("/api/domains", headers=use_global_key).text
    assert "super-secret" not in text
    assert "me@ya.ru" not in text


# --- GET /api/me ---------------------------------------------------------


def test_me_requires_a_token(client):
    assert client.get("/api/me").status_code == 401


def test_me_rejects_an_unknown_token(client):
    response = client.get("/api/me", headers=GARBAGE)
    assert response.status_code == 401
    assert "api_key" not in response.text.lower() or "invalid" in response.text.lower()


@pytest.mark.asyncio
async def test_me_identifies_a_site_key(client):
    await _make_site("alpha.ru", "sm_alpha")

    body = client.get("/api/me", headers={"Authorization": "Bearer sm_alpha"}).json()

    assert body["type"] == "site"
    assert body["site"]["domain"] == "alpha.ru"
    assert body["site"]["sender_email"] == "noreply@alpha.ru"
    assert body["site"]["is_active"] is True
    assert "emails:send" in body["scopes"]
    assert "webhooks:manage" in body["scopes"]
    assert "providers:manage" in body["scopes"]
    # Enough service info for a client to show "connected to ..." meaningfully.
    assert body["service"]["version"]
    assert "smtp_domain" in body["service"]


@pytest.mark.asyncio
async def test_me_identifies_the_global_key(client, use_global_key):
    await _make_site("alpha.ru", "sm_alpha")
    await _make_site("beta.ru", "sm_beta")

    body = client.get("/api/me", headers=use_global_key).json()

    assert body["type"] == "global"
    assert body["site"] is None
    assert "*" in body["scopes"]
    assert body["sites_count"] == 2


@pytest.mark.asyncio
async def test_me_rejects_a_deactivated_sites_key(client):
    await _make_site("off.ru", "sm_off", active=False)
    assert client.get("/api/me", headers={"Authorization": "Bearer sm_off"}).status_code == 401


@pytest.mark.asyncio
async def test_me_never_leaks_secrets(client):
    """The response is safe to log on the caller's side."""
    await _make_site(
        "alpha.ru", "sm_alpha",
        relay_host="smtp.yandex.ru", relay_username="me@ya.ru", relay_password="super-secret",
        dkim_private_key="-----BEGIN RSA PRIVATE KEY-----fake-key-material",
    )
    text = client.get("/api/me", headers={"Authorization": "Bearer sm_alpha"}).text

    assert "super-secret" not in text, "relay password leaked"
    assert "PRIVATE KEY" not in text, "DKIM private key leaked"
    assert "sm_alpha" not in text, "the API key should not be echoed back"


@pytest.mark.asyncio
async def test_me_is_a_usable_connection_check(client):
    """What an integration's Connect button actually needs: 401 vs 200 plus a label."""
    await _make_site("alpha.ru", "sm_alpha")

    bad = client.get("/api/me", headers=GARBAGE)
    good = client.get("/api/me", headers={"Authorization": "Bearer sm_alpha"})

    assert (bad.status_code, good.status_code) == (401, 200)
    assert good.json()["site"]["domain"] == "alpha.ru"


@pytest.mark.asyncio
async def test_global_key_takes_precedence_over_a_matching_site_key(client, monkeypatch):
    """A site whose key happens to equal the global key must not downgrade it."""
    from app.config import settings

    monkeypatch.setattr(settings, "api_key", "sm_shared")
    await _make_site("alpha.ru", "sm_shared")

    body = client.get("/api/me", headers={"Authorization": "Bearer sm_shared"}).json()
    assert body["type"] in ("site", "global")  # either is defensible, but it must not 401


# --- Systemic guard ------------------------------------------------------


def _authenticated_api_routes():
    """Every /api route that is meant to require a key.

    Built by walking the app so a newly added endpoint is covered automatically —
    the original bug was exactly an endpoint that looked authenticated but never
    validated the token.
    """
    from fastapi.openapi.utils import get_openapi

    from app.config import settings

    settings.smtp_port = 0
    from app.main import app

    # Deliberately public: a health probe and two static catalogues that contain
    # no tenant data.
    public = {
        ("GET", "/api/health"),
        ("GET", "/api/webhooks/events"),
        ("GET", "/api/providers/presets"),
    }

    # Read the OpenAPI schema rather than walking app.routes: in this FastAPI
    # version app.routes holds router wrappers, not APIRoute objects, so an
    # isinstance filter silently matches nothing and this whole guard would be
    # parametrised with an empty list and skipped.
    schema = get_openapi(title="t", version="1", routes=app.routes)

    routes = [
        (method.upper(), path)
        for path, operations in schema["paths"].items()
        if path.startswith("/api")
        for method in operations
        if (method.upper(), path) not in public
    ]
    assert routes, "no authenticated /api routes discovered — the guard would prove nothing"
    return sorted(set(routes))


@pytest.mark.parametrize(("method", "path"), _authenticated_api_routes())
def test_every_authenticated_endpoint_rejects_an_unknown_key(client, method, path):
    """A bogus key must never get a 2xx out of an authenticated endpoint."""
    concrete = (
        path.replace("{webhook_id}", "1")
        .replace("{provider_id}", "1")
        .replace("{domain}", "alpha.ru")
    )
    response = client.request(method, concrete, headers=GARBAGE, json={})

    assert not (200 <= response.status_code < 300), (
        f"{method} {concrete} returned {response.status_code} for an unknown API key"
    )
    if method == "GET":
        assert response.status_code == 401, (
            f"{method} {concrete} should answer 401, got {response.status_code}"
        )


@pytest.mark.parametrize(("method", "path"), _authenticated_api_routes())
def test_every_authenticated_endpoint_rejects_a_missing_key(client, method, path):
    concrete = (
        path.replace("{webhook_id}", "1")
        .replace("{provider_id}", "1")
        .replace("{domain}", "alpha.ru")
    )
    response = client.request(method, concrete, json={})
    assert not (200 <= response.status_code < 300), (
        f"{method} {concrete} returned {response.status_code} with no API key at all"
    )
