"""REST API for managing external SMTP providers per site.

Scoped exactly like the webhook API: a per-site key implies its own site, the
global key must name one with ``?site_domain=``.

Passwords are write-only. They are never echoed back — responses carry
``has_password`` instead — so a leaked read-only token cannot harvest relay
credentials.
"""

import asyncio
import datetime
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api_auth import authorized_site
from app.config import settings
from app.database import get_db
from app.models import EmailProvider, Site
from app.providers import (
    IMPLICIT_TLS_PORT,
    PRESETS,
    preset_catalogue,
    record_test_result,
    test_connection,
)
from app.ratelimit import RateLimiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/providers", tags=["providers"])

provider_rate_limit = RateLimiter(settings.rate_limit_api_per_min, name="requests")


# --- Schemas --------------------------------------------------------------


class ProviderCreate(BaseModel):
    name: str
    preset: str = "custom"
    host: str = ""
    port: int | None = None
    username: str = ""
    password: str = ""
    use_tls: bool | None = None
    is_active: bool = True
    priority: int = 100


class ProviderUpdate(BaseModel):
    name: str | None = None
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    use_tls: bool | None = None
    is_active: bool | None = None
    priority: int | None = None


class ProviderOut(BaseModel):
    id: int
    site_domain: str
    name: str
    preset: str
    host: str
    port: int
    username: str
    has_password: bool
    use_tls: bool
    implicit_tls: bool
    is_active: bool
    priority: int
    last_tested_at: datetime.datetime | None = None
    last_test_ok: bool | None = None
    last_test_error: str = ""
    created_at: datetime.datetime | None = None


class ConnectionTest(BaseModel):
    """Ad-hoc parameters, for checking credentials before saving them."""

    host: str
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True


class TestResult(BaseModel):
    ok: bool
    error: str = ""
    steps: list[str] = []


def _to_out(provider: EmailProvider, site: Site) -> ProviderOut:
    return ProviderOut(
        id=provider.id,
        site_domain=site.domain,
        name=provider.name,
        preset=provider.preset,
        host=provider.host,
        port=provider.port,
        username=provider.username,
        has_password=bool(provider.password),
        use_tls=provider.use_tls,
        implicit_tls=provider.port == IMPLICIT_TLS_PORT,
        is_active=provider.is_active,
        priority=provider.priority,
        last_tested_at=provider.last_tested_at,
        last_test_ok=provider.last_test_ok,
        last_test_error=provider.last_test_error,
        created_at=provider.created_at,
    )


async def _get_owned(db: AsyncSession, site: Site, provider_id: int) -> EmailProvider:
    provider = (
        await db.execute(
            select(EmailProvider).where(
                EmailProvider.id == provider_id, EmailProvider.site_id == site.id
            )
        )
    ).scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail=f"Provider {provider_id} not found")
    return provider


# --- Endpoints ------------------------------------------------------------


@router.get("/presets")
async def list_presets():
    """Known providers with their host/port defaults and what they want as a login."""
    return {"presets": preset_catalogue()}


@router.get("", response_model=list[ProviderOut])
async def list_providers(
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    providers = (
        await db.execute(
            select(EmailProvider)
            .where(EmailProvider.site_id == site.id)
            .order_by(EmailProvider.priority, EmailProvider.id)
        )
    ).scalars().all()
    return [_to_out(p, site) for p in providers]


@router.post("", response_model=ProviderOut, status_code=201, dependencies=[Depends(provider_rate_limit)])
async def create_provider(
    payload: ProviderCreate,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    """Add a provider. A known ``preset`` fills in whatever you leave out.

    The active provider with the lowest ``priority`` is used for sending; the
    others stay configured as standby and are tried in order if it fails.
    """
    if payload.preset not in PRESETS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown preset '{payload.preset}'. Valid: {', '.join(PRESETS)}",
        )
    preset = PRESETS[payload.preset]

    host = payload.host or preset.host
    if not host:
        raise HTTPException(
            status_code=422,
            detail=f"host is required (preset '{payload.preset}' does not provide a default)",
        )
    port = payload.port if payload.port is not None else preset.port
    use_tls = payload.use_tls if payload.use_tls is not None else preset.use_tls

    provider = EmailProvider(
        site_id=site.id,
        name=payload.name or preset.label,
        preset=payload.preset,
        host=host,
        port=port,
        username=payload.username,
        password=payload.password,
        use_tls=use_tls,
        is_active=payload.is_active,
        priority=payload.priority,
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    logger.info(
        "Provider %s (%s) added for site %s -> %s:%d",
        provider.id, provider.preset, site.domain, provider.host, provider.port,
    )
    return _to_out(provider, site)


@router.get("/{provider_id}", response_model=ProviderOut)
async def get_provider(
    provider_id: int,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    return _to_out(await _get_owned(db, site, provider_id), site)


@router.patch("/{provider_id}", response_model=ProviderOut)
async def update_provider(
    provider_id: int,
    payload: ProviderUpdate,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    """Update a provider. Omitted fields are left alone.

    Sending ``password`` replaces the stored one; omitting it keeps the existing
    value, so a client that never reads passwords can still edit other fields.
    """
    provider = await _get_owned(db, site, provider_id)
    for attribute in ("name", "host", "port", "username", "use_tls", "is_active", "priority"):
        value = getattr(payload, attribute)
        if value is not None:
            setattr(provider, attribute, value)
    if payload.password is not None:
        provider.password = payload.password
        # Stored credentials changed, so the previous test result says nothing
        # about whether this provider still works.
        provider.last_tested_at = None
        provider.last_test_ok = None
        provider.last_test_error = ""
    await db.commit()
    await db.refresh(provider)
    return _to_out(provider, site)


@router.delete("/{provider_id}", status_code=204)
async def delete_provider(
    provider_id: int,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    provider = await _get_owned(db, site, provider_id)
    await db.execute(delete(EmailProvider).where(EmailProvider.id == provider.id))
    await db.commit()


@router.post("/test", response_model=TestResult, dependencies=[Depends(provider_rate_limit)])
async def test_arbitrary_connection(
    payload: ConnectionTest,
    _site: Site = Depends(authorized_site),
):
    """Check host/port/credentials WITHOUT saving them.

    Useful before creating a provider: it reports which step failed — reachability,
    STARTTLS, or the login itself — instead of only surfacing later as a bounced
    message.
    """
    ok, error, steps = await asyncio.to_thread(
        test_connection,
        host=payload.host,
        port=payload.port,
        username=payload.username,
        password=payload.password,
        use_tls=payload.use_tls,
    )
    return TestResult(ok=ok, error=error, steps=steps)


@router.post("/{provider_id}/test", response_model=TestResult, dependencies=[Depends(provider_rate_limit)])
async def test_saved_provider(
    provider_id: int,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    """Connect and log in using a saved provider's stored credentials.

    The outcome is recorded on the provider, so ``last_test_ok`` answers "did
    this ever work?" without dialling the provider again.
    """
    provider = await _get_owned(db, site, provider_id)
    # Blocking smtplib: off the event loop.
    ok, error, steps = await asyncio.to_thread(
        test_connection,
        host=provider.host,
        port=provider.port,
        username=provider.username,
        password=provider.password,
        use_tls=provider.use_tls,
    )
    record_test_result(provider, ok, error)
    await db.commit()
    return TestResult(ok=ok, error=error, steps=steps)


@router.get("/{provider_id}/resolved-order")
async def show_resolution_order(
    provider_id: int,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    """Explain which relay this site would actually use, and in what order.

    Providers coexist with the older per-site relay fields and the global .env
    relay, and it is not obvious from any single screen which one wins. This makes
    the effective order explicit.
    """
    from app.providers import resolve_relay_targets

    await _get_owned(db, site, provider_id)  # authorisation check only
    targets = await resolve_relay_targets(db, site)
    return {
        "site_domain": site.domain,
        "order": [
            {
                "position": index,
                "source": target.label,
                "host": target.host,
                "port": target.port,
                "implicit_tls": target.port == IMPLICIT_TLS_PORT,
                "authenticated": bool(target.username),
            }
            for index, target in enumerate(targets, start=1)
        ],
        "fallback": "direct MX delivery" if not targets else None,
    }
