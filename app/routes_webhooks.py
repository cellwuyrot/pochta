"""REST API for managing webhook subscriptions.

Every endpoint is scoped to a single site: a per-site API key implies its own
site, while the global admin key must name one with ``?site_domain=``.
"""

import datetime
import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api_auth import authorized_site
from app.config import settings
from app.database import get_db
from app.models import WEBHOOK_EVENTS, Site, Webhook, WebhookDelivery, generate_webhook_secret
from app.ratelimit import RateLimiter
from app.webhook_service import (
    WebhookUrlError,
    dispatch_due_deliveries,
    validate_webhook_url,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

webhook_rate_limit = RateLimiter(settings.rate_limit_api_per_min, name="requests")


# --- Schemas --------------------------------------------------------------


class WebhookCreate(BaseModel):
    url: str
    events: list[str] = Field(default_factory=lambda: list(WEBHOOK_EVENTS))
    description: str = ""
    is_active: bool = True


class WebhookUpdate(BaseModel):
    url: str | None = None
    events: list[str] | None = None
    description: str | None = None
    is_active: bool | None = None


class WebhookOut(BaseModel):
    id: int
    site_domain: str
    url: str
    events: list[str]
    description: str
    secret: str
    is_active: bool
    created_at: datetime.datetime | None = None


class DeliveryOut(BaseModel):
    id: int
    event: str
    status: str
    attempts: int
    response_status: int | None
    error_message: str
    created_at: datetime.datetime | None = None
    completed_at: datetime.datetime | None = None
    next_attempt_at: datetime.datetime | None = None


class TestResult(BaseModel):
    delivery_id: int
    status: str
    response_status: int | None = None
    error_message: str = ""


def _to_out(hook: Webhook, site: Site) -> WebhookOut:
    return WebhookOut(
        id=hook.id,
        site_domain=site.domain,
        url=hook.url,
        events=hook.event_list,
        description=hook.description,
        secret=hook.secret,
        is_active=hook.is_active,
        created_at=hook.created_at,
    )


def _validate_events(events: list[str]) -> str:
    """Normalise a requested event list into the stored CSV form."""
    if not events:
        raise HTTPException(status_code=422, detail="At least one event is required")
    unknown = [e for e in events if e not in WEBHOOK_EVENTS]
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown events: {', '.join(unknown)}. Valid: {', '.join(WEBHOOK_EVENTS)}",
        )
    # De-duplicate while keeping the documented order stable.
    return ",".join(e for e in WEBHOOK_EVENTS if e in set(events))


def _validate_url(url: str) -> str:
    try:
        return validate_webhook_url(url)
    except WebhookUrlError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


async def _get_owned(db: AsyncSession, site: Site, webhook_id: int) -> Webhook:
    hook = (
        await db.execute(
            select(Webhook).where(Webhook.id == webhook_id, Webhook.site_id == site.id)
        )
    ).scalar_one_or_none()
    if not hook:
        raise HTTPException(status_code=404, detail=f"Webhook {webhook_id} not found")
    return hook


# --- Endpoints ------------------------------------------------------------


@router.get("/events")
async def list_event_types():
    """The event names a webhook may subscribe to."""
    return {
        "events": [
            {"name": "email.sent", "description": "An outbound message was accepted by the next hop"},
            {"name": "email.failed", "description": "An outbound message could not be delivered"},
            {"name": "email.received", "description": "An inbound message arrived for one of your domains"},
        ]
    }


@router.get("", response_model=list[WebhookOut])
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    hooks = (
        await db.execute(
            select(Webhook).where(Webhook.site_id == site.id).order_by(Webhook.created_at.desc())
        )
    ).scalars().all()
    return [_to_out(h, site) for h in hooks]


@router.post("", response_model=WebhookOut, status_code=201, dependencies=[Depends(webhook_rate_limit)])
async def create_webhook(
    payload: WebhookCreate,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    """Register an endpoint to receive this site's email events.

    The response contains the signing ``secret`` — store it, it is what you use
    to verify the ``X-Smtp-Signature`` header on every incoming request.
    """
    hook = Webhook(
        site_id=site.id,
        url=_validate_url(payload.url),
        events=_validate_events(payload.events),
        description=payload.description,
        is_active=payload.is_active,
        secret=generate_webhook_secret(),
    )
    db.add(hook)
    await db.commit()
    await db.refresh(hook)
    logger.info("Webhook %s created for site %s -> %s", hook.id, site.domain, hook.url)
    return _to_out(hook, site)


@router.get("/{webhook_id}", response_model=WebhookOut)
async def get_webhook(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    return _to_out(await _get_owned(db, site, webhook_id), site)


@router.patch("/{webhook_id}", response_model=WebhookOut)
async def update_webhook(
    webhook_id: int,
    payload: WebhookUpdate,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    hook = await _get_owned(db, site, webhook_id)
    if payload.url is not None:
        hook.url = _validate_url(payload.url)
    if payload.events is not None:
        hook.events = _validate_events(payload.events)
    if payload.description is not None:
        hook.description = payload.description
    if payload.is_active is not None:
        hook.is_active = payload.is_active
    await db.commit()
    await db.refresh(hook)
    return _to_out(hook, site)


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    hook = await _get_owned(db, site, webhook_id)
    await db.execute(delete(WebhookDelivery).where(WebhookDelivery.webhook_id == hook.id))
    await db.execute(delete(Webhook).where(Webhook.id == hook.id))
    await db.commit()


@router.post("/{webhook_id}/rotate-secret", response_model=WebhookOut)
async def rotate_secret(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    """Issue a new signing secret. The previous one stops validating immediately."""
    hook = await _get_owned(db, site, webhook_id)
    hook.secret = generate_webhook_secret()
    await db.commit()
    await db.refresh(hook)
    return _to_out(hook, site)


@router.post("/{webhook_id}/test", response_model=TestResult)
async def test_webhook(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    """Send a signed sample event now and report what the endpoint answered.

    Unlike real events this does not wait for the background dispatcher, so the
    response tells you straight away whether your endpoint is reachable and
    returning 2xx.
    """
    hook = await _get_owned(db, site, webhook_id)
    delivery = WebhookDelivery(
        webhook_id=hook.id,
        event="webhook.test",
        payload=json.dumps(
            {
                "event": "webhook.test",
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "data": {
                    "site_domain": site.domain,
                    "message": "This is a test event from your SMTP service.",
                },
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
    )
    db.add(delivery)
    await db.commit()
    await db.refresh(delivery)

    await dispatch_due_deliveries()

    refreshed = (
        await db.execute(select(WebhookDelivery).where(WebhookDelivery.id == delivery.id))
    ).scalar_one()
    await db.refresh(refreshed)
    return TestResult(
        delivery_id=refreshed.id,
        status=refreshed.status,
        response_status=refreshed.response_status,
        error_message=refreshed.error_message,
    )


@router.get("/{webhook_id}/deliveries", response_model=list[DeliveryOut])
async def list_deliveries(
    webhook_id: int,
    limit: int = 50,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    """Recent delivery attempts, newest first."""
    hook = await _get_owned(db, site, webhook_id)
    query = select(WebhookDelivery).where(WebhookDelivery.webhook_id == hook.id)
    if status:
        query = query.where(WebhookDelivery.status == status)
    rows = (
        await db.execute(query.order_by(WebhookDelivery.created_at.desc()).limit(min(limit, 200)))
    ).scalars().all()
    return [
        DeliveryOut(
            id=r.id,
            event=r.event,
            status=r.status,
            attempts=r.attempts,
            response_status=r.response_status,
            error_message=r.error_message,
            created_at=r.created_at,
            completed_at=r.completed_at,
            next_attempt_at=r.next_attempt_at,
        )
        for r in rows
    ]


@router.get("/{webhook_id}/stats")
async def delivery_stats(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    site: Site = Depends(authorized_site),
):
    """Delivery counts by status for this webhook."""
    hook = await _get_owned(db, site, webhook_id)
    rows = (
        await db.execute(
            select(WebhookDelivery.status, func.count(WebhookDelivery.id))
            .where(WebhookDelivery.webhook_id == hook.id)
            .group_by(WebhookDelivery.status)
        )
    ).all()
    counts = {status: count for status, count in rows}
    return {
        "webhook_id": hook.id,
        "pending": counts.get("pending", 0),
        "success": counts.get("success", 0),
        "failed": counts.get("failed", 0),
        "total": sum(counts.values()),
    }
