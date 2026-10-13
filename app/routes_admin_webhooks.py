"""Admin panel routes for webhooks.

Kept in its own module rather than piled onto ``routes_admin`` (already 670+
lines covering seven unrelated areas) — a small step towards splitting that file
into a package.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import get_current_admin
from app.database import get_db
from app.models import WEBHOOK_EVENTS, Site, Webhook, WebhookDelivery, generate_webhook_secret
from app.webhook_service import WebhookUrlError, dispatch_due_deliveries, validate_webhook_url

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/webhooks", tags=["admin"])
_BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_BASE_DIR / "templates"))


@router.get("", response_class=HTMLResponse)
async def webhooks_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    hooks = (
        await db.execute(
            select(Webhook).options(selectinload(Webhook.site)).order_by(Webhook.created_at.desc())
        )
    ).scalars().all()

    counts = dict(
        (
            await db.execute(
                select(WebhookDelivery.webhook_id, func.count(WebhookDelivery.id)).group_by(
                    WebhookDelivery.webhook_id
                )
            )
        ).all()
    )
    pending = dict(
        (
            await db.execute(
                select(WebhookDelivery.webhook_id, func.count(WebhookDelivery.id))
                .where(WebhookDelivery.status == "pending")
                .group_by(WebhookDelivery.webhook_id)
            )
        ).all()
    )
    failed = dict(
        (
            await db.execute(
                select(WebhookDelivery.webhook_id, func.count(WebhookDelivery.id))
                .where(WebhookDelivery.status == "failed")
                .group_by(WebhookDelivery.webhook_id)
            )
        ).all()
    )

    return templates.TemplateResponse(
        request,
        "webhooks.html",
        {
            "admin": admin,
            "webhooks": hooks,
            "counts": counts,
            "pending": pending,
            "failed": failed,
        },
    )


@router.get("/new", response_class=HTMLResponse)
async def webhook_new(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    sites = (await db.execute(select(Site).where(Site.is_active.is_(True)))).scalars().all()
    return templates.TemplateResponse(
        request,
        "webhook_form.html",
        {
            "admin": admin,
            "webhook": None,
            "sites": sites,
            "all_events": WEBHOOK_EVENTS,
            "error": "",
        },
    )


async def _render_form_error(request, db, admin, webhook, message: str):
    sites = (await db.execute(select(Site).where(Site.is_active.is_(True)))).scalars().all()
    return templates.TemplateResponse(
        request,
        "webhook_form.html",
        {
            "admin": admin,
            "webhook": webhook,
            "sites": sites,
            "all_events": WEBHOOK_EVENTS,
            "error": message,
        },
    )


@router.post("/new")
async def webhook_create(
    request: Request,
    site_id: int = Form(...),
    url: str = Form(...),
    description: str = Form(""),
    events: list[str] = Form(default=[]),
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    if not events:
        return await _render_form_error(request, db, admin, None, "Выберите хотя бы одно событие")
    try:
        clean_url = validate_webhook_url(url)
    except WebhookUrlError as exc:
        return await _render_form_error(request, db, admin, None, str(exc))

    hook = Webhook(
        site_id=site_id,
        url=clean_url,
        description=description,
        events=",".join(e for e in WEBHOOK_EVENTS if e in set(events)),
        secret=generate_webhook_secret(),
        is_active=True,
    )
    db.add(hook)
    await db.commit()
    return RedirectResponse(url="/admin/webhooks", status_code=status.HTTP_302_FOUND)


@router.get("/{webhook_id}/edit", response_class=HTMLResponse)
async def webhook_edit(
    request: Request,
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    hook = (await db.execute(select(Webhook).where(Webhook.id == webhook_id))).scalar_one_or_none()
    if not hook:
        raise HTTPException(status_code=404)
    sites = (await db.execute(select(Site).where(Site.is_active.is_(True)))).scalars().all()
    return templates.TemplateResponse(
        request,
        "webhook_form.html",
        {
            "admin": admin,
            "webhook": hook,
            "sites": sites,
            "all_events": WEBHOOK_EVENTS,
            "error": "",
        },
    )


@router.post("/{webhook_id}/edit")
async def webhook_update(
    request: Request,
    webhook_id: int,
    site_id: int = Form(...),
    url: str = Form(...),
    description: str = Form(""),
    events: list[str] = Form(default=[]),
    is_active: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    hook = (await db.execute(select(Webhook).where(Webhook.id == webhook_id))).scalar_one_or_none()
    if not hook:
        raise HTTPException(status_code=404)
    if not events:
        return await _render_form_error(request, db, admin, hook, "Выберите хотя бы одно событие")
    try:
        hook.url = validate_webhook_url(url)
    except WebhookUrlError as exc:
        return await _render_form_error(request, db, admin, hook, str(exc))

    hook.site_id = site_id
    hook.description = description
    hook.events = ",".join(e for e in WEBHOOK_EVENTS if e in set(events))
    hook.is_active = is_active
    await db.commit()
    return RedirectResponse(url="/admin/webhooks", status_code=status.HTTP_302_FOUND)


@router.post("/{webhook_id}/delete")
async def webhook_delete(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    await db.execute(delete(WebhookDelivery).where(WebhookDelivery.webhook_id == webhook_id))
    await db.execute(delete(Webhook).where(Webhook.id == webhook_id))
    await db.commit()
    return RedirectResponse(url="/admin/webhooks", status_code=status.HTTP_302_FOUND)


@router.post("/{webhook_id}/toggle")
async def webhook_toggle(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    hook = (await db.execute(select(Webhook).where(Webhook.id == webhook_id))).scalar_one_or_none()
    if not hook:
        raise HTTPException(status_code=404)
    hook.is_active = not hook.is_active
    await db.commit()
    return RedirectResponse(url="/admin/webhooks", status_code=status.HTTP_302_FOUND)


@router.post("/{webhook_id}/rotate-secret")
async def webhook_rotate_secret(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    hook = (await db.execute(select(Webhook).where(Webhook.id == webhook_id))).scalar_one_or_none()
    if not hook:
        raise HTTPException(status_code=404)
    hook.secret = generate_webhook_secret()
    await db.commit()
    return RedirectResponse(url="/admin/webhooks", status_code=status.HTTP_302_FOUND)


@router.post("/{webhook_id}/test")
async def webhook_send_test(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    """Queue a test event and dispatch it immediately."""
    import datetime
    import json

    hook = (await db.execute(select(Webhook).where(Webhook.id == webhook_id))).scalar_one_or_none()
    if not hook:
        raise HTTPException(status_code=404)
    db.add(
        WebhookDelivery(
            webhook_id=hook.id,
            event="webhook.test",
            payload=json.dumps(
                {
                    "event": "webhook.test",
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "data": {"message": "This is a test event from your SMTP service."},
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
        )
    )
    await db.commit()
    await dispatch_due_deliveries()
    return RedirectResponse(
        url=f"/admin/webhooks/{webhook_id}/deliveries", status_code=status.HTTP_302_FOUND
    )


@router.get("/{webhook_id}/deliveries", response_class=HTMLResponse)
async def webhook_deliveries(
    request: Request,
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    hook = (
        await db.execute(
            select(Webhook).options(selectinload(Webhook.site)).where(Webhook.id == webhook_id)
        )
    ).scalar_one_or_none()
    if not hook:
        raise HTTPException(status_code=404)
    deliveries = (
        await db.execute(
            select(WebhookDelivery)
            .where(WebhookDelivery.webhook_id == webhook_id)
            .order_by(WebhookDelivery.created_at.desc())
            .limit(100)
        )
    ).scalars().all()
    return templates.TemplateResponse(
        request,
        "webhook_deliveries.html",
        {"admin": admin, "webhook": hook, "deliveries": deliveries},
    )
