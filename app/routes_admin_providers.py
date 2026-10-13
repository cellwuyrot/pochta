"""Admin-only provider management, queue observability and diagnostics."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_admin
from app.config import settings
from app.database import get_db
from app.models import DeliveryAttempt, EmailProvider, OutboxMessage, Site
from app.providers import PRESETS, record_test_result, resolve_relay_targets, test_connection
from app.routes_admin import templates
from app.smtp_server import _build_tls_context

router = APIRouter(prefix="/admin", dependencies=[Depends(get_current_admin)])


def redirect():
    return RedirectResponse("/admin/providers", status_code=303)


@router.get("/providers")
async def providers(request: Request, db: AsyncSession = Depends(get_db), admin: str = Depends(get_current_admin)):
    rows = (
        (
            await db.execute(
                select(EmailProvider).order_by(EmailProvider.site_id, EmailProvider.priority, EmailProvider.id)
            )
        )
        .scalars()
        .all()
    )
    sites = (await db.execute(select(Site))).scalars().all()
    orders = {site.id: [t.label for t in await resolve_relay_targets(db, site)] for site in sites}
    return templates.TemplateResponse(
        request,
        "providers.html",
        {
            "admin": admin,
            "providers": rows,
            "sites": {s.id: s for s in sites},
            "orders": orders,
            "direct_mx": settings.allow_direct_mx,
        },
    )


@router.get("/providers/new")
@router.get("/providers/{provider_id}/edit")
async def provider_form(
    request: Request,
    provider_id: int | None = None,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    row = await db.get(EmailProvider, provider_id) if provider_id else None
    if provider_id and not row:
        raise HTTPException(404)
    sites = (await db.execute(select(Site).order_by(Site.name))).scalars().all()
    return templates.TemplateResponse(
        request, "provider_form.html", {"admin": admin, "provider": row, "sites": sites, "presets": PRESETS.values()}
    )


@router.post("/providers/new")
@router.post("/providers/{provider_id}/edit")
async def provider_save(request: Request, provider_id: int | None = None, db: AsyncSession = Depends(get_db)):
    form = await request.form()
    try:
        site_id, port, priority = int(form["site_id"]), int(form["port"]), int(form["priority"])
        if not 1 <= port <= 65535 or not 0 <= priority <= 100000:
            raise ValueError("Invalid port or priority")
    except (ValueError, KeyError) as exc:
        raise HTTPException(422, "Invalid provider fields") from exc
    site = await db.get(Site, site_id)
    if not site:
        raise HTTPException(422, "Site not found")
    row = await db.get(EmailProvider, provider_id) if provider_id else EmailProvider(site_id=site_id)
    if provider_id and not row:
        raise HTTPException(404)
    name, host, preset = form.get("name", "").strip(), form.get("host", "").strip(), form.get("preset", "custom")
    if preset not in PRESETS:
        raise HTTPException(422, "Unknown preset")
    host = host or PRESETS[preset].host
    if not name or not host or len(name) > 255 or len(host) > 253 or any(c in host for c in "/:@ \r\n"):
        raise HTTPException(422, "Name and valid SMTP hostname are required")
    use_tls = form.get("use_tls") == "true"
    password = form.get("password", "")
    if form.get("username") and (password or row.password) and port != 465 and not use_tls:
        raise HTTPException(422, "Credentials require TLS")
    row.site_id, row.name, row.host, row.port = site_id, name, host, port
    row.preset, row.username, row.priority = preset, form.get("username", ""), priority
    row.use_tls, row.is_active = use_tls, form.get("is_active") == "true"
    if form.get("clear_password"):
        row.password = ""
    elif password:
        row.password = password
    row.last_tested_at, row.last_test_ok, row.last_test_error = None, None, ""
    db.add(row)
    await db.commit()
    return redirect()


@router.post("/providers/{provider_id}/{action}")
async def provider_action(provider_id: int, action: str, db: AsyncSession = Depends(get_db)):
    row = await db.get(EmailProvider, provider_id)
    if not row:
        raise HTTPException(404)
    if action == "test":
        ok, error, _ = await asyncio.to_thread(
            test_connection, row.host, row.port, row.username, row.password, row.use_tls
        )
        record_test_result(row, ok, error)
    elif action == "primary":
        others = (await db.execute(select(EmailProvider).where(EmailProvider.site_id == row.site_id))).scalars().all()
        for i, other in enumerate(sorted(others, key=lambda p: (p.priority, p.id)), 1):
            other.priority = i * 10
        row.priority, row.is_active = 0, True
    elif action == "toggle":
        row.is_active = not row.is_active
    elif action == "delete":
        await db.delete(row)
    else:
        raise HTTPException(404)
    await db.commit()
    return redirect()


@router.get("/queue")
async def queue(
    request: Request,
    state: str = "",
    page: int = 1,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    conditions = [OutboxMessage.status == state] if state else []
    total = (await db.execute(select(func.count()).select_from(OutboxMessage).where(*conditions))).scalar()
    rows = (
        (
            await db.execute(
                select(OutboxMessage)
                .where(*conditions)
                .order_by(OutboxMessage.created_at.desc())
                .offset((max(page, 1) - 1) * 50)
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request, "queue.html", {"admin": admin, "jobs": rows, "state": state, "page": max(page, 1), "total": total}
    )


@router.get("/messages/{message_id}")
async def message(
    request: Request, message_id: str, db: AsyncSession = Depends(get_db), admin: str = Depends(get_current_admin)
):
    attempts = (
        (
            await db.execute(
                select(DeliveryAttempt).where(DeliveryAttempt.message_id == message_id).order_by(DeliveryAttempt.id)
            )
        )
        .scalars()
        .all()
    )
    row = await db.get(OutboxMessage, message_id)
    if not attempts and not row:
        raise HTTPException(404)
    return templates.TemplateResponse(
        request, "message.html", {"admin": admin, "job": row, "attempts": attempts, "message_id": message_id}
    )


@router.get("/settings")
async def diagnostics(request: Request, db: AsyncSession = Depends(get_db), admin: str = Depends(get_current_admin)):
    await db.execute(select(1))
    tls = await asyncio.to_thread(_build_tls_context)
    states = (await db.execute(select(OutboxMessage.status, func.count()).group_by(OutboxMessage.status))).all()
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "admin": admin,
            "tls": bool(tls),
            "inbound": settings.inbound_enabled,
            "direct_mx": settings.allow_direct_mx,
            "states": states,
            "secure_cookie": settings.cookie_secure,
            "smtp_port": settings.smtp_port,
            "max_recipients": settings.smtp_max_recipients,
            "max_bytes": settings.smtp_max_message_bytes,
        },
    )
