"""Admin project cabinet and a read-only, site-scoped mailbox catalogue."""

import asyncio
import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api_auth import authorized_site
from app.auth import get_current_admin
from app.database import get_db
from app.domain_util import normalize_email
from app.mailboxes import public_mailbox, reconcile_default, validate_sender
from app.models import Mailbox, OutboxMessage, Site
from app.outbox import enqueue_message
from app.providers import test_connection
from app.routes_admin import templates
from app.routes_api import EmailSendRequest, api_rate_limit
from app.smtp_transport import redact_smtp_error

admin_router = APIRouter(prefix="/admin/sites", dependencies=[Depends(get_current_admin)])
api_router = APIRouter(prefix="/api/mailboxes", tags=["mailboxes"])


async def get_site(db, site_id):
    site = await db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Project not found")
    return site


async def get_mailbox(db, site_id, mailbox_id):
    row = await db.get(Mailbox, mailbox_id)
    if not row or row.site_id != site_id:
        raise HTTPException(404, "Mailbox not found in this project")
    return row


def cabinet_redirect(site_id):
    return RedirectResponse(f"/admin/sites/{site_id}", status_code=303)


def form_page(request, site, row, admin, error="", status_code=200):
    return templates.TemplateResponse(request, "mailbox_form.html", {
        "admin": admin, "site": site,
        "mailbox": public_mailbox(row, site.sender_email) if row else None,
        "error": error,
    }, status_code=status_code)


@admin_router.get("/{site_id}")
async def cabinet(request: Request, site_id: int, db: AsyncSession = Depends(get_db),
                  admin: str = Depends(get_current_admin)):
    site = await get_site(db, site_id)
    rows = (await db.execute(select(Mailbox).where(Mailbox.site_id == site_id).order_by(Mailbox.id))).scalars().all()
    jobs = (await db.execute(select(OutboxMessage).where(OutboxMessage.site_id == site_id)
                            .order_by(OutboxMessage.created_at.desc()).limit(10))).scalars().all()
    return templates.TemplateResponse(request, "project.html", {
        "admin": admin, "site": site, "mailboxes": [public_mailbox(m, site.sender_email) for m in rows],
        "jobs": jobs,
    })


@admin_router.get("/{site_id}/mailboxes/new")
async def new_mailbox(request: Request, site_id: int, db: AsyncSession = Depends(get_db),
                      admin: str = Depends(get_current_admin)):
    return form_page(request, await get_site(db, site_id), None, admin)


@admin_router.get("/{site_id}/mailboxes/{mailbox_id}/edit")
async def edit_mailbox(request: Request, site_id: int, mailbox_id: int, db: AsyncSession = Depends(get_db),
                       admin: str = Depends(get_current_admin)):
    site = await get_site(db, site_id)
    return form_page(request, site, await get_mailbox(db, site_id, mailbox_id), admin)


@admin_router.post("/{site_id}/mailboxes/new")
@admin_router.post("/{site_id}/mailboxes/{mailbox_id}/edit")
async def save_mailbox(request: Request, site_id: int, mailbox_id: int | None = None,
                       db: AsyncSession = Depends(get_db), admin: str = Depends(get_current_admin)):
    site = await get_site(db, site_id)
    row = await get_mailbox(db, site_id, mailbox_id) if mailbox_id else None
    form = await request.form()
    try:
        email = normalize_email(str(form.get("email", "")).strip()).lower()
        display_name = str(form.get("display_name", "")).strip()
        password = str(form.get("password", ""))
        if len(display_name) > 255 or any(c in display_name for c in "\r\n"):
            raise ValueError("Имя отправителя: до 255 символов, без переносов строк")
        if len(password) > 1024:
            raise ValueError("Слишком длинный пароль")
        if not password and (not row or not row.password):
            raise ValueError("Укажите пароль почтового ящика Beget, не пароль панели хостинга")
        duplicate = (await db.execute(select(Mailbox).where(
            Mailbox.site_id == site_id, Mailbox.email == email,
        ))).scalar_one_or_none()
        if duplicate and duplicate.id != mailbox_id:
            raise ValueError("Этот адрес уже добавлен в данный проект")
    except ValueError as exc:
        return form_page(request, site, row, admin, str(exc), 422)
    old_email = row.email if row else ""
    row = row or Mailbox(site_id=site_id)
    row.email, row.display_name = email, display_name
    row.smtp_host, row.smtp_port, row.use_tls = "smtp.beget.com", 465, True
    row.is_active = form.get("is_active") == "true"
    if password:
        row.password = password
    row.last_tested_at, row.last_test_ok, row.last_test_error = None, None, ""
    # Once enabled, mailbox mode stays enabled even if all accounts are deleted.
    # This prevents silently reverting to a global relay/direct MX identity.
    first = not site.mailbox_mode
    site.mailbox_mode = True
    if row.is_active and (first or form.get("is_default") == "true" or site.sender_email == old_email):
        site.sender_email, site.sender_name = email, display_name
    db.add(row)
    try:
        await db.flush()
        await reconcile_default(db, site)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        site = await get_site(db, site_id)
        return form_page(request, site, None, admin, "Этот адрес уже существует в проекте", 409)
    return cabinet_redirect(site_id)


@admin_router.post("/{site_id}/mailboxes/{mailbox_id}/{action}", dependencies=[Depends(api_rate_limit)])
async def mailbox_action(site_id: int, mailbox_id: int, action: str, db: AsyncSession = Depends(get_db)):
    site = await get_site(db, site_id)
    row = await get_mailbox(db, site_id, mailbox_id)
    if action == "test":
        if not row.password:
            raise HTTPException(422, "Mailbox has no password")
        ok, error, _ = await asyncio.to_thread(test_connection, row.smtp_host, row.smtp_port,
                                               row.email, row.password, row.use_tls)
        # A malicious server may echo AUTH input in its error response.
        error = redact_smtp_error(error, row.email, row.password)
        row.last_tested_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        row.last_test_ok, row.last_test_error = ok, error[:1000]
    elif action == "default":
        if not row.is_active or not row.password:
            raise HTTPException(422, "Default mailbox must be active and have a password")
        site.sender_email, site.sender_name = row.email, row.display_name
    elif action == "toggle":
        row.is_active = not row.is_active
        await db.flush()
        await reconcile_default(db, site)
    elif action == "delete":
        await db.delete(row)
        await db.flush()
        await reconcile_default(db, site)
    else:
        raise HTTPException(404)
    await db.commit()
    return cabinet_redirect(site_id)


@admin_router.post("/{site_id}/send", dependencies=[Depends(api_rate_limit)])
async def send_from_cabinet(request: Request, site_id: int, db: AsyncSession = Depends(get_db)):
    site = await get_site(db, site_id)
    form = await request.form()
    try:
        req = EmailSendRequest(from_email=str(form.get("from_email", "")), to=str(form.get("to", "")),
                               subject=str(form.get("subject", "")), text=str(form.get("text", "")))
        await validate_sender(db, site, req.from_email)
    except ValueError as exc:
        raise HTTPException(422, "Проверьте адреса, тему, размер текста и активность ящика") from exc
    if not site.mailbox_mode:
        raise HTTPException(422, "Сначала добавьте почтовый ящик")
    row = await enqueue_message(db, site, {
        "from_email": req.from_email, "to_email": req.to, "subject": req.subject,
        "body_html": "", "body_text": req.text,
    })
    await db.commit()
    return RedirectResponse(f"/admin/messages/{row.id}", status_code=303)


@api_router.get("")
async def list_mailboxes(site: Site = Depends(authorized_site), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Mailbox).where(
        Mailbox.site_id == site.id, Mailbox.is_active.is_(True),
    ).order_by(Mailbox.id))).scalars().all()
    return {"site_domain": site.domain, "mailbox_mode": site.mailbox_mode,
            "default_sender": site.sender_email, "mailboxes": [
                {"email": row.email, "display_name": row.display_name,
                 "is_default": row.email == site.sender_email.lower()} for row in rows
            ]}
