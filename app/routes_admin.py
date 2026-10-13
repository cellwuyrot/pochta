"""Admin panel routes."""
import asyncio
import logging
from pathlib import Path

import dns.resolver
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import SESSION_COOKIE, create_session_token, get_current_admin, require_admin
from app.config import settings
from app.database import get_db
from app.models import (
    EmailLog,
    EmailProvider,
    EmailTemplate,
    Site,
    User,
    generate_api_key,
    hash_password,
    verify_password,
)
from app.net_util import resolve_server_ip
from app.ratelimit import RateLimiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])
_BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_BASE_DIR / "templates"))

# Throttle login attempts per IP to blunt credential brute-forcing.
login_rate_limit = RateLimiter(settings.rate_limit_login_per_min, name="login attempts")


def _clean_domain(raw: str) -> str:
    """Strip protocol, trailing slashes and whitespace from a domain input."""
    from app.domain_util import normalize_domain
    try:
        return normalize_domain(raw)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


# --- Auth ---


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": ""})


def _warn_if_cookie_will_be_dropped(request: Request) -> None:
    """Turn a silent login failure into a diagnosable one.

    With COOKIE_SECURE=true the session cookie carries ``Secure``, and browsers
    discard a Secure cookie delivered over plain http:// (an IP address in
    particular). The user then bounces straight back to the login page with no
    error at all, which looks exactly like a wrong password. If we are about to
    hand out a cookie the browser will refuse, say so in the log.
    """
    if not settings.cookie_secure:
        return
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    scheme = forwarded_proto or request.url.scheme
    if scheme == "https":
        return
    logger.warning(
        "Login succeeded over %s:// but COOKIE_SECURE=true, so the browser will discard the "
        "session cookie and the user will appear stuck on the login page. Either serve the "
        "panel over HTTPS, or set COOKIE_SECURE=false in .env for plain-http access.",
        scheme,
    )


@router.post("/login", dependencies=[Depends(login_rate_limit)])
async def login_submit(
    request: Request,
    username: str = Form(...),
    # Default "" rather than required: an empty field is a failed login, not a
    # 422 validation error. verify_password() rejects empty passwords outright.
    password: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    user = (await db.execute(select(User).where(User.username == username, User.is_active.is_(True)))).scalar_one_or_none()
    if user and verify_password(password, user.password_hash, user.password_salt):
        token = create_session_token(username, role=user.role)
        _warn_if_cookie_will_be_dropped(request)
        response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
        # Secure flag (HTTPS-only) is on by default; SameSite=Lax blocks the
        # cookie on cross-site POSTs, which mitigates CSRF on the admin forms.
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="lax",
            secure=settings.cookie_secure,
            max_age=86400 * 7,
        )
        return response
    return templates.TemplateResponse(request, "login.html", {"error": "Неверный логин или пароль"})


@router.post("/logout")
async def logout(admin: str = Depends(get_current_admin)):
    response = RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(SESSION_COOKIE)
    return response


# --- Dashboard ---


@router.get("", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db), admin: str = Depends(get_current_admin)):
    sites_count = (await db.execute(select(func.count(Site.id)))).scalar() or 0
    templates_count = (await db.execute(select(func.count(EmailTemplate.id)))).scalar() or 0
    total_sent = (await db.execute(select(func.count(EmailLog.id)).where(EmailLog.direction == "outgoing", EmailLog.status.in_(["accepted", "sent"])))).scalar() or 0
    total_failed = (await db.execute(select(func.count(EmailLog.id)).where(EmailLog.direction == "outgoing", EmailLog.status.in_(["failed", "unknown"])))).scalar() or 0
    from app.models import OutboxMessage
    queued_count = (await db.execute(select(func.count(OutboxMessage.id)).where(OutboxMessage.status == "queued"))).scalar() or 0
    total_received = (await db.execute(select(func.count(EmailLog.id)).where(EmailLog.direction == "incoming"))).scalar() or 0
    recent_logs = (
        await db.execute(select(EmailLog).order_by(EmailLog.created_at.desc()).limit(10))
    ).scalars().all()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "admin": admin,
            "sites_count": sites_count,
            "templates_count": templates_count,
            "total_sent": total_sent,
            "total_failed": total_failed,
            "queued_count": queued_count,
            "total_received": total_received,
            "recent_logs": recent_logs,
        },
    )


# --- Sites ---


@router.get("/sites", response_class=HTMLResponse)
async def sites_list(request: Request, db: AsyncSession = Depends(get_db), admin: str = Depends(get_current_admin)):
    sites = (await db.execute(select(Site).order_by(Site.created_at.desc()))).scalars().all()
    return templates.TemplateResponse(request, "sites.html", {"admin": admin, "sites": sites})


@router.get("/sites/new", response_class=HTMLResponse)
async def site_new(request: Request, admin: str = Depends(get_current_admin)):
    return templates.TemplateResponse(
        request, "site_form.html", {"admin": admin, "site": None, "provider_count": 0}
    )


@router.post("/sites/new")
async def site_create(
    request: Request,
    name: str = Form(...),
    domain: str = Form(...),
    sender_email: str = Form(...),
    sender_name: str = Form(""),
    relay_host: str = Form(""),
    relay_port: int = Form(587),
    relay_username: str = Form(""),
    relay_password: str = Form(""),
    relay_use_tls: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    from app.dkim_util import generate_dkim_keypair

    domain = _clean_domain(domain)
    dkim_private_key, _ = generate_dkim_keypair()
    site = Site(
        name=name,
        domain=domain,
        sender_email=sender_email,
        sender_name=sender_name,
        relay_host=relay_host,
        relay_port=relay_port,
        relay_username=relay_username,
        relay_password=relay_password,
        relay_use_tls=relay_use_tls,
        dkim_selector="smtp",
        dkim_private_key=dkim_private_key,
    )
    db.add(site)
    await db.commit()
    return RedirectResponse(url="/admin/sites", status_code=status.HTTP_302_FOUND)


@router.get("/sites/{site_id}/edit", response_class=HTMLResponse)
async def site_edit(
    request: Request,
    site_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    site = (await db.execute(select(Site).where(Site.id == site_id))).scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404)
    # Providers configured through the API take precedence over the relay fields
    # on this form; say so rather than letting the two silently disagree.
    provider_count = (
        await db.execute(
            select(func.count(EmailProvider.id)).where(
                EmailProvider.site_id == site.id, EmailProvider.is_active.is_(True)
            )
        )
    ).scalar() or 0
    return templates.TemplateResponse(
        request,
        "site_form.html",
        {"admin": admin, "site": site, "provider_count": provider_count},
    )


@router.post("/sites/{site_id}/edit")
async def site_update(
    request: Request,
    site_id: int,
    name: str = Form(...),
    domain: str = Form(...),
    sender_email: str = Form(...),
    sender_name: str = Form(""),
    is_active: bool = Form(False),
    relay_host: str = Form(""),
    relay_port: int = Form(587),
    relay_username: str = Form(""),
    relay_password: str = Form(""),
    relay_use_tls: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    site = (await db.execute(select(Site).where(Site.id == site_id))).scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404)
    site.name = name
    site.domain = _clean_domain(domain)
    from app.domain_util import normalize_email
    try:
        sender_email = normalize_email(sender_email)
        if site.mailbox_mode:
            from app.mailboxes import validate_sender
            await validate_sender(db, site, sender_email)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    site.sender_email = sender_email.lower() if site.mailbox_mode else sender_email
    site.sender_name = sender_name
    site.is_active = is_active
    site.relay_host = relay_host
    site.relay_port = relay_port
    site.relay_username = relay_username
    if relay_password:
        site.relay_password = relay_password
    if (await request.form()).get("clear_relay_password"):
        site.relay_password = ""
    site.relay_use_tls = relay_use_tls
    await db.commit()
    return RedirectResponse(url="/admin/sites", status_code=status.HTTP_302_FOUND)


@router.post("/sites/{site_id}/delete")
async def site_delete(
    site_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    # ORM cascades remove mailbox secrets and dependent records; bulk delete
    # would bypass cascades and leave orphaned credentials in SQLite.
    site = await db.get(Site, site_id)
    if not site:
        raise HTTPException(404)
    from app.models import DeliveryAttempt, OutboxMessage
    await db.execute(delete(DeliveryAttempt).where(DeliveryAttempt.site_id == site_id))
    await db.execute(delete(OutboxMessage).where(OutboxMessage.site_id == site_id))
    await db.delete(site)
    await db.commit()
    return RedirectResponse(url="/admin/sites", status_code=status.HTTP_302_FOUND)


@router.post("/sites/{site_id}/toggle")
async def site_toggle(
    site_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    site = (await db.execute(select(Site).where(Site.id == site_id))).scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404)
    site.is_active = not site.is_active
    await db.commit()
    return RedirectResponse(url="/admin/sites", status_code=status.HTTP_302_FOUND)


@router.post("/sites/{site_id}/regenerate-key")
async def site_regenerate_key(
    site_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(get_current_admin),
):
    """Generate a new API key for a site."""
    site = (await db.execute(select(Site).where(Site.id == site_id))).scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404)
    site.api_key = generate_api_key()
    await db.commit()
    return RedirectResponse(url="/admin/sites", status_code=status.HTTP_302_FOUND)


@router.get("/sites/{site_id}/dns", response_class=HTMLResponse)
async def site_dns(
    request: Request,
    site_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    site = (await db.execute(select(Site).where(Site.id == site_id))).scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404)
    if site.mailbox_mode:
        return templates.TemplateResponse(request, "mailbox_dns.html", {"admin": admin, "site": site})
    domain = _clean_domain(site.domain)
    server_ip = await asyncio.to_thread(resolve_server_ip)
    smtp_hostname = settings.smtp_domain or ""
    # MX records use hostnames, not IPs.
    if smtp_hostname and not smtp_hostname.replace(".", "").isdigit():
        mx_hostname = smtp_hostname
    else:
        mx_hostname = f"mail.{domain}"
    dns_records = [
        {
            "type": "TXT",
            "name": f"{domain} (или @)",
            "value": f"v=spf1 ip4:{server_ip} ~all",
            "description": "SPF — разрешает серверу отправлять письма",
            "status": "pending",
        },
    ]

    # DKIM — public key derived from the site's private key.
    if site.dkim_private_key:
        from app.dkim_util import dkim_dns_value

        dns_records.append({
            "type": "TXT",
            "name": f"{site.dkim_selector}._domainkey.{domain}",
            "value": dkim_dns_value(site.dkim_private_key),
            "description": "DKIM — публичный ключ для проверки подписи (ключевой фактор доставляемости)",
            "status": "pending",
        })

    dns_records.extend([
        {
            "type": "TXT",
            "name": f"_dmarc.{domain}",
            "value": f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; adkim=s; aspf=s",
            "description": "DMARC — политика обработки писем (строгое выравнивание)",
            "status": "pending",
        },
        {
            "type": "MX",
            "name": f"{domain} (или @)",
            "value": mx_hostname,
            "priority": "10",
            "description": "MX — сервер для приёма писем",
            "status": "pending",
        },
    ])
    if smtp_hostname.replace(".", "").isdigit() or smtp_hostname != mx_hostname:
        dns_records.append({
            "type": "A",
            "name": f"mail.{domain}",
            "value": server_ip,
            "description": f"A — привязка mail.{domain} к IP сервера",
            "status": "pending",
        })

    # PTR (reverse DNS) is set at the hosting/VPS provider, not in the domain
    # zone, but it is essential for direct-to-MX delivery — surface it here.
    dns_records.append({
        "type": "PTR",
        "name": f"{server_ip} (у хостинг-провайдера)",
        "value": mx_hostname,
        "description": "PTR/rDNS — обратная запись IP → hostname. Настраивается в панели VPS",
        "status": "pending",
    })
    return templates.TemplateResponse(
        request,
        "dns.html",
        {"admin": admin, "site": site, "dns_records": dns_records, "server_ip": server_ip},
    )


def _check_dns_records(domain: str, server_ip: str, dkim_selector: str = "") -> dict[str, dict[str, str]]:
    """Check actual DNS records for a domain. Returns status per record type."""
    results: dict[str, dict[str, str]] = {}

    # Check DKIM (selector._domainkey.domain)
    if dkim_selector:
        try:
            dkim_answers = dns.resolver.resolve(f"{dkim_selector}._domainkey.{domain}", "TXT")
            if any("v=DKIM1" in str(r) or "p=" in str(r) for r in dkim_answers):
                results["dkim"] = {"status": "verified", "detail": "DKIM запись найдена"}
            else:
                results["dkim"] = {"status": "missing", "detail": "DKIM запись не найдена"}
        except Exception:
            results["dkim"] = {"status": "missing", "detail": "DKIM запись не найдена"}

    # Check SPF
    try:
        txt_answers = dns.resolver.resolve(domain, "TXT")
        spf_found = any("v=spf1" in str(r) for r in txt_answers)
        spf_has_ip = any(server_ip in str(r) and "v=spf1" in str(r) for r in txt_answers)
        if spf_has_ip:
            results["spf"] = {"status": "verified", "detail": "SPF запись найдена и содержит IP сервера"}
        elif spf_found:
            results["spf"] = {"status": "warning", "detail": f"SPF запись найдена, но не содержит IP {server_ip}"}
        else:
            results["spf"] = {"status": "missing", "detail": "SPF запись не найдена"}
    except Exception:
        results["spf"] = {"status": "missing", "detail": "SPF запись не найдена"}

    # Check DMARC
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_found = any("v=DMARC1" in str(r) for r in dmarc_answers)
        if dmarc_found:
            results["dmarc"] = {"status": "verified", "detail": "DMARC запись найдена"}
        else:
            results["dmarc"] = {"status": "missing", "detail": "DMARC запись не найдена"}
    except Exception:
        results["dmarc"] = {"status": "missing", "detail": "DMARC запись не найдена"}

    # Check MX
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        mx_hosts = [str(r.exchange).rstrip(".") for r in mx_answers]
        # Check if any MX host resolves to the server IP
        mx_matches = False
        for mx_host in mx_hosts:
            if server_ip in mx_host or mx_host == server_ip:
                mx_matches = True
                break
            try:
                a_records = dns.resolver.resolve(mx_host, "A")
                if any(str(r) == server_ip for r in a_records):
                    mx_matches = True
                    break
            except Exception:
                pass
        if mx_matches:
            results["mx"] = {"status": "verified", "detail": f"MX запись указывает на сервер ({', '.join(mx_hosts)})"}
        elif mx_hosts:
            results["mx"] = {
                "status": "warning",
                "detail": f"MX записи найдены ({', '.join(mx_hosts)}), но не указывают на {server_ip}",
            }
        else:
            results["mx"] = {"status": "missing", "detail": "MX записи не найдены"}
    except Exception:
        results["mx"] = {"status": "missing", "detail": "MX записи не найдены"}

    return results


@router.get("/sites/{site_id}/dns/verify")
async def site_dns_verify(
    site_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(get_current_admin),
):
    """Check DNS records for a site and return JSON status."""
    site = (await db.execute(select(Site).where(Site.id == site_id))).scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404)
    if site.mailbox_mode:
        return JSONResponse({"domain": site.domain, "all_verified": False, "records": {},
                             "note": "Mailboxes are hosted by Beget; keep Beget MX and configure DNS there."})
    domain = _clean_domain(site.domain)
    server_ip = await asyncio.to_thread(resolve_server_ip)
    results = await asyncio.to_thread(
        _check_dns_records, domain, server_ip, dkim_selector=site.dkim_selector
    )
    all_verified = all(r["status"] == "verified" for r in results.values())
    return JSONResponse({
        "domain": domain,
        "all_verified": all_verified,
        "records": results,
    })


@router.get("/guide", response_class=HTMLResponse)
async def setup_guide(request: Request, admin: str = Depends(get_current_admin)):
    """Comprehensive setup guide page."""
    return templates.TemplateResponse(
        request,
        "guide.html",
        {"admin": admin, "server_ip": await asyncio.to_thread(resolve_server_ip)},
    )


# --- Users (admin only) ---


@router.get("/users", response_class=HTMLResponse)
async def users_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    users = (await db.execute(select(User).order_by(User.created_at.desc()))).scalars().all()
    return templates.TemplateResponse(
        request, "users.html", {"admin": current_user.username, "users": users, "current_user": current_user},
    )


@router.get("/users/new", response_class=HTMLResponse)
async def user_new(
    request: Request,
    current_user: User = Depends(require_admin),
):
    return templates.TemplateResponse(request, "user_form.html", {"admin": current_user.username, "edit_user": None, "error": ""})


@router.post("/users/new")
async def user_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    existing = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if existing:
        return templates.TemplateResponse(
            request, "user_form.html",
            {"admin": current_user.username, "edit_user": None, "error": "Пользователь с таким логином уже существует"},
        )
    pw_hash, pw_salt = hash_password(password)
    if role not in ("admin", "user"):
        raise HTTPException(422, "Invalid role")
    from app.domain_util import normalize_domain
    domains = (await request.form()).get("smtp_domains", "")
    try:
        domains = ",".join(normalize_domain(d) for d in domains.split(",") if d.strip())
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    user = User(username=username, password_hash=pw_hash, password_salt=pw_salt, role=role, smtp_domains=domains)
    db.add(user)
    await db.commit()
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_302_FOUND)


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
async def user_edit(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    edit_user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not edit_user:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request, "user_form.html", {"admin": current_user.username, "edit_user": edit_user, "error": ""},
    )


@router.post("/users/{user_id}/edit")
async def user_update(
    request: Request,
    user_id: int,
    username: str = Form(...),
    password: str = Form(""),
    role: str = Form("user"),
    is_active: bool = Form(True),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    edit_user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not edit_user:
        raise HTTPException(status_code=404)
    edit_user.username = username
    if role not in ("admin", "user"):
        raise HTTPException(422, "Invalid role")
    from app.domain_util import normalize_domain
    try:
        edit_user.smtp_domains = ",".join(normalize_domain(d) for d in (await request.form()).get("smtp_domains", "").split(",") if d.strip())
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    edit_user.role = role
    edit_user.is_active = is_active
    if password:
        pw_hash, pw_salt = hash_password(password)
        edit_user.password_hash = pw_hash
        edit_user.password_salt = pw_salt
    await db.commit()
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_302_FOUND)


@router.post("/users/{user_id}/delete")
async def user_delete(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    await db.execute(delete(User).where(User.id == user_id))
    await db.commit()
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_302_FOUND)


# --- Templates ---


@router.get("/templates", response_class=HTMLResponse)
async def templates_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    tpls = (
        await db.execute(select(EmailTemplate).options(selectinload(EmailTemplate.site)).order_by(EmailTemplate.created_at.desc()))
    ).scalars().all()
    return templates.TemplateResponse(request, "templates_list.html", {"admin": admin, "templates": tpls})


@router.get("/templates/new", response_class=HTMLResponse)
async def template_new(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    sites = (await db.execute(select(Site).where(Site.is_active.is_(True)))).scalars().all()
    return templates.TemplateResponse(
        request, "template_form.html", {"admin": admin, "template": None, "sites": sites}
    )


@router.post("/templates/new")
async def template_create(
    request: Request,
    site_id: int = Form(...),
    name: str = Form(...),
    slug: str = Form(...),
    subject: str = Form(...),
    body_html: str = Form(...),
    body_text: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    tpl = EmailTemplate(
        site_id=site_id,
        name=name,
        slug=slug,
        subject=subject,
        body_html=body_html,
        body_text=body_text,
    )
    db.add(tpl)
    await db.commit()
    return RedirectResponse(url="/admin/templates", status_code=status.HTTP_302_FOUND)


@router.get("/templates/{tpl_id}/edit", response_class=HTMLResponse)
async def template_edit(
    request: Request,
    tpl_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    tpl = (await db.execute(select(EmailTemplate).where(EmailTemplate.id == tpl_id))).scalar_one_or_none()
    if not tpl:
        raise HTTPException(status_code=404)
    sites = (await db.execute(select(Site).where(Site.is_active.is_(True)))).scalars().all()
    return templates.TemplateResponse(
        request, "template_form.html", {"admin": admin, "template": tpl, "sites": sites}
    )


@router.post("/templates/{tpl_id}/edit")
async def template_update(
    request: Request,
    tpl_id: int,
    site_id: int = Form(...),
    name: str = Form(...),
    slug: str = Form(...),
    subject: str = Form(...),
    body_html: str = Form(...),
    body_text: str = Form(""),
    is_active: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    tpl = (await db.execute(select(EmailTemplate).where(EmailTemplate.id == tpl_id))).scalar_one_or_none()
    if not tpl:
        raise HTTPException(status_code=404)
    tpl.site_id = site_id
    tpl.name = name
    tpl.slug = slug
    tpl.subject = subject
    tpl.body_html = body_html
    tpl.body_text = body_text
    tpl.is_active = is_active
    await db.commit()
    return RedirectResponse(url="/admin/templates", status_code=status.HTTP_302_FOUND)


@router.post("/templates/{tpl_id}/delete")
async def template_delete(
    tpl_id: int,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    await db.execute(delete(EmailTemplate).where(EmailTemplate.id == tpl_id))
    await db.commit()
    return RedirectResponse(url="/admin/templates", status_code=status.HTTP_302_FOUND)


# --- Logs ---


@router.get("/logs", response_class=HTMLResponse)
async def logs_list(
    request: Request,
    page: int = 1,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    per_page = 50
    offset = (page - 1) * per_page
    total = (await db.execute(select(func.count(EmailLog.id)))).scalar() or 0
    logs = (
        await db.execute(select(EmailLog).order_by(EmailLog.created_at.desc()).offset(offset).limit(per_page))
    ).scalars().all()
    total_pages = max(1, (total + per_page - 1) // per_page)
    return templates.TemplateResponse(
        request,
        "logs.html",
        {
            "admin": admin,
            "logs": logs,
            "page": page,
            "total_pages": total_pages,
            "total": total,
        },
    )


@router.post("/logs/clear")
async def logs_clear(db: AsyncSession = Depends(get_db), admin: str = Depends(get_current_admin)):
    await db.execute(delete(EmailLog))
    await db.commit()
    return RedirectResponse(url="/admin/logs", status_code=status.HTTP_302_FOUND)
