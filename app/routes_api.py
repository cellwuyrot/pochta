"""Public API routes for sending emails (Resend-like)."""

import asyncio
import datetime
import logging
import uuid
from html import escape

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.api_auth import (
    ApiIdentity,
    authenticated_identity,
    is_global_key,
    resolve_site_by_key,
    verify_api_key,
)
from app.config import settings
from app.database import get_db
from app.domain_util import normalize_domain, normalize_email
from app.mailboxes import validate_sender
from app.models import DeliveryAttempt, EmailLog, EmailTemplate, Mailbox, Site
from app.providers import resolve_relay_targets, send_via_providers
from app.ratelimit import RateLimiter
from app.webhook_service import enqueue_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["api"])

# Per-IP rate limiter shared across the send endpoints.
api_rate_limit = RateLimiter(settings.rate_limit_api_per_min, name="requests")


def _log_body_preview(html: str, text: str) -> str:
    """Return a stored body preview, honouring the privacy setting.

    When STORE_BODY_PREVIEW is off (default) we do not persist message bodies,
    which otherwise leak OTP codes and personal data into the logs table.
    """
    if not settings.store_body_preview:
        return ""
    source = html or text or ""
    return source[:500]


# --- Models ---


class EmailSendRequest(BaseModel):
    """Resend-like email send request."""

    from_email: str
    to: str | list[str]
    subject: str = Field(max_length=500)
    html: str = Field(default="", max_length=1_000_000)
    text: str = Field(default="", max_length=1_000_000)

    @field_validator("from_email")
    @classmethod
    def sender_valid(cls, value):
        return normalize_email(value)

    @field_validator("to")
    @classmethod
    def recipients_valid(cls, value):
        values = value if isinstance(value, list) else [value]
        if not 1 <= len(values) <= 50:
            raise ValueError("Use 1–50 recipients")
        values = [normalize_email(item) for item in values]
        return values if isinstance(value, list) else values[0]

    @field_validator("subject")
    @classmethod
    def subject_valid(cls, value):
        if "\r" in value or "\n" in value:
            raise ValueError("Subject cannot contain newlines")
        return value


class EmailSendResponse(BaseModel):
    id: str
    message: str = "Accepted by SMTP relay (not mailbox delivery)"


class TemplateSendRequest(BaseModel):
    """Send email via pre-configured template."""

    site_domain: str
    template_slug: str
    to_email: str
    from_email: str | None = None
    variables: dict[str, str] = Field(default_factory=dict, max_length=100)

    @field_validator("from_email")
    @classmethod
    def from_valid(cls, value):
        return normalize_email(value) if value else None

    @field_validator("site_domain")
    @classmethod
    def domain_valid(cls, value):
        return normalize_domain(value)

    @field_validator("to_email")
    @classmethod
    def email_valid(cls, value):
        return normalize_email(value)

    @field_validator("variables")
    @classmethod
    def variables_valid(cls, value):
        if any(len(k) > 100 or len(v) > 10_000 for k, v in value.items()):
            raise ValueError("Template variable too large")
        return value


class SendResponse(BaseModel):
    success: bool
    message: str


class HealthResponse(BaseModel):
    status: str
    version: str
    endpoints: list[str]


class ServiceInfo(BaseModel):
    version: str
    smtp_domain: str


class MeSite(BaseModel):
    """The site a per-site key belongs to. Secrets are intentionally absent."""

    domain: str
    name: str
    sender_email: str
    sender_name: str = ""
    is_active: bool
    has_relay: bool
    dkim_configured: bool
    created_at: datetime.datetime | None = None


class MeResponse(BaseModel):
    type: str
    site: MeSite | None = None
    scopes: list[str]
    sites_count: int | None = None
    service: ServiceInfo


class DomainDNS(BaseModel):
    domain: str
    spf_record: str
    dmarc_record: str
    smtp_server: str


# --- Endpoints ---


@router.get("/health", response_model=HealthResponse)
async def health():
    """Health check with available endpoints list."""
    return HealthResponse(
        status="ok",
        version=__version__,
        endpoints=[
            "GET  /api/health",
            "GET  /api/me",
            "POST /api/emails",
            "POST /api/send",
            "GET  /api/domains",
            "GET  /api/domains/{domain}/dns",
        ],
    )


@router.post("/emails", response_model=EmailSendResponse, dependencies=[Depends(api_rate_limit)])
async def send_email_direct(
    req: EmailSendRequest,
    db: AsyncSession = Depends(get_db),
    auth_token: str = Depends(verify_api_key),
    site_domain: str | None = None,
):
    """Send email directly (Resend-like API).

    Authentication is mandatory. A per-site key scopes sending to that site's
    domain; the optional global key may send as any configured active domain.
    You can only send From a domain you have configured as a Site — arbitrary
    sender spoofing is rejected.

    Example:
        POST /api/emails
        Authorization: Bearer sm_your_site_api_key
        {
            "from_email": "noreply@tophitt.ru",
            "to": "user@example.com",
            "subject": "Код подтверждения",
            "html": "<p>Ваш код: <b>123456</b></p>"
        }
    """
    recipients = req.to if isinstance(req.to, list) else [req.to]
    from_domain = req.from_email.split("@")[-1].lower() if "@" in req.from_email else ""

    # Site keys explicitly scope mailbox identities, even if a project's domain
    # differs from the mailbox domain. Global callers can select ?site_domain=.
    if site_domain:
        try:
            site_domain = normalize_domain(site_domain)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    site = await resolve_site_by_key(db, auth_token)
    if site:
        if site_domain and site_domain != site.domain:
            raise HTTPException(403, "API key is scoped to a different project")
    elif is_global_key(auth_token):
        if site_domain:
            site = (await db.execute(select(Site).where(
                Site.domain == site_domain, Site.is_active.is_(True)
            ))).scalar_one_or_none()
        else:
            candidates = (await db.execute(select(Site).outerjoin(Mailbox).where(
                Site.is_active.is_(True),
                ((Site.mailbox_mode.is_(True) & (Mailbox.email == req.from_email.lower()) & Mailbox.is_active.is_(True))
                 | (Site.mailbox_mode.is_(False) & (Site.domain == from_domain))),
            ).distinct())).scalars().all()
            if len(candidates) > 1:
                raise HTTPException(400, "Mailbox belongs to multiple projects; add ?site_domain=example.com")
            site = candidates[0] if candidates else None
        if not site:
            raise HTTPException(403, "No active project configured for this sender")
    else:
        raise HTTPException(401, "Invalid API key")
    try:
        await validate_sender(db, site, req.from_email)
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc

    email_id = str(uuid.uuid4())
    errors = []

    for to_email in recipients:
        # Walks the site's configured providers in priority order, falling back to
        # the legacy per-site relay and then the global one. Each attempt runs in a
        # worker thread: send_email() is synchronous smtplib with a 30s socket
        # timeout, and calling it inline would block the event loop and freeze
        # every other request, admin panel included.
        success, error, relay_source = await send_via_providers(
            db,
            site,
            message_id=email_id,
            to_email=to_email,
            subject=req.subject,
            body_html=req.html,
            body_text=req.text,
            from_email=req.from_email,
            from_name=site.sender_name,
            dkim_domain=site.domain,
            dkim_selector=site.dkim_selector,
            dkim_private_key=site.dkim_private_key,
        )

        log_entry = EmailLog(
            site_id=site.id,
            direction="outgoing",
            sender=req.from_email,
            recipient=to_email,
            subject=req.subject,
            body_preview=_log_body_preview(req.html, req.text),
            status="accepted" if success else "failed",
            message_id=email_id,
            relay_source=relay_source,
            attempts=(
                await db.execute(
                    select(func.count(DeliveryAttempt.id)).where(
                        DeliveryAttempt.message_id == email_id, DeliveryAttempt.recipient == to_email
                    )
                )
            ).scalar()
            or 0,
            error_message=error,
        )
        db.add(log_entry)

        # Queued in the same transaction as the log row, dispatched later by the
        # background worker, so a subscriber's slow endpoint never delays this
        # response.
        await enqueue_event(
            db,
            site.id,
            "email.sent" if success else "email.failed",
            {
                "email_id": email_id,
                "site_domain": site.domain,
                "from": req.from_email,
                "to": to_email,
                "subject": req.subject,
                "status": "accepted" if success else "failed",
                "error": error or None,
                "relay": relay_source,
            },
        )

        if not success:
            errors.append(f"{to_email}: {error}")

    await db.commit()

    if errors:
        raise HTTPException(status_code=500, detail="; ".join(errors))

    return EmailSendResponse(id=email_id)


@router.post("/send", response_model=SendResponse, dependencies=[Depends(api_rate_limit)])
async def api_send_email(
    req: TemplateSendRequest,
    db: AsyncSession = Depends(get_db),
    auth_token: str = Depends(verify_api_key),
):
    """Send email via site template (legacy endpoint)."""
    site = (
        await db.execute(select(Site).where(Site.domain == req.site_domain, Site.is_active.is_(True)))
    ).scalar_one_or_none()
    if not site:
        raise HTTPException(
            status_code=404,
            detail=f"Site '{req.site_domain}' not found or inactive. Create the site at /admin → Sites.",
        )

    # The key must be this site's key or the global admin key.
    if auth_token != site.api_key and not is_global_key(auth_token):
        raise HTTPException(
            status_code=403,
            detail=f"API key not authorised for site '{req.site_domain}'.",
        )

    template = (
        await db.execute(
            select(EmailTemplate).where(
                EmailTemplate.site_id == site.id,
                EmailTemplate.slug == req.template_slug,
                EmailTemplate.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if not template:
        raise HTTPException(
            status_code=404,
            detail=f"Template '{req.template_slug}' not found or inactive for site '{req.site_domain}'. "
            "Create the template at /admin → Templates.",
        )

    sender = req.from_email or site.sender_email
    try:
        await validate_sender(db, site, sender)
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc

    body_html = template.body_html
    body_text = template.body_text
    subject = template.subject
    for key, value in req.variables.items():
        placeholder = "{{" + key + "}}"
        body_html = body_html.replace(placeholder, escape(value))
        body_text = body_text.replace(placeholder, value)
        subject = subject.replace(placeholder, value)

    email_id = str(uuid.uuid4())
    try:
        EmailSendRequest(from_email=sender, to=req.to_email, subject=subject, html=body_html, text=body_text)
    except ValueError as exc:
        raise HTTPException(422, "Rendered template exceeds limits or contains invalid headers") from exc
    # Same provider resolution and off-loop dispatch as /api/emails.
    success, error, relay_source = await send_via_providers(
        db,
        site,
        message_id=email_id,
        to_email=req.to_email,
        subject=subject,
        body_html=body_html,
        body_text=body_text,
        from_email=sender,
        from_name=site.sender_name,
        dkim_domain=site.domain,
        dkim_selector=site.dkim_selector,
        dkim_private_key=site.dkim_private_key,
    )

    log_entry = EmailLog(
        site_id=site.id,
        direction="outgoing",
        sender=sender,
        recipient=req.to_email,
        subject=subject,
        body_preview=_log_body_preview(body_html, body_text),
        status="accepted" if success else "failed",
        message_id=email_id,
        relay_source=relay_source,
        attempts=(
            await db.execute(select(func.count(DeliveryAttempt.id)).where(DeliveryAttempt.message_id == email_id))
        ).scalar()
        or 0,
        error_message=error,
    )
    db.add(log_entry)
    await enqueue_event(
        db,
        site.id,
        "email.sent" if success else "email.failed",
        {
            "site_domain": site.domain,
            "template_slug": req.template_slug,
            "from": sender,
            "to": req.to_email,
            "subject": subject,
            "status": "accepted" if success else "failed",
            "error": error or None,
            "relay": relay_source,
        },
    )
    await db.commit()

    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to send: {error}")

    return SendResponse(success=True, message="Accepted by SMTP relay (not mailbox delivery)")


@router.get("/me", response_model=MeResponse)
async def whoami(
    db: AsyncSession = Depends(get_db),
    identity: ApiIdentity = Depends(authenticated_identity),
):
    """Validate the caller's API key and report what it grants.

    This is the endpoint an integration's "Connect" screen calls after the user
    pastes a key: 401 means the key is wrong, 200 carries a label to show them
    ("connected to alpha.ru") plus the scopes the key actually has.

    Deliberately returns no secrets — not the API key itself, not relay
    credentials, not DKIM private material — so the response is safe for the
    caller to log or cache.
    """
    service = ServiceInfo(version=__version__, smtp_domain=settings.smtp_domain)

    if identity.is_global:
        total = (await db.execute(select(func.count(Site.id)))).scalar() or 0
        return MeResponse(
            type="global",
            site=None,
            scopes=list(identity.scopes),
            sites_count=total,
            service=service,
        )

    site = identity.site
    return MeResponse(
        type="site",
        site=MeSite(
            domain=site.domain,
            name=site.name,
            sender_email=site.sender_email,
            sender_name=site.sender_name,
            is_active=site.is_active,
            has_relay=bool(await resolve_relay_targets(db, site)),
            dkim_configured=bool(site.dkim_private_key),
            created_at=site.created_at,
        ),
        scopes=list(identity.scopes),
        service=service,
    )


@router.get("/domains")
async def list_domains(
    db: AsyncSession = Depends(get_db),
    identity: ApiIdentity = Depends(authenticated_identity),
):
    """List configured domains visible to this key.

    A per-site key sees only its own domain. This used to return every site to
    any caller, leaking other tenants' domains, sender addresses, names and
    relay status.
    """
    query = select(Site).order_by(Site.created_at.desc())
    if not identity.is_global:
        query = query.where(Site.id == identity.site.id)

    sites = (await db.execute(query)).scalars().all()
    return [
        {
            "domain": s.domain,
            "name": s.name,
            "sender_email": s.sender_email,
            "is_active": s.is_active,
            "has_relay": bool(await resolve_relay_targets(db, s)),
        }
        for s in sites
    ]


@router.get("/domains/{domain}/dns")
async def domain_dns_info(
    domain: str,
    db: AsyncSession = Depends(get_db),
    identity: ApiIdentity = Depends(authenticated_identity),
):
    """Get DNS records that should be configured for the domain.

    A per-site key may only ask about its own domain; anything else is a 404,
    which also avoids confirming whether another tenant's domain exists here.
    """
    if not identity.is_global and domain.lower() != identity.site.domain.lower():
        raise HTTPException(status_code=404, detail=f"Domain '{domain}' not found")

    from app.dkim_util import dkim_dns_value
    from app.net_util import resolve_server_ip

    domain = normalize_domain(domain)
    site = (await db.execute(select(Site).where(Site.domain == domain))).scalar_one_or_none()
    if site and site.mailbox_mode:
        return {"domain": domain, "records": [], "managed_by": "beget",
                "note": "Keep Beget MX. Configure SPF/DKIM/DMARC for each mailbox domain in Beget; "
                        "the project domain may differ. Direct-server DNS records do not apply."}

    # Blocking DNS lookup — keep it off the event loop.
    server_ip = await asyncio.to_thread(resolve_server_ip)
    smtp_host = settings.smtp_domain

    site = (await db.execute(select(Site).where(Site.domain == domain))).scalar_one_or_none()

    records = [
        {
            "type": "TXT",
            "name": domain,
            "value": f"v=spf1 ip4:{server_ip} ~all",
            "description": "SPF — разрешает серверу отправлять письма от имени домена",
        },
    ]

    # DKIM: publish the site's public key so receivers can verify signatures.
    if site and site.dkim_private_key:
        records.append(
            {
                "type": "TXT",
                "name": f"{site.dkim_selector}._domainkey.{domain}",
                "value": dkim_dns_value(site.dkim_private_key),
                "description": "DKIM — публичный ключ для проверки подписи писем",
            }
        )

    records.extend(
        [
            {
                "type": "TXT",
                "name": f"_dmarc.{domain}",
                "value": f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; adkim=s; aspf=s",
                "description": "DMARC — политика обработки неаутентифицированных писем (строгое выравнивание)",
            },
            {
                "type": "MX",
                "name": domain,
                "value": smtp_host,
                "priority": 10,
                "description": "MX — указывает на SMTP-сервер для приёма писем",
            },
        ]
    )

    return {
        "domain": domain,
        "records": records,
        "note": "Добавьте эти записи в DNS-панели вашего хостинга. Также настройте PTR (rDNS) для IP сервера.",
    }
