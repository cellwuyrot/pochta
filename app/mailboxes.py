"""Project-scoped sender identities. A mailbox never fails over to another account."""

from sqlalchemy import select

from app.domain_util import normalize_email
from app.models import Mailbox, Site


async def validate_sender(db, site: Site, sender: str) -> Mailbox | None:
    """Validate on admission AND delivery, so disabling an account affects queued jobs."""
    if not site.is_active:
        raise ValueError("Project is inactive")
    sender = normalize_email(sender)
    if not site.mailbox_mode:
        if sender.rsplit("@", 1)[-1] != site.domain:
            raise ValueError("Sender domain not authorized for this project")
        return None
    mailbox = (await db.execute(select(Mailbox).where(
        Mailbox.site_id == site.id, Mailbox.email == sender.lower(),
    ))).scalar_one_or_none()
    if not mailbox or not mailbox.is_active:
        raise ValueError("Sender mailbox is not registered or is inactive in this project")
    if not mailbox.password:
        raise ValueError("Sender mailbox has no SMTP password")
    return mailbox


async def smtp_project(db, sender: str, allowed_domains: list[str]) -> Site:
    """SMTP user scopes name PROJECT domains, not arbitrary sender domains."""
    projects = (await db.execute(select(Site).where(
        Site.domain.in_(allowed_domains), Site.is_active.is_(True),
    ))).scalars().all()
    matches = []
    for site in projects:
        try:
            await validate_sender(db, site, sender)
        except ValueError:
            continue
        matches.append(site)
    if len(matches) != 1:
        raise ValueError("Sender not allowed or ambiguous; use a project-scoped API key")
    return matches[0]


def public_mailbox(row: Mailbox, default_email: str = "") -> dict:
    """Never serialise the ORM password to a template or response."""
    return {
        "id": row.id, "email": row.email, "display_name": row.display_name,
        "smtp_host": row.smtp_host, "smtp_port": row.smtp_port,
        "is_active": row.is_active, "has_password": bool(row.password),
        "is_default": row.email == default_email.lower(),
        "last_tested_at": row.last_tested_at, "last_test_ok": row.last_test_ok,
        "last_test_error": row.last_test_error,
    }


async def reconcile_default(db, site: Site):
    accounts = (await db.execute(select(Mailbox).where(
        Mailbox.site_id == site.id, Mailbox.is_active.is_(True),
    ).order_by(Mailbox.id))).scalars().all()
    chosen = next((m for m in accounts if m.email == site.sender_email.lower()), None)
    chosen = chosen or (accounts[0] if accounts else None)
    site.sender_email = chosen.email if chosen else ""
    site.sender_name = chosen.display_name if chosen else ""
