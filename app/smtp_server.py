"""SMTP server with authenticated relay support.

- Unauthenticated: accept mail only for local domains (inbound).
- Authenticated (LOGIN): relay to any domain via MX (outbound for Nodemailer).
"""

import asyncio
import base64
import logging
import time
import uuid
from collections import defaultdict
from email import message_from_bytes

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from sqlalchemy import select

from app.config import settings
from app.database import async_session
from app.domain_util import normalize_domain, normalize_email
from app.mailboxes import smtp_project, validate_sender
from app.models import EmailLog, Site, User, verify_password

logger = logging.getLogger(__name__)

_local_domains: set[str] = set()


async def _refresh_local_domains() -> set[str]:
    global _local_domains
    try:
        async with async_session() as session:
            result = await session.execute(
                select(Site.domain).where(Site.is_active.is_(True))
            )
            _local_domains = {row[0].lower() for row in result.fetchall()}
    except Exception as exc:
        logger.warning("Failed to refresh local domains: %s", exc)
    return _local_domains


def _extract_domain(address: str) -> str:
    try:
        return normalize_domain(address.rsplit("@", 1)[-1]) if "@" in address else ""
    except ValueError:
        return ""


class SmtpHandler:
    _account_hits = defaultdict(list)

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        if getattr(session, "authenticated", False):
            if not getattr(session, "ssl", None):
                return "530 STARTTLS required"
            username = getattr(session, "smtp_username", "")
            async with async_session() as db:
                user = (await db.execute(select(User).where(User.username == username, User.is_active.is_(True)))).scalar_one_or_none()
                if not user:
                    return "553 Sender account is inactive"
                allowed = [d.strip() for d in (user.smtp_domains or "").split(",") if d.strip()]
                try:
                    site = await smtp_project(db, normalize_email(address), allowed)
                except ValueError:
                    return "553 Sender not allowed or ambiguous for this account"
                session.smtp_site_id = site.id
            now = time.monotonic()
            hits = [t for t in self._account_hits[username] if t > now - 60]
            if len(hits) >= settings.smtp_account_per_min:
                return "452 Account rate limit exceeded"
            self._account_hits[username] = hits + [now]
        elif not settings.inbound_enabled:
            return "550 Inbound mail disabled"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        domain = _extract_domain(address)
        if len(envelope.rcpt_tos) >= settings.smtp_max_recipients:
            return "452 Too many recipients"
        if not domain:
            return "550 Invalid recipient address"

        authenticated = getattr(session, "authenticated", False)

        if authenticated:
            envelope.rcpt_tos.append(address)
            return "250 OK"

        if not settings.inbound_enabled:
            return "550 Inbound mail disabled"
        await _refresh_local_domains()

        if domain not in _local_domains:
            logger.warning(
                "Rejected relay attempt: %s -> %s (domain %s not local, not authenticated)",
                envelope.mail_from, address, domain,
            )
            return "550 Relay denied — authenticate to send to external domains"

        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        data = envelope.content
        authenticated = getattr(session, "authenticated", False)

        if len(data) > settings.smtp_max_message_bytes:
            return "552 Message too large"
        try:
            msg = message_from_bytes(data)
            subject = msg.get("Subject", "(no subject)")
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
                        break
            else:
                body = (msg.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
        except Exception as e:
            logger.error("Error parsing email: %s", e)
            return "550 Message parse error"

        if authenticated:
            return await self._relay_outbound(mail_from, rcpt_tos, data, subject, body,
                                              site_id=getattr(session, "smtp_site_id", None))

        if not settings.inbound_enabled:
            return "550 Inbound mail disabled"
        return await self._store_inbound(mail_from, rcpt_tos, subject, body, data)

    async def _store_inbound(self, mail_from, rcpt_tos, subject, body, raw_data=b""):
        from app.webhook_service import enqueue_event

        try:
            async with async_session() as session_db:
                # Attribute the message to a site so its webhooks can fire.
                recipient_site = None
                for address in rcpt_tos:
                    recipient_site = (
                        await session_db.execute(
                            select(Site).where(
                                Site.domain == _extract_domain(address),
                                Site.is_active.is_(True),
                            )
                        )
                    ).scalar_one_or_none()
                    if recipient_site:
                        break

                log_entry = EmailLog(
                    site_id=recipient_site.id if recipient_site else None,
                    direction="incoming",
                    sender=mail_from,
                    recipient=", ".join(rcpt_tos),
                    subject=subject,
                    body_preview=body[:1000] if settings.store_body_preview else "",
                    status="received",
                    raw_message=base64.b64encode(raw_data).decode(),
                    message_id=str(uuid.uuid4()),
                )
                session_db.add(log_entry)
                if recipient_site:
                    await enqueue_event(
                        session_db,
                        recipient_site.id,
                        "email.received",
                        {
                            "site_domain": recipient_site.domain,
                            "from": mail_from,
                            "to": list(rcpt_tos),
                            "subject": subject,
                        },
                    )
                await session_db.commit()
            logger.info("Received inbound email from %s to %s: %s", mail_from, rcpt_tos, subject)
        except Exception as e:
            logger.error("Error storing inbound email: %s", e)
            return "451 Temporary storage failure; retry later"
        return "250 Message accepted"

    async def _relay_outbound(self, mail_from, rcpt_tos, raw_data, subject, body, site_id=None):
        from app.outbox import enqueue_message
        try:
            mail_from = normalize_email(mail_from)
            msg = message_from_bytes(raw_data)
            from email.utils import parseaddr
            if len(msg.get_all("From", [])) != 1:
                return "553 Exactly one From header is required"
            header_sender = normalize_email(parseaddr(msg.get("From", ""))[1])
            if _extract_domain(header_sender) != _extract_domain(mail_from):
                return "553 Header From must match envelope domain"
            async with async_session() as db:
                site = await db.get(Site, site_id) if site_id else (
                    await db.execute(select(Site).where(
                        Site.domain == _extract_domain(mail_from), Site.is_active.is_(True)
                    ))).scalar_one_or_none()
                if not site or not site.is_active:
                    return "553 No active project for sender"
                mailbox = await validate_sender(db, site, mail_from)
                if mailbox and header_sender.lower() != mail_from.lower():
                    return "553 Header From must match the registered mailbox"
                if not 1 <= len(rcpt_tos) <= settings.smtp_max_recipients:
                    return "452 Invalid recipient count"
                for recipient in rcpt_tos:
                    await enqueue_message(db, site, {
                        "from_email": mail_from, "to_email": normalize_email(recipient),
                        "subject": subject[:500], "body_html": "", "body_text": body,
                        "raw_message_b64": base64.b64encode(raw_data).decode(),
                    })
                await db.commit()
            return "250 Message durably queued"
        except ValueError:
            return "553 Invalid sender or recipient"
        except Exception:
            logger.exception("SMTP enqueue failed")
            return "451 Temporary storage failure; retry later"


class SmtpAuthenticator:
    def __call__(self, server, session, envelope, mechanism, auth_data):
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=False)

        username = auth_data.login.decode("utf-8")
        password = auth_data.password.decode("utf-8")


        async def _check():
            async with async_session() as db:
                user = (
                    await db.execute(
                        select(User).where(User.username == username, User.is_active.is_(True))
                    )
                ).scalar_one_or_none()
                if user and verify_password(password, user.password_hash, user.password_salt):
                    return True
            return False

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(asyncio.run, _check()).result(timeout=5)
            else:
                result = loop.run_until_complete(_check())
        except Exception as exc:
            logger.error("SMTP auth error: %s", exc)
            result = False

        if result:
            logger.info("SMTP auth success for user: %s", username)
            session.authenticated = True
            session.smtp_username = username
            return AuthResult(success=True)

        logger.warning("SMTP auth failed for user: %s", username)
        return AuthResult(success=False, handled=False)


_controller: Controller | None = None


def _build_tls_context():
    """Build a STARTTLS context from configured cert/key paths, if any."""
    if not (settings.tls_cert_path and settings.tls_key_path):
        return None
    import ssl

    try:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(settings.tls_cert_path, settings.tls_key_path)
        return ctx
    except Exception as exc:
        logger.error("Failed to load TLS cert/key for SMTP: %s", exc)
        return None


def start_smtp_server() -> Controller:
    global _controller
    handler = SmtpHandler()
    authenticator = SmtpAuthenticator()

    tls_context = _build_tls_context()
    # Only offer AUTH over an encrypted channel. Without a cert we still start
    # (so inbound mail works) but AUTH-based relay is refused in cleartext to
    # avoid leaking credentials.
    require_tls_for_auth = True
    if tls_context is None:
        logger.warning(
            "No TLS_CERT_PATH/TLS_KEY_PATH configured: SMTP AUTH requires STARTTLS and will be "
            "unavailable until certs are provided. Set them to enable authenticated relay."
        )

    _controller = Controller(
        handler,
        hostname="0.0.0.0",
        port=settings.smtp_port,
        authenticator=authenticator,
        auth_required=False,
        auth_require_tls=require_tls_for_auth,
        tls_context=tls_context,
        data_size_limit=settings.smtp_max_message_bytes,
    )
    _controller.start()
    logger.info(
        "SMTP server started on port %d (STARTTLS %s)",
        settings.smtp_port,
        "enabled" if tls_context else "disabled",
    )
    return _controller


def stop_smtp_server():
    global _controller
    if _controller:
        _controller.stop()
        logger.info("SMTP server stopped")
        _controller = None
