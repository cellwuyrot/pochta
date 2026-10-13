"""External SMTP provider presets, connection testing, and send-time resolution.

Presets only prefill host/port/TLS and describe what each provider expects as a
username — they are hints, every field stays editable, and "custom" skips them
entirely.
"""

import asyncio
import datetime
import logging
import smtplib
import ssl
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import DeliveryAttempt, EmailProvider, Site
from app.smtp_client import IMPLICIT_TLS_PORT, send_email
from app.smtp_transport import SafeSMTP, SafeSMTP_SSL

logger = logging.getLogger(__name__)

__all__ = [
    "IMPLICIT_TLS_PORT",
    "PRESETS",
    "Preset",
    "RelayTarget",
    "preset_catalogue",
    "record_test_result",
    "resolve_relay_targets",
    "send_via_providers",
    "test_connection",
]


@dataclass(frozen=True)
class Preset:
    name: str
    label: str
    host: str
    port: int
    use_tls: bool = True
    username_hint: str = ""
    docs_url: str = ""
    notes: str = ""
    # Fields the operator must adjust because they are account-specific.
    needs_attention: tuple[str, ...] = field(default_factory=tuple)


PRESETS: dict[str, Preset] = {
    "postmark": Preset(
        name="postmark",
        label="Postmark",
        host="smtp.postmarkapp.com",
        port=587,
        username_hint="Your Server API token, used as BOTH username and password",
        docs_url="https://postmarkapp.com/developer/user-guide/send-email-with-smtp",
    ),
    "sendgrid": Preset(
        name="sendgrid",
        label="SendGrid",
        host="smtp.sendgrid.net",
        port=587,
        username_hint="Literally the word 'apikey'; the password is your API key",
        docs_url="https://www.twilio.com/docs/sendgrid/for-developers/sending-email/getting-started-smtp",
    ),
    "mailgun": Preset(
        name="mailgun",
        label="Mailgun",
        host="smtp.mailgun.org",
        port=587,
        username_hint="postmaster@your-domain (from the Mailgun dashboard)",
        docs_url="https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/#smtp-relay",
    ),
    "ses": Preset(
        name="ses",
        label="Amazon SES",
        host="email-smtp.us-east-1.amazonaws.com",
        port=587,
        username_hint="SES SMTP credentials — NOT your AWS access key",
        docs_url="https://docs.aws.amazon.com/ses/latest/dg/send-email-smtp.html",
        notes="Change the region in the host to match where your SES identity lives.",
        needs_attention=("host",),
    ),
    "yandex": Preset(
        name="yandex",
        label="Yandex 360",
        host="smtp.yandex.ru",
        port=465,
        username_hint="Full mailbox address; the password is an app password",
        docs_url="https://yandex.ru/support/yandex-360/business/mail/en/mail-clients",
        notes="Port 465 is implicit TLS and is handled automatically.",
    ),
    "gmail": Preset(
        name="gmail",
        label="Gmail / Google Workspace",
        host="smtp.gmail.com",
        port=587,
        username_hint="Full Gmail address; the password must be an app password",
        docs_url="https://support.google.com/a/answer/176600",
    ),
    "custom": Preset(
        name="custom",
        label="Custom SMTP",
        host="",
        port=587,
        username_hint="Whatever your provider issued",
        notes="Fill in host, port and credentials yourself.",
    ),
}


def preset_catalogue() -> list[dict]:
    """Serialisable preset list for the API and the admin UI."""
    return [
        {
            "name": p.name,
            "label": p.label,
            "host": p.host,
            "port": p.port,
            "use_tls": p.use_tls,
            "implicit_tls": p.port == IMPLICIT_TLS_PORT,
            "username_hint": p.username_hint,
            "docs_url": p.docs_url,
            "notes": p.notes,
            "needs_attention": list(p.needs_attention),
        }
        for p in PRESETS.values()
    ]


# --- Connection testing ---------------------------------------------------


def test_connection(
    host: str,
    port: int,
    username: str = "",
    password: str = "",
    use_tls: bool = True,
    timeout: float = 15.0,
) -> tuple[bool, str, list[str]]:
    """Dial a provider and, if credentials are given, actually log in.

    Returns ``(ok, error, transcript)``. The transcript is a short human-readable
    list of the steps that succeeded, so a failure says *where* it broke rather
    than just "connection failed".

    Blocking: uses smtplib. Call through ``asyncio.to_thread``.
    """
    steps: list[str] = []
    server: smtplib.SMTP | None = None
    try:
        if port == IMPLICIT_TLS_PORT:
            context = ssl.create_default_context()
            server = SafeSMTP_SSL(host, port, timeout=timeout, context=context)
            steps.append(f"connected to {host}:{port} over implicit TLS")
        else:
            server = SafeSMTP(host, port, timeout=timeout)
            steps.append(f"connected to {host}:{port}")

        code, banner = server.ehlo()
        steps.append(f"EHLO accepted ({code})")

        if port != IMPLICIT_TLS_PORT and use_tls:
            if not server.has_extn("starttls"):
                return False, f"{host}:{port} does not advertise STARTTLS", steps
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            steps.append("STARTTLS negotiated")

        if username and password and port != IMPLICIT_TLS_PORT and not use_tls:
            return False, "Credentials require TLS", steps
        if username and password:
            server.login(username, password)
            steps.append(f"authenticated as {username}")
        else:
            steps.append("no credentials supplied — login not attempted")

        return True, "", steps

    except smtplib.SMTPAuthenticationError as exc:
        return False, f"authentication rejected: {_smtp_error_text(exc)}", steps
    except smtplib.SMTPNotSupportedError as exc:
        return False, f"not supported by server: {exc}", steps
    except ssl.SSLError as exc:
        return False, f"TLS error: {exc}", steps
    except OSError as exc:
        # Covers connection refused, DNS failure and timeouts.
        return False, f"could not reach {host}:{port}: {exc}", steps
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"{type(exc).__name__}: {exc}", steps
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def _smtp_error_text(exc: smtplib.SMTPResponseException) -> str:
    message = exc.smtp_error
    if isinstance(message, bytes):
        message = message.decode("utf-8", errors="replace")
    return f"{exc.smtp_code} {message}".strip()


# --- Send-time resolution -------------------------------------------------


@dataclass(frozen=True)
class RelayTarget:
    """A resolved set of relay parameters to hand to ``send_email``."""

    label: str
    host: str
    port: int
    username: str
    password: str
    use_tls: bool


async def resolve_relay_targets(db: AsyncSession, site: Site) -> list[RelayTarget]:
    """Ordered relay candidates for a site, best first.

    Resolution order, deliberately backwards compatible:

    1. active :class:`EmailProvider` rows for the site, by ``priority`` then id;
    2. the site's own legacy ``relay_*`` fields, still editable in the admin UI;
    3. the global ``RELAY_*`` settings from .env.

    An empty list means "no relay configured" and the caller should fall back to
    direct MX delivery, exactly as before this feature existed.
    """
    targets: list[RelayTarget] = []

    providers = (
        await db.execute(
            select(EmailProvider)
            .where(EmailProvider.site_id == site.id, EmailProvider.is_active.is_(True))
            .order_by(EmailProvider.priority, EmailProvider.id)
        )
    ).scalars().all()
    for provider in providers:
        if not provider.host:
            continue
        targets.append(
            RelayTarget(
                label=f"provider:{provider.name}",
                host=provider.host,
                port=provider.port,
                username=provider.username,
                password=provider.password,
                use_tls=provider.use_tls,
            )
        )

    if site.relay_host:
        targets.append(
            RelayTarget(
                label="site-relay",
                host=site.relay_host,
                port=site.relay_port,
                username=site.relay_username,
                password=site.relay_password,
                use_tls=site.relay_use_tls,
            )
        )

    if settings.relay_host:
        targets.append(
            RelayTarget(
                label="global-relay",
                host=settings.relay_host,
                port=settings.relay_port,
                username=settings.relay_username,
                password=settings.relay_password,
                use_tls=settings.relay_use_tls,
            )
        )

    return targets


async def send_via_providers(db: AsyncSession, site: Site, **send_kwargs) -> tuple[bool, str, str]:
    """Send a message through the site's relays, in priority order.

    Returns ``(success, error, source)`` where ``source`` names whichever relay
    accepted the message (or the last one tried on failure). If a relay refuses
    the connection the next candidate is tried, so a dead provider degrades
    instead of dropping mail.

    With no relay configured anywhere this passes empty relay parameters, which
    makes ``send_email`` fall back to direct MX delivery — the behaviour before
    providers existed.
    """
    targets = await resolve_relay_targets(db, site)
    message_id = send_kwargs.setdefault("message_id", str(uuid.uuid4()))
    def record(source, ok, error):
        db.add(DeliveryAttempt(message_id=message_id, site_id=site.id,
            recipient=send_kwargs["to_email"], relay=source,
            status="accepted" if ok else ("unknown" if error.startswith("uncertain:") else "failed"), error=error[:2000]))

    if not targets:
        if not settings.allow_direct_mx:
            record("none", False, "Direct MX disabled; configure an SMTP provider")
            return False, "Direct MX disabled; configure an SMTP provider", "none"
        success, error = await asyncio.to_thread(
            send_email, relay_host="", relay_username="", relay_password="", **send_kwargs
        )
        record("direct-mx", success, error)
        return success, error, "direct-mx"

    failures: list[str] = []
    for target in targets:
        success, error = await asyncio.to_thread(
            send_email,
            relay_host=target.host,
            relay_port=target.port,
            relay_username=target.username,
            relay_password=target.password,
            relay_use_tls=target.use_tls,
            **send_kwargs,
        )
        if target.password:
            error = error.replace(target.password, "[redacted]")
        record(target.label, success, error)
        if success:
            if failures:
                logger.warning(
                    "Delivered via %s after %d failed relay(s): %s",
                    target.label, len(failures), "; ".join(failures),
                )
            return True, "", target.label
        if error.startswith(("uncertain:", "permanent:")):
            return False, error, target.label
        failures.append(f"{target.label} ({target.host}:{target.port}): {error}")

    return False, "; ".join(failures), targets[-1].label


def record_test_result(provider: EmailProvider, ok: bool, error: str) -> None:
    provider.last_tested_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    provider.last_test_ok = ok
    provider.last_test_error = error[:1000]
