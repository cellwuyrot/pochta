"""Email sending: relay (external SMTP) or direct delivery (MX lookup).

All outbound messages are DKIM-signed (when the site has a key) and always
carry a plain-text alternative plus the headers modern mailbox providers look
for. Signing happens on the exact bytes that go on the wire.
"""

import logging
import re
import smtplib
import ssl
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid

import dns.resolver

from app.config import settings
from app.dkim_util import sign_message
from app.smtp_transport import SafeSMTP, SafeSMTP_SSL

logger = logging.getLogger(__name__)

# Port 465 is implicit TLS (SMTPS): the TLS handshake completes before any SMTP
# conversation, so STARTTLS must not be attempted on it.
IMPLICIT_TLS_PORT = 465


def resolve_mx(domain: str) -> list[str]:
    """Resolve MX records for a domain, return hosts sorted by priority.

    Public because the SMTP relay path in ``smtp_server`` needs it too; it used
    to reach in for the underscore-prefixed name.
    """
    try:
        answers = dns.resolver.resolve(domain, "MX")
        hosts = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in hosts]
    except Exception as exc:
        logger.warning("MX lookup failed for %s: %s", domain, exc)
        return [domain]


def _html_to_text(html: str) -> str:
    """Very small HTML→text fallback so every message has a text/plain part.

    A missing plain-text alternative is a well-known spam signal; this keeps a
    multipart/alternative message even when the caller only supplied HTML.
    """
    text = re.sub(r"(?is)<(script|style).*?</\1>", "", html)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p>", "\n\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _build_message(
    from_email: str,
    from_name: str,
    to_email: str,
    subject: str,
    body_html: str,
    body_text: str,
    reply_to: str = "",
) -> MIMEMultipart:
    sender_header = formataddr((str(Header(from_name, "utf-8")), from_email)) if from_name else from_email
    sender_domain = from_email.split("@")[-1] if "@" in from_email else settings.smtp_domain

    if not body_text and body_html:
        body_text = _html_to_text(body_html)

    msg = MIMEMultipart("alternative")
    msg["From"] = sender_header
    msg["To"] = to_email
    msg["Subject"] = Header(subject, "utf-8")
    msg["Message-ID"] = make_msgid(domain=sender_domain)
    msg["Date"] = formatdate(localtime=True)
    msg["MIME-Version"] = "1.0"
    if reply_to:
        msg["Reply-To"] = reply_to
    # List-Unsubscribe improves reputation and is expected by Gmail/Yahoo for
    # bulk mail. A mailto target works without any extra HTTP endpoint.
    msg["List-Unsubscribe"] = f"<mailto:unsubscribe@{sender_domain}?subject=unsubscribe>"

    # Order matters: least-preferred (plain) first, richest (html) last.
    if body_text:
        msg.attach(MIMEText(body_text, "plain", "utf-8"))
    if body_html:
        msg.attach(MIMEText(body_html, "html", "utf-8"))
    return msg


def _send_via_relay(
    message_bytes: bytes,
    sender: str,
    to_email: str,
    host: str,
    port: int,
    username: str,
    password: str,
    use_tls: bool,
) -> tuple[bool, str]:
    """Send through an external SMTP relay (Gmail, Yandex, SES, ...).

    Port 465 is implicit TLS (SMTPS): the handshake precedes the SMTP
    conversation, so STARTTLS must not be attempted there. Previously every relay
    went through plain ``SMTP`` + ``starttls()``, which cannot talk to a 465
    endpoint at all -- and 465 is the port Yandex documents first.
    """
    server = None
    data_started = False
    try:
        if port == IMPLICIT_TLS_PORT:
            server = SafeSMTP_SSL(host, port, timeout=30, context=ssl.create_default_context())
            server.ehlo()
        else:
            server = SafeSMTP(host, port, timeout=30)
            server.ehlo()
            if use_tls:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
        if username and password and port != IMPLICIT_TLS_PORT and not use_tls:
            return False, "Relay credentials require TLS"
        if username and password:
            server.login(username, password)
        data_started = True
        server.sendmail(sender, [to_email], message_bytes)
        logger.info("Email sent to %s via relay %s:%d", to_email, host, port)
        return True, ""
    except Exception as exc:
        error = ("uncertain: " if data_started and isinstance(exc, (OSError, smtplib.SMTPServerDisconnected)) else "") + str(exc)
        if isinstance(exc, smtplib.SMTPDataError) and exc.smtp_code >= 500:
            error = "permanent: " + error
        logger.error("Relay send to %s via %s:%d failed: %s", to_email, host, port, error)
        return False, error
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def _send_direct(
    message_bytes: bytes,
    sender: str,
    to_email: str,
) -> tuple[bool, str]:
    """Send directly by resolving MX records of the recipient domain."""
    recipient_domain = to_email.split("@")[-1] if "@" in to_email else ""
    if not recipient_domain:
        return False, "Invalid recipient email"

    mx_hosts = resolve_mx(recipient_domain)
    if not mx_hosts:
        return False, f"No MX records found for {recipient_domain}"

    last_error = ""
    for mx_host in mx_hosts:
        server, data_started = None, False
        try:
            server = SafeSMTP(mx_host, 25, timeout=30)
            server.ehlo(settings.smtp_domain)
            try:
                server.starttls(context=ssl.create_default_context())
                server.ehlo(settings.smtp_domain)
            except smtplib.SMTPNotSupportedError:
                pass  # direct MTA delivery uses opportunistic TLS, never AUTH
            data_started = True
            server.sendmail(sender, [to_email], message_bytes)
            return True, ""
        except Exception as exc:
            last_error = f"{mx_host}: {exc}"
            if data_started and isinstance(exc, (OSError, smtplib.SMTPServerDisconnected)):
                return False, "uncertain: " + last_error
            if isinstance(exc, smtplib.SMTPDataError) and exc.smtp_code >= 500:
                return False, "permanent: " + last_error
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    server.close()
    return False, f"All MX servers failed: {last_error}"


def send_email(
    to_email: str,
    subject: str,
    body_html: str,
    body_text: str = "",
    from_email: str = "",
    from_name: str = "",
    relay_host: str = "",
    relay_port: int = 587,
    relay_username: str = "",
    relay_password: str = "",
    relay_use_tls: bool = True,
    reply_to: str = "",
    dkim_domain: str = "",
    dkim_selector: str = "",
    dkim_private_key: str = "",
    raw_message: bytes | None = None,
    message_id: str = "",
) -> tuple[bool, str]:
    """Send an email. Uses relay if configured, otherwise sends directly via MX.

    The message is DKIM-signed when ``dkim_private_key`` is provided.
    """
    host = relay_host or settings.relay_host
    port = relay_port if relay_host else settings.relay_port
    username = relay_username if relay_host else settings.relay_username
    password = relay_password if relay_host else settings.relay_password
    use_tls = relay_use_tls if relay_host else settings.relay_use_tls

    sender = from_email or f"noreply@{settings.smtp_domain}"

    msg = _build_message(
        from_email=sender,
        from_name=from_name,
        to_email=to_email,
        subject=subject,
        body_html=body_html,
        body_text=body_text,
        reply_to=reply_to,
    )

    # Serialize once, then DKIM-sign the exact bytes we will transmit.
    if message_id:
        msg.replace_header("Message-ID", f"<{message_id}@{sender.split('@')[-1]}>")
    message_bytes = raw_message if raw_message is not None else msg.as_bytes()
    if dkim_private_key and dkim_domain:
        message_bytes = sign_message(
            message_bytes,
            domain=dkim_domain,
            selector=dkim_selector or "smtp",
            private_key_pem=dkim_private_key,
        )

    if host:
        return _send_via_relay(message_bytes, sender, to_email, host, port, username, password, use_tls)

    if not settings.allow_direct_mx:
        return False, "Direct MX disabled; configure an SMTP provider"
    return _send_direct(message_bytes, sender, to_email)
