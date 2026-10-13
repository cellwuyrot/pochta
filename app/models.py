import datetime
import hashlib
import hmac
import secrets

import bcrypt
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, validates

from app.domain_util import normalize_domain
from app.secret_store import SecretText


def generate_api_key() -> str:
    """Generate a unique API key with sm_ prefix."""
    return f"sm_{secrets.token_hex(24)}"


def generate_webhook_secret() -> str:
    """Generate a signing secret for a webhook endpoint."""
    return f"whsec_{secrets.token_hex(24)}"


# Event names a webhook can subscribe to. Kept as a tuple so the API can
# validate against it and the admin UI can render checkboxes from it.
WEBHOOK_EVENTS: tuple[str, ...] = (
    "email.sent",
    "email.failed",
    "email.received",
)


def hash_password(password: str, salt: str = "") -> tuple[str, str]:
    """Hash a password with bcrypt.

    Returns (hash, salt). bcrypt embeds its own salt in the hash, so the
    second element is always "" for new hashes. The two-tuple signature is
    kept so the existing schema and callers do not have to change.
    """
    pw_bytes = _bcrypt_input(password)
    pw_hash = bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=12)).decode("utf-8")
    return pw_hash, ""


def verify_password(password: str, hashed: str, salt: str = "") -> bool:
    """Verify a password against a stored hash.

    Supports both new bcrypt hashes (empty salt) and legacy salted SHA-256
    hashes (non-empty salt), so existing accounts keep working until their
    next password change. Both paths use constant-time comparison.

    An empty password is ALWAYS rejected, before either hash path runs. A
    deployment that never set ADMIN_PASSWORD used to store a bcrypt hash of ""
    which this function then validated happily. Because the SMTP AUTH handler
    calls straight into here, and an authenticated SMTP session may relay to any
    domain, that turned the service into an open relay for anyone who guessed
    the admin username. No legitimate login has a blank password, so it is
    refused unconditionally rather than being left to each caller to check.
    """
    if not password or not hashed:
        return False
    if salt:
        # Legacy salted SHA-256 record.
        legacy = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
        return hmac.compare_digest(legacy, hashed)
    try:
        return bcrypt.checkpw(_bcrypt_input(password), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _bcrypt_input(password: str) -> bytes:
    """bcrypt silently truncates input at 72 bytes; pre-hash longer inputs
    so the whole password contributes to the digest."""
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) > 72:
        return hashlib.sha256(pw_bytes).hexdigest().encode("utf-8")
    return pw_bytes


class Base(DeclarativeBase):
    pass


class User(Base):
    """Admin panel user."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    password_salt: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="user")  # "admin" or "user"
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())


    smtp_domains: Mapped[str] = mapped_column(Text, default="")  # empty denies SMTP submission


class Site(Base):
    """Website configuration for sending emails."""

    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    sender_email: Mapped[str] = mapped_column(String(255), nullable=False)
    sender_name: Mapped[str] = mapped_column(String(255), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())

    # SMTP relay override per site (optional)
    relay_host: Mapped[str] = mapped_column(String(255), default="")
    relay_port: Mapped[int] = mapped_column(Integer, default=587)
    relay_username: Mapped[str] = mapped_column(String(255), default="")
    relay_password: Mapped[str] = mapped_column(SecretText, default="")
    relay_use_tls: Mapped[bool] = mapped_column(Boolean, default=True)

    api_key: Mapped[str] = mapped_column(String(255), default=generate_api_key, unique=True)

    # DKIM signing material (per-domain). The private key is generated when the
    # site is created; the matching public key is published in DNS.
    dkim_selector: Mapped[str] = mapped_column(String(63), default="smtp")
    dkim_private_key: Mapped[str] = mapped_column(SecretText, default="")

    @validates("domain")
    def canonical_domain(self, key, value):
        return normalize_domain(value)

    templates: Mapped[list["EmailTemplate"]] = relationship(back_populates="site", cascade="all, delete-orphan")
    logs: Mapped[list["EmailLog"]] = relationship(back_populates="site", cascade="all, delete-orphan")
    webhooks: Mapped[list["Webhook"]] = relationship(back_populates="site", cascade="all, delete-orphan")
    providers: Mapped[list["EmailProvider"]] = relationship(
        back_populates="site", cascade="all, delete-orphan"
    )


class EmailTemplate(Base):
    """Email template (form response) for a site."""

    __tablename__ = "email_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id: Mapped[int] = mapped_column(Integer, ForeignKey("sites.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    body_html: Mapped[str] = mapped_column(Text, nullable=False)
    body_text: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())

    site: Mapped["Site"] = relationship(back_populates="templates")


class EmailLog(Base):
    """Log of sent/received emails."""

    __tablename__ = "email_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id: Mapped[int] = mapped_column(Integer, ForeignKey("sites.id"), nullable=True)
    direction: Mapped[str] = mapped_column(String(10), nullable=False)  # 'outgoing' or 'incoming'
    sender: Mapped[str] = mapped_column(String(255), nullable=False)
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), default="")
    body_preview: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(50), default="sent")  # sent, failed, received
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())

    message_id: Mapped[str] = mapped_column(String(255), default="")
    relay_source: Mapped[str] = mapped_column(String(255), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    raw_message: Mapped[str] = mapped_column(SecretText, default="")  # base64 MIME, inbound only

    site: Mapped["Site"] = relationship(back_populates="logs")


class Webhook(Base):
    """An HTTP endpoint that receives email events for one site."""

    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id: Mapped[int] = mapped_column(Integer, ForeignKey("sites.id"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="")
    # Subscribed events, stored as a comma-separated list of WEBHOOK_EVENTS
    # names. A plain string keeps this portable across SQLite and Postgres
    # without needing a JSON column or an association table.
    events: Mapped[str] = mapped_column(String(500), default="")
    secret: Mapped[str] = mapped_column(String(255), default=generate_webhook_secret)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())

    site: Mapped["Site"] = relationship(back_populates="webhooks")
    deliveries: Mapped[list["WebhookDelivery"]] = relationship(
        back_populates="webhook", cascade="all, delete-orphan"
    )

    @property
    def event_list(self) -> list[str]:
        return [e for e in (self.events or "").split(",") if e]

    def subscribes_to(self, event: str) -> bool:
        return event in self.event_list


class WebhookDelivery(Base):
    """One attempt-tracked delivery of one event to one webhook.

    Rows are written synchronously when the event happens and are picked up by
    the background dispatcher, so a delivery survives a restart and the admin
    panel has a real audit trail. ``next_attempt_at`` drives the retry backoff.
    """

    __tablename__ = "webhook_deliveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    webhook_id: Mapped[int] = mapped_column(Integer, ForeignKey("webhooks.id"), nullable=False)
    event: Mapped[str] = mapped_column(String(50), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    # pending -> success | failed (failed = retries exhausted)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    # Response status code only. The body is deliberately NOT stored: webhook
    # URLs are caller-supplied, so persisting responses would turn the delivery
    # log into a way to read back whatever the URL returns.
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str] = mapped_column(Text, default="")
    next_attempt_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)

    webhook: Mapped["Webhook"] = relationship(back_populates="deliveries")


class EmailProvider(Base):
    """An external SMTP provider (SES, Postmark, Mailgun, …) used for sending.

    A site may hold several: the active one with the lowest ``priority`` is used,
    and the rest act as standby or as targets to switch to. Sending walks them in
    priority order, so a provider that is refusing connections falls through to
    the next instead of dropping the message.
    """

    __tablename__ = "email_providers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id: Mapped[int] = mapped_column(Integer, ForeignKey("sites.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # One of providers.PRESETS, or "custom".
    preset: Mapped[str] = mapped_column(String(50), default="custom")

    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=587)
    username: Mapped[str] = mapped_column(String(255), default="")
    password: Mapped[str] = mapped_column(SecretText, default="")
    # STARTTLS on submission ports. Port 465 is implicit TLS and is detected
    # from the port number rather than this flag.
    use_tls: Mapped[bool] = mapped_column(Boolean, default=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Lower wins. Ties broken by id so ordering is always deterministic.
    priority: Mapped[int] = mapped_column(Integer, default=100)

    # Result of the last connection test, so the UI and API can show whether the
    # credentials were ever known to work without re-dialling the provider.
    last_tested_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_test_error: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())

    site: Mapped["Site"] = relationship(back_populates="providers")


class DeliveryAttempt(Base):
    __tablename__ = 'delivery_attempts'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    message_id: Mapped[str] = mapped_column(String(255), index=True)
    site_id: Mapped[int] = mapped_column(Integer, ForeignKey('sites.id'))
    recipient: Mapped[str] = mapped_column(String(255))
    relay: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(50))
    error: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())


class OutboxMessage(Base):
    __tablename__ = 'outbox_messages'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    site_id: Mapped[int] = mapped_column(Integer, ForeignKey('sites.id'), index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(SecretText)
    status: Mapped[str] = mapped_column(String(30), default='queued')
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    relay: Mapped[str] = mapped_column(String(255), default='')
    error: Mapped[str] = mapped_column(Text, default='')
    next_attempt_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    __table_args__ = (__import__('sqlalchemy').UniqueConstraint('site_id', 'idempotency_key'),)
