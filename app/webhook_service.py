"""Webhook fan-out: event enqueueing, signing, and the retrying dispatcher.

Design notes
------------
Deliveries are *persisted* the moment an event happens, then picked up by a
background task. That costs one INSERT on the request path but buys three
things: the API response never waits on a subscriber's server, a delivery
survives a process restart, and the admin panel gets a real audit trail.

The dispatcher is deliberately in-process and single-instance, matching the rest
of the service (SQLite, one container). Running two replicas would double-send;
that needs a shared queue or a row lock, and is called out in the README.
"""

import asyncio
import datetime
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import time
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session
from app.models import Webhook, WebhookDelivery

logger = logging.getLogger(__name__)

def _utcnow() -> datetime.datetime:
    """Naive UTC now.

    datetime.utcnow() is deprecated in 3.12, but the DateTime columns here are
    naive, so a tz-aware value cannot be stored directly.
    """
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


SIGNATURE_HEADER = "X-Smtp-Signature"
EVENT_HEADER = "X-Smtp-Event"
DELIVERY_HEADER = "X-Smtp-Delivery-Id"
ATTEMPT_HEADER = "X-Smtp-Attempt"

# Retry backoff in seconds, indexed by the attempt that just failed. Past the
# end of the tuple the last value repeats.
_BACKOFF_SECONDS: tuple[int, ...] = (10, 60, 300, 1800)


class WebhookUrlError(ValueError):
    """Raised when a subscriber URL is malformed or points somewhere unsafe."""


# --- URL validation -------------------------------------------------------


def validate_webhook_url(url: str) -> str:
    """Return a normalised subscriber URL or raise :class:`WebhookUrlError`.

    Blocks non-HTTP schemes and, unless explicitly allowed, any host that
    resolves into loopback / private / link-local space. This is the SSRF guard:
    a site API key should not be usable to make the server probe its own
    network or read a cloud metadata endpoint.
    """
    url = (url or "").strip()
    if not url:
        raise WebhookUrlError("URL is required")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise WebhookUrlError("URL must start with http:// or https://")
    if settings.webhook_require_https and parsed.scheme != "https":
        raise WebhookUrlError("URL must use https://")
    if not parsed.hostname:
        raise WebhookUrlError("URL has no host")

    if not settings.webhook_allow_private_targets:
        for address in _resolve_all(parsed.hostname):
            if _is_private(address):
                raise WebhookUrlError(
                    f"URL resolves to a private or loopback address ({address}). "
                    "Set WEBHOOK_ALLOW_PRIVATE_TARGETS=true if this is intentional."
                )
    return url


def _resolve_all(hostname: str) -> list[str]:
    """Every address a hostname resolves to, or the literal if it is an IP."""
    try:
        ipaddress.ip_address(hostname)
        return [hostname]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        raise WebhookUrlError(f"could not resolve host '{hostname}': {exc}") from exc
    return [info[4][0] for info in infos]


def _is_private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True  # unparseable: treat as unsafe
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


# --- Signing --------------------------------------------------------------


def sign_payload(secret: str, body: bytes, timestamp: int | None = None) -> tuple[str, int]:
    """Return ``(header_value, timestamp)`` for a request body.

    The signed string is ``"{timestamp}.{body}"``, so a captured request cannot
    be replayed later against a subscriber that checks the age. The header format
    mirrors the convention Stripe popularised, which most webhook consumers and
    libraries already understand:

        X-Smtp-Signature: t=1699999999,v1=<hex hmac-sha256>
    """
    ts = int(time.time()) if timestamp is None else timestamp
    signed = f"{ts}.".encode() + body
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={digest}", ts


def verify_signature(secret: str, body: bytes, header: str, tolerance_seconds: int = 300) -> bool:
    """Verify a signature header. Provided so subscribers (and tests) can reuse
    exactly the same logic that produced it."""
    parts = dict(
        piece.split("=", 1) for piece in (header or "").split(",") if "=" in piece
    )
    ts_raw, provided = parts.get("t"), parts.get("v1")
    if not ts_raw or not provided:
        return False
    try:
        ts = int(ts_raw)
    except ValueError:
        return False
    if tolerance_seconds and abs(int(time.time()) - ts) > tolerance_seconds:
        return False
    expected, _ = sign_payload(secret, body, timestamp=ts)
    expected_digest = expected.split("v1=", 1)[1]
    return hmac.compare_digest(expected_digest, provided)


# --- Enqueueing -----------------------------------------------------------


async def enqueue_event(db: AsyncSession, site_id: int | None, event: str, data: dict) -> int:
    """Queue ``event`` for every active webhook of ``site_id`` subscribed to it.

    Adds delivery rows to the caller's session WITHOUT committing, so the events
    land in the same transaction as whatever caused them. Returns how many rows
    were added. Never raises: a webhook problem must not fail an email send.
    """
    if site_id is None:
        return 0
    try:
        hooks = (
            await db.execute(
                select(Webhook).where(Webhook.site_id == site_id, Webhook.is_active.is_(True))
            )
        ).scalars().all()

        payload = json.dumps(
            {
                "event": event,
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "data": data,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

        queued = 0
        for hook in hooks:
            if not hook.subscribes_to(event):
                continue
            db.add(WebhookDelivery(webhook_id=hook.id, event=event, payload=payload))
            queued += 1
        return queued
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to enqueue webhook event %s for site %s: %s", event, site_id, exc)
        return 0


# --- Dispatching ----------------------------------------------------------


async def _send_one(client: httpx.AsyncClient, delivery_id: int) -> None:
    """Attempt one delivery and record the outcome."""
    async with async_session() as db:
        delivery = (
            await db.execute(select(WebhookDelivery).where(WebhookDelivery.id == delivery_id))
        ).scalar_one_or_none()
        if delivery is None or delivery.status != "pending":
            return
        hook = (
            await db.execute(select(Webhook).where(Webhook.id == delivery.webhook_id))
        ).scalar_one_or_none()
        if hook is None:
            delivery.status = "failed"
            delivery.error_message = "webhook was deleted"
            delivery.completed_at = _utcnow()
            await db.commit()
            return

        body = delivery.payload.encode("utf-8")
        signature, _ = sign_payload(hook.secret, body)
        delivery.attempts += 1
        attempt = delivery.attempts

        try:
            await asyncio.to_thread(validate_webhook_url, hook.url)
            response = await client.post(
                hook.url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    SIGNATURE_HEADER: signature,
                    EVENT_HEADER: delivery.event,
                    DELIVERY_HEADER: str(delivery.id),
                    ATTEMPT_HEADER: str(attempt),
                    "User-Agent": "smtp-service-webhooks/1",
                },
            )
            delivery.response_status = response.status_code
            if 200 <= response.status_code < 300:
                delivery.status = "success"
                delivery.error_message = ""
                delivery.completed_at = _utcnow()
                logger.info(
                    "Webhook %s delivered event %s (attempt %d, HTTP %d)",
                    hook.id, delivery.event, attempt, response.status_code,
                )
            else:
                _schedule_retry(delivery, f"HTTP {response.status_code}", attempt)
        except Exception as exc:
            delivery.response_status = None
            _schedule_retry(delivery, str(exc)[:500], attempt)

        await db.commit()


def _schedule_retry(delivery: WebhookDelivery, error: str, attempt: int) -> None:
    """Mark a delivery for another attempt, or give up if retries ran out."""
    delivery.error_message = error
    if attempt >= max(1, settings.webhook_max_attempts):
        delivery.status = "failed"
        delivery.completed_at = _utcnow()
        logger.warning(
            "Webhook delivery %s gave up after %d attempts: %s", delivery.id, attempt, error
        )
        return
    backoff = _BACKOFF_SECONDS[min(attempt - 1, len(_BACKOFF_SECONDS) - 1)]
    delivery.next_attempt_at = _utcnow() + datetime.timedelta(seconds=backoff)
    logger.info(
        "Webhook delivery %s failed (attempt %d: %s); retrying in %ds",
        delivery.id, attempt, error, backoff,
    )


async def dispatch_due_deliveries() -> int:
    """Send every delivery whose retry time has come. Returns how many were tried.

    Exposed separately from the worker loop so tests can drive one tick
    deterministically instead of waiting on a timer.
    """
    async with async_session() as db:
        due = (
            await db.execute(
                select(WebhookDelivery.id)
                .where(
                    WebhookDelivery.status == "pending",
                    WebhookDelivery.next_attempt_at <= _utcnow(),
                )
                .order_by(WebhookDelivery.next_attempt_at)
                .limit(max(1, settings.webhook_concurrency))
            )
        ).scalars().all()

    if not due:
        return 0

    timeout = httpx.Timeout(settings.webhook_timeout_seconds)
    from app.webhook_transport import webhook_transport
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=webhook_transport(), trust_env=False) as client:
        await asyncio.gather(*(_send_one(client, did) for did in due), return_exceptions=True)
    return len(due)


_worker_task: asyncio.Task | None = None


async def _worker_loop() -> None:
    while True:
        try:
            await dispatch_due_deliveries()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - keep the loop alive
            logger.error("Webhook dispatcher tick failed: %s", exc)
        await asyncio.sleep(max(0.1, settings.webhook_poll_interval_seconds))


def start_webhook_worker() -> None:
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(_worker_loop())
        logger.info(
            "Webhook dispatcher started (poll %.1fs, max %d attempts)",
            settings.webhook_poll_interval_seconds, settings.webhook_max_attempts,
        )


async def stop_webhook_worker() -> None:
    global _worker_task
    if _worker_task is not None:
        _worker_task.cancel()
        try:
            await _worker_task
        except (asyncio.CancelledError, Exception):
            pass
        _worker_task = None
        logger.info("Webhook dispatcher stopped")
