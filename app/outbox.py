"""Durable, single-process SQLite outbox. Never automatically replay uncertain sends."""

import asyncio
import base64
import datetime as dt
import hashlib
import json
import logging
import uuid

from sqlalchemy import delete, select

from app.config import settings
from app.database import async_session
from app.models import EmailLog, OutboxMessage, Site
from app.providers import send_via_providers
from app.webhook_service import enqueue_event

logger = logging.getLogger(__name__)
_task = None
_lock = asyncio.Lock()


def now():
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


async def enqueue_message(db, site, payload, idempotency_key=None):
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    fingerprint = hashlib.sha256(encoded.encode()).hexdigest()
    if idempotency_key:
        existing = (
            await db.execute(
                select(OutboxMessage).where(
                    OutboxMessage.site_id == site.id, OutboxMessage.idempotency_key == idempotency_key
                )
            )
        ).scalar_one_or_none()
        if existing:
            if existing.fingerprint != fingerprint:
                raise ValueError("Idempotency key already used with different content")
            return existing
    row = OutboxMessage(
        id=str(uuid.uuid4()),
        site_id=site.id,
        idempotency_key=idempotency_key,
        fingerprint=fingerprint,
        payload=encoded,
        status="queued",
        attempts=0,
        next_attempt_at=now(),
    )
    db.add(row)
    await db.flush()
    return row


async def recover_interrupted():
    async with async_session() as db:
        rows = (await db.execute(select(OutboxMessage).where(OutboxMessage.status == "sending"))).scalars().all()
        for row in rows:
            row.status = "unknown"
            row.error = "Worker interrupted during send; verify relay logs before resubmitting"
            row.completed_at = now()
        await db.commit()


async def dispatch_due(limit=20):
    if _lock.locked():
        return 0
    async with _lock:
        async with async_session() as db:
            rows = (
                (
                    await db.execute(
                        select(OutboxMessage)
                        .where(OutboxMessage.status == "queued", OutboxMessage.next_attempt_at <= now())
                        .order_by(OutboxMessage.created_at)
                        .limit(limit)
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                # Commit sending BEFORE the network call: after a crash this is unknown,
                # not queued, so an ambiguous remote acceptance is not replayed.
                row.status = "sending"
                row.attempts += 1
                await db.commit()
                site = await db.get(Site, row.site_id)
                ok, error, source = False, "Site missing or inactive", "none"
                payload = json.loads(row.payload)
                if site and site.is_active:
                    kwargs = dict(payload)
                    raw = kwargs.pop("raw_message_b64", "")
                    if raw:
                        kwargs["raw_message"] = base64.b64decode(raw)
                    try:
                        ok, error, source = await send_via_providers(
                            db,
                            site,
                            message_id=row.id,
                            from_name=site.sender_name,
                            dkim_domain=site.domain,
                            dkim_selector=site.dkim_selector,
                            dkim_private_key=site.dkim_private_key,
                            **kwargs,
                        )
                    except Exception:
                        logger.exception("Outbox send interrupted")
                        error = "uncertain: delivery exception; inspect relay logs"
                row.relay, row.error = source, error[:2000]
                if ok:
                    row.status = "accepted"
                elif error.startswith("uncertain:"):
                    row.status = "unknown"
                elif (
                    error.startswith("permanent:")
                    or row.attempts >= settings.outbox_max_attempts
                    or not site
                    or not site.is_active
                ):
                    row.status = "failed"
                else:
                    row.status = "queued"
                    row.next_attempt_at = now() + dt.timedelta(seconds=min(3600, 10 * 2 ** (row.attempts - 1)))
                if row.status != "queued":
                    row.completed_at = now()
                db.add(
                    EmailLog(
                        site_id=site.id if site else None,
                        direction="outgoing",
                        sender=payload["from_email"],
                        recipient=payload["to_email"],
                        subject=payload["subject"][:500],
                        status=row.status,
                        error_message=row.error,
                        message_id=row.id,
                        relay_source=source,
                        attempts=row.attempts,
                    )
                )
                if site and row.status in ("accepted", "failed"):
                    await enqueue_event(
                        db,
                        site.id,
                        "email.sent" if ok else "email.failed",
                        {
                            "email_id": row.id,
                            "from": payload["from_email"],
                            "to": payload["to_email"],
                            "subject": payload["subject"],
                            "status": row.status,
                            "relay": source,
                            "error": row.error or None,
                        },
                    )
                await db.commit()
            # Drop sensitive completed payloads after the retention period, retaining audit rows.
            cutoff = now() - dt.timedelta(days=settings.outbox_retention_days)
            await db.execute(delete(OutboxMessage).where(OutboxMessage.completed_at < cutoff))
            await db.commit()
            return len(rows)


async def _run():
    await recover_interrupted()
    while True:
        try:
            await dispatch_due()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Outbox tick failed")
        await asyncio.sleep(settings.outbox_poll_seconds)


def start_outbox_worker():
    global _task
    _task = asyncio.create_task(_run(), name="smtp-outbox")


async def stop_outbox_worker():
    global _task
    if _task:
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
        _task = None
