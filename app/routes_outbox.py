"""Additive async API; legacy /emails and /send remain synchronous."""

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api_auth import authorized_site
from app.database import get_db
from app.models import OutboxMessage, Site
from app.outbox import enqueue_message
from app.routes_api import EmailSendRequest, api_rate_limit

router = APIRouter(prefix="/api/outbox", tags=["outbox"])


def output(row):
    return {
        "id": row.id,
        "status": row.status,
        "attempts": row.attempts,
        "relay": row.relay,
        "error": row.error,
        "created_at": row.created_at,
        "next_attempt_at": row.next_attempt_at,
        "completed_at": row.completed_at,
    }


@router.post("", status_code=202, dependencies=[Depends(api_rate_limit)])
async def queue_email(
    req: EmailSendRequest,
    site: Site = Depends(authorized_site),
    db: AsyncSession = Depends(get_db),
    idempotency_key: str | None = Header(default=None, max_length=255),
):
    if req.from_email.rsplit("@", 1)[-1] != site.domain:
        raise HTTPException(403, "Sender domain not authorized")
    recipients = req.to if isinstance(req.to, list) else [req.to]
    # One row per request avoids partial enqueue; multi-recipient sending stays on legacy endpoint.
    if len(recipients) != 1:
        raise HTTPException(422, "Outbox endpoint accepts exactly one recipient per job")
    payload = {
        "from_email": req.from_email,
        "to_email": recipients[0],
        "subject": req.subject,
        "body_html": req.html,
        "body_text": req.text,
    }
    try:
        row = await enqueue_message(db, site, payload, idempotency_key)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        # Concurrent duplicate won the unique constraint; verify content, not just key.
        try:
            row = await enqueue_message(db, site, payload, idempotency_key)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return output(row)


@router.get("/{message_id}")
async def message_status(message_id: str, site: Site = Depends(authorized_site), db: AsyncSession = Depends(get_db)):
    row = await db.get(OutboxMessage, message_id)
    if not row or row.site_id != site.id:
        raise HTTPException(404, "Message not found")
    return output(row)
