"""End-to-end webhook delivery against a real HTTP receiver.

Uses a throwaway ThreadingHTTPServer rather than mocking httpx, so the test
exercises the actual request the subscriber would see: headers, raw body, and a
signature the subscriber can verify with the documented helper.
"""
import datetime
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from sqlalchemy import select

from app.database import async_session
from app.models import Site, Webhook, WebhookDelivery
from app.webhook_service import (
    ATTEMPT_HEADER,
    EVENT_HEADER,
    SIGNATURE_HEADER,
    dispatch_due_deliveries,
    enqueue_event,
    verify_signature,
)


class _Receiver:
    """Captures what the dispatcher actually POSTs."""

    def __init__(self, url: str):
        self.url = url
        self.requests: list[dict] = []
        self.status = 200


@pytest.fixture
def receiver(monkeypatch):
    from app.config import settings

    # The receiver lives on loopback, which the SSRF guard blocks by default.
    monkeypatch.setattr(settings, "webhook_allow_private_targets", True)

    state_holder: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", 0) or 0)
            body = self.rfile.read(length)
            state_holder["state"].requests.append(
                {"headers": dict(self.headers), "body": body, "path": self.path}
            )
            self.send_response(state_holder["state"].status)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    state = _Receiver(f"http://127.0.0.1:{port}/hook")
    state_holder["state"] = state
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield state
    server.shutdown()
    server.server_close()


async def _make_webhook(site: Site, url: str, events: str = "email.sent", active: bool = True) -> Webhook:
    async with async_session() as db:
        hook = Webhook(
            site_id=site.id,
            url=url,
            events=events,
            secret="whsec_" + "b" * 48,
            is_active=active,
        )
        db.add(hook)
        await db.commit()
        await db.refresh(hook)
        return hook


async def _deliveries(webhook_id: int) -> list[WebhookDelivery]:
    async with async_session() as db:
        return list(
            (
                await db.execute(
                    select(WebhookDelivery)
                    .where(WebhookDelivery.webhook_id == webhook_id)
                    .order_by(WebhookDelivery.id)
                )
            ).scalars().all()
        )


# --- Enqueueing -----------------------------------------------------------


async def test_event_is_queued_only_for_subscribed_webhooks(site, receiver):
    subscribed = await _make_webhook(site, receiver.url, events="email.sent")
    other = await _make_webhook(site, receiver.url, events="email.received")

    async with async_session() as db:
        queued = await enqueue_event(db, site.id, "email.sent", {"to": "a@example.com"})
        await db.commit()

    assert queued == 1
    assert len(await _deliveries(subscribed.id)) == 1
    assert await _deliveries(other.id) == []


async def test_inactive_webhook_receives_nothing(site, receiver):
    hook = await _make_webhook(site, receiver.url, events="email.sent", active=False)

    async with async_session() as db:
        queued = await enqueue_event(db, site.id, "email.sent", {"to": "a@example.com"})
        await db.commit()

    assert queued == 0
    assert await _deliveries(hook.id) == []


async def test_events_are_scoped_to_their_site(site, receiver):
    """A webhook must not receive another site's events."""
    async with async_session() as db:
        other_site = Site(
            name="Other", domain="other.test", sender_email="n@other.test", api_key="sm_other"
        )
        db.add(other_site)
        await db.commit()
        await db.refresh(other_site)

    hook = await _make_webhook(site, receiver.url, events="email.sent")

    async with async_session() as db:
        queued = await enqueue_event(db, other_site.id, "email.sent", {"to": "a@example.com"})
        await db.commit()

    assert queued == 0
    assert await _deliveries(hook.id) == []


# --- Dispatching ----------------------------------------------------------


async def test_delivery_reaches_receiver_with_verifiable_signature(site, receiver):
    hook = await _make_webhook(site, receiver.url, events="email.sent")

    async with async_session() as db:
        await enqueue_event(db, site.id, "email.sent", {"to": "user@example.com", "status": "sent"})
        await db.commit()

    assert await dispatch_due_deliveries() == 1
    assert len(receiver.requests) == 1

    request = receiver.requests[0]
    assert verify_signature(hook.secret, request["body"], request["headers"][SIGNATURE_HEADER]) is True
    assert request["headers"][EVENT_HEADER] == "email.sent"
    assert request["headers"][ATTEMPT_HEADER] == "1"
    assert request["headers"]["Content-Type"] == "application/json"

    body = json.loads(request["body"])
    assert body["event"] == "email.sent"
    assert body["data"]["to"] == "user@example.com"

    delivery = (await _deliveries(hook.id))[0]
    assert delivery.status == "success"
    assert delivery.response_status == 200
    assert delivery.attempts == 1
    assert delivery.completed_at is not None


async def test_signature_fails_with_the_wrong_secret(site, receiver):
    """Guard against a signature that would verify against anything."""
    await _make_webhook(site, receiver.url, events="email.sent")
    async with async_session() as db:
        await enqueue_event(db, site.id, "email.sent", {"to": "user@example.com"})
        await db.commit()
    await dispatch_due_deliveries()

    request = receiver.requests[0]
    assert verify_signature("whsec_wrong", request["body"], request["headers"][SIGNATURE_HEADER]) is False


async def test_non_2xx_schedules_a_retry_rather_than_failing(site, receiver, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "webhook_max_attempts", 3)
    hook = await _make_webhook(site, receiver.url, events="email.sent")
    receiver.status = 500

    async with async_session() as db:
        await enqueue_event(db, site.id, "email.sent", {"to": "user@example.com"})
        await db.commit()

    await dispatch_due_deliveries()

    delivery = (await _deliveries(hook.id))[0]
    assert delivery.status == "pending", "a 500 must be retried, not written off"
    assert delivery.attempts == 1
    assert delivery.response_status == 500
    assert "500" in delivery.error_message
    assert delivery.next_attempt_at > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # Backoff means an immediate second tick must not pick it up again.
    assert await dispatch_due_deliveries() == 0
    assert len(receiver.requests) == 1


async def test_retries_are_exhausted_then_marked_failed(site, receiver, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "webhook_max_attempts", 2)
    hook = await _make_webhook(site, receiver.url, events="email.sent")
    receiver.status = 503

    async with async_session() as db:
        await enqueue_event(db, site.id, "email.sent", {"to": "user@example.com"})
        await db.commit()

    await dispatch_due_deliveries()
    await _make_due(hook.id)
    await dispatch_due_deliveries()

    delivery = (await _deliveries(hook.id))[0]
    assert delivery.status == "failed"
    assert delivery.attempts == 2
    assert delivery.completed_at is not None
    assert len(receiver.requests) == 2

    # And it stays out of the queue afterwards.
    await _make_due(hook.id)
    assert await dispatch_due_deliveries() == 0


async def test_a_recovering_endpoint_succeeds_on_retry(site, receiver, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "webhook_max_attempts", 5)
    hook = await _make_webhook(site, receiver.url, events="email.sent")
    receiver.status = 502

    async with async_session() as db:
        await enqueue_event(db, site.id, "email.sent", {"to": "user@example.com"})
        await db.commit()

    await dispatch_due_deliveries()
    receiver.status = 200  # endpoint comes back
    await _make_due(hook.id)
    await dispatch_due_deliveries()

    delivery = (await _deliveries(hook.id))[0]
    assert delivery.status == "success"
    assert delivery.attempts == 2
    assert delivery.error_message == ""


async def test_unreachable_host_is_recorded_without_crashing(site, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "webhook_allow_private_targets", True)
    monkeypatch.setattr(settings, "webhook_max_attempts", 1)
    monkeypatch.setattr(settings, "webhook_timeout_seconds", 2.0)
    # Port 1 on loopback: nothing listens, connection refused immediately.
    hook = await _make_webhook(site, "http://127.0.0.1:1/hook", events="email.sent")

    async with async_session() as db:
        await enqueue_event(db, site.id, "email.sent", {"to": "user@example.com"})
        await db.commit()

    await dispatch_due_deliveries()

    delivery = (await _deliveries(hook.id))[0]
    assert delivery.status == "failed"
    assert delivery.response_status is None
    assert delivery.error_message


async def test_response_body_is_not_persisted(site, receiver):
    """The delivery log must not become a way to read back arbitrary URLs."""
    hook = await _make_webhook(site, receiver.url, events="email.sent")
    async with async_session() as db:
        await enqueue_event(db, site.id, "email.sent", {"to": "user@example.com"})
        await db.commit()
    await dispatch_due_deliveries()

    delivery = (await _deliveries(hook.id))[0]
    stored = f"{delivery.error_message}{delivery.payload}"
    assert "ok" not in stored.replace("webhook", ""), "response body leaked into the delivery row"


async def _make_due(webhook_id: int) -> None:
    """Rewind next_attempt_at so the next tick picks the delivery up."""
    async with async_session() as db:
        rows = (
            await db.execute(
                select(WebhookDelivery).where(WebhookDelivery.webhook_id == webhook_id)
            )
        ).scalars().all()
        for row in rows:
            row.next_attempt_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(seconds=1)
        await db.commit()
