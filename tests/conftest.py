"""Shared test fixtures.

Environment variables are set BEFORE importing anything from ``app`` because
``app.config.settings`` and ``app.database.engine`` are module-level singletons
built at import time.
"""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="smtp-tests-")

# A known-good baseline config. Individual tests override what they need.
os.environ.update(
    {
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD": "test-password",
        "SECRET_KEY": "0" * 64,
        "COOKIE_SECURE": "false",
        "DATABASE_URL": f"sqlite+aiosqlite:///{os.path.join(_TMP, 'test.db')}",
        "SMTP_DOMAIN": "mail.example.test",
        "STORE_BODY_PREVIEW": "false",
        # Existing compatibility tests explicitly enable legacy delivery / local webhooks.
        "ALLOW_DIRECT_MX": "true",
        "SMTP_ALLOW_PRIVATE_TARGETS": "true",
        "WEBHOOK_REQUIRE_HTTPS": "false",
    }
)

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import delete  # noqa: E402

from app.database import async_session, engine  # noqa: E402
from app.models import (  # noqa: E402
    Base,
    DeliveryAttempt,
    EmailLog,
    EmailProvider,
    EmailTemplate,
    OutboxMessage,
    Site,
    User,
    Webhook,
    WebhookDelivery,
)

# Child tables first: these are bulk deletes, which do not run ORM-level
# cascades, so anything holding a foreign key must go before its parent.
_TRUNCATION_ORDER = (
    DeliveryAttempt,
    OutboxMessage,
    WebhookDelivery,
    Webhook,
    EmailProvider,
    EmailLog,
    EmailTemplate,
    Site,
    User,
)


@pytest_asyncio.fixture(autouse=True)
async def clean_database():
    """Fresh schema state for every test.

    Every table has to be listed here. A missing one leaks rows into the next
    test — pending webhook deliveries from an earlier test, for instance, get
    picked up by a later dispatcher tick and quietly break its assertions.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_session() as db:
        for model in _TRUNCATION_ORDER:
            await db.execute(delete(model))
        await db.commit()
    yield


def test_every_table_is_truncated_between_tests():
    """Guard: adding a model without adding it above would silently leak state."""
    mapped = {m.class_ for m in Base.registry.mappers}
    missing = mapped - set(_TRUNCATION_ORDER)
    assert not missing, f"add these to _TRUNCATION_ORDER in conftest: {sorted(m.__name__ for m in missing)}"


@pytest_asyncio.fixture
async def site():
    """An active site with a known API key."""
    async with async_session() as db:
        s = Site(
            name="Test Site",
            domain="example.com",
            sender_email="noreply@example.com",
            sender_name="Test",
            api_key="sm_testkey",
            dkim_private_key="",
        )
        db.add(s)
        await db.commit()
        await db.refresh(s)
        return s


@pytest.fixture
def free_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def repo_root():
    from pathlib import Path

    return Path(__file__).resolve().parent.parent
