"""Regression: a slow email send must not freeze the whole service.

``send_email`` is synchronous (smtplib, 30s timeout). If a request handler calls
it directly instead of handing it to a worker thread, the asyncio event loop is
blocked and every other request — including the admin panel and /api/health —
stalls for the duration.

The server runs in its own thread with its own event loop so that a blocked
server loop cannot silently also block the test's own timing code.
"""
import concurrent.futures
import threading
import time

import httpx
import pytest
import uvicorn

SLOW_SEND_SECONDS = 2.0
# Generous: on an unblocked loop /api/health answers in single-digit ms.
MAX_ACCEPTABLE_HEALTH_SECONDS = 0.5


@pytest.fixture
def live_server(free_port):
    """Run the real ASGI app in a background thread."""
    from app.config import settings

    settings.smtp_port = free_port + 1  # avoid clashing with the web port

    from app.main import app

    config = uvicorn.Config(app, host="127.0.0.1", port=free_port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base = f"http://127.0.0.1:{free_port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            httpx.get(f"{base}/api/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("server did not come up")

    yield base

    server.should_exit = True
    thread.join(timeout=15)


@pytest.mark.asyncio
async def test_slow_send_does_not_block_other_requests(live_server, site, monkeypatch):
    import app.providers as providers

    def slow_send(*args, **kwargs):
        """Stand-in for any blocking network I/O inside send_email."""
        time.sleep(SLOW_SEND_SECONDS)
        return True, ""

    # Patched on app.providers, because that is the module whose global
    # send_email the request path actually calls (via send_via_providers).
    monkeypatch.setattr(providers, "send_email", slow_send)

    with httpx.Client(base_url=live_server, timeout=30) as client:
        baseline = _time_health(client)
        assert baseline < MAX_ACCEPTABLE_HEALTH_SECONDS, f"health slow even at rest: {baseline:.3f}s"

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            send_started = time.perf_counter()
            send = pool.submit(
                client.post,
                "/api/emails",
                headers={"Authorization": f"Bearer {site.api_key}"},
                json={
                    "from_email": "noreply@example.com",
                    "to": "someone@example.net",
                    "subject": "hello",
                    "html": "<p>hi</p>",
                },
            )
            # Let the request reach the handler and enter the blocking call.
            time.sleep(0.4)

            during = _time_health(client)
            send_response = send.result(timeout=30)
            send_duration = time.perf_counter() - send_started

    assert send_response.status_code == 200, send_response.text
    # Guard against a false pass: if the monkeypatch ever misses its target the
    # send returns instantly, every health check is fast, and this test would
    # "pass" while exercising nothing.
    assert send_duration >= SLOW_SEND_SECONDS * 0.8, (
        f"the send completed in {send_duration:.2f}s, so the slow stand-in was not "
        f"in effect and this test is not exercising the blocking path at all"
    )
    assert during < MAX_ACCEPTABLE_HEALTH_SECONDS, (
        f"/api/health took {during:.3f}s while one email was sending "
        f"(baseline {baseline:.3f}s). The event loop is blocked: send_email() is "
        f"called synchronously inside an async handler."
    )


def _time_health(client: httpx.Client) -> float:
    start = time.perf_counter()
    response = client.get("/api/health")
    elapsed = time.perf_counter() - start
    assert response.status_code == 200
    return elapsed
