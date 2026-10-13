"""Pin each webhook TCP connection to freshly validated public DNS answers.

HTTPcore performs TLS later with the original hostname, preserving SNI and cert
verification. Environment proxies are disabled so they cannot bypass this guard.
The small httpx pool hook is covered by tests and pinned to httpx 0.x/httpcore 1.x.
"""

import asyncio

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend

from app.config import settings


class PublicNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, backend=None):
        self.backend = backend or AutoBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        from app.webhook_service import WebhookUrlError, _is_private, _resolve_all

        addresses = await asyncio.to_thread(_resolve_all, host)
        if not addresses or any(_is_private(address) for address in addresses):
            raise WebhookUrlError("Webhook TCP target is not public")
        # A numeric IP cannot change under a second DNS resolution.
        last_error = None
        for address in dict.fromkeys(addresses):
            try:
                return await self.backend.connect_tcp(
                    address, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        raise last_error

    async def connect_unix_socket(self, *args, **kwargs):
        raise ValueError("Unix sockets forbidden for webhooks")

    async def sleep(self, seconds):
        await self.backend.sleep(seconds)


def webhook_transport():
    transport = httpx.AsyncHTTPTransport(retries=0)
    if not settings.webhook_allow_private_targets:
        transport._pool._network_backend = PublicNetworkBackend()
    return transport
