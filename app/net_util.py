"""Small networking helpers shared across route modules.

Everything here does blocking DNS I/O. Callers inside async request handlers
must invoke these through ``asyncio.to_thread`` so the event loop stays free.
"""

import threading
import time

from app.config import settings

# Resolving SMTP_DOMAIN used to hit the network on every admin page view. The A
# record for our own hostname changes very rarely, so a short TTL cache removes
# almost all of those lookups while still picking up a real IP change quickly.
_CACHE_TTL_SECONDS = 300
_cache_lock = threading.Lock()
_cached_ip: tuple[float, str] | None = None


def resolve_server_ip(*, use_cache: bool = True) -> str:
    """Return the sending server's IPv4 address for SPF/A records.

    If ``SMTP_DOMAIN`` is already an IP it is returned as-is; otherwise it is
    resolved to an A record. Falls back to the configured value on failure.

    Blocking: performs DNS I/O. Call via ``asyncio.to_thread`` from async code.
    """
    global _cached_ip

    raw = (settings.smtp_domain or "").strip()
    if _is_ipv4(raw):
        return raw

    if use_cache:
        with _cache_lock:
            if _cached_ip is not None:
                cached_at, value = _cached_ip
                if time.monotonic() - cached_at < _CACHE_TTL_SECONDS:
                    return value

    resolved = _resolve_a_record(raw)
    with _cache_lock:
        _cached_ip = (time.monotonic(), resolved)
    return resolved


def _resolve_a_record(hostname: str) -> str:
    try:
        import dns.resolver

        answers = dns.resolver.resolve(hostname, "A")
        return str(list(answers)[0])
    except Exception:
        return hostname


def _is_ipv4(value: str) -> bool:
    """True for a dotted-quad IPv4 literal.

    The previous check was ``value.replace(".", "").isdigit()``, which also
    matched things like "1.2.3.4.5" and "999.999.999.999".
    """
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def reset_ip_cache() -> None:
    """Drop the cached lookup (used by tests and after a config change)."""
    global _cached_ip
    with _cache_lock:
        _cached_ip = None
