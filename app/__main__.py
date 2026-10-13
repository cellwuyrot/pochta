"""Canonical launch command: python -m app (WEB_PORT defaults to 3005)."""

import uvicorn

from app.config import settings


def main() -> None:
    uvicorn.run(
        "app.main:app",
        host=settings.web_host,
        port=settings.web_port,
        workers=1,
        forwarded_allow_ips=settings.trusted_proxy_ips or "127.0.0.1",
    )


if __name__ == "__main__":
    main()
