import logging
import secrets
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

# Known-insecure placeholder shipped in .env.example. Never usable in production.
INSECURE_DEFAULT_SECRET = "change-me-to-a-random-string"


class Settings(BaseSettings):
    smtp_domain: str = "localhost"
    smtp_port: int = 2525
    smtp_host_port: int = Field(default=587, ge=1, le=65535)
    web_host: str = "127.0.0.1"
    web_port: int = Field(default=3005, ge=1, le=65535)

    admin_username: str = "admin"
    admin_password: str = ""
    secret_key: str = ""
    api_key: str = ""

    database_url: str = "sqlite+aiosqlite:///./data/smtp.db"

    tls_cert_path: str = ""
    tls_key_path: str = ""

    relay_host: str = ""
    relay_port: int = 587
    relay_username: str = ""
    relay_password: str = ""
    relay_use_tls: bool = True

    smtp_allow_private_targets: bool = False
    allow_direct_mx: bool = False
    inbound_enabled: bool = False
    smtp_max_recipients: int = 50
    smtp_max_message_bytes: int = 10 * 1024 * 1024
    smtp_account_per_min: int = 30
    trusted_proxy_ips: str = ""
    data_encryption_keys: str = ""
    outbox_poll_seconds: float = 2.0
    outbox_max_attempts: int = 5
    outbox_retention_days: int = 7

    # --- Security / hardening knobs ---
    # Send the Secure flag on the session cookie (requires HTTPS in front of the
    # app). Set to false ONLY for local http:// development.
    cookie_secure: bool = True
    # Expose the interactive Swagger UI at /api/docs. Off by default because it
    # enumerates the API surface to anonymous visitors.
    api_docs_enabled: bool = False
    # Persist raw email bodies (and thus OTP codes) in the logs table. Off by
    # default for privacy; enable only if you understand the exposure.
    store_body_preview: bool = False
    # Simple in-memory rate limits (per client IP, per minute).
    rate_limit_api_per_min: int = 60
    rate_limit_login_per_min: int = 10

    # --- Webhooks ---
    # Per-request timeout when POSTing an event to a subscriber URL.
    webhook_timeout_seconds: float = 10.0
    # Total attempts per delivery before it is marked failed (1 = no retries).
    webhook_max_attempts: int = 5
    # How often the background dispatcher looks for due deliveries.
    webhook_poll_interval_seconds: float = 5.0
    # Deliveries dispatched concurrently per poll tick.
    webhook_concurrency: int = 5
    # Allow webhook URLs pointing at loopback/private/link-local addresses.
    # Off by default: webhook URLs come from whoever holds a site API key, and a
    # URL like http://169.254.169.254/ would otherwise aim the server at cloud
    # metadata or other internal services (SSRF).
    webhook_allow_private_targets: bool = False
    # Require https:// for subscriber URLs. Off by default so that enabling
    # private targets is enough to test against http://localhost.
    webhook_require_https: bool = True

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


def _ensure_secret_key(s: Settings) -> None:
    """Guarantee a strong session-signing key.

    If SECRET_KEY is unset or still the insecure example value, generate a
    random 256-bit key and persist it to ``data/.secret_key`` so it survives
    restarts (otherwise every restart would invalidate all sessions). This
    closes the "forgeable admin session cookie" hole on manual installs that
    never edited .env.
    """
    if s.secret_key and s.secret_key != INSECURE_DEFAULT_SECRET:
        return

    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    key_file = data_dir / ".secret_key"

    if key_file.exists():
        s.secret_key = key_file.read_text(encoding="utf-8").strip()
    else:
        new_key = secrets.token_hex(32)
        key_file.write_text(new_key, encoding="utf-8")
        try:
            key_file.chmod(0o600)
        except OSError:
            pass
        s.secret_key = new_key

    logger.warning(
        "SECRET_KEY was unset or the insecure default; using an auto-generated key "
        "persisted at %s. For multi-instance deployments set SECRET_KEY explicitly in .env.",
        key_file,
    )


settings = Settings()
_ensure_secret_key(settings)
