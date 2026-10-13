"""Signature generation and verification, and the SSRF guard on subscriber URLs."""
import time

import pytest

from app.webhook_service import (
    WebhookUrlError,
    sign_payload,
    validate_webhook_url,
    verify_signature,
)

SECRET = "whsec_" + "a" * 48
BODY = b'{"event":"email.sent","data":{"to":"user@example.com"}}'


def test_signature_roundtrip():
    header, ts = sign_payload(SECRET, BODY)
    assert header.startswith(f"t={ts},v1=")
    assert verify_signature(SECRET, BODY, header) is True


def test_signature_rejects_wrong_secret():
    header, _ = sign_payload(SECRET, BODY)
    assert verify_signature("whsec_different", BODY, header) is False


def test_signature_rejects_tampered_body():
    header, _ = sign_payload(SECRET, BODY)
    assert verify_signature(SECRET, BODY + b" ", header) is False


def test_signature_rejects_replay_outside_tolerance():
    old = int(time.time()) - 3600
    header, _ = sign_payload(SECRET, BODY, timestamp=old)
    # Valid HMAC, but too old: the timestamp is inside the signed string
    # precisely so that a captured request cannot be replayed later.
    assert verify_signature(SECRET, BODY, header, tolerance_seconds=300) is False
    assert verify_signature(SECRET, BODY, header, tolerance_seconds=0) is True


@pytest.mark.parametrize("header", ["", "garbage", "t=abc,v1=x", "v1=onlysig", "t=123"])
def test_signature_rejects_malformed_headers(header):
    assert verify_signature(SECRET, BODY, header) is False


def test_signature_covers_timestamp_not_just_body():
    """Swapping in a different timestamp must invalidate the signature."""
    header, ts = sign_payload(SECRET, BODY)
    digest = header.split("v1=", 1)[1]
    forged = f"t={ts + 1},v1={digest}"
    assert verify_signature(SECRET, BODY, forged) is False


# --- SSRF guard -----------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/hook",
        "http://localhost/hook",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://10.0.0.5/hook",
        "http://192.168.1.10/hook",
        "http://[::1]/hook",
        "http://0.0.0.0/hook",
    ],
)
def test_private_targets_are_rejected_by_default(url, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "webhook_allow_private_targets", False)
    with pytest.raises(WebhookUrlError):
        validate_webhook_url(url)


@pytest.mark.parametrize("url", ["ftp://example.com/x", "file:///etc/passwd", "gopher://x", ""])
def test_non_http_schemes_are_rejected(url):
    with pytest.raises(WebhookUrlError):
        validate_webhook_url(url)


def test_private_targets_allowed_when_explicitly_enabled(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "webhook_allow_private_targets", True)
    assert validate_webhook_url("http://127.0.0.1:9000/hook") == "http://127.0.0.1:9000/hook"


def test_https_can_be_required(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "webhook_allow_private_targets", True)
    monkeypatch.setattr(settings, "webhook_require_https", True)
    with pytest.raises(WebhookUrlError, match="https"):
        validate_webhook_url("http://127.0.0.1:9000/hook")
    assert validate_webhook_url("https://127.0.0.1:9000/hook")
