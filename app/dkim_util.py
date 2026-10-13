"""DKIM key generation, DNS record helpers, and message signing.

DKIM is the single most important lever for inbox placement: it lets a
receiving server cryptographically verify that the message really came from
your domain and was not altered in transit. Gmail, Yahoo and Outlook all
weight DKIM heavily, and a valid DKIM signature is required for DMARC to pass
via the DKIM path.
"""

import base64
import logging

logger = logging.getLogger(__name__)


def generate_dkim_keypair() -> tuple[str, str]:
    """Generate a 2048-bit RSA keypair for DKIM.

    Returns ``(private_key_pem, dns_txt_value)`` where ``dns_txt_value`` is the
    full value to publish at ``<selector>._domainkey.<domain>``.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1, what dkimpy expects
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    dns_value = dkim_dns_value(private_pem)
    return private_pem, dns_value


def dkim_dns_value(private_key_pem: str) -> str:
    """Return the public DKIM TXT record value for a given private key."""
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    return f"v=DKIM1; k=rsa; p={pub_b64}"


def sign_message(
    message_bytes: bytes,
    domain: str,
    selector: str,
    private_key_pem: str,
) -> bytes:
    """Return ``message_bytes`` with a prepended DKIM-Signature header.

    On any failure the original message is returned unchanged so that a signing
    problem never blocks delivery (it only costs the DKIM boost).
    """
    if not private_key_pem or not domain or not selector:
        return message_bytes
    try:
        import dkim

        signature = dkim.sign(
            message=message_bytes,
            selector=selector.encode("ascii"),
            domain=domain.encode("ascii"),
            privkey=private_key_pem.encode("utf-8"),
            # Sign the headers that matter for identity + integrity. Signing
            # From is mandatory; Subject/Date/To/MIME headers harden against
            # tampering and improve alignment.
            include_headers=[
                b"from",
                b"to",
                b"subject",
                b"date",
                b"message-id",
                b"mime-version",
                b"content-type",
            ],
        )
        return signature + message_bytes
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("DKIM signing failed for domain %s: %s", domain, exc)
        return message_bytes
