"""One canonical DNS domain representation for UI, API and SMTP."""

import re


def normalize_domain(raw: str) -> str:
    domain = raw.strip()
    domain = re.sub(r"^https?://", "", domain, flags=re.I).strip("/").rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid IDN domain") from exc
    if (
        len(domain) > 253
        or not domain
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split("."))
    ):
        raise ValueError("Invalid domain: use a DNS hostname, not a URL path or port")
    return domain


def normalize_email(value: str) -> str:
    if len(value) > 254 or value.count("@") != 1 or any(c in value for c in "\r\n ,<>"):
        raise ValueError("Invalid email address")
    local, domain = value.rsplit("@", 1)
    if not local or len(local) > 64 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
        raise ValueError("Invalid email address")
    return local + "@" + normalize_domain(domain)
