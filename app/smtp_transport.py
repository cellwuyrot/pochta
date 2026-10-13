"""Validated, IP-pinned SMTP connections with original-host TLS verification."""

import ipaddress
import smtplib
import socket

from app.config import settings


def target_ips(host, port):
    if not settings.smtp_allow_private_targets and port not in (25, 465, 587, 2525):
        raise ValueError("SMTP port must be 25, 465, 587 or 2525")
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(row[4][0] for row in answers))
    if not addresses or (
        not settings.smtp_allow_private_targets and any(not ipaddress.ip_address(ip).is_global for ip in addresses)
    ):
        raise ValueError("SMTP host must resolve only to public addresses")
    return addresses


def pinned_socket(host, port, timeout, source_address=None):
    error = None
    for ip in target_ips(host, port):
        try:
            return socket.create_connection((ip, port), timeout, source_address)
        except OSError as exc:
            error = exc
    raise error


class SafeSMTP(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        return pinned_socket(host, port, timeout, self.source_address)


class SafeSMTP_SSL(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        sock = pinned_socket(host, port, timeout, self.source_address)
        try:
            return self.context.wrap_socket(sock, server_hostname=host)
        except Exception:
            sock.close()
            raise
