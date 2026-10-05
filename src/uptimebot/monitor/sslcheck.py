"""TLS certificate inspection.

The one subtlety that matters here: to report that a certificate has
*already* expired, the handshake must be allowed to complete even though the
certificate is invalid. Verification is therefore disabled for the inspection
socket, and a separate verifying probe (see ``checker.py``) is what actually
marks the site as down.

``trustme`` is not needed: tests generate certificates with ``cryptography``.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from ..models import Monitor, SslInfo

log = logging.getLogger(__name__)

UTC = timezone.utc

# The inspection socket must tolerate an expired, self-signed or mismatched
# certificate, otherwise the very conditions we want to report cannot be read.
_INSPECT_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_INSPECT_CTX.check_hostname = False
_INSPECT_CTX.verify_mode = ssl.CERT_NONE

# A separate context, used only to report whether the chain actually validates.
_VERIFY_CTX = ssl.create_default_context()


class SslChecker:
    """Fetches and parses the leaf certificate of a host."""

    def __init__(self, *, timeout: float = 10.0, allow_private_network: bool = False) -> None:
        self._timeout = timeout
        self._allow_private_network = allow_private_network

    async def check(self, monitor: Monitor) -> SslInfo:
        host = monitor.host
        if not host:
            return SslInfo(checked_at=datetime.now(UTC), error="Host tidak bisa ditentukan dari URL")

        if monitor.url.lower().startswith("http://"):
            return SslInfo(
                checked_at=datetime.now(UTC),
                error="URL memakai http:// — tidak ada sertifikat untuk diperiksa",
            )

        # A monitor on an internal host needs the same opt-in as its HTTP
        # probe, otherwise its certificate could never be inspected.
        allow_private = monitor.allow_private_network or self._allow_private_network

        try:
            return await asyncio.to_thread(self._check_sync, host, monitor.port, allow_private)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - report, never raise
            log.debug("ssl check failed for %s: %s", host, exc)
            return SslInfo(checked_at=datetime.now(UTC), error=f"{type(exc).__name__}: {exc}"[:300])

    def _check_sync(self, host: str, port: int, allow_private: bool = False) -> SslInfo:
        from .ssrf import BlockedTargetError, resolve_target

        try:
            target = resolve_target(f"https://{host}:{port}", allow_private_network=allow_private)
        except BlockedTargetError as exc:
            return SslInfo(checked_at=datetime.now(UTC), error=str(exc))

        # Connect to the address that was just vetted rather than re-resolving
        # the name, then restore the original hostname for SNI and the
        # certificate check.
        with socket.create_connection(target.sockaddr, timeout=self._timeout) as raw:
            with _INSPECT_CTX.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                tls_version = tls.version()

        if not der:
            return SslInfo(checked_at=datetime.now(UTC), error="Server tidak mengirim sertifikat")

        # Load the DER directly. ``ssl.DER_cert_to_PEM_cert`` returns ``str`` and
        # ``load_pem_x509_certificate`` requires ``bytes``, which is why this
        # used to fail on every real host once cryptography tightened its types.
        cert = x509.load_der_x509_certificate(der)
        now = datetime.now(UTC)
        not_after = _not_after(cert)
        issuer = _rdn(cert.issuer, NameOID.COMMON_NAME) or _rdn(cert.issuer, NameOID.ORGANIZATION_NAME)
        subject_cn = _rdn(cert.subject, NameOID.COMMON_NAME)
        chain_ok = _chain_valid(host, port)

        days_left: int | None = None
        if not_after is not None:
            # Floor, so a certificate with 6 hours left reports 0 days rather
            # than 1, which keeps the 1-day alert honest.
            days_left = (not_after - now).days

        return SslInfo(
            checked_at=now,
            not_after=not_after,
            days_left=days_left,
            issuer=issuer,
            subject_cn=subject_cn,
            tls_version=tls_version,
            chain_ok=chain_ok,
        )


def _not_after(cert: x509.Certificate) -> datetime | None:
    """Read the expiry, tolerating older ``cryptography`` versions."""
    value = getattr(cert, "not_valid_after_utc", None)
    if value is None:
        value = cert.not_valid_after.replace(tzinfo=UTC)
    return value


def _rdn(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except (IndexError, x509.ExtensionNotFound):
        return None


def san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


def fingerprint(cert: x509.Certificate, length: int = 16) -> str:
    """Short SHA-256 fingerprint, for the SSL table."""
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{byte:02X}" for byte in digest[: length // 2])


def _chain_valid(host: str, port: int) -> bool:
    """Whether a normal client would accept this certificate.

    Reported as information only: the probe result is the source of truth for
    whether a monitor is up.
    """
    try:
        with socket.create_connection((host, port), timeout=5.0) as raw:
            with _VERIFY_CTX.wrap_socket(raw, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False
