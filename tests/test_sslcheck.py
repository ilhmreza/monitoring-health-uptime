"""Real TLS handshakes for the certificate inspector.

These tests stand up an actual TLS server on loopback and read its certificate
through the production code path. That matters: the DER-to-PEM conversion used
to hand ``str`` to ``cryptography`` and broke every real host, while a suite of
fakes happily reported success. A test that mocks the socket cannot catch that
class of bug, so the socket stays real here.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import socket
import ssl
import threading
from contextlib import closing

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from uptimebot.models import Monitor
from uptimebot.monitor.sslcheck import SslChecker, fingerprint, san_dns_names

UTC = dt.timezone.utc


def _self_signed(
    not_after: dt.datetime, common_name: str = "localhost"
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    # An expired certificate still needs a validity window that ends in the past,
    # so the start moves back with it rather than tracking "now".
    not_before = min(dt.datetime.now(UTC) - dt.timedelta(days=1), not_after - dt.timedelta(days=1))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _handshake(context: ssl.SSLContext, raw: socket.socket) -> None:
    with closing(raw):
        try:
            with context.wrap_socket(raw, server_side=True):
                pass
        except OSError:
            pass


def _tls_server(tmp_path, cert: x509.Certificate, key: rsa.RSAPrivateKey) -> tuple[str, int]:
    """Serve ``cert`` on loopback forever, return its ``(host, port)``.

    ``load_cert_chain`` only accepts file paths, so the material is written out
    first. What travels on the wire is DER either way, and DER is what the
    inspector reads back.
    """
    cert_pem = tmp_path / "cert.pem"
    key_pem = tmp_path / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_pem), keyfile=str(key_pem))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)

    def serve() -> None:
        while True:
            try:
                raw, _ = listener.accept()
            except OSError:
                return
            # One handshake per connection is enough: the inspector opens its own.
            threading.Thread(target=_handshake, args=(context, raw), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[:2]


def _monitor(port: int, **overrides) -> Monitor:
    fields = {
        "id": "m1",
        "name": "loopback tls",
        "url": f"https://127.0.0.1:{port}/",
        "allow_private_network": True,
        "ssl_check": True,
    }
    fields.update(overrides)
    return Monitor(**fields)


def test_reads_certificate_from_real_socket(tmp_path) -> None:
    """The regression: parsing must yield real data, not a type error."""
    _, port = _tls_server(tmp_path, *_self_signed(dt.datetime.now(UTC) + dt.timedelta(days=45)))

    info = asyncio.run(SslChecker(timeout=10.0).check(_monitor(port)))

    assert info.error is None, f"inspector failed: {info.error}"
    assert info.not_after is not None
    # The window is 45 days, minus the sliver between building the certificate
    # and reading it back, and the remainder is floored. Hence 44 or 45.
    assert info.days_left in (44, 45)
    assert info.subject_cn == "localhost"
    assert info.issuer == "localhost"
    assert info.tls_version is not None
    # Self-signed, so a normal client would reject it. That is information, not
    # an error, and must not stop the expiry from being read.
    assert info.chain_ok is False


def test_hours_left_reports_zero_days_not_one(tmp_path) -> None:
    """Flooring is what keeps the 1-day alert honest.

    A certificate with six hours left must read as 0 days remaining, otherwise
    every threshold would fire a day early.
    """
    _, port = _tls_server(tmp_path, *_self_signed(dt.datetime.now(UTC) + dt.timedelta(hours=6)))

    info = asyncio.run(SslChecker(timeout=10.0).check(_monitor(port)))

    assert info.error is None, f"inspector failed: {info.error}"
    assert info.days_left == 0


def test_expired_certificate_is_reported_not_hidden(tmp_path) -> None:
    """An expired cert is exactly the case worth alerting on."""
    _, port = _tls_server(tmp_path, *_self_signed(dt.datetime.now(UTC) - dt.timedelta(days=2)))

    info = asyncio.run(SslChecker(timeout=10.0).check(_monitor(port)))

    assert info.error is None
    assert info.not_after is not None
    assert info.not_after < dt.datetime.now(UTC)
    assert info.days_left == -3


def test_http_monitor_is_skipped_without_error() -> None:
    info = asyncio.run(SslChecker().check(_monitor(80, url="http://127.0.0.1:80/")))

    assert info.error is not None
    assert "http://" in info.error


def test_https_monitor_reaching_nothing_reports_instead_of_raising() -> None:
    """Bind then release, so the port is almost certainly closed."""
    with closing(socket.socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    info = asyncio.run(SslChecker(timeout=2.0).check(_monitor(port)))

    assert info.not_after is None
    # The message names the failure instead of leaking a bare traceback.
    assert info.error
    assert "TypeError" not in info.error


def test_private_network_requires_opt_in(tmp_path) -> None:
    _, port = _tls_server(tmp_path, *_self_signed(dt.datetime.now(UTC) + dt.timedelta(days=10)))

    info = asyncio.run(SslChecker(timeout=5.0).check(_monitor(port, allow_private_network=False)))

    assert info.not_after is None
    assert info.error is not None
    assert "loopback" in info.error.lower() or "private" in info.error.lower()


def test_helpers_read_names_and_fingerprint(tmp_path) -> None:
    cert, key = _self_signed(dt.datetime.now(UTC) + dt.timedelta(days=5), "contoh.example")
    _, port = _tls_server(tmp_path, cert, key)

    info = asyncio.run(SslChecker(timeout=10.0).check(_monitor(port)))

    assert info.error is None, f"inspector failed: {info.error}"
    assert san_dns_names(cert) == ["contoh.example"]
    # Eight uppercase hex pairs, as the SSL table renders them.
    parts = fingerprint(cert).split(":")
    assert len(parts) == 8
    assert all(len(part) == 2 and part == part.upper() for part in parts)