"""Outbound URL safety checks (SSRF defence).

The web UI lets an authenticated user type any URL, and the server then
fetches it from wherever it is deployed. On a Docker host that reaches the
private network the monitor itself lives in, and on a cloud VM it reaches the
instance metadata endpoint, which hands out IAM credentials.

Two layers are used:

1. A *static* check on the URL as typed, so the user gets an immediate,
   explanatory error in the browser.
2. A *resolution* check performed by the checker right before connecting, so
   a hostname that resolves to a private address — including one that only
   starts doing so later — is still refused.
3. A *post-connection* check on the peer address the socket actually reached,
   which closes the DNS-rebinding window that layers 1 and 2 leave open: a
   hostname can resolve to a public address for our lookup and a private one
   for the connection milliseconds later. When the rebind is detected the
   response is discarded and the probe fails.

This is defence in depth rather than strict address pinning. Pinning the
connection to the vetted address would require a custom resolver wired into
httpcore; the peer check is the pragmatic equivalent that keeps httpx's
connection pooling.

Opting in per monitor via ``allow_private_network`` is required for anything
on RFC1918 space.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Cloud instance-metadata endpoints. These are link-local, so the general
# link-local rule below already covers them; they are listed explicitly to
# produce a clearer error message than "private address blocked".
_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / GCP / OpenStack / DigitalOcean
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud
        "metadata.google.internal",
        "metadata.goog",
    }
)

# Names that always mean the local machine. They are refused statically so the
# user gets the error in the browser instead of discovering it from a failed
# probe minutes later. Anything else is left to the resolution pass, because a
# hostname that resolves to loopback is caught there.
_LOCAL_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }
)


class BlockedTargetError(ValueError):
    """Raised when a URL is refused by the SSRF guard.

    This means a policy decision: the address exists, and we are declining to
    connect to it.
    """


class ResolutionError(BlockedTargetError):
    """Raised when a hostname cannot be looked up at all.

    Deliberately a subclass of :class:`BlockedTargetError` so that any existing
    ``except BlockedTargetError`` still refuses to connect — an unresolvable
    name must never fall through to a request. It is separate so the failure can
    be *reported* as the DNS problem it is: a typo, a dead record, or a name
    that only resolves on a network we are not on. Reporting these as a
    policy block sends the operator hunting for an SSRF misconfiguration that
    does not exist, and makes a real block indistinguishable from a typo.
    """


@dataclass(frozen=True, slots=True)
class TargetAddress:
    """A resolved address that has already been approved."""

    host: str
    port: int
    family: int  # socket.AF_INET or socket.AF_INET6
    sockaddr: tuple


def _is_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """Return ``(blocked, reason)`` for a single resolved address."""
    if ip.is_loopback:
        return True, "loopback address"
    if ip.is_link_local:
        return True, "link-local address (including cloud metadata endpoints)"
    if ip.is_private:
        return True, "private network address (RFC1918)"
    if ip.is_multicast:
        return True, "multicast address"
    if ip.is_reserved:
        return True, "reserved address range"
    if ip.is_unspecified:
        return True, "unspecified address"
    # Carrier-grade NAT: 100.64.0.0/10. Not covered by is_private in some
    # Python versions, and a real routing path into an operator network.
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return True, "carrier-grade NAT range"
    return False, ""


def validate_url_static(url: str, *, allow_private_network: bool) -> None:
    """Validate the URL as typed, before any DNS lookup.

    Raises :class:`BlockedTargetError` with a message suitable for showing
    next to the form field.
    """
    url = (url or "").strip()
    if not url:
        raise BlockedTargetError("URL wajib diisi")

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise BlockedTargetError(f"URL tidak valid: {exc}") from exc

    if not parts.scheme:
        raise BlockedTargetError("URL harus memuat skema, contoh: https://example.com")

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedTargetError(
            f"Skema '{scheme}' tidak diizinkan. Gunakan http atau https"
        )

    try:
        host = parts.hostname
    except ValueError as exc:
        # urlsplit raises for malformed hosts like "http://[::1" or a port
        # that is not a number.
        raise BlockedTargetError(f"Host tidak valid: {exc}") from exc

    if not host:
        raise BlockedTargetError("URL harus memuat hostname")

    host = host.lower().strip(".")
    if host in _METADATA_HOSTS:
        raise BlockedTargetError(
            "Endpoint metadata cloud diblokir demi keamanan"
        )

    if host in _LOCAL_HOSTNAMES and not allow_private_network:
        raise BlockedTargetError(
            f"Host '{host}' menunjuk ke mesin ini sendiri (loopback address). "
            "Centang 'izinkan jaringan privat' jika memang ingin memantaunya."
        )

    if allow_private_network:
        return

    # A literal IP in the URL can be judged without a DNS lookup.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        return  # a hostname; re-checked after resolution
    blocked, reason = _is_forbidden(literal)
    if blocked:
        raise BlockedTargetError(
            f"Alamat {literal} diblokir ({reason}). "
            "Centang 'izinkan jaringan privat' jika memang ingin memantau alamat internal."
        )


def resolve_target(
    url: str,
    *,
    allow_private_network: bool,
    port: int | None = None,
) -> TargetAddress:
    """Resolve a hostname and pick an address that passes the SSRF guard.

    Returns the first acceptable address, so a dual-stack host with one
    routable and one internal address still works.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().strip(".")
    if not host:
        raise BlockedTargetError("URL tidak memuat hostname")

    resolved_port = port or (parts.port or (443 if parts.scheme == "https" else 80))

    # Literal address: no lookup needed.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if not allow_private_network:
            blocked, reason = _is_forbidden(literal)
            if blocked:
                raise BlockedTargetError(f"Alamat {literal} diblokir ({reason})")
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        sockaddr: tuple = (host, resolved_port, 0, 0) if family == socket.AF_INET6 else (host, resolved_port)
        return TargetAddress(host=host, port=resolved_port, family=family, sockaddr=sockaddr)

    try:
        infos = socket.getaddrinfo(host, resolved_port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ResolutionError(
            f"Host '{host}' tidak bisa di-resolve: {exc.strerror or exc}"
        ) from exc

    if not infos:
        raise ResolutionError(f"Host '{host}' tidak bisa di-resolve")

    candidates: list[tuple[int, tuple, ipaddress.IPv4Address | ipaddress.IPv6Address]] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        ip_text = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_text.split("%", 1)[0])
        except ValueError:
            continue
        candidates.append((family, sockaddr, ip))

    if allow_private_network:
        family, sockaddr, _ip = candidates[0]
        return TargetAddress(host=host, port=resolved_port, family=family, sockaddr=sockaddr)

    for family, sockaddr, ip in candidates:
        blocked, _reason = _is_forbidden(ip)
        if not blocked:
            return TargetAddress(host=host, port=resolved_port, family=family, sockaddr=sockaddr)

    _family, _sockaddr, ip = candidates[0]
    blocked, reason = _is_forbidden(ip)
    raise BlockedTargetError(
        f"Host '{host}' hanyaresolve ke alamat terlarang ({ip}: {reason})"
    )


def normalise_url(url: str) -> str:
    """Canonicalise a URL so the same service always looks the same.

    Lowercases the scheme and host, drops a default port, and removes the
    fragment. Dropping the default port matters because the monitor id is
    derived from the URL: without it, ``https://example.com`` and
    ``https://example.com:443`` would become two different monitors for one
    service.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is not None:
        default = {"http": 80, "https": 443}.get(scheme)
        if port == default:
            port = None
    netloc = host if not port else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


# ---------------------------------------------------------------------------
# Post-connection peer verification
# ---------------------------------------------------------------------------

def peer_address(response: object) -> tuple[str, int] | None:
    """The address the socket actually connected to, if the transport says.

    httpcore keeps the live stream on the response; ``server_addr`` is the
    remote end. Returns ``None`` when the transport does not expose it, which
    callers must treat as "unknown" rather than "allowed".
    """
    extensions = getattr(response, "extensions", None)
    if not isinstance(extensions, dict):
        return None
    stream = extensions.get("network_stream")
    if stream is None or not hasattr(stream, "get_extra_info"):
        return None
    for key in ("server_addr", "client_addr"):
        try:
            info = stream.get_extra_info(key)
        except Exception:  # noqa: BLE001 - transport internals vary
            continue
        if isinstance(info, tuple) and len(info) >= 2:
            try:
                return str(info[0]), int(info[1])
            except (TypeError, ValueError):
                continue
    return None


def verify_peer(response: object, *, allow_private_network: bool) -> str | None:
    """Return a failure message when the connected peer is not permitted.

    Called after the response headers arrive but before anything is read from
    the body, so a rebound connection is discarded rather than consumed.
    """
    if allow_private_network:
        return None
    peer = peer_address(response)
    if peer is None:
        return None
    try:
        ip = ipaddress.ip_address(peer[0].split("%", 1)[0])
    except ValueError:
        return None
    blocked, reason = _is_forbidden(ip)
    if blocked:
        return (
            f"Koneksi sampai ke alamat terlarang ({ip}: {reason}). "
            "Kemungkinan DNS target dialihkan setelah pemeriksaan awal."
        )
    return None
