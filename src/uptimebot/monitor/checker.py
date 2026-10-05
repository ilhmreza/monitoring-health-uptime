"""HTTP availability probe.

A probe answers one question: is this service usable by a real client right
now? That means status code, a bounded response time, and optionally a
keyword the body must contain (a service returning a 200 error page is not
up). Every distinct failure is classified so the Discord report tells the PIC
where to start looking.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

import httpx

from ..models import CheckResult, FailureKind, Monitor
from .ssrf import (
    BlockedTargetError,
    ResolutionError,
    resolve_target,
    verify_peer,
)

log = logging.getLogger(__name__)

UTC = timezone.utc

# A probe should measure user-perceived latency, not download speed. Reading
# a small prefix of the body is enough to find a keyword and to avoid pulling
# a multi-megabyte page every 30 seconds.
MAX_BODY_BYTES = 64 * 1024
FOLLOW_REDIRECTS = 3

# Status codes that mean "the service is answering" even if a health endpoint
# redirects. Anything in 2xx/3xx counts as reachable; a 4xx/5xx does not.
DEFAULT_EXPECT_STATUS: tuple[int, ...] = (200,)


class Checker:
    """Runs probes for monitors against a shared connection pool."""

    def __init__(self, *, allow_private_network: bool = False) -> None:
        self._allow_private_network = allow_private_network
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        if self._client is not None:
            return
        limits = httpx.Limits(max_connections=64, max_keepalive_connections=16)
        self._client = httpx.AsyncClient(
            limits=limits,
            follow_redirects=False,
            timeout=httpx.Timeout(15.0),
            trust_env=False,  # never honour HTTP_PROXY from the host environment
        )
        log.info("probe client started")

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            log.info("probe client closed")

    async def check(self, monitor: Monitor) -> CheckResult:
        """Probe one monitor and classify the outcome.

        Never raises: an unexpected exception is reported as a failed check so
        one bad monitor cannot take down the scheduler.
        """
        started = time.perf_counter()
        checked_at = datetime.now(UTC)
        allow_private = monitor.allow_private_network or self._allow_private_network

        try:
            # Resolve and vet the target before any bytes leave the host.
            target = resolve_target(monitor.url, allow_private_network=allow_private)
        except ResolutionError as exc:
            # A name that does not resolve is a DNS problem, not a policy
            # decision, and the two need different fixes from whoever is on
            # call. Ordered before BlockedTargetError because it subclasses it.
            return self._fail(checked_at, started, FailureKind.DNS, str(exc))
        except BlockedTargetError as exc:
            return self._fail(checked_at, started, FailureKind.BLOCKED_NETWORK, str(exc))

        if self._client is None:
            await self.start()
        assert self._client is not None

        try:
            return await self._probe(monitor, checked_at, started)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a probe must never crash the loop
            elapsed = (time.perf_counter() - started) * 1000
            log.exception("unexpected probe error for %s", monitor.id)
            return CheckResult(
                ok=False,
                checked_at=checked_at,
                latency_ms=elapsed,
                failure_kind=FailureKind.UNEXPECTED,
                error=f"{type(exc).__name__}: {exc}"[:400],
            )

    async def _probe(
        self, monitor: Monitor, checked_at: datetime, started: float
    ) -> CheckResult:
        assert self._client is not None
        timeout = httpx.Timeout(
            monitor.timeout_seconds, connect=min(10.0, monitor.timeout_seconds)
        )
        expect = set(monitor.expect_status or DEFAULT_EXPECT_STATUS)
        follow = FOLLOW_REDIRECTS > 0
        current_url = monitor.url
        allow_private = monitor.allow_private_network or self._allow_private_network

        for _hop in range(FOLLOW_REDIRECTS + 1):
            try:
                response = await self._client.request(
                    monitor.method,
                    current_url,
                    headers=monitor.resolved_headers(),
                    timeout=timeout,
                    follow_redirects=False,
                )
            except httpx.ConnectTimeout as exc:
                return self._fail(checked_at, started, FailureKind.TIMEOUT, f"Connect timeout: {exc}")
            except httpx.ReadTimeout as exc:
                return self._fail(checked_at, started, FailureKind.TIMEOUT, f"Read timeout: {exc}")
            except httpx.ConnectError as exc:
                kind = _classify_connect_error(exc)
                return self._fail(checked_at, started, kind, _short(exc))
            except httpx.ProxyError as exc:
                return self._fail(checked_at, started, FailureKind.UNEXPECTED, f"Proxy error: {_short(exc)}")
            except httpx.TooManyRedirects as exc:
                return self._fail(checked_at, started, FailureKind.TOO_MANY_REDIRECTS, _short(exc))
            except httpx.InvalidURL as exc:
                return self._fail(checked_at, started, FailureKind.UNEXPECTED, f"URL tidak valid: {_short(exc)}")
            except httpx.TransportError as exc:
                return self._fail(checked_at, started, FailureKind.TIMEOUT, _short(exc))
            except httpx.HTTPError as exc:
                return self._fail(checked_at, started, FailureKind.UNEXPECTED, _short(exc))

            # The pre-flight DNS check can be raced by a rebind, so confirm the
            # peer we actually reached before reading a single body byte.
            peer_problem = verify_peer(response, allow_private_network=allow_private)
            if peer_problem is not None:
                await response.aclose()
                return self._fail(
                    checked_at, started, FailureKind.BLOCKED_NETWORK, peer_problem
                )

            status = response.status_code

            if follow and status in (301, 302, 303, 307, 308) and "location" in response.headers:
                location = response.headers["location"]
                next_url = str(httpx.URL(current_url).join(location))
                # Revalidate the redirect target: a public host that 302s to
                # 169.254.169.254 is the classic SSRF bypass.
                try:
                    resolve_target(next_url, allow_private_network=allow_private)
                except ResolutionError as exc:
                    return self._fail(checked_at, started, FailureKind.DNS, str(exc))
                except BlockedTargetError as exc:
                    return self._fail(checked_at, started, FailureKind.BLOCKED_NETWORK, str(exc))
                current_url = next_url
                continue

            body_snippet = await _read_prefix(response)

            if status not in expect:
                return self._fail(
                    checked_at,
                    started,
                    FailureKind.STATUS_UNEXPECTED,
                    f"HTTP {status} (diharapkan: {_fmt_expect(expect)})",
                    status_code=status,
                )

            if monitor.keyword and monitor.keyword.lower() not in body_snippet.lower():
                return self._fail(
                    checked_at,
                    started,
                    FailureKind.KEYWORD_MISSING,
                    f"Keyword '{monitor.keyword}' tidak ditemukan di body",
                    status_code=status,
                )

            elapsed = (time.perf_counter() - started) * 1000
            return CheckResult(
                ok=True,
                checked_at=checked_at,
                latency_ms=elapsed,
                status_code=status,
                failure_kind=FailureKind.NONE,
            )

        return self._fail(
            checked_at,
            started,
            FailureKind.TOO_MANY_REDIRECTS,
            f"Lebih dari {FOLLOW_REDIRECTS} redirect",
        )

    @staticmethod
    def _fail(
        checked_at: datetime,
        started: float,
        kind: FailureKind,
        error: str,
        *,
        status_code: int | None = None,
    ) -> CheckResult:
        return CheckResult(
            ok=False,
            checked_at=checked_at,
            latency_ms=(time.perf_counter() - started) * 1000,
            status_code=status_code,
            failure_kind=kind,
            error=error,
        )


async def _read_prefix(response: httpx.Response) -> str:
    """Read at most ``MAX_BODY_BYTES`` of the body, ignoring decode errors."""
    try:
        return response.text[:MAX_BODY_BYTES]
    except (httpx.ResponseNotRead, UnicodeDecodeError, ValueError):
        return ""


def _classify_connect_error(exc: httpx.ConnectError) -> FailureKind:
    """Tell a refused connection apart from DNS, TLS and unroutable failures.

    All of these surface as ``ConnectError``. "Connection refused" means
    something is listening and said no, NXDOMAIN means the hostname is wrong,
    and a certificate problem means the service is up but misconfigured — three
    very different things for whoever is on call.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    causes: list[str] = []
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        causes.append(f"{type(current).__name__}: {current}")
        current = current.__cause__ or current.__context__
    blob = " | ".join(causes).lower()

    if any(marker in blob for marker in _DNS_MARKERS):
        return FailureKind.DNS

    if any(marker in blob for marker in _TLS_MARKERS):
        return FailureKind.TLS

    if any(marker in blob for marker in _REFUSED_MARKERS):
        return FailureKind.CONNECTION_REFUSED

    if any(marker in blob for marker in _UNREACHABLE_MARKERS):
        return FailureKind.TIMEOUT

    # Nothing recognisable: report it as an unexpected error rather than
    # claiming a refused connection that never happened.
    return FailureKind.UNEXPECTED


_DNS_MARKERS = (
    "name or service not known",
    "nodename nor servname",
    "temporary failure in name resolution",
    "no address associated with hostname",
    "getaddrinfo failed",
    "name resolution",
    "could not resolve",
)

_TLS_MARKERS = (
    "certificate verify failed",
    "certificate has expired",
    "certificate not yet valid",
    "ssl: wrong version number",
    "tlsv1",
    "sslv3",
    "handshake",
    "hostname mismatch",
    "unable to get local issuer",
    "self signed certificate",
    "sslerror",
)

_REFUSED_MARKERS = (
    "connection refused",
    "econnrefused",
    "actively refused",
)

_UNREACHABLE_MARKERS = (
    "no route to host",
    "ehostunreach",
    "enetunreach",
    "network is unreachable",
    "connection reset",
    "econnreset",
    "broken pipe",
)


def _short(exc: BaseException, limit: int = 300) -> str:
    text = str(exc).strip() or type(exc).__name__
    return text[:limit]


def _fmt_expect(expect: set[int]) -> str:
    return ", ".join(str(code) for code in sorted(expect))
