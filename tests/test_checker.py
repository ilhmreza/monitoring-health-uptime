"""Probe classification.

The checker is the part of this project that decides whether a service is up
and, when it is not, *why* — that reason is what the Discord report shows the
person on call. Every distinct failure therefore needs its own test: lumping a
DNS mistake in with a refused connection or a blocked address costs whoever is
on call an hour of looking in the wrong place.

These tests drive a fake httpx client, so nothing here touches the network. The
SSRF guard itself is exercised for real in ``test_ssrf.py``; here it is kept in
the loop on purpose, driven by literal addresses, so the checker's mapping of
guard outcomes onto failure kinds is what is under test.
"""

from __future__ import annotations

import socket

import httpx
import pytest

from uptimebot.models import FailureKind, Monitor
from uptimebot.monitor.checker import FOLLOW_REDIRECTS, Checker

# A public address, so the SSRF guard passes it and the probe proceeds.
PUBLIC_URL = "https://93.184.216.34/health"


# ----- fake transport -------------------------------------------------------


class FakeResponse:
    """The slice of ``httpx.Response`` that the checker actually touches."""

    def __init__(
        self,
        status_code: int = 200,
        *,
        text: str = "",
        headers: dict[str, str] | None = None,
        server_addr: tuple[str, int] | None = None,
        probe: "Recorder | None" = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._text = text
        self.probe = probe
        self.closed = False
        self.extensions: dict[str, object] = {}
        if server_addr is not None:
            self.extensions["network_stream"] = FakeStream(server_addr)

    @property
    def text(self) -> str:
        # A real body read is what a rebind must prevent, so the tests assert
        # on this being untouched.
        if self.probe is not None:
            self.probe.body_reads += 1
        return self._text

    async def aclose(self) -> None:
        self.closed = True


class FakeStream:
    def __init__(self, server_addr: tuple[str, int]) -> None:
        self._server_addr = server_addr

    def get_extra_info(self, key: str):
        if key == "server_addr":
            return self._server_addr
        if key == "client_addr":
            return ("93.184.216.34", 40000)
        return None


class Recorder:
    """A stand-in for ``httpx.AsyncClient`` that replays scripted outcomes."""

    def __init__(self, *outcomes) -> None:
        self._outcomes = list(outcomes)
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.body_reads = 0

    async def request(self, method, url, *, headers=None, timeout=None, follow_redirects=False):
        self.requests.append((method, url, dict(headers or {})))
        if not self._outcomes:
            raise AssertionError(f"unexpected extra request to {url}")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, FakeResponse):
            outcome.probe = self
            return outcome
        return FakeResponse(outcome, probe=self)

    async def aclose(self) -> None:
        return None


def checker_for(recorder: Recorder, *, allow_private_network: bool = False) -> Checker:
    checker = Checker(allow_private_network=allow_private_network)
    checker._client = recorder  # the real client is never started
    return checker


@pytest.fixture
def make_monitor():
    def build(**overrides) -> Monitor:
        base = {"id": "uji", "name": "Uji", "url": PUBLIC_URL, "method": "GET"}
        base.update(overrides)
        return Monitor(**base)  # type: ignore[arg-type]

    return build


# ----- the happy path -------------------------------------------------------


async def test_a_service_answering_the_expected_status_is_up(make_monitor):
    recorder = Recorder(200)

    result = await checker_for(recorder).check(make_monitor())

    assert result.ok is True
    assert result.failure_kind is FailureKind.NONE
    assert result.status_code == 200
    assert result.latency_ms is not None


async def test_a_204_health_endpoint_counts_as_up_when_expected(make_monitor):
    recorder = Recorder(204)

    result = await checker_for(recorder).check(make_monitor(expect_status=[200, 204]))

    assert result.ok is True


async def test_a_keyword_on_a_bodyless_endpoint_is_reported_not_silently_passed(make_monitor):
    """A misconfiguration that would otherwise sit there for months.

    A 204 has no body by definition, so requiring a keyword in it can never
    succeed. The probe must say so rather than reporting the service as up,
    because otherwise the monitor is simply dead and nobody notices.
    """
    recorder = Recorder(204)

    result = await checker_for(recorder).check(
        make_monitor(expect_status=[200, 204], keyword="ok")
    )

    assert result.failure_kind is FailureKind.KEYWORD_MISSING
    assert result.status_code == 204


async def test_a_keyword_is_matched_case_insensitively(make_monitor):
    recorder = Recorder(FakeResponse(200, text="<h1>Service OK</h1>"))

    result = await checker_for(recorder).check(make_monitor(keyword="ok"))

    assert result.ok is True


# ----- status and body ------------------------------------------------------


async def test_an_unexpected_status_is_reported_with_the_code_it_saw(make_monitor):
    recorder = Recorder(503)

    result = await checker_for(recorder).check(make_monitor(expect_status=[200]))

    assert result.ok is False
    assert result.failure_kind is FailureKind.STATUS_UNEXPECTED
    assert result.status_code == 503
    assert "503" in result.error


async def test_a_200_error_page_still_counts_as_down(make_monitor):
    """A service that answers 200 with a failure page is not usable.

    This is the case plain status monitoring misses entirely.
    """
    recorder = Recorder(FakeResponse(200, text="<html>gateway error</html>"))

    result = await checker_for(recorder).check(make_monitor(keyword="healthy"))

    assert result.failure_kind is FailureKind.KEYWORD_MISSING
    assert result.status_code == 200


async def test_a_failed_probe_still_measures_a_latency(make_monitor):
    """Regression guard: the value must never be None.

    ``CheckRepo.record`` rounds this to store it, and a failure path that
    produced ``None`` there would have crashed on the first failed probe.
    """
    recorder = Recorder(500)

    result = await checker_for(recorder).check(make_monitor(expect_status=[200]))

    assert result.latency_ms is not None
    assert result.latency_ms >= 0


# ----- the SSRF guard, and telling its outcomes apart ------------------------


async def test_a_private_address_is_refused_before_any_bytes_leave_the_host(make_monitor):
    recorder = Recorder(200)

    result = await checker_for(recorder).check(make_monitor(url="http://127.0.0.1/"))

    assert result.failure_kind is FailureKind.BLOCKED_NETWORK
    assert recorder.requests == [], "a blocked target must never be requested"


async def test_the_metadata_endpoint_is_refused(make_monitor):
    recorder = Recorder(200)

    result = await checker_for(recorder).check(
        make_monitor(url="http://169.254.169.254/latest/meta-data/")
    )

    assert result.failure_kind is FailureKind.BLOCKED_NETWORK
    assert recorder.requests == []


async def test_a_monitor_can_opt_into_a_private_address(make_monitor):
    """Per-monitor opt-in is the only way to watch something on your own LAN."""
    recorder = Recorder(200)

    result = await checker_for(recorder).check(
        make_monitor(url="http://10.0.0.5/health", allow_private_network=True)
    )

    assert result.ok is True
    assert len(recorder.requests) == 1


async def test_the_global_switch_also_allows_private_addresses(make_monitor):
    recorder = Recorder(200)

    result = await checker_for(recorder, allow_private_network=True).check(
        make_monitor(url="http://10.0.0.5/health")
    )

    assert result.ok is True


async def test_an_unresolvable_host_is_a_dns_failure_not_a_policy_block(make_monitor, monkeypatch):
    """A typo and a refused address are both "down", but not the same problem.

    Reporting NXDOMAIN as a block sends the operator looking for an SSRF
    misconfiguration that does not exist, and hides the actual cause in a field
    that reads like a security event.
    """

    def boom(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    recorder = Recorder(200)

    result = await checker_for(recorder).check(
        make_monitor(url="https://tpyo.example.com/health")
    )

    assert result.failure_kind is FailureKind.DNS
    assert result.failure_kind is not FailureKind.BLOCKED_NETWORK
    assert recorder.requests == []


async def test_a_rebound_connection_is_discarded_without_reading_the_body(make_monitor):
    """The classic DNS rebind: vetted as public, then answered privately.

    The response must be dropped on the headers alone. Reading the body first
    would already have delivered whatever the internal service returned.
    """
    recorder = Recorder(FakeResponse(200, text="internal secret", server_addr=("127.0.0.1", 8000)))

    result = await checker_for(recorder).check(make_monitor())

    assert result.failure_kind is FailureKind.BLOCKED_NETWORK
    assert recorder.body_reads == 0, "the body of a rebound response was read"


async def test_a_rebound_connection_is_allowed_when_the_monitor_opts_in(make_monitor):
    recorder = Recorder(FakeResponse(200, text="ok", server_addr=("10.0.0.5", 8000)))

    result = await checker_for(recorder).check(make_monitor(allow_private_network=True))

    assert result.ok is True


async def test_a_transport_without_peer_information_is_not_treated_as_a_failure(
    make_monitor,
):
    """httpx may not expose the socket; that must not invent an outage."""
    recorder = Recorder(FakeResponse(200, text="ok"))

    result = await checker_for(recorder).check(make_monitor())

    assert result.ok is True


# ----- redirects ------------------------------------------------------------


async def test_a_redirect_to_a_private_address_is_refused(make_monitor):
    """A public host that 302s to the metadata endpoint is the known bypass."""
    recorder = Recorder(FakeResponse(302, headers={"location": "http://169.254.169.254/latest/"}))

    result = await checker_for(recorder).check(make_monitor())

    assert result.failure_kind is FailureKind.BLOCKED_NETWORK
    assert len(recorder.requests) == 1, "the redirect target must not be requested"


async def test_a_redirect_to_an_unresolvable_host_is_a_dns_failure(make_monitor, monkeypatch):
    recorder = Recorder(
        FakeResponse(302, headers={"location": "https://gone.example.com/health"})
    )

    def boom(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", boom)

    result = await checker_for(recorder).check(make_monitor())

    assert result.failure_kind is FailureKind.DNS


async def test_a_redirect_chain_is_followed_and_can_succeed(make_monitor):
    recorder = Recorder(
        FakeResponse(301, headers={"location": "/v2/health"}),
        FakeResponse(200, text="ok"),
    )

    result = await checker_for(recorder).check(make_monitor())

    assert result.ok is True
    assert [url for _method, url, _headers in recorder.requests] == [
        PUBLIC_URL,
        "https://93.184.216.34/v2/health",
    ]


async def test_a_redirect_loop_is_bounded(make_monitor):
    """An endless redirect must stop rather than hammer the target."""
    recorder = Recorder(
        *[FakeResponse(302, headers={"location": "/next"}) for _ in range(10)]
    )

    result = await checker_for(recorder).check(make_monitor())

    assert result.failure_kind is FailureKind.TOO_MANY_REDIRECTS
    assert len(recorder.requests) == FOLLOW_REDIRECTS + 1


# ----- transport-level failures ---------------------------------------------


def connect_error(message: str) -> httpx.ConnectError:
    return httpx.ConnectError(message)


async def test_a_refused_connection_is_reported_as_refused(make_monitor):
    recorder = Recorder(connect_error("[Errno 111] Connection refused"))

    result = await checker_for(recorder).check(make_monitor())

    assert result.failure_kind is FailureKind.CONNECTION_REFUSED


async def test_a_connect_timeout_is_reported_as_a_timeout(make_monitor):
    recorder = Recorder(httpx.ConnectTimeout("timed out"))

    result = await checker_for(recorder).check(make_monitor())

    assert result.failure_kind is FailureKind.TIMEOUT


async def test_a_certificate_problem_is_its_own_failure_kind(make_monitor):
    """TLS says the service is up but misconfigured, which is a different call."""
    recorder = Recorder(
        connect_error("certificate verify failed: self signed certificate")
    )

    result = await checker_for(recorder).check(make_monitor())

    assert result.failure_kind is FailureKind.TLS


async def test_a_dns_failure_at_connect_time_is_still_a_dns_failure(make_monitor):
    recorder = Recorder(connect_error("[Errno -2] Name or service not known"))

    result = await checker_for(recorder).check(make_monitor())

    assert result.failure_kind is FailureKind.DNS


async def test_an_unexpected_error_fails_the_probe_instead_of_the_scheduler(make_monitor):
    """One broken monitor must not be able to stop the probe loop."""
    recorder = Recorder(RuntimeError("kaboom"))

    result = await checker_for(recorder).check(make_monitor())

    assert result.ok is False
    assert result.failure_kind is FailureKind.UNEXPECTED
    assert "kaboom" in result.error


# ----- request shape --------------------------------------------------------


async def test_the_configured_method_is_used(make_monitor):
    recorder = Recorder(200)

    await checker_for(recorder).check(make_monitor(method="HEAD"))

    assert [method for method, _url, _headers in recorder.requests] == ["HEAD"]


async def test_secrets_are_read_from_the_environment_not_the_database(make_monitor, monkeypatch):
    """``headers_env`` stores variable names only, so a token is never persisted."""
    monkeypatch.setenv("API_TOKEN_PROD", "rahasia-token")
    recorder = Recorder(200)

    await checker_for(recorder).check(
        make_monitor(headers_env={"Authorization": "API_TOKEN_PROD"})
    )

    _method, _url, headers = recorder.requests[0]
    assert headers["Authorization"] == "rahasia-token"


async def test_a_header_whose_variable_is_unset_is_omitted(make_monitor, monkeypatch):
    """An unset variable must be dropped, never sent as a literal placeholder."""
    monkeypatch.delenv("API_TOKEN_PROD", raising=False)
    recorder = Recorder(200)

    await checker_for(recorder).check(
        make_monitor(headers_env={"Authorization": "API_TOKEN_PROD"})
    )

    _method, _url, headers = recorder.requests[0]
    assert "Authorization" not in headers
