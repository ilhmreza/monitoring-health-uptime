"""SSRF guard tests.

The web UI accepts a URL from an authenticated user and the server fetches it
from wherever it is deployed. These tests pin the cases that turn that into
access to the host's private network or the cloud metadata endpoint.
"""

from __future__ import annotations

import socket

import pytest

from uptimebot.monitor.ssrf import (
    BlockedTargetError,
    normalise_url,
    peer_address,
    resolve_target,
    validate_url_static,
    verify_peer,
)

PRIVATE = "https://10.0.0.5/health"
ALLOW = True
BLOCK = False


# ----- static validation ---------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/",
        "https://127.0.0.1:8443/admin",
        "http://localhost:8080/",
        "https://[::1]/",
        "https://10.1.2.3/",
        "https://192.168.1.1/",
        "https://172.16.9.9/",
        "https://169.254.169.254/latest/meta-data/",
        "https://100.100.100.200/",
        "https://0.0.0.0/",
        "https://224.0.0.1/",
        "https://100.64.1.1/",
    ],
)
def test_private_and_metadata_targets_are_refused(url):
    with pytest.raises(BlockedTargetError):
        validate_url_static(url, allow_private_network=BLOCK)


@pytest.mark.parametrize(
    "url",
    ["https://example.com/", "http://example.com:8080/x?y=1", "https://sub.example.co.id/"],
)
def test_public_urls_pass(url):
    validate_url_static(url, allow_private_network=BLOCK)


def test_the_same_private_url_passes_with_the_opt_in():
    validate_url_static(PRIVATE, allow_private_network=ALLOW)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/",
        "dict://example.com:11211/",
        "javascript:alert(1)",
    ],
)
def test_non_http_schemes_are_refused(url):
    with pytest.raises(BlockedTargetError):
        validate_url_static(url, allow_private_network=ALLOW)


@pytest.mark.parametrize("url", ["", "   ", "example.com", "https://"])
def test_malformed_urls_are_refused_with_a_readable_error(url):
    with pytest.raises(BlockedTargetError) as excinfo:
        validate_url_static(url, allow_private_network=ALLOW)
    # The message is shown next to the form field, so it must not be empty.
    assert str(excinfo.value)


def test_a_hostname_that_is_only_later_private_passes_the_static_check():
    """The static pass cannot know, so the resolution pass has to catch it."""
    validate_url_static("https://internal.example.com/", allow_private_network=BLOCK)


def test_the_block_message_suggests_the_opt_in():
    with pytest.raises(BlockedTargetError) as excinfo:
        validate_url_static("https://10.0.0.5/", allow_private_network=BLOCK)
    assert "private" in str(excinfo.value).lower()


# ----- resolution ----------------------------------------------------------


def test_a_literal_private_address_is_refused_at_resolution():
    with pytest.raises(BlockedTargetError):
        resolve_target(PRIVATE, allow_private_network=BLOCK)


def test_a_literal_private_address_resolves_with_the_opt_in():
    target = resolve_target("https://10.0.0.5:8443/x", allow_private_network=ALLOW)

    assert target.host == "10.0.0.5"
    assert target.port == 8443
    assert target.family == socket.AF_INET


def test_a_hostname_resolving_only_to_private_space_is_refused(monkeypatch):
    fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.1.1", 443))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: fake)

    with pytest.raises(BlockedTargetError):
        resolve_target("https://rebind.example.com/", allow_private_network=BLOCK)


def test_a_dual_stack_host_uses_the_routable_address(monkeypatch):
    """A public host with one stray AAAA must still be monitorable."""
    fake = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::1", 443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: fake)

    target = resolve_target("https://dual.example.com/", allow_private_network=BLOCK)

    assert target.sockaddr[0] == "93.184.216.34"


def test_an_unresolvable_host_is_reported_not_crashed(monkeypatch):
    def boom(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", boom)

    with pytest.raises(BlockedTargetError):
        resolve_target("https://nope.invalid/", allow_private_network=BLOCK)


def test_resolution_picks_the_default_port_for_the_scheme():
    # A literal address keeps this test off the network.
    assert resolve_target("https://93.184.216.34/", allow_private_network=ALLOW).port == 443
    assert resolve_target("http://93.184.216.34/", allow_private_network=ALLOW).port == 80
    assert resolve_target("https://93.184.216.34:8443/", allow_private_network=ALLOW).port == 8443


# ----- post-connection peer check -----------------------------------------


class FakeStream:
    def __init__(self, **info):
        self._info = info

    def get_extra_info(self, key):
        return self._info.get(key)


class FakeResponse:
    def __init__(self, stream=None):
        self.extensions = {} if stream is None else {"network_stream": stream}


def test_a_rebound_connection_to_loopback_is_caught():
    response = FakeResponse(FakeStream(server_addr=("127.0.0.1", 443)))

    message = verify_peer(response, allow_private_network=BLOCK)

    assert message is not None
    assert "terlarang" in message


def test_a_rebound_connection_to_the_metadata_endpoint_is_caught():
    response = FakeResponse(FakeStream(server_addr=("169.254.169.254", 80)))

    assert verify_peer(response, allow_private_network=BLOCK) is not None


def test_a_genuinely_public_peer_passes():
    response = FakeResponse(FakeStream(server_addr=("93.184.216.34", 443)))

    assert verify_peer(response, allow_private_network=BLOCK) is None


def test_a_private_peer_is_allowed_when_the_monitor_opts_in():
    response = FakeResponse(FakeStream(server_addr=("10.0.0.5", 443)))

    assert verify_peer(response, allow_private_network=ALLOW) is None


def test_an_ipv6_peer_with_a_zone_id_is_still_parsed():
    response = FakeResponse(FakeStream(server_addr=("fe80::1%eth0", 443)))

    assert verify_peer(response, allow_private_network=BLOCK) is not None


def test_a_transport_that_exposes_nothing_is_not_a_failure():
    """httpx is allowed to hide the socket; the probe must still work."""
    assert peer_address(FakeResponse()) is None
    assert verify_peer(FakeResponse(), allow_private_network=BLOCK) is None


def test_a_transport_that_raises_is_not_a_crash():
    class Hostile:
        def get_extra_info(self, key):
            raise RuntimeError("transport internals changed")

    assert peer_address(FakeResponse(Hostile())) is None


# ----- normalisation -------------------------------------------------------


def test_normalise_lowercases_the_host_and_drops_a_default_port():
    assert normalise_url("HTTPS://Example.COM:443/path") == "https://example.com/path"
    assert normalise_url("http://example.com:8080/x") == "http://example.com:8080/x"


def test_normalise_keeps_the_query_but_drops_the_fragment():
    assert normalise_url("https://example.com/a?b=1#frag") == "https://example.com/a?b=1"
