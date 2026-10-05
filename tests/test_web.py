"""Web layer tests.

Runs a real app against a temporary database over the ASGI test client, so the
auth gate, the CSRF rule and the templates are all exercised together rather
than mocked apart.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from uptimebot.db import Database, StateRepo
from uptimebot.models import MonitorState
from uptimebot.web.app import create_app

UTC = timezone.utc
NOW = datetime.now(UTC)
PASSWORD = "rahasia-uji-12345"


def csrf_of(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "no CSRF token in the rendered form"
    return match.group(1)


def monitor_payload(name: str, url: str, csrf: str, **overrides) -> dict[str, str]:
    """A complete, valid monitor form submission.

    The form posts every field, so tests send every field too — otherwise a
    test that means to check persistence ends up checking form validation.
    """
    payload = {
        "csrf_token": csrf,
        "name": name,
        "url": url,
        "method": "GET",
        "expect_status": "200, 204",
        "interval_seconds": "30",
        "timeout_seconds": "10",
        "failure_threshold": "3",
        "notify_user_ids": "",
        "notify_on": ["down", "recovery", "ssl"],
        "ssl_check": "on",
        "ssl_warn_days": "30,14,7,1",
        "enabled": "on",
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def client(settings_factory, password_hash):
    """An unauthenticated client against a throwaway database."""
    settings = settings_factory(
        ui_username="admin",
        ui_password_hash=password_hash,
        secret_key="pytest-secret-key",
        cookie_secure=False,
    )
    with TestClient(create_app(settings, start_scheduler=False)) as test_client:
        yield test_client


@pytest.fixture
def authed(client):
    """The same client, logged in, with its CSRF token ready to use."""
    response = client.post(
        "/login", data={"username": "admin", "password": PASSWORD}, follow_redirects=False
    )
    assert response.status_code == 303
    return client


@pytest.fixture
def csrf(authed):
    return csrf_of(authed.get("/monitors/new").text)


# ----- auth gate -----------------------------------------------------------


def test_anonymous_visitor_is_redirected_to_the_login_page(client):
    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert "/login" in response.headers["location"]


def test_the_login_page_does_not_leak_whether_a_password_is_configured(client):
    assert client.get("/login").status_code == 200


def test_a_wrong_password_does_not_open_a_session(client):
    response = client.post(
        "/login",
        data={"username": "admin", "password": "salah-sekali"},
        follow_redirects=False,
    )

    assert response.status_code == 401
    assert "session" not in response.cookies


def test_repeated_wrong_passwords_are_throttled(client, password_hash):
    """Brute force has to be slow, not merely discouraged."""
    statuses = [
        client.post(
            "/login",
            data={"username": "admin", "password": f"salah-{i}"},
            follow_redirects=False,
        ).status_code
        for i in range(8)
    ]

    assert statuses[-1] == 429


def test_a_lockout_cannot_be_delivered_by_someone_elses_address(settings_factory, password_hash):
    """One attacker must not be able to lock the admin out for good.

    Behind Caddy the app's immediate peer is the proxy, so keying the throttle
    on the peer alone would put every visitor in one bucket. An attacker could
    then spend the attempt budget on purpose and keep the single admin locked
    out indefinitely. With ``TRUST_PROXY`` on, the bucket is per real client, so
    a lockout only ever inconveniences the address that caused it.
    """
    app_settings = settings_factory(
        ui_username="admin",
        ui_password_hash=password_hash,
        secret_key="pytest-secret-key",
        cookie_secure=False,
        trust_proxy=True,
    )
    with TestClient(create_app(app_settings, start_scheduler=False)) as attacker:
        for _ in range(8):
            attacker.post(
                "/login",
                data={"username": "admin", "password": "salah"},
                headers={"X-Forwarded-For": "198.51.100.7"},
                follow_redirects=False,
            )
        blocked = attacker.post(
            "/login",
            data={"username": "admin", "password": "salah"},
            headers={"X-Forwarded-For": "198.51.100.7"},
            follow_redirects=False,
        )
        assert blocked.status_code == 429, "the attacker's own address is locked out"

        admin = TestClient(attacker.app)
        admin.headers.update({"X-Forwarded-For": "203.0.113.9"})
        allowed = admin.post(
            "/login",
            data={"username": "admin", "password": PASSWORD},
            follow_redirects=False,
        )

    assert allowed.status_code == 303, "a different client must not inherit the lockout"


def test_a_forged_forwarded_header_cannot_buy_a_fresh_throttle_budget(
    settings_factory, password_hash
):
    """The header is only trusted when the proxy is known to replace it.

    If a client could pick its own key, the throttle would reset on every
    request and stop being a throttle at all. A garbage header must therefore
    fall back to the peer rather than minting a new bucket.
    """
    app_settings = settings_factory(
        ui_username="admin",
        ui_password_hash=password_hash,
        secret_key="pytest-secret-key",
        cookie_secure=False,
        trust_proxy=True,
    )
    with TestClient(create_app(app_settings, start_scheduler=False)) as forged:
        statuses = [
            forged.post(
                "/login",
                data={"username": "admin", "password": "salah"},
                headers={"X-Forwarded-For": f"not-an-ip-{i}"},
                follow_redirects=False,
            ).status_code
            for i in range(8)
        ]

    assert statuses[-1] == 429, "a spoofable header must not reset the counter"


def test_logging_out_ends_the_session(authed):
    assert authed.get("/").status_code == 200
    authed.post("/logout", follow_redirects=False)

    assert authed.get("/", follow_redirects=False).status_code == 303


# ----- CSRF ----------------------------------------------------------------


def test_a_post_without_a_csrf_token_is_refused(client):
    client.post(
        "/login", data={"username": "admin", "password": PASSWORD}, follow_redirects=False
    )

    response = client.post(
        "/monitors",
        data={"name": "Tanpa CSRF", "url": "https://example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 403


def test_a_forged_csrf_token_is_refused(authed):
    response = authed.post(
        "/monitors",
        data={"name": "Palsu", "url": "https://example.com", "csrf_token": "not-a-real-token"},
        follow_redirects=False,
    )

    assert response.status_code == 403


# ----- monitor CRUD --------------------------------------------------------


def test_creating_a_monitor_persists_it(authed, csrf):
    response = authed.post(
        "/monitors",
        data=monitor_payload("Layanan A", "https://a.example.com", csrf),
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "Layanan A" in authed.get("/").text


def test_an_invalid_url_is_rejected_with_a_readable_message(authed, csrf):
    response = authed.post(
        "/monitors",
        data=monitor_payload("Buruk", "bukan-url", csrf),
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "URL" in response.text


def test_a_private_address_is_refused_by_the_form(authed, csrf):
    """The SSRF guard has to fire in the browser, not only at probe time."""
    response = authed.post(
        "/monitors",
        data=monitor_payload("Internal", "http://169.254.169.254/latest/meta-data/", csrf),
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "metadata" in response.text.lower() or "diblokir" in response.text.lower()


def test_a_failed_edit_keeps_what_the_user_typed(authed, csrf):
    created = authed.post(
        "/monitors",
        data=monitor_payload("Asli", "https://a.example.com", csrf),
        follow_redirects=False,
    )
    monitor_id = created.headers["location"].rsplit("/", 1)[-1].split("?")[0]

    response = authed.post(
        f"/monitors/{monitor_id}",
        data=monitor_payload("Diubah", "", csrf),
        follow_redirects=False,
    )

    assert response.status_code == 400
    # The name the user typed must survive a rejected submit.
    assert "Diubah" in response.text


def test_pausing_a_monitor_removes_it_from_the_scheduler(authed, csrf):
    created = authed.post(
        "/monitors",
        data=monitor_payload("Jeda", "https://a.example.com", csrf),
        follow_redirects=False,
    )
    monitor_id = created.headers["location"].rsplit("/", 1)[-1].split("?")[0]

    response = authed.post(
        f"/monitors/{monitor_id}/toggle", data={"csrf_token": csrf}, follow_redirects=False
    )

    assert response.status_code == 303
    assert "DIJEDA" in authed.get("/").text


def test_deleting_a_monitor_removes_it(authed, csrf):
    created = authed.post(
        "/monitors",
        data=monitor_payload("Hapus", "https://a.example.com", csrf),
        follow_redirects=False,
    )
    monitor_id = created.headers["location"].rsplit("/", 1)[-1].split("?")[0]

    response = authed.post(
        f"/monitors/{monitor_id}/delete", data={"csrf_token": csrf}, follow_redirects=False
    )

    assert response.status_code == 303
    assert "Hapus" not in authed.get("/").text


def test_an_unknown_monitor_is_a_404_not_a_500(authed):
    assert authed.get("/monitors/tidak-ada").status_code == 404


# ----- the live table ------------------------------------------------------


def test_a_down_monitor_shows_its_outage_and_no_healthy_run(authed, csrf, settings_factory):
    """Regression: a stale ``up_since`` used to survive into a DOWN row.

    The dashboard showed "up for 2 days" beside a service that had been down
    for an hour, because the clearing write was coalesced away. The state is
    seeded through a second connection to the same WAL file, which the running
    app then reads.
    """
    created = authed.post(
        "/monitors",
        data=monitor_payload("Flapping", "https://a.example.com", csrf),
        follow_redirects=False,
    )
    monitor_id = created.headers["location"].rsplit("/", 1)[-1].split("?")[0]

    db = Database(settings_factory().database_path)
    # Two days healthy, then an outage an hour long.
    asyncio.run(_seed_state(db, monitor_id, down=True))

    row = _row_for(authed.get("/").text, "Flapping")

    assert row is not None, "monitor did not render"
    assert "1 jam" in row, f"expected the outage duration, got: {row}"
    # The healthy run must be gone rather than reported alongside the outage.
    assert "2 hari" not in row, f"stale healthy run still shown: {row}"


def test_a_healthy_monitor_reports_its_run_length(authed, csrf, settings_factory):
    """The other half of the same fix: an UP row must show the healthy run."""
    created = authed.post(
        "/monitors",
        data=monitor_payload("Sehat", "https://b.example.com", csrf),
        follow_redirects=False,
    )
    monitor_id = created.headers["location"].rsplit("/", 1)[-1].split("?")[0]

    db = Database(settings_factory().database_path)
    asyncio.run(_seed_state(db, monitor_id, down=False))

    row = _row_for(authed.get("/").text, "Sehat")

    assert row is not None
    assert "3 hari" in row, f"expected the healthy run length, got: {row}"


async def _seed_state(db: Database, monitor_id: str, *, down: bool) -> None:
    """Write a two-day healthy run, optionally followed by an outage."""
    await db.connect()
    try:
        state = StateRepo(db)
        await state.record_check(
            monitor_id,
            ok=True,
            state=MonitorState.UP,
            consecutive_failures=0,
            down_since=None,
            up_since=NOW - timedelta(days=2),
            at=NOW - timedelta(hours=1) if down else NOW,
        )
        if down:
            await state.record_check(
                monitor_id,
                ok=False,
                state=MonitorState.DOWN,
                consecutive_failures=3,
                down_since=NOW - timedelta(hours=1),
                up_since=None,
                at=NOW,
            )
        else:
            await state.record_check(
                monitor_id,
                ok=True,
                state=MonitorState.UP,
                consecutive_failures=0,
                down_since=None,
                up_since=NOW - timedelta(days=3),
                at=NOW,
            )
    finally:
        await db.close()


def _row_for(html: str, name: str) -> str | None:
    """The ``<tr>`` a monitor's name appears in, for targeted assertions."""
    for chunk in html.split("<tr>"):
        if name in chunk:
            return chunk.split("</tr>")[0]
    return None


def test_the_dashboard_renders_both_duration_columns(authed, csrf):
    created = authed.post(
        "/monitors",
        data=monitor_payload("Kolom", "https://c.example.com", csrf),
        follow_redirects=False,
    )
    assert created.status_code == 303

    response = authed.get("/partials/monitor-table")

    assert response.status_code == 200
    assert "DOWN sejak" in response.text
    assert "UP sejak" in response.text


def test_an_empty_dashboard_says_so_instead_of_rendering_an_empty_table(authed):
    """No monitors is a state the operator needs to be told about, not shown as blanks."""
    response = authed.get("/partials/monitor-table")

    assert response.status_code == 200
    assert "Belum ada monitor" in response.text


# ----- static assets and health -------------------------------------------


def test_health_reports_not_ready_while_the_scheduler_is_off(client):
    """A container with no scheduler must not be sent traffic."""
    assert client.get("/healthz").status_code == 503


@pytest.mark.parametrize("path", ["/static/app.css", "/static/htmx.min.js"])
def test_static_assets_are_served_from_disk(client, path):
    """No CDN: the UI has to work on a host that cannot reach the internet."""
    response = client.get(path)

    assert response.status_code == 200
    assert response.content
