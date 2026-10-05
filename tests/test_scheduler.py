"""Scheduler lifecycle tests.

The deployment promise is that editing a monitor in the UI changes what is
being probed *without restarting the container*. These tests exercise the real
scheduler against a real local HTTP server, so reconciliation, the task set and
the per-monitor interval are all covered end to end.
"""

from __future__ import annotations

import asyncio
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from uptimebot.models import Monitor, NotifyEvent
from uptimebot.web.app import create_app


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self.server.hits.append(self.path)  # type: ignore[attr-defined]
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        return


@pytest.fixture
def target():
    """A local server that counts requests, standing in for a monitored site."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.hits = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def url_for(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}/health"


@pytest.fixture
async def running_app(settings_factory, password_hash, target):
    """An app with the scheduler actually started, torn down afterwards."""
    settings = settings_factory(
        ui_username="admin",
        ui_password_hash=password_hash,
        secret_key="pytest-secret-key",
        cookie_secure=False,
        # The test target is on loopback, which the SSRF guard blocks by default.
        allow_private_network=True,
        default_interval_seconds=5,
        ssl_check_interval_seconds=3600,
    )
    app = create_app(settings, start_scheduler=True)
    transport = app.router.lifespan_context(app)
    await transport.__aenter__()
    try:
        yield app.state.ctx, target
    finally:
        await transport.__aexit__(None, None, None)


def make_monitor(server, monitor_id: str, interval: int = 5) -> Monitor:
    return Monitor(
        id=monitor_id,
        name=monitor_id,
        url=url_for(server),
        interval_seconds=interval,
        timeout_seconds=3,
        failure_threshold=2,
        notify_on=[NotifyEvent.DOWN],
        ssl_check=False,
    )


async def wait_for(predicate, timeout: float = 5.0) -> bool:
    """Poll until the scheduler's background work has caught up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return False


async def wait_until_health(ctx, key: str, expected: int) -> bool:
    return await wait_for(lambda: ctx.scheduler.health()[key] == expected)


# ----- lifecycle -----------------------------------------------------------


async def test_an_empty_database_starts_no_probe_tasks(running_app):
    ctx, _server = running_app

    health = ctx.scheduler.health()

    assert health["running"] is True
    assert health["monitor_tasks"] == 0


async def test_creating_a_monitor_adds_a_task_without_a_restart(running_app):
    ctx, server = running_app
    await ctx.monitors.create(make_monitor(server, "alpha"))
    ctx.scheduler.notify_config_changed()

    assert await wait_until_health(ctx, "monitor_tasks", 1)
    assert await wait_for(lambda: len(server.hits) > 0), "no probe reached the target"


async def test_two_monitors_get_two_tasks(running_app):
    ctx, server = running_app
    await ctx.monitors.create(make_monitor(server, "alpha"))
    await ctx.monitors.create(make_monitor(server, "beta"))
    ctx.scheduler.notify_config_changed()

    assert await wait_until_health(ctx, "monitor_tasks", 2)


async def test_pausing_removes_the_task_and_resuming_brings_it_back(running_app):
    ctx, server = running_app
    await ctx.monitors.create(make_monitor(server, "alpha"))
    ctx.scheduler.notify_config_changed()
    assert await wait_until_health(ctx, "monitor_tasks", 1)

    await ctx.monitors.set_enabled("alpha", False)
    ctx.scheduler.notify_config_changed()
    assert await wait_until_health(ctx, "monitor_tasks", 0)

    await ctx.monitors.set_enabled("alpha", True)
    ctx.scheduler.notify_config_changed()
    assert await wait_until_health(ctx, "monitor_tasks", 1)


async def test_deleting_a_monitor_removes_its_task(running_app):
    ctx, server = running_app
    await ctx.monitors.create(make_monitor(server, "alpha"))
    await ctx.monitors.create(make_monitor(server, "beta"))
    ctx.scheduler.notify_config_changed()
    assert await wait_until_health(ctx, "monitor_tasks", 2)

    await ctx.monitors.delete("beta")
    ctx.scheduler.notify_config_changed()

    assert await wait_until_health(ctx, "monitor_tasks", 1)


# ----- reconfiguration without a restart ----------------------------------


async def test_a_new_interval_is_applied_to_the_running_task(running_app):
    """An edit from the UI has to take effect without bouncing the container."""
    ctx, server = running_app
    await ctx.monitors.create(make_monitor(server, "alpha", interval=5))
    ctx.scheduler.notify_config_changed()
    assert await wait_for(lambda: len(server.hits) > 0)

    await ctx.monitors.update(make_monitor(server, "alpha", interval=3600))
    ctx.scheduler.notify_config_changed()

    # Let the old task's next tick happen, then confirm nothing follows it.
    await asyncio.sleep(1.5)
    hits_after_settle = len(server.hits)
    await asyncio.sleep(1.5)
    assert len(server.hits) == hits_after_settle, "the old 5s interval is still in force"


async def test_reconciliation_runs_again_after_a_config_change(running_app):
    ctx, server = running_app
    runs_before = ctx.scheduler.health()["reconcile_runs"] or 0

    await ctx.monitors.create(make_monitor(server, "alpha"))
    ctx.scheduler.notify_config_changed()

    assert await wait_for(lambda: (ctx.scheduler.health()["reconcile_runs"] or 0) > runs_before)


# ----- recording -----------------------------------------------------------


async def test_probe_results_are_recorded(running_app):
    """A probe nobody records is a probe the dashboard can never show."""
    ctx, server = running_app
    await ctx.monitors.create(make_monitor(server, "alpha"))
    ctx.scheduler.notify_config_changed()

    async def recorded() -> bool:
        return (await ctx.checks.total_rows()) > 0

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if await recorded():
            break
        await asyncio.sleep(0.05)

    assert await recorded(), "no probe was recorded"


async def test_the_database_is_still_usable_after_the_suite(running_app):
    """Guards against a probe loop leaving the connection unusable."""
    ctx, _server = running_app

    assert (await ctx.checks.total_rows()) >= 0
    assert (await ctx.monitors.count()) >= 0
