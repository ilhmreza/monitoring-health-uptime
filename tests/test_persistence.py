"""State and check persistence tests.

The dashboard's "down for 2 hours" number is only trustworthy if the timestamps
behind it survive a restart, so these tests reopen the database rather than
trusting an in-memory object.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from uptimebot.db import CheckRepo, Database, MonitorRepo, StateRepo
from uptimebot.models import CheckResult, Monitor, MonitorState

UTC = timezone.utc
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
MONITOR_ID = "layanan-a"


async def seed_monitor(db: Database) -> Monitor:
    """Create the monitor a state row hangs off.

    ``monitor_state.monitor_id`` is a foreign key, so a state row cannot exist
    without its monitor — which is why every test here seeds one first.
    """
    monitor = Monitor(id=MONITOR_ID, name="Layanan A", url="https://a.example.com")
    await MonitorRepo(db).create(monitor)
    return monitor


@pytest.fixture
async def seeded_db(db):
    await seed_monitor(db)
    return db


# ----- self-healing --------------------------------------------------------


async def test_a_monitor_without_a_state_row_is_repaired_not_fatal(seeded_db):
    """A monitor created seconds ago has no state row until its first probe."""
    row = await StateRepo(seeded_db).get(MONITOR_ID)

    assert row.state is MonitorState.UNKNOWN
    assert row.down_since is None
    assert row.up_since is None


async def test_a_state_row_cannot_exist_without_its_monitor(db):
    """Guards the foreign key that the repair path above depends on."""
    with pytest.raises(Exception):
        await StateRepo(db).record_check(
            "tidak-ada",
            ok=True,
            state=MonitorState.UP,
            consecutive_failures=0,
            down_since=None,
            up_since=NOW,
            at=NOW,
        )


# ----- up_since ------------------------------------------------------------


async def test_a_healthy_run_is_anchored_and_does_not_slide(seeded_db):
    """Three passing probes an hour apart must keep pointing at the first."""
    state = StateRepo(seeded_db)
    started = NOW - timedelta(days=6)

    for offset in (0, 1, 2):
        await state.record_check(
            MONITOR_ID,
            ok=True,
            state=MonitorState.UP,
            consecutive_failures=0,
            down_since=None,
            up_since=started,
            at=NOW + timedelta(hours=offset),
        )
        assert (await state.get(MONITOR_ID)).up_since == started


async def test_an_ongoing_outage_clears_the_healthy_run(seeded_db):
    state = StateRepo(seeded_db)
    await state.record_check(
        MONITOR_ID,
        ok=True,
        state=MonitorState.UP,
        consecutive_failures=0,
        down_since=None,
        up_since=NOW - timedelta(days=2),
        at=NOW,
    )
    await state.record_check(
        MONITOR_ID,
        ok=False,
        state=MonitorState.DOWN,
        consecutive_failures=3,
        down_since=NOW,
        up_since=None,
        at=NOW,
    )

    row = await state.get(MONITOR_ID)

    assert row.state is MonitorState.DOWN
    assert row.up_since is None
    assert row.down_since == NOW


async def test_a_failure_inside_the_threshold_keeps_the_healthy_run(seeded_db):
    """One dropped packet is not an outage, so 'up for' must keep counting."""
    state = StateRepo(seeded_db)
    started = NOW - timedelta(hours=3)

    await state.record_check(
        MONITOR_ID,
        ok=True,
        state=MonitorState.UP,
        consecutive_failures=0,
        down_since=None,
        up_since=started,
        at=NOW,
    )
    await state.record_check(
        MONITOR_ID,
        ok=False,
        state=MonitorState.UP,
        consecutive_failures=1,
        down_since=None,
        up_since=started,
        at=NOW,
    )

    row = await state.get(MONITOR_ID)

    assert row.state is MonitorState.UP
    assert row.consecutive_failures == 1
    assert row.up_since == started


async def test_the_repository_writes_both_clocks_verbatim(seeded_db):
    """``None`` means 'this run is over', so it must not be coalesced away.

    The state machine is the only thing that decides when a clock starts or
    stops; the repository just stores the answer.
    """
    state = StateRepo(seeded_db)
    started = NOW - timedelta(days=1)
    await state.record_check(
        MONITOR_ID,
        ok=True,
        state=MonitorState.UP,
        consecutive_failures=0,
        down_since=None,
        up_since=started,
        at=NOW,
    )
    assert (await state.get(MONITOR_ID)).up_since == started

    await state.record_check(
        MONITOR_ID,
        ok=False,
        state=MonitorState.DOWN,
        consecutive_failures=3,
        down_since=NOW,
        up_since=None,
        at=NOW,
    )
    assert (await state.get(MONITOR_ID)).up_since is None


# ----- restart persistence -------------------------------------------------


async def reopen(path: Path) -> Database:
    """Open the file the way a fresh process would."""
    db = Database(path)
    await db.connect()
    return db


async def test_down_and_up_survive_a_restart(tmp_path):
    """The whole point of persisting: the duration is right after a redeploy."""
    path = tmp_path / "uptimebot.db"
    down_since = NOW - timedelta(minutes=90)

    db = Database(path)
    try:
        await db.connect()
        await db.init_schema()
        await seed_monitor(db)
        await StateRepo(db).record_check(
            MONITOR_ID,
            ok=False,
            state=MonitorState.DOWN,
            consecutive_failures=4,
            down_since=down_since,
            up_since=None,
            at=NOW,
        )
    finally:
        await db.close()

    db2 = await reopen(path)
    try:
        row = await StateRepo(db2).get(MONITOR_ID)
        assert row.state is MonitorState.DOWN
        assert row.down_since == down_since
        assert row.consecutive_failures == 4
    finally:
        await db2.close()


async def test_an_ongoing_healthy_run_survives_a_restart(tmp_path):
    path = tmp_path / "uptimebot.db"
    started = NOW - timedelta(days=9)

    db = Database(path)
    try:
        await db.connect()
        await db.init_schema()
        await seed_monitor(db)
        await StateRepo(db).record_check(
            MONITOR_ID,
            ok=True,
            state=MonitorState.UP,
            consecutive_failures=0,
            down_since=None,
            up_since=started,
            at=NOW,
        )
    finally:
        await db.close()

    db2 = await reopen(path)
    try:
        assert (await StateRepo(db2).get(MONITOR_ID)).up_since == started
    finally:
        await db2.close()


# ----- pause ---------------------------------------------------------------


async def test_pausing_clears_both_durations(seeded_db):
    """A paused monitor is not up and not down, so neither clock may run."""
    state = StateRepo(seeded_db)
    await state.record_check(
        MONITOR_ID,
        ok=True,
        state=MonitorState.UP,
        consecutive_failures=0,
        down_since=None,
        up_since=NOW - timedelta(days=4),
        at=NOW,
    )

    await state.reset_for_pause(MONITOR_ID, NOW)
    row = await state.get(MONITOR_ID)

    assert row.state is MonitorState.PAUSED
    assert row.up_since is None
    assert row.down_since is None
    assert row.consecutive_failures == 0


# ----- probe history -------------------------------------------------------


async def test_uptime_percentage_ignores_checks_outside_the_window(seeded_db):
    from uptimebot.db.database import utcnow

    checks = CheckRepo(seeded_db)
    real_now = utcnow()

    def result(ok: bool, at: datetime) -> CheckResult:
        if ok:
            return CheckResult(ok=True, latency_ms=10.0, status_code=200, checked_at=at)
        return CheckResult(ok=False, latency_ms=None, status_code=None, error="boom", checked_at=at)

    await checks.record(MONITOR_ID, result(True, real_now))
    await checks.record(MONITOR_ID, result(False, real_now))
    # An outage last week must not drag down today's percentage.
    await checks.record(MONITOR_ID, result(False, real_now - timedelta(days=5)))

    stats = await checks.stats(MONITOR_ID, timedelta(hours=24), "24 jam")

    assert stats.total == 2
    assert stats.successful == 1
    assert stats.uptime_percent == pytest.approx(50.0, abs=0.01)


async def test_a_window_of_only_failures_still_reports_a_percentage(seeded_db):
    """A service that is entirely down has no latency to average."""
    from uptimebot.db.database import utcnow

    checks = CheckRepo(seeded_db)
    real_now = utcnow()
    for _ in range(3):
        await checks.record(
            MONITOR_ID,
            CheckResult(
                ok=False,
                latency_ms=None,
                status_code=None,
                error="connection refused",
                checked_at=real_now,
            ),
        )

    stats = await checks.stats(MONITOR_ID, timedelta(hours=24), "24 jam")

    assert stats.total == 3
    assert stats.uptime_percent == pytest.approx(0.0)
    assert stats.avg_latency_ms is None
    assert stats.p95_latency_ms is None


async def test_a_window_with_no_probes_reports_nothing_rather_than_zero(seeded_db):
    """No data is not the same as zero percent uptime."""
    stats = await CheckRepo(seeded_db).stats(MONITOR_ID, timedelta(hours=24), "24 jam")

    assert stats.total == 0
    assert stats.uptime_percent is None


async def test_retention_prunes_only_old_probes(seeded_db):
    """Retention is measured against the wall clock, not against probe time."""
    from uptimebot.db.database import utcnow

    checks = CheckRepo(seeded_db)
    real_now = utcnow()
    await checks.record(
        MONITOR_ID,
        CheckResult(ok=True, latency_ms=5.0, status_code=200, checked_at=real_now),
    )
    await checks.record(
        MONITOR_ID,
        CheckResult(
            ok=True,
            latency_ms=5.0,
            status_code=200,
            checked_at=real_now - timedelta(days=40),
        ),
    )

    deleted = await seeded_db.prune_checks(30)

    assert deleted == 1
    assert (await checks.stats(MONITOR_ID, timedelta(hours=24), "24 jam")).total == 1
