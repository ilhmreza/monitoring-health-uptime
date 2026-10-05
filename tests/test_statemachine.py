"""State machine tests.

The alerting rules are the part of a monitor most likely to be wrong and hardest
to debug from production logs, so they are pinned here rather than only covered
by an end-to-end script.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from uptimebot.models import (
    SSL_SEVERITY_EXPIRED,
    SSL_SEVERITY_HEALTHY,
    CheckResult,
    MonitorState,
    severity_label,
    ssl_severity,
)
from uptimebot.monitor.statemachine import (
    ActionKind,
    evaluate_check,
    evaluate_ssl,
)

UTC = timezone.utc
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)

OK = CheckResult(ok=True, latency_ms=42.0, status_code=200, checked_at=NOW)
FAIL = CheckResult(
    ok=False,
    latency_ms=None,
    status_code=None,
    error="connection refused",
    failure_kind="connection_refused",
    checked_at=NOW,
)


def decide(
    *,
    result: CheckResult = OK,
    state: MonitorState = MonitorState.UP,
    failures: int = 0,
    down_since: datetime | None = None,
    up_since: datetime | None = None,
    last_ok_at: datetime | None = None,
    last_reminder_at: datetime | None = None,
    threshold: int = 3,
    now: datetime = NOW,
    reminder: timedelta = timedelta(minutes=30),
):
    return evaluate_check(
        current_state=state,
        consecutive_failures=failures,
        down_since=down_since,
        last_ok_at=last_ok_at,
        result=result,
        failure_threshold=threshold,
        reminder_interval=reminder,
        last_reminder_at=last_reminder_at,
        now=now,
        up_since=up_since,
    )


# ----- happy path ----------------------------------------------------------


def test_first_success_marks_up_without_alerting():
    """UNKNOWN -> UP on the first check is not newsworthy."""
    decision = decide(result=OK, state=MonitorState.UNKNOWN)

    assert decision.state is MonitorState.UP
    assert decision.actions == []
    assert decision.up_since == NOW


def test_success_keeps_an_existing_healthy_run_anchored():
    """Repeated passes must not slide the 'up for' window forward."""
    started = NOW - timedelta(days=6)
    later = NOW + timedelta(minutes=5)

    decision = decide(result=OK, state=MonitorState.UP, up_since=started, now=later)

    assert decision.state is MonitorState.UP
    assert decision.up_since == started


# ----- failure threshold ---------------------------------------------------


@pytest.mark.parametrize("failures_before, expected_state", [(0, MonitorState.UP), (1, MonitorState.UP)])
def test_failures_below_threshold_do_not_page(failures_before, expected_state):
    decision = decide(result=FAIL, state=MonitorState.UP, failures=failures_before)

    assert decision.state is expected_state
    assert decision.consecutive_failures == failures_before + 1
    assert [a.kind for a in decision.actions] == []


def test_threshold_failure_raises_the_alert():
    decision = decide(result=FAIL, state=MonitorState.UP, failures=2)

    assert decision.state is MonitorState.DOWN
    assert [a.kind for a in decision.actions] == [ActionKind.ALERT_DOWN]


def test_outage_anchors_to_last_success_not_to_the_alert():
    """'Down for 2 minutes' must mean 2 minutes, not 0 minutes."""
    last_ok = NOW - timedelta(minutes=2)
    decision = decide(
        result=FAIL, state=MonitorState.UP, failures=2, last_ok_at=last_ok
    )

    assert decision.state is MonitorState.DOWN
    assert decision.down_since == last_ok


def test_outage_without_any_prior_success_falls_back_to_now():
    decision = decide(result=FAIL, state=MonitorState.UNKNOWN, failures=2)

    assert decision.state is MonitorState.DOWN
    assert decision.down_since == NOW


def test_threshold_of_one_alerts_on_the_first_failure():
    decision = decide(result=FAIL, state=MonitorState.UNKNOWN, threshold=1)

    assert decision.state is MonitorState.DOWN
    assert [a.kind for a in decision.actions] == [ActionKind.ALERT_DOWN]


def test_zero_threshold_is_clamped_so_it_still_takes_one_failure():
    """A misconfigured threshold of 0 must not alert on zero failures."""
    decision = decide(result=FAIL, state=MonitorState.UNKNOWN, threshold=0)

    assert decision.consecutive_failures == 1
    assert decision.state is MonitorState.DOWN


# ----- recovery ------------------------------------------------------------


def test_recovery_reports_outage_duration_then_clears_bookkeeping():
    down_since = NOW - timedelta(minutes=42)
    decision = decide(result=OK, state=MonitorState.DOWN, down_since=down_since)

    assert decision.state is MonitorState.UP
    assert decision.down_since is None
    assert decision.up_since == NOW
    assert [a.kind for a in decision.actions] == [ActionKind.ALERT_RECOVERY]
    assert decision.actions[0].downtime == timedelta(minutes=42)


def test_recovery_never_reports_negative_downtime_on_a_clock_skew():
    """A backwards clock must not produce a negative duration in a Discord alert."""
    decision = decide(
        result=OK, state=MonitorState.DOWN, down_since=NOW + timedelta(minutes=5)
    )

    assert decision.actions[0].downtime == timedelta(0)


# ----- reminder cadence ----------------------------------------------------


def test_reminder_fires_when_the_interval_has_elapsed():
    down_since = NOW - timedelta(hours=2)
    decision = decide(
        result=FAIL,
        state=MonitorState.DOWN,
        failures=9,
        down_since=down_since,
        last_reminder_at=NOW - timedelta(minutes=31),
    )

    assert decision.reminder_due is True
    assert [a.kind for a in decision.actions] == [ActionKind.ALERT_REMINDER]
    assert decision.actions[0].downtime == timedelta(hours=2)


def test_reminder_is_silent_before_the_interval_elapses():
    decision = decide(
        result=FAIL,
        state=MonitorState.DOWN,
        failures=9,
        down_since=NOW - timedelta(minutes=10),
        last_reminder_at=NOW - timedelta(minutes=29),
    )

    assert decision.reminder_due is False
    assert decision.actions == []


def test_reminder_carries_the_ongoing_outage_not_zero():
    decision = decide(
        result=FAIL,
        state=MonitorState.DOWN,
        failures=5,
        down_since=NOW - timedelta(hours=6),
        last_reminder_at=None,
    )

    assert decision.actions[0].downtime == timedelta(hours=6)


# ----- paused --------------------------------------------------------------


def test_a_paused_monitor_never_produces_an_incident():
    decision = decide(result=FAIL, state=MonitorState.PAUSED, failures=7)

    assert decision.state is MonitorState.PAUSED
    assert decision.actions == []
    assert decision.consecutive_failures == 7


# ----- SSL escalation ------------------------------------------------------


def test_severity_is_ordered_mildest_bracket_first():
    """Guards the numbering itself.

    Severity 1 must be the widest bracket and the largest count the tightest,
    because ``ssl_notified_severity`` is compared with ``>`` to detect
    escalation, and the UI maps these numbers onto badges and labels.
    """
    brackets = (30, 14, 7, 1)

    assert ssl_severity(31, brackets) == SSL_SEVERITY_HEALTHY
    assert ssl_severity(30, brackets) == 1
    assert ssl_severity(15, brackets) == 1
    assert ssl_severity(14, brackets) == 2
    assert ssl_severity(8, brackets) == 2
    assert ssl_severity(7, brackets) == 3
    assert ssl_severity(2, brackets) == 3
    assert ssl_severity(1, brackets) == 4
    assert ssl_severity(0, brackets) == 4
    assert ssl_severity(-1, brackets) == SSL_SEVERITY_EXPIRED


def test_the_tightest_bracket_is_labelled_critical():
    """A one-day warning must not read as 'INFO' just above the expiry line."""
    assert severity_label(ssl_severity(1, (30, 14, 7, 1))) == "KRITIS"
    assert severity_label(ssl_severity(20, (30, 14, 7, 1))) == "INFO"
    assert severity_label(SSL_SEVERITY_EXPIRED) == "EXPIRED"
    assert severity_label(SSL_SEVERITY_HEALTHY) == "SEHAT"


def test_severity_never_inverts_for_any_warn_days_configuration():
    """A custom bracket list must not flip the scale back on itself."""
    for brackets in [(30, 14, 7, 1), (60, 30), (90, 45, 10), (1,)]:
        severities = [ssl_severity(d, brackets) for d in (300, 60, 20, 5, 1, 0, -5)]
        # Healthy first, expired last, and strictly non-decreasing between.
        assert severities[0] == SSL_SEVERITY_HEALTHY
        assert severities[-1] == SSL_SEVERITY_EXPIRED
        assert severities == sorted(severities)
        assert severities.count(SSL_SEVERITY_EXPIRED) == 1


def ssl_decision(days_left: int | None, notified: int):
    return evaluate_ssl(
        days_left=days_left,
        warn_days=(30, 14, 7, 1),
        notified_severity=notified,
        inspection_ok=days_left is not None,
    )


def test_far_future_certificate_is_healthy_and_silent():
    decision = ssl_decision(days_left=90, notified=0)

    assert decision.severity == SSL_SEVERITY_HEALTHY
    assert decision.should_notify is False


def test_entering_a_warning_band_notifies_once():
    first = ssl_decision(days_left=20, notified=0)
    repeat = ssl_decision(days_left=20, notified=first.notified_severity)

    assert first.should_notify is True
    assert repeat.should_notify is False


def test_escalating_to_critical_notifies_again():
    """20 days left and 5 days left are different brackets, so the second warns."""
    warned = ssl_decision(days_left=20, notified=0)
    critical = ssl_decision(days_left=5, notified=warned.notified_severity)

    assert critical.severity > warned.severity
    assert critical.should_notify is True


def test_two_days_apart_inside_one_bracket_do_not_warn_again():
    """Escalation is per bracket, not per day — otherwise 20 warnings a day."""
    warned = ssl_decision(days_left=20, notified=0)
    later = ssl_decision(days_left=16, notified=warned.notified_severity)

    assert later.severity == warned.severity
    assert later.should_notify is False


def test_de_escalating_after_renewal_does_not_notify():
    """A renewed certificate is good news and must stay silent."""
    critical = ssl_decision(days_left=2, notified=0)
    renewed = ssl_decision(days_left=200, notified=critical.notified_severity)

    assert renewed.severity == SSL_SEVERITY_HEALTHY
    assert renewed.should_notify is False


def test_expired_certificate_is_the_most_severe():
    decision = ssl_decision(days_left=-1, notified=0)

    assert decision.severity == SSL_SEVERITY_EXPIRED
    assert decision.should_notify is True


def test_unreadable_certificate_keeps_the_previous_severity():
    """A failed inspection must not look like a renewal, nor a new incident."""
    decision = evaluate_ssl(
        days_left=None,
        warn_days=(30, 14, 7, 1),
        notified_severity=2,
        inspection_ok=False,
    )

    assert decision.severity == 2
    assert decision.should_notify is False
