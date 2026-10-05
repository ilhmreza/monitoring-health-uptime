"""Availability state machine.

Deliberately pure: ``evaluate_check`` takes the current state plus a probe
result and returns the next state and the alerts to emit. No I/O, no clock
reads, no database. That keeps the alerting rules — the part of a monitoring
tool most likely to be wrong and hardest to reproduce — fully testable.

The rules:

* A failure only counts once the streak reaches ``failure_threshold``, so one
  dropped packet does not page anyone.
* ``down_since`` is the last known-good moment, not the moment the threshold
  was crossed, so "down for 2 minutes" is true rather than "down for 0
  minutes" on every incident.
* Recovery reports how long the outage lasted, then clears the streak.
* While still down, a reminder is due every ``reminder_interval`` so the
  alert cannot be quietly forgotten.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from ..models import (
    SSL_SEVERITY_HEALTHY,
    CheckResult,
    MonitorState,
    SslInfo,
    severity_label,
    ssl_severity,
)


class ActionKind(str, Enum):
    ALERT_DOWN = "alert_down"
    ALERT_RECOVERY = "alert_recovery"
    ALERT_REMINDER = "alert_reminder"
    ALERT_SSL = "alert_ssl"


@dataclass(slots=True)
class Action:
    """Something the scheduler should report."""

    kind: ActionKind
    result: CheckResult | None = None
    downtime: timedelta | None = None
    ssl: SslInfo | None = None
    ssl_severity: int = 0
    ssl_label: str = ""


@dataclass(slots=True)
class Decision:
    """The outcome of evaluating one probe result."""

    state: MonitorState
    consecutive_failures: int
    down_since: datetime | None
    # Start of the current healthy run. Set only on the transition into UP, and
    # cleared when the state leaves UP, so it survives repeated passing probes.
    up_since: datetime | None = None
    actions: list[Action] = field(default_factory=list)
    reminder_due: bool = False

    @property
    def alerts(self) -> list[Action]:
        return self.actions


@dataclass(slots=True)
class SslDecision:
    """The outcome of evaluating one certificate inspection."""

    should_notify: bool
    notified_severity: int
    severity: int
    label: str


def evaluate_check(
    *,
    current_state: MonitorState,
    consecutive_failures: int,
    down_since: datetime | None,
    last_ok_at: datetime | None,
    result: CheckResult,
    failure_threshold: int,
    reminder_interval: timedelta,
    last_reminder_at: datetime | None,
    now: datetime,
    up_since: datetime | None = None,
) -> Decision:
    """Advance the state machine by one probe.

    ``up_since`` mirrors ``down_since`` for the healthy side: it is anchored on
    the transition into UP, so the dashboard can report "up for 6 days" without
    that number sliding forward on every successful probe.
    """
    if current_state is MonitorState.PAUSED:
        # A paused monitor is not being observed, so nothing it returns should
        # look like an incident.
        return Decision(
            state=MonitorState.PAUSED,
            consecutive_failures=consecutive_failures,
            down_since=down_since,
            up_since=up_since,
        )

    if result.ok:
        if current_state is MonitorState.DOWN and down_since is not None:
            downtime = max(now - down_since, timedelta(0))
            return Decision(
                state=MonitorState.UP,
                consecutive_failures=0,
                down_since=None,
                # Recovery starts a fresh healthy run.
                up_since=now,
                actions=[Action(ActionKind.ALERT_RECOVERY, result=result, downtime=downtime)],
            )
        # Includes UNKNOWN -> UP on the very first successful check, which is
        # not newsworthy. An existing run keeps its original start.
        return Decision(
            state=MonitorState.UP,
            consecutive_failures=0,
            down_since=None,
            up_since=up_since if current_state is MonitorState.UP else now,
        )

    failures = consecutive_failures + 1
    threshold = max(1, failure_threshold)

    if current_state is MonitorState.DOWN:
        due = (
            last_reminder_at is None
            or (now - last_reminder_at) >= reminder_interval
        )
        if due:
            downtime = (
                max(now - down_since, timedelta(0)) if down_since is not None else None
            )
            return Decision(
                state=MonitorState.DOWN,
                consecutive_failures=failures,
                down_since=down_since,
                up_since=None,
                actions=[Action(ActionKind.ALERT_REMINDER, result=result, downtime=downtime)],
                reminder_due=True,
            )
        return Decision(
            state=MonitorState.DOWN,
            consecutive_failures=failures,
            down_since=down_since,
            up_since=None,
        )

    # Currently UP or UNKNOWN, and this probe failed.
    if failures >= threshold:
        # Anchor the outage to the last success so the reported duration is
        # the real one; fall back to now if the monitor has never been seen up.
        anchor = last_ok_at or now
        return Decision(
            state=MonitorState.DOWN,
            consecutive_failures=failures,
            down_since=anchor,
            up_since=None,
            actions=[Action(ActionKind.ALERT_DOWN, result=result)],
        )

    return Decision(
        state=current_state,
        consecutive_failures=failures,
        down_since=down_since,
        # Still inside the tolerable streak: the healthy run is not over yet.
        up_since=up_since,
    )


def evaluate_ssl(
    *,
    days_left: int | None,
    warn_days: tuple[int, ...] | list[int],
    notified_severity: int,
    inspection_ok: bool,
) -> SslDecision:
    """Decide whether this certificate warrants a warning.

    A warning fires only when the certificate has entered a *more urgent*
    bracket than the one already announced, so a 30-day warning is not
    repeated on every check. Once the certificate is healthy again the stored
    severity resets, which is what lets a renewed certificate warn again
    later in its life.

    A failed inspection (TLS handshake refused, no certificate presented) is
    deliberately silent: ``days_left`` is unknown, so there is no severity to
    escalate, and the previously announced severity is kept rather than reset.
    Resetting on an error would mean the next successful inspection re-announces
    the same warning.
    """
    if not inspection_ok or days_left is None:
        return SslDecision(
            should_notify=False,
            notified_severity=notified_severity,
            severity=notified_severity,
            label=severity_label(notified_severity),
        )

    brackets = tuple(sorted({int(d) for d in warn_days}, reverse=True))
    severity = ssl_severity(days_left, brackets)

    if severity == SSL_SEVERITY_HEALTHY:
        return SslDecision(
            should_notify=False,
            notified_severity=SSL_SEVERITY_HEALTHY,
            severity=SSL_SEVERITY_HEALTHY,
            label=severity_label(SSL_SEVERITY_HEALTHY),
        )

    if severity > notified_severity:
        return SslDecision(
            should_notify=True,
            notified_severity=severity,
            severity=severity,
            label=severity_label(severity),
        )

    return SslDecision(
        should_notify=False,
        notified_severity=notified_severity,
        severity=severity,
        label=severity_label(severity),
    )
