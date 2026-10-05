"""Runtime state transitions for monitors.

This is the only place that mutates ``monitor_state``. Keeping every
transition behind one repository means the scheduler cannot accidentally
half-write a state change and leave ``down_since`` inconsistent with
``state``.
"""

from __future__ import annotations

from datetime import datetime

from ..models import MonitorState, MonitorStateRow
from .database import Database, from_iso, to_iso, utcnow


class StateRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get(self, monitor_id: str) -> MonitorStateRow:
        row = await self.db.fetch_one(
            "SELECT * FROM monitor_state WHERE monitor_id = ?", (monitor_id,)
        )
        if row is None:
            # Self-heal: a monitor row without a state row is repairable, and
            # repairing it here beats crashing the scheduler.
            await self.ensure_row(monitor_id)
            return MonitorStateRow(monitor_id=monitor_id)
        return MonitorStateRow(
            monitor_id=row["monitor_id"],
            state=_coerce(row["state"]),
            consecutive_failures=row["consecutive_failures"],
            down_since=from_iso(row["down_since"]),
            up_since=from_iso(row["up_since"]),
            last_check_at=from_iso(row["last_check_at"]),
            last_ok_at=from_iso(row["last_ok_at"]),
            last_reminder_at=from_iso(row["last_reminder_at"]),
            ssl_notified_severity=row["ssl_notified_severity"],
            last_alert_at=from_iso(row["last_alert_at"]),
        )

    async def ensure_row(self, monitor_id: str) -> None:
        await self.db.execute(
            "INSERT OR IGNORE INTO monitor_state (monitor_id) VALUES (?)", (monitor_id,)
        )

    # ----- individual field updates ---------------------------------------

    async def record_check(
        self,
        monitor_id: str,
        *,
        ok: bool,
        state: MonitorState,
        consecutive_failures: int,
        down_since: datetime | None,
        at: datetime,
        up_since: datetime | None,
    ) -> None:
        """Persist the outcome of one probe together with its state.

        ``down_since`` and ``up_since`` are written exactly as given: the state
        machine is the only thing that decides when either clock starts or
        stops, and both are needed. Writing them verbatim matters because
        ``None`` means "this run is over" — coalescing the column would make it
        impossible to ever clear the value, and the dashboard would keep
        reporting a healthy run for a service that has since gone down.
        """
        await self.ensure_row(monitor_id)
        await self.db.execute(
            """
            UPDATE monitor_state SET
                state = ?,
                consecutive_failures = ?,
                down_since = ?,
                up_since = ?,
                last_check_at = ?,
                last_ok_at = CASE WHEN ? = 1 THEN ? ELSE last_ok_at END
            WHERE monitor_id = ?
            """,
            (
                state.value,
                consecutive_failures,
                to_iso(down_since),
                to_iso(up_since),
                to_iso(at),
                int(ok),
                to_iso(at),
                monitor_id,
            ),
        )


    async def record_reminder(self, monitor_id: str, at: datetime) -> None:
        await self.db.execute(
            "UPDATE monitor_state SET last_reminder_at = ? WHERE monitor_id = ?",
            (to_iso(at), monitor_id),
        )

    async def record_alert(self, monitor_id: str, at: datetime) -> None:
        await self.db.execute(
            "UPDATE monitor_state SET last_alert_at = ? WHERE monitor_id = ?",
            (to_iso(at), monitor_id),
        )

    async def set_ssl_notified_severity(self, monitor_id: str, severity: int) -> None:
        """Record the highest SSL severity already announced.

        Resetting to 0 is meaningful: it means the certificate was renewed and
        any future warning should be sent again.
        """
        await self.ensure_row(monitor_id)
        await self.db.execute(
            "UPDATE monitor_state SET ssl_notified_severity = ? WHERE monitor_id = ?",
            (severity, monitor_id),
        )

    async def reset_for_pause(self, monitor_id: str, at: datetime) -> None:
        """Clear outage bookkeeping when a monitor is paused.

        A paused monitor's previous outage is finished business; keeping a
        stale ``down_since`` would make the dashboard claim a service is down
        while nobody is checking it. The healthy run is cleared for the same
        reason: on resume the run starts counting again.
        """
        await self.db.execute(
            """
            UPDATE monitor_state SET
                state = ?, consecutive_failures = 0, down_since = NULL,
                up_since = NULL, last_reminder_at = NULL
            WHERE monitor_id = ?
            """,
            (MonitorState.PAUSED.value, monitor_id),
        )


def _coerce(raw: str | None) -> MonitorState:
    try:
        return MonitorState(raw)  # type: ignore[arg-type]
    except ValueError:
        return MonitorState.UNKNOWN
