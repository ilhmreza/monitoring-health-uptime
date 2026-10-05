"""Monitor configuration CRUD."""

from __future__ import annotations

import re
from typing import Any

import aiosqlite

from ..models import Monitor, MonitorState, MonitorWithState, NotifyEvent
from .database import Database, dumps, from_iso, loads, to_iso, utcnow

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_SLUG_STRIP = re.compile(r"[^a-z0-9._-]+")


class ValidationError(ValueError):
    """Monitor input rejected before it reaches the database."""


def slugify_id(raw: str) -> str:
    """Normalise a monitor id to a URL-safe, storable form."""
    cleaned = _SLUG_STRIP.sub("-", raw.strip().lower()).strip("-.")
    if not cleaned:
        raise ValidationError("id monitor tidak boleh kosong")
    if not _ID_RE.match(cleaned):
        raise ValidationError(
            "id monitor harus diawali huruf/angka dan hanya boleh berisi a-z, 0-9, '.', '_', '-'"
        )
    return cleaned[:64]


def _row_to_monitor(row: aiosqlite.Row) -> Monitor:
    return Monitor(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        method=row["method"],
        expect_status=loads(row["expect_status"], [200]),
        headers_env=loads(row["headers_env"], {}),
        keyword=row["keyword"],
        interval_seconds=row["interval_seconds"],
        timeout_seconds=row["timeout_seconds"],
        failure_threshold=row["failure_threshold"],
        notify_user_ids=loads(row["notify_user_ids"], []),
        notify_role_ids=loads(row["notify_role_ids"], []),
        notify_on=[NotifyEvent(v) for v in loads(row["notify_on"], ["down", "recovery", "ssl"])],
        ssl_check=bool(row["ssl_check"]),
        ssl_warn_days=loads(row["ssl_warn_days"], [30, 14, 7, 1]),
        allow_private_network=bool(row["allow_private_network"]),
        enabled=bool(row["enabled"]),
        created_at=from_iso(row["created_at"]),
        updated_at=from_iso(row["updated_at"]),
    )


_COLUMNS = (
    "id, name, url, method, expect_status, headers_env, keyword, interval_seconds, "
    "timeout_seconds, failure_threshold, notify_user_ids, notify_role_ids, notify_on, "
    "ssl_check, ssl_warn_days, allow_private_network, enabled, created_at, updated_at"
)


class MonitorRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ----- reads -----------------------------------------------------------

    async def get(self, monitor_id: str) -> Monitor | None:
        row = await self.db.fetch_one("SELECT * FROM monitors WHERE id = ?", (monitor_id,))
        return _row_to_monitor(row) if row else None

    async def list_all(self) -> list[Monitor]:
        rows = await self.db.fetch_all("SELECT * FROM monitors ORDER BY name COLLATE NOCASE")
        return [_row_to_monitor(r) for r in rows]

    async def list_enabled(self) -> list[Monitor]:
        rows = await self.db.fetch_all(
            "SELECT * FROM monitors WHERE enabled = 1 ORDER BY name COLLATE NOCASE"
        )
        return [_row_to_monitor(r) for r in rows]

    async def list_with_state(self) -> list[MonitorWithState]:
        """Monitors joined with their runtime state, for the dashboard.

        LEFT JOIN because a monitor created seconds ago may not have a state
        row yet; the UI renders that as 'unknown' rather than dropping it.
        """
        rows = await self.db.fetch_all(
            """
            SELECT m.*, s.state AS st_state, s.consecutive_failures AS st_failures,
                   s.down_since AS st_down_since, s.up_since AS st_up_since,
                   s.last_check_at AS st_last_check,
                   s.last_ok_at AS st_last_ok, s.last_reminder_at AS st_last_reminder,
                   s.last_alert_at AS st_last_alert,
                   s.ssl_notified_severity AS st_ssl_sev
            FROM monitors m
            LEFT JOIN monitor_state s ON s.monitor_id = m.id
            ORDER BY m.name COLLATE NOCASE
            """
        )
        return [_row_to_monitor_with_state(r) for r in rows]

    # ----- writes ----------------------------------------------------------

    async def create(self, monitor: Monitor) -> Monitor:
        if await self.get(monitor.id) is not None:
            raise ValidationError(f"monitor dengan id '{monitor.id}' sudah ada")
        now = to_iso(utcnow())
        await self.db.execute(
            f"""
            INSERT INTO monitors ({_COLUMNS})
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                monitor.id,
                monitor.name,
                monitor.url,
                monitor.method,
                dumps(monitor.expect_status),
                dumps(monitor.headers_env),
                monitor.keyword,
                monitor.interval_seconds,
                monitor.timeout_seconds,
                monitor.failure_threshold,
                dumps(monitor.notify_user_ids),
                dumps(monitor.notify_role_ids),
                dumps([e.value for e in monitor.notify_on]),
                int(monitor.ssl_check),
                dumps(monitor.ssl_warn_days),
                int(monitor.allow_private_network),
                int(monitor.enabled),
                now,
                now,
            ),
        )
        # A state row always exists, so the scheduler never has to handle
        # "no row" as a special case.
        await self.db.execute(
            "INSERT OR IGNORE INTO monitor_state (monitor_id) VALUES (?)", (monitor.id,)
        )
        created = await self.get(monitor.id)
        assert created is not None
        return created

    async def update(self, monitor: Monitor) -> Monitor:
        await self.db.execute(
            f"""
            UPDATE monitors SET
                name=?, url=?, method=?, expect_status=?, headers_env=?, keyword=?,
                interval_seconds=?, timeout_seconds=?, failure_threshold=?,
                notify_user_ids=?, notify_role_ids=?, notify_on=?, ssl_check=?,
                ssl_warn_days=?, allow_private_network=?, enabled=?, updated_at=?
            WHERE id=?
            """,
            (
                monitor.name,
                monitor.url,
                monitor.method,
                dumps(monitor.expect_status),
                dumps(monitor.headers_env),
                monitor.keyword,
                monitor.interval_seconds,
                monitor.timeout_seconds,
                monitor.failure_threshold,
                dumps(monitor.notify_user_ids),
                dumps(monitor.notify_role_ids),
                dumps([e.value for e in monitor.notify_on]),
                int(monitor.ssl_check),
                dumps(monitor.ssl_warn_days),
                int(monitor.allow_private_network),
                int(monitor.enabled),
                to_iso(utcnow()),
                monitor.id,
            ),
        )
        updated = await self.get(monitor.id)
        assert updated is not None
        return updated

    async def set_enabled(self, monitor_id: str, enabled: bool) -> None:
        await self.db.execute(
            "UPDATE monitors SET enabled = ?, updated_at = ? WHERE id = ?",
            (int(enabled), to_iso(utcnow()), monitor_id),
        )

    async def delete(self, monitor_id: str) -> bool:
        """Remove a monitor. Cascades to state, checks and SSL rows."""
        cursor = await self.db.conn.execute("DELETE FROM monitors WHERE id = ?", (monitor_id,))
        return bool(cursor.rowcount)

    async def count(self) -> int:
        return int(await self.db.scalar("SELECT COUNT(*) FROM monitors", default=0))


def _coerce_state(raw: Any) -> MonitorState:
    try:
        return MonitorState(raw)
    except ValueError:
        return MonitorState.UNKNOWN


def _row_to_monitor_with_state(row: aiosqlite.Row) -> MonitorWithState:
    """Build a dashboard view from the monitors LEFT JOIN monitor_state query.

    Every ``st_*`` column is nullable, both because the join can miss and
    because the columns themselves are NULL before the first check.
    """
    def opt(key: str) -> Any:
        return row[key] if key in row.keys() else None

    return MonitorWithState(
        monitor=_row_to_monitor(row),
        state=_coerce_state(opt("st_state")),
        consecutive_failures=opt("st_failures") or 0,
        down_since=from_iso(opt("st_down_since")),
        up_since=from_iso(opt("st_up_since")),
        last_check_at=from_iso(opt("st_last_check")),
        last_ok_at=from_iso(opt("st_last_ok")),
        last_reminder_at=from_iso(opt("st_last_reminder")),
        last_alert_at=from_iso(opt("st_last_alert")),
        ssl_notified_severity=opt("st_ssl_sev") or 0,
    )
