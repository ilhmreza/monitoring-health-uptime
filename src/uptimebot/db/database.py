"""SQLite access layer.

The monitor loop and the web UI share one connection. ``aiosqlite`` runs every
statement on a worker thread, so the event loop is never blocked, and a single
connection means queries serialise naturally instead of racing for the write
lock (WAL still gives us concurrent readers).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import aiosqlite

log = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

UTC = timezone.utc


def to_iso(moment: datetime | None) -> str | None:
    """Serialise a datetime to a sortable UTC string."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def from_iso(value: str | None) -> datetime | None:
    """Parse a stored timestamp back into an aware UTC datetime."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        log.warning("unparseable timestamp in database: %r", value)
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        log.warning("corrupt JSON column, using fallback: %r", value)
        return fallback


class Database:
    """Thin async wrapper around aiosqlite."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._conn: aiosqlite.Connection | None = None

    # ----- lifecycle -------------------------------------------------------

    async def connect(self) -> None:
        if self._conn is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path, isolation_level=None)
        self._conn.row_factory = aiosqlite.Row
        await self._apply_pragmas()
        log.info("database ready at %s", self.path)

    async def _apply_pragmas(self) -> None:
        # WAL lets the dashboard read while the scheduler writes.
        await self.conn.execute("PRAGMA journal_mode=WAL")
        # NORMAL is the standard durability/throughput trade-off for WAL and
        # is safe here: a lost tail row on power loss only costs one probe
        # sample, never a state transition.
        await self.conn.execute("PRAGMA synchronous=NORMAL")
        await self.conn.execute("PRAGMA foreign_keys=ON")
        await self.conn.execute("PRAGMA busy_timeout=5000")

    async def init_schema(self) -> None:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        await self.conn.executescript(schema)
        log.info("schema applied")

    async def close(self) -> None:
        if self._conn is None:
            return
        try:
            await self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:  # noqa: BLE001 - best effort on shutdown
            pass
        await self._conn.close()
        self._conn = None
        log.info("database closed")

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("database is not connected; call connect() first")
        return self._conn

    # ----- queries ---------------------------------------------------------

    async def fetch_all(self, sql: str, params: Sequence[Any] = ()) -> list[aiosqlite.Row]:
        async with self.conn.execute(sql, params) as cursor:
            return list(await cursor.fetchall())

    async def fetch_one(self, sql: str, params: Sequence[Any] = ()) -> aiosqlite.Row | None:
        async with self.conn.execute(sql, params) as cursor:
            return await cursor.fetchone()

    async def fetch_value(self, sql: str, params: Sequence[Any] = (), default: Any = None) -> Any:
        row = await self.fetch_one(sql, params)
        if row is None:
            return default
        return row[0]

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        await self.conn.execute(sql, params)

    async def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        await self.conn.executemany(sql, rows)

    async def scalar(self, sql: str, params: Sequence[Any] = (), default: Any = None) -> Any:
        return await self.fetch_value(sql, params, default)

    # ----- maintenance -----------------------------------------------------

    async def prune_checks(self, retention_days: int) -> int:
        """Delete probe samples older than the retention window."""
        boundary = utcnow() - timedelta(days=retention_days)
        cursor = await self.conn.execute(
            "DELETE FROM checks WHERE ts < ?", (to_iso(boundary),)
        )
        deleted = max(cursor.rowcount or 0, 0)
        if deleted:
            log.info("pruned %s check rows older than %s days", deleted, retention_days)
        return deleted

    async def optimize(self) -> None:
        """Refresh query planner statistics; safe to call opportunistically."""
        try:
            await self.conn.execute("PRAGMA optimize")
        except Exception as exc:  # noqa: BLE001 - purely an optimisation
            log.debug("PRAGMA optimize failed: %s", exc)
