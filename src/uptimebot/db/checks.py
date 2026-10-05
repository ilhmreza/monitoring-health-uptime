"""Probe history: writes, aggregates and chart buckets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import ceil

from ..models import CheckResult, LatencyBucket, UptimeStats
from .database import Database, from_iso, to_iso, utcnow

UTC = timezone.utc


@dataclass(slots=True)
class FailedProbe:
    """One recorded failure, as shown in the incident list."""

    ts: datetime
    status_code: int | None = None
    error: str | None = None
    latency_ms: float | None = None
    failure_kind: str = "unknown"


class CheckRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def record(self, monitor_id: str, result: CheckResult) -> None:
        # A failed probe has no response, so latency is NULL rather than 0 —
        # rounding it unconditionally would raise on the first outage, which is
        # exactly when the history matters most.
        latency = result.latency_ms
        await self.db.execute(
            """
            INSERT INTO checks (monitor_id, ts, ok, status_code, latency_ms, error, failure_kind)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                monitor_id,
                to_iso(result.checked_at),
                int(result.ok),
                result.status_code,
                round(latency, 2) if latency is not None else None,
                result.error,
                result.failure_kind.value,
            ),
        )

    async def stats(self, monitor_id: str, window: timedelta, label: str) -> UptimeStats:
        """Uptime percentage and latency percentiles over a trailing window.

        p95 is computed in Python rather than SQL because SQLite has no
        ``PERCENTILE`` function; the row count per monitor per day is small
        (a 30 s interval is 2880 rows), so this stays cheap.
        """
        since = to_iso(utcnow() - window)
        rows = await self.db.fetch_all(
            """
            SELECT ok, latency_ms FROM checks
            WHERE monitor_id = ? AND ts >= ?
            ORDER BY ts
            """,
            (monitor_id, since),
        )
        if not rows:
            return UptimeStats(window_label=label)

        total = len(rows)
        successful = sum(1 for r in rows if r["ok"])
        latencies = sorted(r["latency_ms"] for r in rows if r["ok"] and r["latency_ms"] is not None)

        return UptimeStats(
            window_label=label,
            total=total,
            successful=successful,
            avg_latency_ms=(sum(latencies) / len(latencies)) if latencies else None,
            p95_latency_ms=_percentile(latencies, 0.95),
        )

    async def buckets(
        self, monitor_id: str, window: timedelta, target_points: int = 96
    ) -> list[LatencyBucket]:
        """Aggregate history into fixed-width buckets for the chart.

        Aggregating server-side keeps the payload at a fixed size regardless
        of interval and retention: a 7-day view at 30 s would otherwise be
        20k rows.
        """
        since = utcnow() - window
        since_iso = to_iso(since)
        rows = await self.db.fetch_all(
            "SELECT ts, ok, latency_ms FROM checks WHERE monitor_id = ? AND ts >= ? ORDER BY ts",
            (monitor_id, since_iso),
        )
        if not rows:
            return []

        width_seconds = max(1, int(ceil(window.total_seconds() / max(target_points, 1))))
        width = timedelta(seconds=width_seconds)
        epoch = datetime(1970, 1, 1, tzinfo=UTC)

        grouped: dict[datetime, list[tuple[bool, float | None]]] = {}
        for row in rows:
            moment = from_iso(row["ts"])
            if moment is None:
                continue
            offset = int((moment - epoch).total_seconds())
            edge = epoch + timedelta(seconds=(offset // width_seconds) * width_seconds)
            grouped.setdefault(edge, []).append((bool(row["ok"]), row["latency_ms"]))

        out: list[LatencyBucket] = []
        for edge in sorted(grouped):
            samples = grouped[edge]
            good = [lat for ok, lat in samples if ok and lat is not None]
            out.append(
                LatencyBucket(
                    bucket_start=edge,
                    total=len(samples),
                    successful=sum(1 for ok, _ in samples if ok),
                    avg_latency_ms=(sum(good) / len(good)) if good else None,
                )
            )
        return out

    async def recent_failures(
        self, monitor_id: str, limit: int = 10
    ) -> list[FailedProbe]:
        """Most recent failed probes, newest first, for the incident list."""
        rows = await self.db.fetch_all(
            """
            SELECT ts, status_code, error, latency_ms, failure_kind FROM checks
            WHERE monitor_id = ? AND ok = 0
            ORDER BY ts DESC LIMIT ?
            """,
            (monitor_id, limit),
        )
        out: list[FailedProbe] = []
        for row in rows:
            moment = from_iso(row["ts"])
            if moment is not None:
                out.append(
                    FailedProbe(
                        ts=moment,
                        status_code=row["status_code"],
                        error=row["error"],
                        latency_ms=row["latency_ms"],
                        failure_kind=row["failure_kind"] or "unknown",
                    )
                )
        return out

    async def total_rows(self) -> int:
        return int(await self.db.scalar("SELECT COUNT(*) FROM checks", default=0))

    async def aggregates_for_all(self, window: timedelta) -> dict[str, dict]:
        """24-hour aggregates for every monitor in one pass.

        The dashboard needs this for all rows at once, so computing it per
        monitor would issue N queries on every 5-second poll.
        """
        since = to_iso(utcnow() - window)
        rows = await self.db.fetch_all(
            """
            SELECT monitor_id,
                   COUNT(*)                    AS total,
                   SUM(ok)                     AS successful,
                   AVG(CASE WHEN ok = 1 THEN latency_ms END) AS avg_latency
            FROM checks
            WHERE ts >= ?
            GROUP BY monitor_id
            """,
            (since,),
        )
        out: dict[str, dict] = {}
        for row in rows:
            total = row["total"] or 0
            successful = row["successful"] or 0
            out[row["monitor_id"]] = {
                "total": total,
                "successful": successful,
                "uptime_percent": (successful / total * 100.0) if total else None,
                "avg_latency_ms": row["avg_latency"],
            }
        return out

    async def latest_per_monitor(self) -> dict[str, dict]:
        """The most recent probe for each monitor.

        Uses a join on ``MAX(ts)`` rather than a correlated subquery per row,
        so it stays a single indexed scan as history grows.
        """
        rows = await self.db.fetch_all(
            """
            SELECT c.monitor_id, c.ts, c.ok, c.latency_ms, c.status_code
            FROM checks c
            JOIN (
                SELECT monitor_id, MAX(ts) AS latest_ts
                FROM checks
                GROUP BY monitor_id
            ) newest
              ON c.monitor_id = newest.monitor_id
             AND c.ts = newest.latest_ts
            """
        )
        out: dict[str, dict] = {}
        for row in rows:
            # Two rows can share a timestamp when a monitor is polled on the
            # same tick; prefer the successful one rather than either.
            candidate = {
                "ts": from_iso(row["ts"]),
                "ok": bool(row["ok"]),
                "latency_ms": row["latency_ms"],
                "status_code": row["status_code"],
            }
            existing = out.get(row["monitor_id"])
            if existing is None or (candidate["ok"] and not existing["ok"]):
                out[row["monitor_id"]] = candidate
        return out


def _percentile(sorted_values: list[float], fraction: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = fraction * (len(sorted_values) - 1)
    low = int(position)
    high = min(low + 1, len(sorted_values) - 1)
    weight = position - low
    return sorted_values[low] * (1 - weight) + sorted_values[high] * weight
