"""Audit trail for configuration changes.

A UI that can disable a monitor or retarget its alerts is a UI worth being
able to audit after the fact.
"""

from __future__ import annotations

from typing import Any

from .database import Database, dumps, from_iso, to_iso, utcnow


class AuditRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def record(
        self, actor: str, action: str, target: str | None = None, detail: Any = None
    ) -> None:
        await self.db.execute(
            "INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (to_iso(utcnow()), actor, action, target, dumps(detail) if detail else None),
        )

    async def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = await self.db.fetch_all(
            "SELECT ts, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                # Parsed, not the raw string: the template formats it as UTC.
                "ts": from_iso(r["ts"]),
                "actor": r["actor"],
                "action": r["action"],
                "target": r["target"],
                "monitor_id": r["target"],
                "detail": r["detail"],
            }
            for r in rows
        ]
