"""Web admin account and Discord username resolution cache."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import aiosqlite

from .database import Database, from_iso, to_iso, utcnow


class UserRepo:
    """Single admin account.

    The bcrypt hash from ``UI_PASSWORD_HASH`` wins when set, so a deployment
    can be sealed by environment alone; the table exists so the password can
    also be rotated from the UI.
    """

    def __init__(self, db: Database) -> None:
        self.db = db

    async def get_hash(self, username: str) -> str | None:
        row = await self.db.fetch_one(
            "SELECT password_hash FROM web_user WHERE username = ?", (username,)
        )
        return row["password_hash"] if row else None

    async def set_hash(self, username: str, password_hash: str) -> None:
        now = to_iso(utcnow())
        await self.db.execute(
            """
            INSERT INTO web_user (username, password_hash, created_at, updated_at)
            VALUES (?,?,?,?)
            ON CONFLICT(username) DO UPDATE SET
                password_hash = excluded.password_hash,
                updated_at = excluded.updated_at
            """,
            (username, password_hash, now, now),
        )


class DiscordUserRepo:
    """Cache mapping Discord usernames to numeric user IDs.

    Kept as a table rather than in memory so a container restart does not
    force another round trip to Discord, and so the UI can still autocomplete
    while Discord is unreachable.
    """

    def __init__(self, db: Database) -> None:
        self.db = db

    async def upsert_many(self, users: list[dict[str, Any]], source_channel: str) -> int:
        if not users:
            return 0
        now = to_iso(utcnow())
        rows = [
            (
                str(u["id"]),
                str(u.get("username") or ""),
                u.get("global_name"),
                source_channel,
                now,
            )
            for u in users
            if u.get("id") and u.get("username")
        ]
        if not rows:
            return 0
        await self.db.executemany(
            """
            INSERT INTO discord_users
                (user_id, username, global_name, source_channel, resolved_at)
            VALUES (?,?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                global_name = excluded.global_name,
                source_channel = excluded.source_channel,
                resolved_at = excluded.resolved_at
            """,
            rows,
        )
        return len(rows)

    async def search(self, query: str, limit: int = 10) -> list[dict[str, str]]:
        """Prefix search, case-insensitive, for the @username autocomplete."""
        pattern = f"{query.lower()}%"
        rows = await self.db.fetch_all(
            """
            SELECT user_id, username, global_name FROM discord_users
            WHERE username LIKE ? COLLATE NOCASE
            ORDER BY
                CASE WHEN username = ? COLLATE NOCASE THEN 0 ELSE 1 END,
                username COLLATE NOCASE
            LIMIT ?
            """,
            (pattern, query, limit),
        )
        return [_user_dict(r) for r in rows]

    async def count(self) -> int:
        return int(await self.db.scalar("SELECT COUNT(*) FROM discord_users", default=0))

    async def all_users(self, limit: int = 500) -> list[dict[str, str]]:
        rows = await self.db.fetch_all(
            "SELECT user_id, username, global_name FROM discord_users "
            "ORDER BY username COLLATE NOCASE LIMIT ?",
            (limit,),
        )
        return [_user_dict(r) for r in rows]


class SslStateRepo:
    """Persisted certificate facts, so the UI never triggers a TLS handshake."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def upsert(
        self,
        monitor_id: str,
        *,
        not_after: datetime | None,
        days_left: int | None,
        issuer: str | None,
        subject_cn: str | None,
        tls_version: str | None,
        chain_ok: bool | None,
        checked_at: datetime | None,
        error: str | None,
        severity: int = 0,
    ) -> None:
        await self.db.execute(
            """
            INSERT INTO ssl_state
                (monitor_id, not_after, days_left, issuer, subject_cn, tls_version,
                 chain_ok, last_checked, last_error, severity)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(monitor_id) DO UPDATE SET
                not_after = excluded.not_after,
                days_left = excluded.days_left,
                issuer = excluded.issuer,
                subject_cn = excluded.subject_cn,
                tls_version = excluded.tls_version,
                chain_ok = excluded.chain_ok,
                last_checked = excluded.last_checked,
                last_error = excluded.last_error,
                severity = excluded.severity
            """,
            (
                monitor_id,
                to_iso(not_after),
                days_left,
                issuer,
                subject_cn,
                tls_version,
                None if chain_ok is None else int(chain_ok),
                to_iso(checked_at),
                error,
                severity,
            ),
        )

    async def get(self, monitor_id: str) -> dict[str, Any] | None:
        row = await self.db.fetch_one("SELECT * FROM ssl_state WHERE monitor_id = ?", (monitor_id,))
        return _ssl_dict(row) if row else None

    async def list_all(self) -> list[dict[str, Any]]:
        """Every known certificate, joined with the monitor name for the table."""
        rows = await self.db.fetch_all(
            """
            SELECT s.*, m.name AS monitor_name, m.url AS monitor_url, m.enabled AS monitor_enabled
            FROM ssl_state s
            JOIN monitors m ON m.id = s.monitor_id
            ORDER BY s.days_left IS NULL, s.days_left ASC
            """
        )
        return [_ssl_dict(r) for r in rows]


def _ssl_dict(row: aiosqlite.Row) -> dict[str, Any]:
    keys = row.keys()
    url = row["monitor_url"] if "monitor_url" in keys else None
    host = None
    if url:
        try:
            host = (urlsplit(url).hostname or "").lower() or None
        except ValueError:
            host = None
    return {
        "monitor_id": row["monitor_id"],
        "monitor_name": row["monitor_name"] if "monitor_name" in keys else None,
        "monitor_url": url,
        "monitor_enabled": bool(row["monitor_enabled"]) if "monitor_enabled" in keys else None,
        "host": host,
        "not_after": from_iso(row["not_after"]),
        "days_left": row["days_left"],
        "issuer": row["issuer"],
        "subject_cn": row["subject_cn"],
        "tls_version": row["tls_version"],
        "chain_ok": None if row["chain_ok"] is None else bool(row["chain_ok"]),
        "severity": row["severity"] or 0,
        # ``last_checked`` in SQL, ``last_checked_at`` in the templates.
        "last_checked_at": from_iso(row["last_checked"]),
        "last_error": row["last_error"],
    }


def _user_dict(row: aiosqlite.Row) -> dict[str, str]:
    return {
        "user_id": row["user_id"],
        "username": row["username"],
        "global_name": row["global_name"] or row["username"],
    }
