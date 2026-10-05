"""Resolve ``@username`` to a numeric Discord user ID.

A webhook cannot look up guild members — it has no identity of its own. So
resolution uses a bot token against a deliberately narrow permission set.

Why message history works: the bot needs only ``View Channel`` and
``Read Message History`` in the reporting channel. Reading the last N
messages yields every mentioned user plus every author, which is normally
enough to map a name to an ID. This avoids the ``GUILD_MEMBERS`` privileged
intent, which would need verification in the developer portal.

Nothing here is load-bearing: if the bot is missing, offline, or the user has
never posted in that channel, resolution fails softly and the UI falls back
to manual ID entry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

log = logging.getLogger(__name__)

API_BASE = "https://discord.com/api/v10"
REQUEST_TIMEOUT = 15.0

# One page is the maximum Discord allows.
HISTORY_LIMIT = 100
# Two pages cover a busy channel without hammering the API.
DEFAULT_PAGES = 2

# Never let a scan grow the cache without bound.
MAX_CACHED_USERS = 2000


class ResolveError(RuntimeError):
    """Username could not be resolved; the UI should fall back to manual IDs."""


@dataclass(slots=True)
class ResolveResult:
    user_id: str
    username: str
    global_name: str | None = None
    matched: int = 1
    candidates: list[dict[str, str]] = field(default_factory=list)


class DiscordResolver:
    """Builds a username -> ID map from channel message history."""

    def __init__(
        self,
        *,
        bot_token: str,
        guild_id: str,
        channel_id: str | None,
        client: httpx.AsyncClient | None = None,
        pages: int = DEFAULT_PAGES,
    ) -> None:
        self._token = bot_token
        self._guild_id = guild_id
        self._channel_id = channel_id
        self._client = client
        self._owns_client = client is None
        self._pages = max(1, min(pages, 5))
        self._cache: dict[str, dict[str, str]] = {}

    @property
    def configured(self) -> bool:
        return bool(self._token and self._guild_id and self._channel_id)

    @property
    def channel_id(self) -> str:
        return self._channel_id or ""

    def cached(self) -> dict[str, dict[str, str]]:
        return dict(self._cache)

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(REQUEST_TIMEOUT),
                trust_env=False,
                follow_redirects=True,
                headers={
                    "Authorization": f"Bot {self._token}",
                    "User-Agent": "DiscordBot (https://github.com/, 1.0)",
                },
            )
            self._owns_client = True
        return self._client

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    # ----- resolution ------------------------------------------------------

    async def refresh(self) -> list[dict[str, Any]]:
        """Scan recent history and return every user found.

        Returned rows are ready to upsert into ``discord_users`` so the UI can
        autocomplete even while Discord is unreachable.
        """
        if not self.configured:
            raise ResolveError(
                "DISCORD_BOT_TOKEN / DISCORD_GUILD_ID / DISCORD_REPORT_CHANNEL_ID belum lengkap"
            )
        client = self._ensure_client()
        found: dict[str, dict[str, Any]] = {}
        before: str | None = None

        for page in range(self._pages):
            url = f"{API_BASE}/channels/{self._channel_id}/messages"
            params: dict[str, Any] = {"limit": HISTORY_LIMIT}
            if before:
                params["before"] = before
            try:
                response = await client.get(url, params=params)
            except httpx.HTTPError as exc:
                raise ResolveError(f"Gagal menghubungi Discord: {exc}") from exc

            if response.status_code in (403, 401):
                raise ResolveError(
                    f"Discord menolak akses (HTTP {response.status_code}). "
                    "Pastikan bot ada di server dan punya izin View Channel + "
                    "Read Message History di channel reporting."
                )
            if response.status_code == 404:
                raise ResolveError(
                    "Channel tidak ditemukan. Periksa DISCORD_REPORT_CHANNEL_ID."
                )
            if response.status_code == 429:
                raise ResolveError("Discord rate limit. Coba lagi beberapa saat lagi.")
            if response.status_code >= 400:
                raise ResolveError(f"Discord API error HTTP {response.status_code}")

            try:
                messages = response.json()
            except ValueError as exc:
                raise ResolveError("Respons Discord tidak valid") from exc
            if not isinstance(messages, list) or not messages:
                break

            for message in messages:
                if not isinstance(message, dict):
                    continue
                for user in _users_in_message(message):
                    found.setdefault(str(user["id"]), user)

            last_id = messages[-1].get("id") if isinstance(messages[-1], dict) else None
            if not last_id or last_id == before:
                break
            before = str(last_id)
            log.debug("scanned page %s of channel history (%s users so far)", page + 1, len(found))

        if not found:
            raise ResolveError(
                "Tidak ada pengguna yang bisa dibaca dari riwayat channel. "
                "Coba mention PIC di channel tersebut sekali, lalu ulangi."
            )

        rows = list(found.values())[:MAX_CACHED_USERS]
        self._cache = {
            str(u["id"]): {
                "user_id": str(u["id"]),
                "username": str(u.get("username") or ""),
                "global_name": u.get("global_name"),
            }
            for u in rows
            if u.get("username")
        }
        log.info("resolved %s Discord users from channel history", len(self._cache))
        return [
            {
                "id": str(u["id"]),
                "username": str(u.get("username") or ""),
                "global_name": u.get("global_name"),
            }
            for u in rows
            if u.get("username")
        ]

    async def resolve(self, query: str) -> ResolveResult:
        """Find the best match for a name the user typed.

        Matches on username first, then display name, and refuses to guess
        when two people share a name: a wrong ID means a wrong human gets
        paged at 3am.
        """
        needle = (query or "").strip().lstrip("@").lower()
        if not needle:
            raise ResolveError("Nama tidak boleh kosong")
        if not self._cache:
            await self.refresh()

        by_username: dict[str, list[dict[str, str]]] = {}
        by_global: dict[str, list[dict[str, str]]] = {}
        for entry in self._cache.values():
            by_username.setdefault(entry["username"].lower(), []).append(entry)
            if entry.get("global_name"):
                by_global.setdefault(str(entry["global_name"]).lower(), []).append(entry)

        # Exact match on username, then on display name, then prefix matches.
        matches = by_username.get(needle, []) or by_global.get(needle, [])
        if not matches:
            matches = [
                entry
                for index_map in (by_username, by_global)
                for name, entries in index_map.items()
                if name.startswith(needle)
                for entry in entries
            ]

        if not matches:
            raise ResolveError(
                f"'{query}' tidak ditemukan di riwayat channel. "
                "Coba User ID manual, atau mention orang tersebut di channel reporting."
            )
        if len(matches) > 1:
            names = ", ".join(sorted(f"@{m['username']}" for m in matches[:5]))
            raise ResolveError(
                f"'{query}' cocok dengan lebih dari satu orang ({names}). "
                "Pakai User ID manual agar tidak salah mention."
            )

        best = matches[0]
        return ResolveResult(
            user_id=best["user_id"],
            username=best["username"],
            global_name=best.get("global_name"),
            matched=len(matches),
            candidates=matches,
        )

    async def find(self, query: str) -> list[dict[str, str]]:
        """Autocomplete helper: best-effort prefix search, never raises."""
        needle = (query or "").strip().lstrip("@").lower()
        if not needle:
            return []
        if not self._cache:
            try:
                await self.refresh()
            except ResolveError as exc:
                log.debug("autocomplete refresh failed: %s", exc)
                return []
        scored: list[tuple[int, str, dict[str, str]]] = []
        for entry in self._cache.values():
            username = entry["username"].lower()
            global_name = str(entry.get("global_name") or "").lower()
            if username.startswith(needle):
                score = 0 if username == needle else 1
                scored.append((score, entry["username"], entry))
            elif global_name.startswith(needle):
                scored.append((2, entry["username"], entry))
        scored.sort(key=lambda item: (item[0], item[1].lower()))
        return [entry for _score, _name, entry in scored[:10]]


def _users_in_message(message: dict[str, Any]) -> list[dict[str, Any]]:
    """Every mentionable user in a message: its mentions, plus a real author.

    A webhook is not a person. Its messages carry ``webhook_id`` at the message
    level, and ``<@webhook_id>`` alerts nobody, so the webhook author is dropped.
    Mentions inside those messages are kept on purpose: mentioning a PIC inside
    a bot alert is exactly how these channels reveal who to page.
    """
    out: list[dict[str, Any]] = []
    author = message.get("author")
    if not message.get("webhook_id") and isinstance(author, dict) and author.get("id"):
        out.append(author)
    mentions = message.get("mentions")
    if isinstance(mentions, list):
        for mention in mentions:
            if isinstance(mention, dict) and mention.get("id"):
                out.append(mention)
    return out
