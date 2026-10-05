"""The username-to-ID resolver built from channel history.

The regression this file exists for: a webhook-authored message used to be
counted as a person, so the monitor form offered the webhook as a notify target
and ``<@webhook_id>`` would have paged nobody. The messages carry the webhook id
at the message level, so that is what gets filtered.
"""

from __future__ import annotations

import httpx
import pytest

from uptimebot.discord.resolve import DiscordResolver, ResolveError, _users_in_message

TOKEN = "token"
GUILD = "1001"
CHANNEL = "2002"
# A fixture, never a real Discord id: this value is compared for equality only,
# so any placeholder works and nothing here can leak a live webhook.
WEBHOOK_ID = "webhook-fixture-id"


def _author(user_id: str, username: str, global_name: str | None = None, bot: bool = False) -> dict:
    return {
        "id": user_id,
        "username": username,
        "global_name": global_name,
        "bot": bot,
        "discriminator": "0" if not bot else "0000",
    }


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _resolver(handler, **kwargs) -> DiscordResolver:
    defaults = {"bot_token": TOKEN, "guild_id": GUILD, "channel_id": CHANNEL}
    defaults.update(kwargs)
    return DiscordResolver(client=_client(handler), **defaults)


def test_users_in_message_drops_a_webhook_author_but_keeps_its_mentions() -> None:
    """The webhook is not a person; the humans it mentions still are.

    Mentions inside a bot alert are the usual way a PIC enters this map, so
    dropping the whole message would defeat the documented workflow.
    """
    message = {
        "webhook_id": WEBHOOK_ID,
        "author": _author(WEBHOOK_ID, "UptimeBot", bot=True),
        "mentions": [_author("77", "rina")],
    }

    users = _users_in_message(message)

    assert [u["id"] for u in users] == ["77"]


def test_users_in_message_collects_author_and_mentions() -> None:
    message = {
        "author": _author("1", "budi"),
        "mentions": [_author("2", "siti")],
    }

    users = _users_in_message(message)

    assert [u["id"] for u in users] == ["1", "2"]


def test_users_in_message_tolerates_missing_parts() -> None:
    assert _users_in_message({}) == []
    assert _users_in_message({"author": {"username": "no-id"}}) == []
    assert _users_in_message({"mentions": "not-a-list"}) == []


def test_refresh_skips_webhook_authored_messages() -> None:
    pages = [
        [
            {
                "id": "900",
                "webhook_id": WEBHOOK_ID,
                "author": _author(WEBHOOK_ID, "UptimeBot", bot=True),
                "mentions": [],
            }
        ]
    ]

    async def handler(request: httpx.Request) -> httpx.Response:
        body = pages.pop(0) if pages else []
        return httpx.Response(200, json=body)

    resolver = _resolver(handler)

    async def run():
        return await resolver.refresh()

    import asyncio

    with pytest.raises(ResolveError) as caught:
        asyncio.run(run())

    # Nothing mentionable was left, and the message says what to do about it.
    assert "mention" in str(caught.value).lower()


def test_refresh_keeps_people_from_webhook_message_mentions() -> None:
    """The filter is on authorship, not on the whole message.

    A webhook posting an alert that mentions a human is exactly how these
    channels look in practice, so the mentioned human must survive.
    """
    body = [
        {
            "id": "901",
            "webhook_id": WEBHOOK_ID,
            "author": _author(WEBHOOK_ID, "UptimeBot", bot=True),
            "mentions": [_author("77", "rina", global_name="Rina S")],
        }
    ]

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body if request.url.params.get("before") is None else [])

    resolver = _resolver(handler)

    import asyncio

    rows = asyncio.run(resolver.refresh())

    assert [r["id"] for r in rows] == ["77"]
    assert rows[0]["username"] == "rina"


def test_refresh_keeps_real_bots() -> None:
    """A real bot member is not a webhook and stays a valid target."""
    body = [{"id": "902", "author": _author("88", "ci-runner", bot=True), "mentions": []}]

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body if request.url.params.get("before") is None else [])

    resolver = _resolver(handler)

    import asyncio

    rows = asyncio.run(resolver.refresh())

    assert [r["id"] for r in rows] == ["88"]


def test_configured_needs_all_three() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        return httpx.Response(200, json=[])

    assert _resolver(handler).configured is True
    assert _resolver(handler, bot_token="").configured is False
    assert _resolver(handler, guild_id="").configured is False
    assert _resolver(handler, channel_id="").configured is False


def test_refresh_reports_forbidden_with_the_permission_hint() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Missing Access"})

    resolver = _resolver(handler)

    import asyncio

    with pytest.raises(ResolveError) as caught:
        asyncio.run(resolver.refresh())

    assert "403" in str(caught.value)
    assert "Read Message History" in str(caught.value)


def test_refresh_reports_missing_channel() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Unknown Channel"})

    resolver = _resolver(handler)

    import asyncio

    with pytest.raises(ResolveError) as caught:
        asyncio.run(resolver.refresh())

    assert "DISCORD_REPORT_CHANNEL_ID" in str(caught.value)


def test_refresh_tolerates_rate_limit() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "You are being rate limited."})

    resolver = _resolver(handler)

    import asyncio

    with pytest.raises(ResolveError) as caught:
        asyncio.run(resolver.refresh())

    assert "rate limit" in str(caught.value).lower()


def test_resolve_refuses_to_guess_between_two_people() -> None:
    """Paging the wrong human at 3am is worse than not paging at all."""
    resolver = DiscordResolver(bot_token=TOKEN, guild_id=GUILD, channel_id=CHANNEL)
    resolver._cache = {
        "1": {"user_id": "1", "username": "budi.santoso", "global_name": "Budi S"},
        "2": {"user_id": "2", "username": "budi.saputra", "global_name": "Budi P"},
    }

    import asyncio

    with pytest.raises(ResolveError) as caught:
        asyncio.run(resolver.resolve("budi"))

    assert "lebih dari satu" in str(caught.value)


def test_resolve_prefers_an_exact_username_over_a_prefix() -> None:
    """An exact hit is unambiguous, so the prefix collision must not block it."""
    resolver = DiscordResolver(bot_token=TOKEN, guild_id=GUILD, channel_id=CHANNEL)
    resolver._cache = {
        "1": {"user_id": "1", "username": "budi", "global_name": "Budi"},
        "2": {"user_id": "2", "username": "budi.santoso", "global_name": "Budi S"},
    }

    import asyncio

    assert asyncio.run(resolver.resolve("budi")).user_id == "1"


def test_resolve_matches_username_then_display_name() -> None:
    resolver = DiscordResolver(bot_token=TOKEN, guild_id=GUILD, channel_id=CHANNEL)
    resolver._cache = {
        "1": {"user_id": "1", "username": "rina", "global_name": "Rina Statistik"},
    }

    import asyncio

    by_username = asyncio.run(resolver.resolve("rina"))
    by_display = asyncio.run(resolver.resolve("Rina Statistik"))

    assert by_username.user_id == "1"
    assert by_display.user_id == "1"


def test_find_is_best_effort_and_never_raises() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Missing Access"})

    resolver = _resolver(handler)

    import asyncio

    assert asyncio.run(resolver.find("apa saja")) == []


def test_find_rejects_empty_query_without_calling_the_api() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("API should not be called for an empty query")

    resolver = _resolver(handler)

    import asyncio

    assert asyncio.run(resolver.find("  ")) == []