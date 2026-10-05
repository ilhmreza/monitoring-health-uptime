"""Discord integration: webhook delivery, message building, name resolution."""

from __future__ import annotations

from .embeds import (
    ACTION_EVENT,
    DiscordMessage,
    EmbedBuilder,
    build_allowed_mentions,
    build_message,
    channel_mention,
    event_for_action,
    mention_prefix,
    valid_snowflakes,
)
from .resolve import DiscordResolver, ResolveError, ResolveResult
from .webhook import DeliveryResult, WebhookClient, WebhookNotConfigured

__all__ = [
    "ACTION_EVENT",
    "DeliveryResult",
    "DiscordMessage",
    "DiscordResolver",
    "EmbedBuilder",
    "ResolveError",
    "ResolveResult",
    "WebhookClient",
    "WebhookNotConfigured",
    "build_allowed_mentions",
    "build_message",
    "channel_mention",
    "event_for_action",
    "mention_prefix",
    "valid_snowflakes",
]
