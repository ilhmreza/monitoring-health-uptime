"""Discord message construction.

Two rules govern everything here, both of which are easy to get wrong:

1. **A mention only pings if it sits in the top-level ``content`` field.**
   Discord renders mentions inside embeds but never notifies anyone. So
   ``content`` carries the mention plus a fixed sentence, and every piece of
   user-controlled data — monitor name, URL, error text — goes into the
   embed, where it is inert.

2. **``allowed_mentions`` is always explicit, with ``parse: []``.** Monitor
   names come from the web UI, so a monitor literally named ``<@everyone>``
   must not be able to ping a whole server. ``parse`` and ``users``/``roles``
   are mutually exclusive in the API: sending both is a 400.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from ..models import (
    COLOR_DOWN,
    COLOR_NEUTRAL,
    COLOR_SSL,
    COLOR_SSL_CRITICAL,
    COLOR_UP,
    DISCORD_CONTENT_LIMIT,
    DISCORD_EMBED_DESCRIPTION_LIMIT,
    DISCORD_EMBED_FIELD_VALUE_LIMIT,
    DISCORD_EMBED_FOOTER_LIMIT,
    DISCORD_EMBED_TITLE_LIMIT,
    DISCORD_MAX_EMBEDS,
    CheckResult,
    Monitor,
    NotifyEvent,
    SslInfo,
    UptimeStats,
    format_duration,
    sanitize_discord_text,
    truncate,
)
from ..monitor.statemachine import Action, ActionKind

# Discord snowflakes are 17-20 digits today. Anything else is dropped before
# it reaches the API, so a typo cannot become a bogus mention.
_SNOWFLAKE_RE = re.compile(r"^\d{15,25}$")

_WEBHOOK_NAME = "UptimeBot"
_LABEL_LIMIT = 200
_TITLE_HEADROOM = 16  # room for the leading emoji and a suffix like " — MASIH DOWN"


@dataclass(slots=True)
class DiscordMessage:
    """A ready-to-send webhook payload."""

    content: str
    embeds: list[dict[str, Any]] = field(default_factory=list)
    allowed_mentions: dict[str, Any] = field(default_factory=lambda: {"parse": []})
    username: str | None = None

    def payload(self) -> dict[str, Any]:
        body: dict[str, Any] = {"allowed_mentions": self.allowed_mentions}
        if self.content:
            body["content"] = self.content
        if self.embeds:
            body["embeds"] = self.embeds[:DISCORD_MAX_EMBEDS]
        if self.username:
            body["username"] = truncate(self.username, 80)
        return body


def valid_snowflakes(ids: Any) -> list[str]:
    """Keep only well-formed Discord IDs, de-duplicated, order preserved.

    Accepts bare IDs and the ``<@id>`` / ``<@&id>`` markup forms so values
    pasted straight out of Discord are accepted.
    """
    if not ids:
        return []
    if isinstance(ids, str):
        ids = [ids]
    seen: set[str] = set()
    out: list[str] = []
    for raw in ids:
        candidate = str(raw).strip()
        if candidate.startswith("<@&") and candidate.endswith(">"):
            candidate = candidate[3:-1]
        elif candidate.startswith("<@") and candidate.endswith(">"):
            candidate = candidate[2:-1]
        if not _SNOWFLAKE_RE.match(candidate) or candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


def build_allowed_mentions(
    user_ids: Any = None, role_ids: Any = None
) -> dict[str, Any]:
    """Build ``allowed_mentions`` so that only the listed targets can ping.

    ``parse`` is always empty. Populating ``users``/``roles`` while also
    listing their kind in ``parse`` is a hard 400 from Discord, so the two
    are never combined.
    """
    allowed: dict[str, Any] = {"parse": []}
    users = valid_snowflakes(user_ids)
    roles = valid_snowflakes(role_ids)
    if users:
        allowed["users"] = users[:100]
    if roles:
        allowed["roles"] = roles[:100]
    return allowed


def mention_prefix(user_ids: Any = None, role_ids: Any = None) -> str:
    """Render ``<@id> <@&id>`` for the top-level content field."""
    return " ".join(
        [f"<@{uid}>" for uid in valid_snowflakes(user_ids)]
        + [f"<@&{rid}>" for rid in valid_snowflakes(role_ids)]
    )


def channel_mention(channel_id: str | None) -> str:
    """``<#id>`` jump link, or empty when the channel is unknown."""
    candidate = str(channel_id or "").strip()
    return f"<#{candidate}>" if _SNOWFLAKE_RE.match(candidate) else ""


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _fmt_ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f} ms"


def _fmt_pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}%"


def _discord_ts(moment: datetime | None) -> str:
    """Markdown timestamp, rendered in each reader's local timezone."""
    return "-" if moment is None else f"<t:{int(moment.timestamp())}:f>"


def _field(name: str, value: str, inline: bool = False) -> dict[str, Any]:
    """Build an embed field, clamped to Discord's 1024-character value limit."""
    return {
        "name": truncate(name, 256),
        "value": truncate(value or "-", DISCORD_EMBED_FIELD_VALUE_LIMIT),
        "inline": inline,
    }


def _code_block(text: str) -> str:
    return f"```\n{text}\n```"


def _clean(embed: dict[str, Any]) -> dict[str, Any]:
    """Drop keys with a None value; Discord rejects explicit nulls."""
    return {k: v for k, v in embed.items() if v is not None}


def _url_or_none(monitor: Monitor) -> str | None:
    """Only advertise a clickable link for a real http(s) URL."""
    return monitor.url if monitor.url.lower().startswith(("http://", "https://")) else None


def _title(emoji: str, monitor: Monitor, suffix: str = "") -> str:
    room = DISCORD_EMBED_TITLE_LIMIT - len(emoji) - len(suffix) - 2
    return truncate(f"{emoji} {sanitize_discord_text(monitor.name, room)}{suffix}", DISCORD_EMBED_TITLE_LIMIT)


def _footer(public_url: str | None) -> dict[str, str]:
    text = f"{_WEBHOOK_NAME} · dashboard" if public_url else _WEBHOOK_NAME
    return {"text": truncate(text, DISCORD_EMBED_FOOTER_LIMIT)}


class EmbedBuilder:
    """Builds the content/embed pair for every message the bot sends."""

    def __init__(
        self,
        *,
        tz: ZoneInfo,
        report_channel_id: str | None = None,
        public_url: str | None = None,
    ) -> None:
        self.tz = tz
        self.report_channel_id = report_channel_id
        self.public_url = public_url

    # ----- alert messages --------------------------------------------------

    def down(self, monitor: Monitor, action: Action, stats: UptimeStats | None) -> DiscordMessage:
        result = action.result
        fields = [
            _field(
                "Status",
                f"🔴 **DOWN** — {sanitize_discord_text(result.label if result else 'tidak diketahui')}",
                inline=True,
            ),
            _field("Waktu down", f"⏱️ **{format_duration(action.downtime)}**", inline=True),
            _field("Response time", f"⏱️ {_fmt_ms(result.latency_ms if result else None)}", inline=True),
        ]
        if result is not None and result.status_code is not None:
            fields.append(_field("HTTP status", f"`{result.status_code}`", inline=True))
        if result is not None and result.error:
            fields.append(_field("Detail", _code_block(sanitize_discord_text(result.error, 900))))
        fields.extend(self._uptime_fields(stats))
        fields.extend(self._action_fields(monitor))

        embed = _clean(
            {
                "title": _title("🔴", monitor),
                "url": _url_or_none(monitor),
                "description": truncate(
                    sanitize_discord_text(monitor.url, 500), DISCORD_EMBED_DESCRIPTION_LIMIT
                ),
                "color": COLOR_DOWN,
                "fields": fields,
                "timestamp": result.checked_at.isoformat() if result else None,
                "footer": _footer(self.public_url),
            }
        )
        return self._wrap(monitor, "**DOWN** — mohon segera dicek.", embed)

    def recovery(self, monitor: Monitor, action: Action, stats: UptimeStats | None) -> DiscordMessage:
        result = action.result
        fields = [
            _field("Status", "🟢 **UP** — layanan kembali normal", inline=True),
            _field("Durasi downtime", f"✅ Total **{format_duration(action.downtime)}**", inline=True),
            _field("Response time", f"⏱️ {_fmt_ms(result.latency_ms if result else None)}", inline=True),
        ]
        fields.extend(self._uptime_fields(stats))
        fields.extend(self._action_fields(monitor))

        embed = _clean(
            {
                "title": _title("🟢", monitor),
                "url": _url_or_none(monitor),
                "description": truncate(
                    sanitize_discord_text(monitor.url, 500), DISCORD_EMBED_DESCRIPTION_LIMIT
                ),
                "color": COLOR_UP,
                "fields": fields,
                "timestamp": result.checked_at.isoformat() if result else None,
                "footer": _footer(self.public_url),
            }
        )
        return self._wrap(monitor, "**KEMBALI UP** — sudah resolved.", embed)

    def reminder(self, monitor: Monitor, action: Action, stats: UptimeStats | None) -> DiscordMessage:
        result = action.result
        fields = [
            _field(
                "Status",
                f"🔴 **MASIH DOWN** — {sanitize_discord_text(result.label if result else '-')}",
                inline=True,
            ),
            _field("Total downtime", f"⏱️ **{format_duration(action.downtime)}**", inline=True),
        ]
        if result is not None and result.error:
            fields.append(_field("Detail", _code_block(sanitize_discord_text(result.error, 900))))
        fields.extend(self._uptime_fields(stats))
        fields.extend(self._action_fields(monitor))

        embed = _clean(
            {
                "title": _title("🔴", monitor, " — MASIH DOWN"),
                "url": _url_or_none(monitor),
                "description": truncate(
                    sanitize_discord_text(monitor.url, 500), DISCORD_EMBED_DESCRIPTION_LIMIT
                ),
                "color": COLOR_DOWN,
                "fields": fields,
                "timestamp": result.checked_at.isoformat() if result else None,
                "footer": _footer(self.public_url),
            }
        )
        return self._wrap(monitor, "**MASIH DOWN** — masih perlu dicek.", embed)

    def ssl(self, monitor: Monitor, action: Action) -> DiscordMessage:
        info = action.ssl
        assert info is not None
        days = info.days_left
        expired = days is not None and days < 0

        if expired:
            headline = "🔴 **SERTIFIKAT SSL SUDAH EXPIRED**"
            if days is not None:
                headline += f" (**{-days} hari lalu**)"
            sentence = "**SERTIFIKAT SSL EXPIRED** — segera perbaiki."
            color = COLOR_DOWN
        else:
            headline = (
                f"⚠️ Sertifikat SSL akan expire dalam **{days} hari**"
                if days is not None
                else "⚠️ Peringatan sertifikat SSL"
            )
            sentence = "**SSL akan expire** — segera perpanjang."
            color = COLOR_SSL_CRITICAL if action.ssl_severity >= 3 else COLOR_SSL

        fields = [
            _field("Status", headline),
            _field("Kedaluwarsa", _discord_ts(info.not_after), inline=True),
            _field(
                "Sisa waktu",
                "**sudah lewat**" if expired else f"**{days} hari**",
                inline=True,
            ),
            _field("Tingkat", str(action.ssl_label or "INFO"), inline=True),
        ]
        if info.issuer:
            fields.append(_field("Issuer", sanitize_discord_text(info.issuer, _LABEL_LIMIT), inline=True))
        if info.subject_cn:
            fields.append(_field("Common Name", f"`{sanitize_discord_text(info.subject_cn, _LABEL_LIMIT)}`", inline=True))
        if info.tls_version:
            fields.append(_field("TLS", sanitize_discord_text(info.tls_version, 40), inline=True))
        if info.chain_ok is False:
            fields.append(
                _field("⚠️ Rantai sertifikat", "Tidak valid — browser akan menampilkan peringatan")
            )
        if info.error:
            fields.append(_field("Error inspeksi", _code_block(sanitize_discord_text(info.error, 500))))
        fields.extend(self._action_fields(monitor))

        embed = _clean(
            {
                "title": _title("🔐", monitor),
                "url": _url_or_none(monitor),
                "description": truncate(
                    sanitize_discord_text(monitor.url, 500), DISCORD_EMBED_DESCRIPTION_LIMIT
                ),
                "color": color,
                "fields": fields,
                "timestamp": info.checked_at.isoformat(),
                "footer": _footer(self.public_url),
            }
        )
        return self._wrap(monitor, sentence, embed)

    # ----- operator-triggered messages -------------------------------------

    def test_alert(self, monitor: Monitor, note: str = "Tes manual dari dashboard") -> DiscordMessage:
        """A synthetic alert for the UI's Test button.

        Never touches monitor state, so pressing it cannot mask a real outage.
        """
        embed = _clean(
            {
                "title": _title("🧪", monitor),
                "description": truncate(
                    sanitize_discord_text(note)
                    + "\n\nBentuk notifikasi ini sama persis dengan yang dikirim saat kejadian nyata.",
                    DISCORD_EMBED_DESCRIPTION_LIMIT,
                ),
                "color": COLOR_NEUTRAL,
                "fields": [
                    _field("URL", f"`{sanitize_discord_text(monitor.url, _LABEL_LIMIT)}`"),
                    _field("Waktu", _discord_ts(datetime.now(self.tz)), inline=True),
                    _field("Mention", _mention_summary(monitor), inline=True),
                ],
                "footer": _footer(self.public_url),
            }
        )
        return self._wrap(monitor, "**TES NOTIFIKASI** — ini bukan kondisi nyata.", embed)

    def test_mention(self, monitor: Monitor) -> DiscordMessage:
        """A bare mention, to verify the configured PIC actually gets pinged."""
        has_targets = bool(
            valid_snowflakes(monitor.notify_user_ids) or valid_snowflakes(monitor.notify_role_ids)
        )
        if not has_targets:
            return DiscordMessage(
                content=(
                    "⚠️ **Belum ada target mention** untuk "
                    f"`{sanitize_discord_text(monitor.name, 100)}`. "
                    "Isi User ID atau Role ID di halaman edit monitor."
                ),
                allowed_mentions={"parse": []},
            )
        return DiscordMessage(
            content=truncate(
                f"{mention_prefix(monitor.notify_user_ids, monitor.notify_role_ids)} "
                f"tes mention untuk **{sanitize_discord_text(monitor.name, 100)}**. "
                "Kalau pesan ini masuk, konfigurasi mention sudah benar.",
                DISCORD_CONTENT_LIMIT,
            ),
            allowed_mentions=build_allowed_mentions(monitor.notify_user_ids, monitor.notify_role_ids),
        )

    def monitor_deleted(self, monitor_id: str, name: str) -> DiscordMessage:
        return DiscordMessage(
            content=(
                f"🗑️ Monitor **{sanitize_discord_text(name, 100)}** "
                f"(`{sanitize_discord_text(monitor_id, 64)}`) telah dihapus."
            ),
            allowed_mentions={"parse": []},
        )

    def pause_state(self, monitor: Monitor, paused: bool, actor: str) -> DiscordMessage:
        verb = "dijeda" if paused else "dilanjutkan"
        return DiscordMessage(
            content=(
                f"{'⏸️' if paused else '▶️'} Monitor **{sanitize_discord_text(monitor.name, 100)}** "
                f"telah **{verb}** oleh `{sanitize_discord_text(actor, 64)}`."
            ),
            allowed_mentions={"parse": []},
        )

    def startup_banner(self, monitor_count: int, webhook_ok: bool) -> DiscordMessage:
        """One message on boot, so a silent bot is visibly alive."""
        state = "terhubung" if webhook_ok else "**belum dikonfigurasi**"
        return DiscordMessage(
            content=f"✅ UptimeBot aktif — **{monitor_count} monitor** dipantau. Webhook: {state}.",
            allowed_mentions={"parse": []},
        )

    # ----- internals -------------------------------------------------------

    def _wrap(self, monitor: Monitor, sentence: str, embed: dict[str, Any]) -> DiscordMessage:
        """Attach the mention-carrying content to a finished embed."""
        return DiscordMessage(
            content=truncate(self._content(monitor, sentence), DISCORD_CONTENT_LIMIT),
            embeds=[embed],
            allowed_mentions=build_allowed_mentions(
                monitor.notify_user_ids, monitor.notify_role_ids
            ),
        )

    def _content(self, monitor: Monitor, sentence: str) -> str:
        """Compose top-level content: mention first, then a fixed sentence.

        Only the configured mention IDs are interpolated here, because this is
        the one field Discord will actually notify on.
        """
        pieces = [
            p
            for p in (mention_prefix(monitor.notify_user_ids, monitor.notify_role_ids), sentence)
            if p
        ]
        channel = channel_mention(self.report_channel_id)
        if channel:
            pieces.append(channel)
        return " ".join(pieces)

    def _uptime_fields(self, stats: UptimeStats | None) -> list[dict[str, Any]]:
        if stats is None or stats.total == 0:
            return []
        return [
            _field(
                "Statistik 24 jam",
                f"Uptime **{_fmt_pct(stats.uptime_percent)}**\n"
                f"Rata-rata **{_fmt_ms(stats.avg_latency_ms)}** · "
                f"p95 **{_fmt_ms(stats.p95_latency_ms)}**\n"
                f"Total probe: {stats.total} ({stats.successful} berhasil)",
                inline=True,
            )
        ]

    def _action_fields(self, monitor: Monitor) -> list[dict[str, Any]]:
        if not self.public_url:
            return []
        link = f"[Buka di dashboard]({self.public_url}/monitors/{monitor.id})"
        return [_field("Tindakan", truncate(link, 500))]


def _mention_summary(monitor: Monitor) -> str:
    users = valid_snowflakes(monitor.notify_user_ids)
    roles = valid_snowflakes(monitor.notify_role_ids)
    if not users and not roles:
        return "_(belum ada)_"
    return f"{len(users)} user · {len(roles)} role"


ACTION_EVENT: dict[ActionKind, NotifyEvent] = {
    ActionKind.ALERT_DOWN: NotifyEvent.DOWN,
    ActionKind.ALERT_REMINDER: NotifyEvent.DOWN,
    ActionKind.ALERT_RECOVERY: NotifyEvent.RECOVERY,
    ActionKind.ALERT_SSL: NotifyEvent.SSL,
}


def event_for_action(action: Action) -> NotifyEvent:
    """Which subscription an action belongs to, for ``notify_on`` filtering."""
    return ACTION_EVENT[action.kind]


def build_message(
    builder: EmbedBuilder,
    monitor: Monitor,
    action: Action,
    stats: UptimeStats | None = None,
) -> DiscordMessage:
    """Dispatch an action to the matching builder method."""
    handlers = {
        ActionKind.ALERT_DOWN: lambda: builder.down(monitor, action, stats),
        ActionKind.ALERT_RECOVERY: lambda: builder.recovery(monitor, action, stats),
        ActionKind.ALERT_REMINDER: lambda: builder.reminder(monitor, action, stats),
        ActionKind.ALERT_SSL: lambda: builder.ssl(monitor, action),
    }
    handler = handlers.get(action.kind)
    if handler is None:
        raise ValueError(f"unknown action kind: {action.kind!r}")
    return handler()


__all__ = [
    "ACTION_EVENT",
    "DiscordMessage",
    "EmbedBuilder",
    "build_allowed_mentions",
    "build_message",
    "channel_mention",
    "event_for_action",
    "mention_prefix",
    "valid_snowflakes",
]
