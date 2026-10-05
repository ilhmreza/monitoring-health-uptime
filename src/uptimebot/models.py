"""Domain types shared across the monitor, database and Discord layers.

Kept free of I/O so it can be imported from anywhere without creating
import cycles.
"""

from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, NamedTuple
from urllib.parse import urlsplit

UTC = timezone.utc

# Discord's hard limits. Exceeding them makes the API reject the whole
# payload, so every user-controlled string is truncated before it is used.
DISCORD_CONTENT_LIMIT = 2000
DISCORD_EMBED_DESCRIPTION_LIMIT = 4096
DISCORD_EMBED_FIELD_VALUE_LIMIT = 1024
DISCORD_EMBED_TITLE_LIMIT = 256
DISCORD_EMBED_FOOTER_LIMIT = 2048
DISCORD_MAX_EMBEDS = 10


class MonitorState(str, Enum):
    """Lifecycle of a monitor's availability."""

    UNKNOWN = "unknown"
    UP = "up"
    DOWN = "down"
    PAUSED = "paused"


class NotifyEvent(str, Enum):
    """Subscribable events, stored as a list on each monitor."""

    DOWN = "down"
    RECOVERY = "recovery"
    SSL = "ssl"


class FailureKind(str, Enum):
    """Why a probe failed.

    Distinguishing these matters: a DNS failure and a 500 are both "down"
    to a user, but they point the PIC at completely different causes.
    """

    NONE = "none"
    DNS = "dns"
    CONNECTION_REFUSED = "connection_refused"
    TIMEOUT = "timeout"
    TLS = "tls"
    STATUS_UNEXPECTED = "status_unexpected"
    KEYWORD_MISSING = "keyword_missing"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    BLOCKED_NETWORK = "blocked_network"
    UNEXPECTED = "unexpected"


# Human-readable prefix shown in the Discord embed.
FAILURE_LABEL: dict[FailureKind, str] = {
    FailureKind.NONE: "OK",
    FailureKind.DNS: "DNS tidak bisa di-resolve",
    FailureKind.CONNECTION_REFUSED: "Koneksi ditolak",
    FailureKind.TIMEOUT: "Timeout",
    FailureKind.TLS: "Kesalahan TLS/SSL",
    FailureKind.STATUS_UNEXPECTED: "Status HTTP tidak sesuai harapan",
    FailureKind.KEYWORD_MISSING: "Keyword wajib tidak ditemukan",
    FailureKind.TOO_MANY_REDIRECTS: "Terlalu banyak redirect",
    FailureKind.BLOCKED_NETWORK: "Diblokir oleh proteksi SSRF",
    FailureKind.UNEXPECTED: "Error tidak terduga",
}

# Embed accent colour, Discord decimal.
COLOR_UP = 0x2ECC71
COLOR_DOWN = 0xE74C3C
COLOR_SSL = 0xF1C40F
COLOR_SSL_CRITICAL = 0xE67E22
COLOR_PAUSED = 0x95A5A6
COLOR_NEUTRAL = 0x586069


# ---------------------------------------------------------------------------
# SSL severity
# ---------------------------------------------------------------------------

SSL_SEVERITY_HEALTHY = 0
SSL_SEVERITY_EXPIRED = 100


def ssl_severity(days_left: int, warn_days: tuple[int, ...]) -> int:
    """Map remaining days to a severity where higher means more urgent.

    Brackets are derived from ``warn_days`` (e.g. ``(30, 14, 7, 1)``) so the
    config file is the single source of truth. The most urgent real-world
    bracket — "already expired" — always outranks the configured ones.

    A certificate is graded by the *tightest* bracket it still satisfies: 8 days
    left falls inside both the 30-day and the 7-day bracket, and it must be
    graded as the 7-day warning. Severity 1 is therefore the mildest configured
    bracket and the bracket count is the tightest.

    The ordering matters beyond labels: the stored ``ssl_notified_severity`` is
    compared with ``>`` to decide whether a warning is new news, so a
    certificate escalating from 20 days to 5 days left must produce a strictly
    larger number.
    """
    if days_left < 0:
        return SSL_SEVERITY_EXPIRED
    brackets = sorted({int(d) for d in warn_days}, reverse=True)
    for index, threshold in enumerate(sorted(brackets)):
        if days_left <= threshold:
            return len(brackets) - index
    return SSL_SEVERITY_HEALTHY


def severity_label(severity: int) -> str:
    if severity >= SSL_SEVERITY_EXPIRED:
        return "EXPIRED"
    if severity >= 4:
        return "KRITIS"
    if severity >= 2:
        return "PERINGATAN"
    if severity >= 1:
        return "INFO"
    return "SEHAT"


class SslBadge(NamedTuple):
    """A severity rendered for the UI.

    The badge text is derived from the remaining days rather than from the
    bracket index, because the brackets come from ``SSL_WARN_DAYS`` and can be
    reconfigured — a template that hardcoded "kurang dari 7 hari" would quietly
    start lying the moment somebody changed the thresholds.
    """

    css: str
    text: str


def ssl_badge(severity: int, days_left: int | None) -> SslBadge:
    """Render a certificate's urgency as a badge.

    ``days_left`` is ``None`` when the last inspection could not read the
    certificate, which is a separate condition from expiry and is shown as such
    rather than as a healthy result.
    """
    if days_left is None:
        return SslBadge("unknown", "Tidak terbaca")
    if days_left < 0:
        return SslBadge("expired", "Kedaluwarsa")
    if severity >= 4:
        return SslBadge("crit", f"{days_left} hari")
    if severity >= 2:
        return SslBadge("warn", f"{days_left} hari")
    if severity >= 1:
        return SslBadge("warn", f"{days_left} hari")
    return SslBadge("ok", f"{days_left} hari")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def sanitize_discord_text(value: Any, limit: int = DISCORD_EMBED_DESCRIPTION_LIMIT) -> str:
    """Make arbitrary user-controlled text safe to place inside an embed.

    Embed fields never ping anybody, but a monitor name containing Discord
    markup should still be neutralised so the message reads cleanly, and the
    string must be truncated to the field limit or the API rejects the payload.
    """
    text = "" if value is None else str(value)
    # Drop control and invisible characters used to spoof names; keep tab,
    # newline and carriage return for genuinely multi-line values.
    text = "".join(
        ch for ch in text if ch in "\t\n\r" or (unicodedata.category(ch)[0] != "C")
    )
    # Angle brackets are the vector for <@id> / <#id> / <@&id> markup.
    text = text.replace("<", "\u2039").replace(">", "\u203a")
    text = re.sub(r"@(everyone|here)\b", "@\u200b", text, flags=re.IGNORECASE)
    return truncate(text.strip(), limit)


def truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "\u2026"


def format_duration(delta: timedelta | None) -> str:
    """Render a duration compactly: ``2h 14m``, ``3d 4j``, ``45d``.

    Returns ``"-"`` for a missing duration so templates never render ``None``.
    """
    if delta is None:
        return "-"
    total_seconds = int(max(0, delta.total_seconds()))
    if total_seconds < 60:
        return f"{total_seconds} detik"

    minutes, seconds = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    parts: list[str] = []
    if days:
        parts.append(f"{days} hari")
    if hours and days < 7:
        parts.append(f"{hours} jam")
    if minutes and not days and hours < 1:
        parts.append(f"{minutes} menit")
    if not parts:
        parts.append(f"{minutes} menit")
    return " ".join(parts)


def format_utc(moment: datetime | None) -> str:
    return "-" if moment is None else moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_relative(moment: datetime | None) -> str:
    """Render how long ago something happened: ``baru saja``, ``4 menit lalu``.

    The dashboard refreshes every 5 seconds, so an absolute timestamp would
    need constant attention from the reader.
    """
    if moment is None:
        return "-"
    elapsed = int((datetime.now(UTC) - moment.astimezone(UTC)).total_seconds())
    if elapsed < 0:
        return "baru saja"
    if elapsed < 10:
        return "baru saja"
    if elapsed < 60:
        return f"{elapsed} detik lalu"
    if elapsed < 3600:
        return f"{elapsed // 60} menit lalu"
    if elapsed < 86400:
        return f"{elapsed // 3600} jam lalu"
    return f"{elapsed // 86400} hari lalu"


# ---------------------------------------------------------------------------
# Domain objects
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Monitor:
    """A configured monitoring target."""

    id: str
    name: str
    url: str
    method: str = "GET"
    expect_status: list[int] = field(default_factory=lambda: [200])
    headers_env: dict[str, str] = field(default_factory=dict)
    keyword: str | None = None
    interval_seconds: int = 60
    timeout_seconds: int = 10
    failure_threshold: int = 3
    notify_user_ids: list[str] = field(default_factory=list)
    notify_role_ids: list[str] = field(default_factory=list)
    notify_on: list[NotifyEvent] = field(default_factory=lambda: [NotifyEvent.DOWN, NotifyEvent.RECOVERY, NotifyEvent.SSL])
    ssl_check: bool = True
    ssl_warn_days: list[int] = field(default_factory=lambda: [30, 14, 7, 1])
    allow_private_network: bool = False
    enabled: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @property
    def host(self) -> str:
        """Hostname extracted for the SSL check, without the port."""
        try:
            return (urlsplit(self.url).hostname or "").lower()
        except ValueError:
            return ""

    @property
    def port(self) -> int:
        try:
            parts = urlsplit(self.url)
        except ValueError:
            return 443
        if parts.port:
            return parts.port
        return 443 if parts.scheme == "https" else 80

    @property
    def wants(self) -> set[NotifyEvent]:
        return set(self.notify_on)

    def resolved_headers(self, environ: dict[str, str] | None = None) -> dict[str, str]:
        """Build real request headers, pulling secrets from the environment.

        ``headers_env`` stores only variable *names*, so an API token never
        lands in the database. A referenced variable that is not set is
        skipped rather than sent as a literal ``${NAME}``.
        """
        env = os.environ if environ is None else environ
        headers: dict[str, str] = {
            "User-Agent": "UptimeBot/1.0 (+https://github.com/)",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        }
        for header, env_name in self.headers_env.items():
            value = env.get(env_name, "")
            if value:
                headers[header] = value
        return headers


@dataclass(slots=True)
class CheckResult:
    """Outcome of a single HTTP probe."""

    ok: bool
    checked_at: datetime
    latency_ms: float
    status_code: int | None = None
    failure_kind: FailureKind = FailureKind.NONE
    error: str | None = None

    @property
    def label(self) -> str:
        if self.ok:
            return "OK"
        return FAILURE_LABEL.get(self.failure_kind, self.failure_kind.value)


@dataclass(slots=True)
class SslInfo:
    """Result of a certificate inspection."""

    checked_at: datetime
    not_after: datetime | None = None
    days_left: int | None = None
    issuer: str | None = None
    subject_cn: str | None = None
    tls_version: str | None = None
    chain_ok: bool | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.not_after is not None

    @property
    def expired(self) -> bool:
        return self.days_left is not None and self.days_left < 0


@dataclass(slots=True)
class MonitorStateRow:
    """Mutable runtime state for a monitor, persisted in ``monitor_state``."""

    monitor_id: str
    state: MonitorState = MonitorState.UNKNOWN
    consecutive_failures: int = 0
    down_since: datetime | None = None
    up_since: datetime | None = None
    last_check_at: datetime | None = None
    last_ok_at: datetime | None = None
    last_reminder_at: datetime | None = None
    ssl_notified_severity: int = 0
    last_alert_at: datetime | None = None


@dataclass(slots=True)
class MonitorWithState:
    """A monitor plus its live state, as rendered by the dashboard."""

    monitor: Monitor
    state: MonitorState = MonitorState.UNKNOWN
    consecutive_failures: int = 0
    down_since: datetime | None = None
    up_since: datetime | None = None
    last_check_at: datetime | None = None
    last_ok_at: datetime | None = None
    last_reminder_at: datetime | None = None
    last_alert_at: datetime | None = None
    ssl_notified_severity: int = 0

    # Filled in by the dashboard query, not by the scheduler.
    uptime_24h: float | None = None
    avg_latency_24h: float | None = None
    last_latency_ms: float | None = None
    last_status_code: int | None = None
    ssl: dict[str, Any] | None = None

    @property
    def downtime(self) -> timedelta | None:
        """How long the monitor has been continuously down, if it is down.

        Measured from the persisted ``down_since`` rather than from process
        start, so the number stays correct across restarts and deploys.
        """
        if self.state is not MonitorState.DOWN or self.down_since is None:
            return None
        return datetime.now(UTC) - self.down_since

    @property
    def effective_state(self) -> MonitorState:
        """A paused monitor is never up or down, whatever the probe says."""
        if not self.monitor.enabled:
            return MonitorState.PAUSED
        return self.state

    @property
    def uptime_run(self) -> timedelta | None:
        """How long the current unbroken healthy run has lasted, if it is up.

        Measured from the persisted ``up_since`` rather than from process
        start, so the number stays correct across restarts.
        """
        if self.state is not MonitorState.UP or self.up_since is None:
            return None
        return max(datetime.now(UTC) - self.up_since, timedelta(0))

    @property
    def last_check_label(self) -> str:
        return format_relative(self.last_check_at)


@dataclass(slots=True)
class UptimeStats:
    """Aggregate probe results over a time window."""

    window_label: str
    total: int = 0
    successful: int = 0
    avg_latency_ms: float | None = None
    p95_latency_ms: float | None = None

    @property
    def uptime_percent(self) -> float | None:
        if self.total == 0:
            return None
        return (self.successful / self.total) * 100.0


@dataclass(slots=True)
class LatencyBucket:
    """One point on the history chart."""

    bucket_start: datetime
    total: int
    successful: int
    avg_latency_ms: float | None

    @property
    def uptime_percent(self) -> float:
        if self.total == 0:
            return 100.0
        return (self.successful / self.total) * 100.0
