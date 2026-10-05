"""Server bootstrap: logging, warnings, and the uvicorn run.

Kept apart from :mod:`uptimebot.cli` so that the CLI stays importable without
pulling in uvicorn, which keeps ``genkey`` and ``hash-password`` fast.
"""

from __future__ import annotations

import logging
import sys

import uvicorn

from .settings import Settings, SettingsError, load_settings
from .web.app import create_app

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)-28s %(message)s"


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    # httpx logs a line per request at INFO, which floods the console at a
    # 30-second probe interval.
    for noisy in ("httpx", "httpcore", "aiosqlite", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def preflight_warnings(settings: Settings) -> list[str]:
    """Human-readable reasons the setup is incomplete."""
    out: list[str] = []
    if not settings.auth_configured:
        out.append(
            "UI belum bisa diakses: set UI_PASSWORD_HASH dan SECRET_KEY di .env. "
            "Buat dengan 'python -m uptimebot genkey' dan "
            "'python -m uptimebot hash-password'."
        )
    if not settings.discord.webhook_configured:
        out.append("DISCORD_WEBHOOK_URL kosong: notifikasi tidak akan terkirim.")
    if not settings.discord.resolver_configured:
        out.append(
            "Auto-resolve @username nonaktif: isi DISCORD_BOT_TOKEN, "
            "DISCORD_GUILD_ID dan DISCORD_REPORT_CHANNEL_ID."
        )
    return out


def main() -> int:
    try:
        settings = load_settings()
    except SettingsError as exc:
        print(f"Konfigurasi tidak valid: {exc}", file=sys.stderr)
        return 2

    configure_logging(settings.log_level)
    log = logging.getLogger("uptimebot")

    for warning in preflight_warnings(settings):
        log.warning("%s", warning)
    log.info(
        "database=%s tz=%s monitors_interval=%ss",
        settings.database_path,
        settings.timezone.key,
        settings.default_interval_seconds,
    )

    app = create_app(settings)

    # Uvicorn handles SIGTERM itself and runs the lifespan shutdown, which stops
    # the scheduler and flushes the webhook queue.
    uvicorn.run(
        app,
        host=settings.bind_host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,
        proxy_headers=True,
        # The app sits behind Caddy, so honour X-Forwarded-Proto for redirects.
        forwarded_allow_ips="*",
    )
    return 0


__all__ = ["main", "configure_logging", "preflight_warnings"]
