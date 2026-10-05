"""Application settings, loaded from environment variables.

Secrets live here and nowhere else. Monitor configuration lives in the
database so the web UI can edit it without file-write races.
"""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_SSL_WARN_DAYS: tuple[int, ...] = (30, 14, 7, 1)

_ENV_FILE_LOADED = False


class SettingsError(RuntimeError):
    """Raised when required configuration is missing or malformed."""


def _raw(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


#: Values that legitimately contain a ``$``. A bcrypt hash is ``$2b$12$...``,
#: and Docker Compose treats ``$name`` inside an ``env_file`` value as a
#: variable reference, so it silently deletes everything from the second ``$``
#: onwards. The result is a hash that fails to parse and makes login impossible,
#: with no error pointing at the real cause. Quoting the value does not help.
#: These therefore support a ``<NAME>_FILE`` companion that is read from disk
#: instead, which is also how Docker's own secrets are delivered.
FILE_INDIRECTED = (
    "UI_PASSWORD_HASH",
    "SECRET_KEY",
    "DISCORD_WEBHOOK_URL",
    "DISCORD_BOT_TOKEN",
)


def _secret(name: str) -> str:
    """Read a secret from ``NAME`` or, failing that, from ``NAME_FILE``.

    The file wins when both are set, so an operator can leave a stale value in
    ``.env`` without it silently taking effect.
    """
    path = _raw(f"{name}_FILE")
    if path:
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise SettingsError(f"{name}_FILE tidak bisa dibaca ({path}): {exc}") from exc
        content = content.strip().lstrip("\ufeff")
        # `hash-password` and `genkey` print a ready-to-paste `NAME=value` line,
        # so redirecting their output straight into a secret file is the obvious
        # thing to do. Accept that rather than making the operator strip it.
        prefix = f"{name}="
        if content.startswith(prefix):
            content = content[len(prefix):].strip()
        return content
    return _raw(name)


def _interpolation_hint(value: str, name: str) -> str:
    """Name the real cause when a value looks eaten by ``$`` interpolation.

    A bcrypt hash whose salt is missing still starts with ``$2b$12``, so it
    looks almost right. Without this hint the operator regenerates the hash,
    pastes the same mangled value in, and concludes the tool is broken.
    """
    if value.startswith("$2") and "$" in value[3:]:
        return (
            f"Nilai {name} tampak sudah rusak oleh interpolasi '$' — Docker "
            f"Compose menghapus bagian hash setelah karakter '$' kedua. "
            f"Jangan menaruh nilai ini langsung di .env atau env_file; pakai "
            f"berkas rahasia: set {name}_FILE=/run/secrets/{name.lower()} "
            f"(lihat docker-compose.yml)."
        )
    return ""


def _int(name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = _raw(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SettingsError(f"{name} must be an integer, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise SettingsError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise SettingsError(f"{name} must be <= {maximum}, got {value}")
    return value


def _bool(name: str, default: bool) -> bool:
    raw = _raw(name).lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise SettingsError(f"{name} must be a boolean-ish value, got {raw!r}")


def _csv_ints(name: str, default: tuple[int, ...] = ()) -> tuple[int, ...]:
    raw = _raw(name)
    if not raw:
        return default
    out: list[int] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            out.append(int(chunk))
        except ValueError as exc:
            raise SettingsError(f"{name} must be comma-separated integers, got {chunk!r}") from exc
    return tuple(out)


def load_env_file(path: str | Path) -> bool:
    """Load ``KEY=VALUE`` pairs into ``os.environ`` without overwriting existing keys.

    Deliberately minimal: no interpolation, no export handling beyond the
    common ``export KEY=VALUE`` form, no multi-line values. Environment
    variables set by the container runtime always win.
    """
    global _ENV_FILE_LOADED
    if _ENV_FILE_LOADED:
        return True
    env_path = Path(path)
    if not env_path.is_file():
        return False
    try:
        content = env_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SettingsError(f"cannot read {env_path}: {exc}") from exc

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
    _ENV_FILE_LOADED = True
    return True


@dataclass(frozen=True, slots=True)
class DiscordSettings:
    """Credentials and identifiers for the Discord integration."""

    webhook_url: str = ""
    bot_token: str = ""
    guild_id: str = ""
    report_channel_id: str = ""

    @property
    def webhook_configured(self) -> bool:
        return bool(self.webhook_url)

    @property
    def resolver_configured(self) -> bool:
        """@username resolution needs a bot token plus somewhere to read from.

        The resolver scans channel message history, so a guild alone is not
        enough: without a report channel there is nothing to scan.
        """
        return bool(self.bot_token and self.guild_id and self.report_channel_id)

    @property
    def report_channel_id_or_empty(self) -> str:
        return self.report_channel_id


@dataclass(frozen=True, slots=True)
class Settings:
    """Fully validated runtime configuration."""

    database_path: Path
    bind_host: str
    port: int
    log_level: str
    public_url: str
    timezone: ZoneInfo

    ui_username: str
    ui_password_hash: str
    secret_key: str
    cookie_secure: bool
    trust_proxy: bool

    default_interval_seconds: int
    default_timeout_seconds: int
    default_failure_threshold: int
    reminder_interval_minutes: int
    ssl_warn_days: tuple[int, ...]
    ssl_check_interval_seconds: int
    retention_days: int

    allow_private_network: bool
    login_max_attempts: int
    login_lockout_seconds: int

    discord: DiscordSettings = field(default_factory=DiscordSettings)

    # ----- derived helpers -------------------------------------------------

    @property
    def auth_configured(self) -> bool:
        return bool(self.ui_username and self.ui_password_hash and self.secret_key)

    def describe_public_state(self) -> dict[str, object]:
        """Non-secret configuration summary for the dashboard's setup banner."""
        return {
            "discord_webhook": self.discord.webhook_configured,
            "discord_resolver": self.discord.resolver_configured,
            "report_channel": bool(self.discord.report_channel_id),
            "auth": self.auth_configured,
            "timezone": self.timezone.key,
            "ssl_warn_days": list(self.ssl_warn_days),
            "private_network_blocked": not self.allow_private_network,
        }


_BCRYPT_RE = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")


def _is_bcrypt_hash(value: str) -> bool:
    return bool(_BCRYPT_RE.match(value))


def load_settings(env_file: str | Path = ".env") -> Settings:
    """Build a :class:`Settings` from the environment, raising on bad input."""
    load_env_file(env_file)

    database_path = Path(_raw("DATABASE_PATH", "data/uptimebot.db")).resolve()
    tz_name = _raw("TZ", "Asia/Jakarta")
    try:
        timezone = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise SettingsError(
            f"TZ={tz_name!r} is not a valid IANA timezone (e.g. 'Asia/Jakarta')"
        ) from exc

    password_hash = _secret("UI_PASSWORD_HASH")
    if password_hash and not _is_bcrypt_hash(password_hash):
        raise SettingsError(
            "UI_PASSWORD_HASH does not look like a bcrypt hash. "
            "Generate one with: python -m uptimebot hash-password. "
            + _interpolation_hint(password_hash, "UI_PASSWORD_HASH")
        )

    ssl_warn_days = _csv_ints("SSL_WARN_DAYS", DEFAULT_SSL_WARN_DAYS)
    if not ssl_warn_days:
        raise SettingsError("SSL_WARN_DAYS must list at least one threshold")
    if any(d < 0 for d in ssl_warn_days):
        raise SettingsError("SSL_WARN_DAYS values must be >= 0")
    # Normalise to most-severe-last ordering so escalation logic is a simple scan.
    ssl_warn_days = tuple(sorted(set(ssl_warn_days), reverse=True))

    return Settings(
        database_path=database_path,
        bind_host=_raw("BIND_HOST", "0.0.0.0"),
        port=_int("PORT", 8000, minimum=1, maximum=65535),
        log_level=_raw("LOG_LEVEL", "INFO").upper(),
        public_url=_raw("PUBLIC_URL", "").rstrip("/"),
        timezone=timezone,
        ui_username=_raw("UI_USERNAME", "admin"),
        ui_password_hash=password_hash,
        secret_key=_secret("SECRET_KEY"),
        cookie_secure=_bool("COOKIE_SECURE", True),
        # Only safe behind a proxy that REPLACES X-Forwarded-For. It is read
        # solely to key the login throttle by client IP; trusting a header a
        # client can also set would let an attacker mint a fresh bucket per
        # request and defeat the throttle entirely.
        trust_proxy=_bool("TRUST_PROXY", False),
        default_interval_seconds=_int("DEFAULT_INTERVAL_SECONDS", 60, minimum=5, maximum=86400),
        default_timeout_seconds=_int("DEFAULT_TIMEOUT_SECONDS", 10, minimum=1, maximum=120),
        default_failure_threshold=_int("DEFAULT_FAILURE_THRESHOLD", 3, minimum=1, maximum=20),
        reminder_interval_minutes=_int("REMINDER_INTERVAL_MINUTES", 30, minimum=1, maximum=10080),
        ssl_warn_days=ssl_warn_days,
        ssl_check_interval_seconds=_int("SSL_CHECK_INTERVAL_SECONDS", 21600, minimum=300),
        retention_days=_int("RETENTION_DAYS", 30, minimum=1, maximum=3650),
        allow_private_network=_bool("ALLOW_PRIVATE_NETWORK", False),
        login_max_attempts=_int("LOGIN_MAX_ATTEMPTS", 5, minimum=1, maximum=100),
        login_lockout_seconds=_int("LOGIN_LOCKOUT_SECONDS", 300, minimum=1),
        discord=DiscordSettings(
            webhook_url=_secret("DISCORD_WEBHOOK_URL"),
            bot_token=_secret("DISCORD_BOT_TOKEN"),
            guild_id=_raw("DISCORD_GUILD_ID"),
            report_channel_id=_raw("DISCORD_REPORT_CHANNEL_ID"),
        ),
    )


def generate_secret_key() -> str:
    """A fresh session-signing key."""
    return secrets.token_urlsafe(48)
