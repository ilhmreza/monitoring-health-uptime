"""Shared pytest fixtures.

Every test gets its own temporary SQLite file, so tests never share state and
never touch the operator's real database in ``data/``.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from uptimebot.db import CheckRepo, Database, MonitorRepo, StateRepo  # noqa: E402
from uptimebot.models import Monitor  # noqa: E402
from uptimebot.settings import DiscordSettings, Settings  # noqa: E402

TEST_PASSWORD = "rahasia-uji-12345"


def pytest_sessionstart(session: pytest.Session) -> None:
    """Fail loudly if the async tests would be silently skipped.

    ``asyncio_mode = "auto"`` lives in pyproject.toml. If pytest is invoked
    from a directory that does not see that config, pytest-asyncio skips every
    ``async def`` test instead of running it, and the run still reports green.
    Half the suite — the persistence and scheduler tests — would go unchecked
    without a word. A skipped test that was meant to run is a failure here.
    """
    if _asyncio_mode(session.config) == "auto":
        return
    raise pytest.UsageError(
        "asyncio_mode is not 'auto', so async tests would be silently skipped. "
        "Run pytest from the project root, or pass -o asyncio_mode=auto"
    )


def _asyncio_mode(config: pytest.Config) -> str | None:
    """The effective asyncio mode, whether it came from the ini file or CLI."""
    try:
        return config.getini("asyncio_mode")
    except (ValueError, KeyError):
        # The option is unregistered, which means pytest-asyncio is not loaded.
        return config.getoption("asyncio_mode", None)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop a developer's real ``.env`` from leaking into the test run.

    ``load_settings`` reads ``os.environ`` and only skips keys that are already
    present, so pre-existing values have to be cleared rather than overwritten.
    """
    for key in (
        "DATABASE_PATH",
        "UI_USERNAME",
        "UI_PASSWORD_HASH",
        "SECRET_KEY",
        "COOKIE_SECURE",
        "TRUST_PROXY",
        "TZ",
        "BIND_HOST",
        "PORT",
        "PUBLIC_URL",
        "LOG_LEVEL",
        "ALLOW_PRIVATE_NETWORK",
        "DISCORD_WEBHOOK_URL",
        "DISCORD_BOT_TOKEN",
        "DISCORD_GUILD_ID",
        "DISCORD_REPORT_CHANNEL_ID",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def settings_factory(tmp_path: Path):
    """Build a :class:`Settings` pointed at a throwaway database.

    Returns a callable so a test can tweak the database path (for the
    restart-persistence cases) or any other field without re-listing them.
    """

    def build(**overrides) -> Settings:
        base = {
            "database_path": tmp_path / "uptimebot.db",
            "bind_host": "127.0.0.1",
            "port": 8123,
            "log_level": "WARNING",
            "public_url": "",
            "timezone": ZoneInfo("Asia/Jakarta"),
            "ui_username": "admin",
            "ui_password_hash": "",
            "secret_key": "pytest-secret-key-not-for-production",
            "cookie_secure": False,
            "trust_proxy": False,
            "default_interval_seconds": 60,
            "default_timeout_seconds": 10,
            "default_failure_threshold": 3,
            "reminder_interval_minutes": 30,
            "ssl_warn_days": (30, 14, 7, 1),
            "ssl_check_interval_seconds": 21600,
            "retention_days": 30,
            "allow_private_network": False,
            "login_max_attempts": 5,
            "login_lockout_seconds": 300,
            "discord": DiscordSettings(),
        }
        base.update(overrides)
        return Settings(**base)  # type: ignore[arg-type]

    return build


@pytest.fixture
def settings(settings_factory) -> Settings:
    return settings_factory()


@pytest.fixture
def password_hash() -> str:
    from uptimebot.web.auth import hash_password

    # Low rounds: these hashes exist for a few milliseconds of test setup and
    # are never used to protect anything.
    return hash_password(TEST_PASSWORD, rounds=4)


@pytest.fixture
async def db(tmp_path: Path):
    """A connected, schema-initialised database, closed on teardown."""
    database = Database(tmp_path / "uptimebot.db")
    await database.connect()
    await database.init_schema()
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
def make_monitor():
    """Build a Monitor with test-friendly defaults."""

    def build(**overrides) -> Monitor:
        base = {
            "id": "uji",
            "name": "Uji",
            "url": "https://example.com",
            "interval_seconds": 60,
        }
        base.update(overrides)
        return Monitor(**base)  # type: ignore[arg-type]

    return build


@pytest.fixture
async def repos(db) -> Iterator[dict]:
    """The three repositories the scheduler needs, over a fresh database."""
    yield {
        "monitors": MonitorRepo(db),
        "state": StateRepo(db),
        "checks": CheckRepo(db),
    }
