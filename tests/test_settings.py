"""Secret loading.

The one behaviour here that is not obvious: a bcrypt hash cannot survive being
passed through Docker Compose's environment, so it has to arrive as a file.
These tests pin both halves of that — the file indirection works, and a value
that Compose has already eaten is reported with the real cause rather than
"your hash is wrong".
"""

from __future__ import annotations

import pytest

from uptimebot.settings import SettingsError, load_settings

# A real bcrypt hash, generated once. It protects nothing; the point is that it
# has the shape Compose destroys.
REAL_HASH = "$2b$12$si9K7ErZDfDaqDPAsg0Yvub1GwCr/Lfm.9SJiZ7IAixWg7utcD16O"


@pytest.fixture(autouse=True)
def clean(monkeypatch: pytest.MonkeyPatch):
    for key in (
        "UI_PASSWORD_HASH",
        "UI_PASSWORD_HASH_FILE",
        "SECRET_KEY",
        "SECRET_KEY_FILE",
        "DISCORD_WEBHOOK_URL",
        "DISCORD_WEBHOOK_URL_FILE",
    ):
        monkeypatch.delenv(key, raising=False)


def base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UI_USERNAME", "admin")
    monkeypatch.setenv("SECRET_KEY", "s" * 64)
    monkeypatch.setenv("PUBLIC_URL", "")


# ----- file indirection -----------------------------------------------------


def test_a_hash_can_be_supplied_as_a_file(monkeypatch, tmp_path):
    """The only way a bcrypt hash survives a Docker Compose deployment."""
    base_env(monkeypatch)
    secret = tmp_path / "hash"
    secret.write_text(REAL_HASH, encoding="utf-8")
    monkeypatch.setenv("UI_PASSWORD_HASH_FILE", str(secret))

    settings = load_settings(env_file=tmp_path / "absent.env")

    assert settings.ui_password_hash == REAL_HASH


def test_a_secret_file_may_keep_the_printed_name_prefix(monkeypatch, tmp_path):
    """`hash-password` prints `UI_PASSWORD_HASH=...`, so redirecting it works."""
    base_env(monkeypatch)
    secret = tmp_path / "hash"
    secret.write_text(f"UI_PASSWORD_HASH={REAL_HASH}\n", encoding="utf-8")
    monkeypatch.setenv("UI_PASSWORD_HASH_FILE", str(secret))

    settings = load_settings(env_file=tmp_path / "absent.env")

    assert settings.ui_password_hash == REAL_HASH


def test_a_secret_file_wins_over_a_stale_env_value(monkeypatch, tmp_path):
    """Otherwise an operator who forgets to delete .env keeps the old secret."""
    base_env(monkeypatch)
    secret = tmp_path / "hash"
    secret.write_text(REAL_HASH, encoding="utf-8")
    monkeypatch.setenv("UI_PASSWORD_HASH", "$2b$12$stale")
    monkeypatch.setenv("UI_PASSWORD_HASH_FILE", str(secret))

    settings = load_settings(env_file=tmp_path / "absent.env")

    assert settings.ui_password_hash == REAL_HASH


def test_the_secret_key_can_be_supplied_as_a_file(monkeypatch, tmp_path):
    monkeypatch.setenv("UI_USERNAME", "admin")
    monkeypatch.setenv("UI_PASSWORD_HASH", REAL_HASH)
    secret = tmp_path / "key"
    secret.write_text("k" * 64, encoding="utf-8")
    monkeypatch.setenv("SECRET_KEY_FILE", str(secret))

    settings = load_settings(env_file=tmp_path / "absent.env")

    assert settings.secret_key == "k" * 64


def test_an_unreadable_secret_file_is_a_clear_error(monkeypatch, tmp_path):
    base_env(monkeypatch)
    monkeypatch.setenv("UI_PASSWORD_HASH_FILE", str(tmp_path / "tidak-ada"))

    with pytest.raises(SettingsError, match="tidak bisa dibaca"):
        load_settings(env_file=tmp_path / "absent.env")


# ----- the Compose trap -----------------------------------------------------


def test_a_hash_eaten_by_compose_is_rejected(monkeypatch, tmp_path):
    base_env(monkeypatch)
    # Exactly what Compose delivers: `$2b$12$` survives, the salt does not.
    monkeypatch.setenv("UI_PASSWORD_HASH", "$2b$12/Lfm.9SJiZ7IAixWg7utcD16O")

    with pytest.raises(SettingsError):
        load_settings(env_file=tmp_path / "absent.env")


def test_the_error_names_interpolation_rather_than_blaming_the_hash(monkeypatch, tmp_path):
    """The operator's next move depends entirely on this sentence.

    Told only "that is not a bcrypt hash", the natural response is to
    regenerate the hash and paste the same mangled value in again, and then to
    conclude the tool is broken.
    """
    base_env(monkeypatch)
    monkeypatch.setenv("UI_PASSWORD_HASH", "$2b$12/Lfm.9SJiZ7IAixWg7utcD16O")

    with pytest.raises(SettingsError) as excinfo:
        load_settings(env_file=tmp_path / "absent.env")

    message = str(excinfo.value)
    assert "interpolasi" in message
    assert "_FILE" in message, "the message must point at the way out"


def test_an_empty_webhook_file_means_not_configured(monkeypatch, tmp_path):
    """The webhook file is created empty before Discord is set up."""
    base_env(monkeypatch)
    monkeypatch.setenv("UI_PASSWORD_HASH", REAL_HASH)
    secret = tmp_path / "webhook"
    secret.write_text("\n", encoding="utf-8")
    monkeypatch.setenv("DISCORD_WEBHOOK_URL_FILE", str(secret))

    settings = load_settings(env_file=tmp_path / "absent.env")

    assert settings.discord.webhook_url == ""
    assert settings.discord.webhook_configured is False


def test_a_byte_order_mark_does_not_corrupt_the_hash(monkeypatch, tmp_path):
    """PowerShell 5.1's `Set-Content -Encoding utf8` writes a BOM.

    A Windows operator creating the secret file the obvious way gets a leading
    U+FEFF, which ``str.strip()`` does not remove, and the hash is then
    rejected for looking malformed. A confusing failure for a file that is
    correct as far as anyone reading it is concerned.
    """
    base_env(monkeypatch)
    secret = tmp_path / "hash"
    secret.write_text(REAL_HASH, encoding="utf-8-sig")

    monkeypatch.setenv("UI_PASSWORD_HASH_FILE", str(secret))
    settings = load_settings(env_file=tmp_path / "absent.env")
    assert settings.ui_password_hash == REAL_HASH

    # And a UTF-8 BOM bytes, which is what actually lands on disk.
    raw = tmp_path / "hash-bytes"
    raw.write_bytes(b"\xef\xbb\xbf" + REAL_HASH.encode("ascii"))
    monkeypatch.setenv("UI_PASSWORD_HASH_FILE", str(raw))
    settings = load_settings(env_file=tmp_path / "absent.env")
    assert settings.ui_password_hash == REAL_HASH
