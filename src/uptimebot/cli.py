"""Command line helpers: secret generation, config import, preflight checks.

``serve`` is the default because that is how the container runs. The rest exist
so an operator can set up a fresh install without a Python prompt or an editor:

    python -m uptimebot genkey
    python -m uptimebot hash-password
    python -m uptimebot import-config config/monitors.example.yml
    python -m uptimebot check
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys
from pathlib import Path
from typing import Any, Sequence

import yaml

from .db import Database, MonitorRepo, ValidationError, slugify_id
from .models import Monitor, NotifyEvent
from .monitor.ssrf import BlockedTargetError, validate_url_static
from .settings import Settings, SettingsError, generate_secret_key, load_settings
from .web.auth import hash_password

log = logging.getLogger("uptimebot.cli")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="uptimebot",
        description="Uptime & SSL monitor with Discord reporting.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("serve", help="run the web server and monitor loop (default)")

    genkey = sub.add_parser("genkey", help="print a fresh SECRET_KEY")
    genkey.add_argument("--write", metavar="ENV_FILE", help="append to this .env file instead")

    hash_cmd = sub.add_parser("hash-password", help="print a bcrypt UI_PASSWORD_HASH")
    hash_cmd.add_argument(
        "password",
        nargs="?",
        help=(
            "password to hash. Omit it to be prompted without echo. Passing it "
            "here exposes it in the process list and shell history, so only use "
            "this form for an initial throwaway password."
        ),
    )
    hash_cmd.add_argument("--rounds", type=int, default=12, help="bcrypt cost (default 12)")

    imp = sub.add_parser("import-config", help="import monitors from a YAML file, once")
    imp.add_argument("path", nargs="?", default="config/monitors.example.yml")
    imp.add_argument(
        "--replace",
        action="store_true",
        help="overwrite a monitor that already exists (default: skip it)",
    )

    sub.add_parser("check", help="validate configuration and report what is missing")

    args = parser.parse_args(argv)
    command = args.command or "serve"

    if command == "genkey":
        return _cmd_genkey(args)
    if command == "hash-password":
        return _cmd_hash_password(args)
    if command == "import-config":
        return _cmd_import_config(args)
    if command == "check":
        return _cmd_check()
    if command == "serve":
        from .server import main as serve_main

        return serve_main()
    parser.print_help()
    return 1


# ---------------------------------------------------------------------------
# Secret helpers
# ---------------------------------------------------------------------------

def _cmd_genkey(args: argparse.Namespace) -> int:
    key = generate_secret_key()
    if not args.write:
        print(key)
        return 0
    path = Path(args.write)
    try:
        existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    except OSError as exc:
        print(f"Tidak bisa membaca {path}: {exc}", file=sys.stderr)
        return 1
    if "SECRET_KEY=" in existing:
        print(
            f"{path} sudah punya SECRET_KEY. Ganti manual supaya session yang aktif "
            "ikut logout.",
            file=sys.stderr,
        )
        return 1
    with path.open("a", encoding="utf-8") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write(f"SECRET_KEY={key}\n")
    print(f"SECRET_KEY ditulis ke {path}")
    return 0


def _cmd_hash_password(args: argparse.Namespace) -> int:
    password = args.password
    if not password:
        if not sys.stdin.isatty():
            print("stdin bukan terminal; berikan password sebagai argumen", file=sys.stderr)
            return 1
        password = getpass.getpass("Password untuk UI (min. 10 karakter): ")
        again = getpass.getpass("Ulangi: ")
        if password != again:
            print("Password tidak cocok.", file=sys.stderr)
            return 1
    try:
        digest = hash_password(password, rounds=args.rounds)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"UI_PASSWORD_HASH={digest}")
    return 0


# ---------------------------------------------------------------------------
# YAML import
# ---------------------------------------------------------------------------

def _cmd_import_config(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.is_file():
        print(f"File tidak ditemukan: {path}", file=sys.stderr)
        return 1
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        print(f"YAML tidak valid: {exc}", file=sys.stderr)
        return 1
    if not isinstance(document, dict) or not isinstance(document.get("monitors"), list):
        print("File harus punya kunci top-level 'monitors' (list).", file=sys.stderr)
        return 1

    try:
        settings = load_settings()
    except SettingsError as exc:
        print(f"Konfigurasi tidak valid: {exc}", file=sys.stderr)
        return 1

    defaults = document.get("defaults") or {}
    fallback = document.get("discord") or {}
    monitors, rejected = _parse_monitors(document["monitors"], defaults, fallback, settings)
    if rejected:
        print(f"{len(rejected)} entri dilewati karena tidak valid:")
        for problem in rejected:
            print(f"  ! {problem}")
    if not monitors:
        print("Tidak ada monitor yang bisa diimpor.", file=sys.stderr)
        return 1

    async def run() -> int:
        db = Database(settings.database_path)
        await db.connect()
        await db.init_schema()
        repo = MonitorRepo(db)
        created = 0
        skipped: list[str] = []
        try:
            for monitor in monitors:
                if await repo.get(monitor.id) is not None:
                    if not args.replace:
                        print(f"  lewati  {monitor.id} (sudah ada)")
                        skipped.append(monitor.id)
                        continue
                    await repo.update(monitor)
                    print(f"  update  {monitor.id}")
                    created += 1
                    continue
                await repo.create(monitor)
                print(f"  tambah  {monitor.id}")
                created += 1
        except (ValidationError, BlockedTargetError) as exc:
            print(f"Gagal: {exc}", file=sys.stderr)
            return 1
        finally:
            await db.close()
        print(f"\n{created} monitor diproses, {len(skipped)} dilewati.")
        print(f"Database: {settings.database_path}")
        print("Selanjutnya jalankan 'python -m uptimebot' lalu login ke UI.")
        return 0

    return asyncio.run(run())


def _parse_monitors(
    entries: list[Any],
    defaults: dict[str, Any],
    fallback: dict[str, Any],
    settings: Settings,
) -> tuple[list[Monitor], list[str]]:
    """Turn YAML entries into :class:`Monitor` objects, skipping bad ones.

    A malformed entry should not abort a whole import, so problems are
    collected and reported while the usable monitors still land.
    """
    out: list[Monitor] = []
    rejected: list[str] = []

    for index, raw in enumerate(entries, start=1):
        label = f"monitors[{index}]"
        if not isinstance(raw, dict):
            rejected.append(f"{label}: bukan mapping")
            continue
        name = str(raw.get("name") or "").strip()
        url = str(raw.get("url") or "").strip()
        if not url:
            rejected.append(f"{label} ({name or '?'}): URL kosong")
            continue

        try:
            monitor_id = slugify_id(str(raw.get("id") or name or url))
        except ValidationError as exc:
            rejected.append(f"{label} ({name}): {exc}")
            continue

        allow_private = bool(
            raw.get("allow_private_network", settings.allow_private_network)
        )
        try:
            validate_url_static(url, allow_private_network=allow_private)
        except BlockedTargetError as exc:
            rejected.append(f"{label} ({monitor_id}): {exc}")
            continue

        notify_on_raw = raw.get("notify_on") or ["down", "recovery", "ssl"]
        notify_on: list[NotifyEvent] = []
        for item in notify_on_raw:
            try:
                notify_on.append(NotifyEvent(str(item).strip().lower()))
            except ValueError:
                rejected.append(f"{label} ({monitor_id}): notify_on '{item}' tidak dikenal")

        user_ids = _as_str_list(
            raw.get("notify_user_ids", fallback.get("notify_user_ids")), "notify_user_ids"
        )
        role_ids = _as_str_list(
            raw.get("notify_role_ids", fallback.get("notify_role_ids")), "notify_role_ids"
        )
        if not _valid_snowflakes(user_ids + role_ids, label):
            rejected.append(f"{label} ({monitor_id}): ID Discord tidak valid")

        warn_days = raw.get("ssl_warn_days") or list(settings.ssl_warn_days)
        try:
            warn_days = sorted({int(d) for d in warn_days}, reverse=True)
        except (TypeError, ValueError):
            rejected.append(f"{label} ({monitor_id}): ssl_warn_days bukan angka")
            warn_days = list(settings.ssl_warn_days)

        headers_env = raw.get("headers_env") or {}
        if not isinstance(headers_env, dict):
            rejected.append(f"{label} ({monitor_id}): headers_env harus mapping")
            headers_env = {}

        out.append(
            Monitor(
                id=monitor_id,
                name=name or monitor_id,
                url=url,
                method=str(raw.get("method") or "GET").upper(),
                expect_status=_as_int_list(raw.get("expect_status") or [200], "expect_status"),
                headers_env={str(k): str(v) for k, v in headers_env.items()},
                keyword=(str(raw["keyword"]) if raw.get("keyword") else None),
                interval_seconds=int(raw.get("interval_seconds") or defaults.get("interval_seconds") or settings.default_interval_seconds),
                timeout_seconds=int(raw.get("timeout_seconds") or defaults.get("timeout_seconds") or settings.default_timeout_seconds),
                failure_threshold=int(raw.get("failure_threshold") or defaults.get("failure_threshold") or settings.default_failure_threshold),
                notify_user_ids=user_ids,
                notify_role_ids=role_ids,
                notify_on=notify_on or list(NotifyEvent),
                ssl_check=bool(raw.get("ssl_check", True)),
                ssl_warn_days=warn_days if raw.get("ssl_check", True) else [],
                allow_private_network=allow_private,
                enabled=bool(raw.get("enabled", True)),
            )
        )
    return out, rejected


def _as_str_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [chunk for chunk in str(value).replace(",", " ").split() if chunk]


def _as_int_list(value: Any, label: str) -> list[int]:
    if not isinstance(value, (list, tuple)):
        value = [value]
    out: list[int] = []
    for item in value:
        try:
            code = int(item)
        except (TypeError, ValueError):
            continue
        if 100 <= code <= 599:
            out.append(code)
    return out or [200]


def _valid_snowflakes(values: list[str], label: str) -> bool:
    import re

    pattern = re.compile(r"^\d{15,25}$")
    return all(pattern.match(v) for v in values)


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def _cmd_check() -> int:
    try:
        settings = load_settings()
    except SettingsError as exc:
        print(f"GAGAL: {exc}", file=sys.stderr)
        return 2

    db = settings.database_path
    print("Konfigurasi environment")
    print(f"  database          : {db} ({'ada' if db.exists() else 'belum dibuat'})")
    print(f"  listen            : {settings.bind_host}:{settings.port}")
    print(f"  public url        : {settings.public_url or '(belum diisi)'}")
    print(f"  timezone          : {settings.timezone.key}")
    print(f"  cookie secure     : {settings.cookie_secure}")
    print(f"  interval default  : {settings.default_interval_seconds}s")
    print(f"  ssl warn days     : {', '.join(str(d) for d in settings.ssl_warn_days)}")
    print(f"  retensi riwayat   : {settings.retention_days} hari")
    print("Discord")
    print(f"  webhook           : {'ada' if settings.discord.webhook_configured else 'KOSONG'}")
    print(f"  bot token         : {'ada' if settings.discord.bot_token else 'KOSONG'}")
    print(f"  guild id          : {settings.discord.guild_id or 'KOSONG'}")
    print(f"  report channel id : {settings.discord.report_channel_id or 'KOSONG'}")
    print(f"  auto-resolve      : {'aktif' if settings.discord.resolver_configured else 'nonaktif (ID manual)'}")
    print("UI")
    print(f"  username          : {settings.ui_username or 'KOSONG'}")
    print(f"  password hash     : {'ada' if settings.ui_password_hash else 'KOSONG'}")
    print(f"  secret key        : {'ada' if settings.secret_key else 'KOSONG'}")

    problems: list[str] = []
    if not settings.auth_configured:
        problems.append(
            "UI tidak bisa diakses. Jalankan 'python -m uptimebot genkey' dan "
            "'python -m uptimebot hash-password', lalu isi SECRET_KEY, "
            "UI_PASSWORD_HASH di .env."
        )
    if not settings.discord.webhook_configured:
        problems.append("DISCORD_WEBHOOK_URL kosong: tidak ada notifikasi yang dikirim.")
    if not settings.secret_key:
        problems.append("SECRET_KEY kosong: session tidak bisa ditandatangani.")
    if settings.cookie_secure and not settings.public_url.startswith("https"):
        problems.append(
            "COOKIE_SECURE=true tapi PUBLIC_URL bukan https. Browser akan "
            "menolak cookie bila diakses lewat http."
        )
    try:
        db.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        problems.append(f"Folder database tidak bisa dibuat: {exc}")

    if problems:
        print("\nPerlu diperbaiki:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nSemua wajib sudah terisi.")
    return 0


__all__ = ["main"]
