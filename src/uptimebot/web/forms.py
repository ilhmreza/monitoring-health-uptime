"""Form parsing and validation for the monitor editor.

All user input arrives here, before it reaches the database or an outbound
request. Validation is deliberately chatty: the operator gets a list of
specific, actionable problems rather than a generic 500.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..db import ValidationError, slugify_id
from ..models import Monitor, NotifyEvent
from ..monitor.ssrf import BlockedTargetError, validate_url_static
from ..settings import Settings

VALID_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

# Header names allowed through to the probe. Deliberately narrow: an operator
# should not be able to set Host, Transfer-Encoding or Authorization-by-raw-value.
ALLOWED_HEADERS = frozenset(
    {
        "accept",
        "accept-language",
        "authorization",
        "cache-control",
        "content-type",
        "if-none-match",
        "pragma",
        "user-agent",
        "x-api-key",
        "x-auth-token",
        "x-requested-with",
    }
)

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(slots=True)
class FormResult:
    monitor: Monitor | None = None
    errors: list[str] = field(default_factory=list)
    values: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.monitor is not None and not self.errors


def _text(form: Any, key: str, default: str = "") -> str:
    raw = form.get(key, default)
    return str(raw).strip() if raw is not None else default


def _int(form: Any, key: str, default: int, lo: int, hi: int, errors: list[str]) -> int:
    raw = _text(form, key)
    if raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        errors.append(f"'{key}' harus berupa bilangan bulat")
        return default
    if not lo <= value <= hi:
        errors.append(f"'{key}' harus antara {lo} dan {hi}")
        return default
    return value


def parse_status_codes(raw: str, errors: list[str]) -> list[int]:
    codes: list[int] = []
    for chunk in re.split(r"[,\s]+", raw.strip()):
        if not chunk:
            continue
        try:
            code = int(chunk)
        except ValueError:
            errors.append(f"Status HTTP '{chunk}' bukan angka")
            continue
        if not 100 <= code <= 599:
            errors.append(f"Status HTTP {code} di luar rentang 100-599")
            continue
        if code not in codes:
            codes.append(code)
    if not codes:
        errors.append("Isi minimal satu status HTTP yang dianggap sehat")
        return [200]
    return codes


def parse_headers_env(raw: str, errors: list[str]) -> dict[str, str]:
    """Parse ``Header-Name: ENV_VAR_NAME`` lines.

    Only the *name* of the environment variable is stored, so an API token
    never reaches the database or the web form.
    """
    out: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        header, sep, env_name = line.partition(":")
        header = header.strip()
        env_name = env_name.strip()
        if not sep or not header or not env_name:
            errors.append(f"Baris header tidak valid: '{line}' (format: Nama-Header: NAMA_ENV)")
            continue
        if header.lower() not in ALLOWED_HEADERS:
            allowed = ", ".join(sorted(ALLOWED_HEADERS))
            errors.append(f"Header '{header}' tidak diizinkan. Yang diizinkan: {allowed}")
            continue
        if not _ENV_NAME_RE.match(env_name):
            errors.append(f"Nama environment variable '{env_name}' tidak valid (huruf/angka/underscore)")
            continue
        out[header] = env_name
    return out


def parse_ids(raw: str, errors: list[str], label: str) -> list[str]:
    """Parse a list of Discord IDs from comma/space separated text.

    Malformed entries are reported, but a warning is not fatal: an operator
    mid-edit should still be able to save.
    """
    out: list[str] = []
    for chunk in re.split(r"[,\s]+", raw.strip()):
        if not chunk:
            continue
        candidate = chunk.strip()
        if candidate.startswith("<@&") and candidate.endswith(">"):
            candidate = candidate[3:-1]
        elif candidate.startswith("<@") and candidate.endswith(">"):
            candidate = candidate[2:-1]
        if not re.match(r"^\d{15,25}$", candidate):
            errors.append(f"{label} '{chunk}' bukan User/Role ID Discord yang valid")
            continue
        if candidate not in out:
            out.append(candidate)
    return out


def parse_warn_days(raw: str, errors: list[str], fallback: list[int]) -> list[int]:
    if not raw.strip():
        return list(fallback)
    days: list[int] = []
    for chunk in re.split(r"[,\s]+", raw.strip()):
        if not chunk:
            continue
        try:
            value = int(chunk)
        except ValueError:
            errors.append(f"Threshold SSL '{chunk}' bukan angka")
            continue
        if not 0 <= value <= 3650:
            errors.append(f"Threshold SSL {value} harus antara 0 dan 3650")
            continue
        if value not in days:
            days.append(value)
    if not days:
        return list(fallback)
    # Most severe last, so escalation is a simple comparison downstream.
    return sorted(days, reverse=True)


def parse_monitor_form(
    form: Any, settings: Settings, *, existing: Monitor | None = None
) -> FormResult:
    """Validate a submitted monitor form into a :class:`Monitor`."""
    errors: list[str] = []
    values: dict[str, Any] = {}

    raw_id = _text(form, "id")
    if existing is not None:
        monitor_id = existing.id
    else:
        try:
            monitor_id = slugify_id(raw_id or _text(form, "name"))
        except ValidationError as exc:
            monitor_id = ""
            errors.append(str(exc))
    values["id"] = monitor_id

    name = _text(form, "name")
    if not name:
        errors.append("Nama monitor wajib diisi")
    elif len(name) > 120:
        errors.append("Nama monitor maksimal 120 karakter")
    values["name"] = name

    url = _text(form, "url")
    values["url"] = url
    allow_private = "allow_private_network" in form
    values["allow_private_network"] = allow_private
    if not url:
        errors.append("URL wajib diisi")
    else:
        try:
            validate_url_static(url, allow_private_network=allow_private)
        except BlockedTargetError as exc:
            errors.append(str(exc))

    method = (_text(form, "method") or "GET").upper()
    if method not in VALID_METHODS:
        errors.append(f"Method '{method}' tidak didukung")
        method = "GET"
    values["method"] = method

    expect_status = parse_status_codes(_text(form, "expect_status", "200"), errors)
    values["expect_status"] = expect_status

    headers_env = parse_headers_env(_text(form, "headers_env"), errors)
    values["headers_env"] = headers_env

    keyword = _text(form, "keyword") or None
    values["keyword"] = keyword

    interval = _int(
        form, "interval_seconds", settings.default_interval_seconds, 5, 86400, errors
    )
    timeout = _int(form, "timeout_seconds", settings.default_timeout_seconds, 1, 120, errors)
    if timeout > interval:
        errors.append("Timeout harus lebih kecil atau sama dengan interval")
    threshold = _int(
        form, "failure_threshold", settings.default_failure_threshold, 1, 20, errors
    )
    values.update(interval_seconds=interval, timeout_seconds=timeout, failure_threshold=threshold)

    user_ids = parse_ids(_text(form, "notify_user_ids"), errors, "User ID")
    role_ids = parse_ids(_text(form, "notify_role_ids"), errors, "Role ID")
    values["notify_user_ids"] = user_ids
    values["notify_role_ids"] = role_ids

    selected = form.getlist("notify_on") if hasattr(form, "getlist") else []
    notify_on = [NotifyEvent(v) for v in selected if v in {e.value for e in NotifyEvent}]
    if not notify_on:
        errors.append("Pilih minimal satu jenis notifikasi (down / recovery / ssl)")
    values["notify_on"] = notify_on

    ssl_check = "ssl_check" in form
    values["ssl_check"] = ssl_check
    fallback_days = existing.ssl_warn_days if existing else list(settings.ssl_warn_days)
    warn_days = parse_warn_days(_text(form, "ssl_warn_days"), errors, fallback_days)
    if not ssl_check:
        warn_days = []
    values["ssl_warn_days"] = warn_days

    enabled = "enabled" in form
    values["enabled"] = enabled

    if errors:
        return FormResult(errors=errors, values=values)

    monitor = Monitor(
        id=monitor_id,
        name=name,
        url=url,
        method=method,
        expect_status=expect_status,
        headers_env=headers_env,
        keyword=keyword,
        interval_seconds=interval,
        timeout_seconds=timeout,
        failure_threshold=threshold,
        notify_user_ids=user_ids,
        notify_role_ids=role_ids,
        notify_on=notify_on,
        ssl_check=ssl_check,
        ssl_warn_days=warn_days,
        allow_private_network=allow_private,
        enabled=enabled,
        created_at=existing.created_at if existing else None,
    )
    return FormResult(monitor=monitor, errors=[], values=values)


def display_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or url).lower()
    except ValueError:
        return url


# Every field the editor renders, with the default used when nothing is bound yet.
FORM_DEFAULTS: dict[str, Any] = {
    "id": "",
    "name": "",
    "url": "",
    "method": "GET",
    "expect_status": [200],
    "headers_env": "",
    "keyword": "",
    "interval_seconds": 60,
    "timeout_seconds": 10,
    "failure_threshold": 3,
    "notify_user_ids": [],
    "notify_role_ids": [],
    "notify_on": ["down", "recovery", "ssl"],
    "ssl_check": True,
    "ssl_warn_days": [30, 14, 7, 1],
    "allow_private_network": False,
    "enabled": True,
}

# Fields rendered as comma-separated text rather than a list.
_LIST_AS_TEXT = frozenset({"expect_status", "ssl_warn_days"})


def form_view(monitor: Monitor | None, values: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """One flat dict for the template, whichever state the page is in.

    Three cases collapse here: a blank new form, an existing record, and a
    rejected submission (where ``values`` must win so the operator does not
    lose their typing). List fields are pre-joined for the text inputs.
    """
    merged: dict[str, Any] = dict(FORM_DEFAULTS)
    merged["interval_seconds"] = settings.default_interval_seconds
    merged["timeout_seconds"] = settings.default_timeout_seconds
    merged["failure_threshold"] = settings.default_failure_threshold
    merged["ssl_warn_days"] = list(settings.ssl_warn_days)

    if monitor is not None:
        for key in FORM_DEFAULTS:
            if hasattr(monitor, key):
                merged[key] = getattr(monitor, key)
    merged.update({k: v for k, v in values.items() if k in FORM_DEFAULTS})

    for key in _LIST_AS_TEXT:
        raw = merged.get(key) or []
        merged[key] = ", ".join(str(item) for item in raw)

    for key in ("headers_env", "keyword"):
        raw = merged.get(key)
        if isinstance(raw, dict):
            merged[key] = "\n".join(f"{name}: {env}" for name, env in raw.items())
    for key in ("notify_user_ids", "notify_role_ids"):
        if isinstance(merged.get(key), list):
            merged[key] = ", ".join(merged[key])
    if isinstance(merged.get("notify_on"), list):
        # NotifyEvent is a str mixin, but ``str()`` on it yields
        # "NotifyEvent.DOWN", so unwrap to the raw value for the template.
        merged["notify_on"] = [
            getattr(item, "value", item) for item in merged["notify_on"]
        ]

    return merged
