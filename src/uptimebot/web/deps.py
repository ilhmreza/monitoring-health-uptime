"""Shared application state and request dependencies."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from ..db import AuditRepo, CheckRepo, Database, DiscordUserRepo, MonitorRepo, SslStateRepo, StateRepo, UserRepo
from ..discord import DiscordResolver, EmbedBuilder, WebhookClient
from ..monitor.scheduler import Scheduler
from ..settings import Settings
from ..web.auth import (
    CSRF_FIELD,
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    LoginThrottle,
    Session,
    validate_session,
)

log = logging.getLogger(__name__)

TEMPLATE_DIR = "templates"
STATIC_DIR = "static"


@dataclass(slots=True)
class AppContext:
    """Everything a request handler or background task needs."""

    settings: Settings
    db: Database
    monitors: MonitorRepo
    state: StateRepo
    checks: CheckRepo
    ssl_state: SslStateRepo
    discord_users: DiscordUserRepo
    web_user: UserRepo
    audit: AuditRepo
    webhook: WebhookClient
    embeds: EmbedBuilder
    resolver: DiscordResolver | None
    scheduler: Scheduler
    throttle: LoginThrottle
    templates: Jinja2Templates

    @property
    def password_hash(self) -> str:
        """The active credential. A .env value overrides anything in the DB."""
        return self.settings.ui_password_hash

    async def dashboard_rows(self, window: timedelta | None = None) -> list[Any]:
        """Monitors plus live stats, assembled with three queries.

        The dashboard polls every five seconds, so everything is fetched for all
        monitors at once rather than per row.
        """
        window = window or timedelta(hours=24)
        rows = await self.monitors.list_with_state()
        aggregates = await self.checks.aggregates_for_all(window)
        latest = await self.checks.latest_per_monitor()
        ssl_rows = {entry["monitor_id"]: entry for entry in await self.ssl_state.list_all()}

        for row in rows:
            stats = aggregates.get(row.monitor.id)
            if stats:
                row.uptime_24h = stats["uptime_percent"]
                row.avg_latency_24h = stats["avg_latency_ms"]
            newest = latest.get(row.monitor.id)
            if newest:
                row.last_latency_ms = newest["latency_ms"]
                row.last_status_code = newest["status_code"]
            row.ssl = ssl_rows.get(row.monitor.id)
        return rows


def get_context(request: Request) -> AppContext:
    ctx = getattr(request.app.state, "ctx", None)
    if ctx is None:  # pragma: no cover - only reachable if wiring is broken
        raise HTTPException(status_code=500, detail="aplikasi belum diinisialisasi")
    return ctx


async def current_session(request: Request) -> Session | None:
    """Validate the session cookie against the current password hash."""
    ctx = get_context(request)
    raw = request.session.get("__session__")
    session = Session.from_dict(raw)
    return validate_session(session, ctx.password_hash)


async def require_auth(request: Request) -> Session:
    """Dependency for every page that needs a logged-in admin."""
    if not get_context(request).settings.auth_configured:
        # Refuse to serve a UI that nobody can authenticate against.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="UI belum dikonfigurasi: set UI_PASSWORD_HASH dan SECRET_KEY",
        )
    session = await current_session(request)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    return session


def require_csrf(session: Session, form: Any) -> None:
    """Double-submit CSRF check for a state-changing form post."""
    supplied = form.get(CSRF_FIELD, "") if hasattr(form, "get") else ""
    if not supplied or supplied != session.csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Token CSRF tidak valid"
        )


def setup_middleware(app: Any, settings: Settings) -> None:
    """Session signing.

    ``itsdangerous`` signs the cookie, so a tampered payload is rejected
    without any server-side session store.
    """
    if settings.secret_key:
        app.add_middleware(
            SessionMiddleware,
            secret_key=settings.secret_key,
            session_cookie=SESSION_COOKIE,
            max_age=SESSION_MAX_AGE,
            same_site="lax",
            # Secure is safe because the provided compose terminates TLS at
            # Caddy and the browser only ever talks HTTPS.
            https_only=settings.cookie_secure,
        )


__all__ = [
    "AppContext",
    "CSRF_FIELD",
    "Depends",
    "LoginThrottle",
    "Session",
    "STATIC_DIR",
    "TEMPLATE_DIR",
    "current_session",
    "get_context",
    "require_auth",
    "require_csrf",
    "setup_middleware",
]
