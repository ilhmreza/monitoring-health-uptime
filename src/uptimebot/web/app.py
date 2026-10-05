"""FastAPI application factory and lifespan wiring.

The monitor scheduler and the web server share one event loop, which keeps
the deployment to a single container and lets the UI change monitors without
a restart: the API sets an event, the scheduler reconciles.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..db import (
    AuditRepo,
    CheckRepo,
    Database,
    DiscordUserRepo,
    MonitorRepo,
    SslStateRepo,
    StateRepo,
    UserRepo,
)
from ..discord import DiscordResolver, EmbedBuilder, WebhookClient
from ..models import format_duration, format_relative, format_utc, ssl_badge
from ..monitor.scheduler import Scheduler
from ..settings import Settings
from .auth import LoginThrottle
from .deps import AppContext, STATIC_DIR, TEMPLATE_DIR, setup_middleware

log = logging.getLogger(__name__)

DESCRIPTION = """
Uptime, downtime-duration and SSL-expiry monitoring with Discord reporting.

* Probe HTTP, track outage duration, alert after a configurable failure streak
* Warn on certificate expiry at 30 / 14 / 7 / 1 days and once expired
* Re-ping the on-call while an incident is still open
"""


def create_app(settings: Settings, *, start_scheduler: bool = True) -> FastAPI:
    """Build the application. ``start_scheduler=False`` is used by the tests."""
    base_dir = _base_dir()
    templates = Jinja2Templates(directory=str(base_dir / TEMPLATE_DIR))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = Database(settings.database_path)
        await db.connect()
        await db.init_schema()
        await db.optimize()

        monitors = MonitorRepo(db)
        state = StateRepo(db)
        checks = CheckRepo(db)
        ssl_state = SslStateRepo(db)
        discord_users = DiscordUserRepo(db)
        web_user = UserRepo(db)
        audit = AuditRepo(db)

        embeds = EmbedBuilder(
            tz=settings.timezone,
            report_channel_id=settings.discord.report_channel_id,
            public_url=settings.public_url or None,
        )
        webhook = WebhookClient(settings.discord.webhook_url)
        resolver = (
            DiscordResolver(
                bot_token=settings.discord.bot_token,
                guild_id=settings.discord.guild_id,
                channel_id=settings.discord.report_channel_id,
            )
            if settings.discord.resolver_configured
            else None
        )
        scheduler = Scheduler(
            settings=settings,
            db=db,
            monitors=monitors,
            state=state,
            checks=checks,
            ssl_state=ssl_state,
            webhook=webhook,
            embeds=embeds,
        )

        app.state.ctx = AppContext(
            settings=settings,
            db=db,
            monitors=monitors,
            state=state,
            checks=checks,
            ssl_state=ssl_state,
            discord_users=discord_users,
            web_user=web_user,
            audit=audit,
            webhook=webhook,
            embeds=embeds,
            resolver=resolver,
            scheduler=scheduler,
            throttle=LoginThrottle(
                max_attempts=settings.login_max_attempts,
                lockout_seconds=settings.login_lockout_seconds,
            ),
            templates=templates,
        )
        templates.env.globals.update(
            monitor_state_labels=_state_labels(),
            format_utc=format_utc,
            format_relative=format_relative,
            format_duration=format_duration,
            ssl_badge=ssl_badge,
        )

        if start_scheduler:
            await scheduler.start()
            count = await monitors.count()
            if webhook.configured:
                await webhook.send(embeds.startup_banner(count, webhook_ok=True))
            log.info("UptimeBot ready with %s monitor(s)", count)

        try:
            yield
        finally:
            if start_scheduler:
                await scheduler.stop()
            if resolver is not None:
                await resolver.close()
            await db.close()

    app = FastAPI(
        title="UptimeBot",
        description=DESCRIPTION,
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    setup_middleware(app, settings)

    app.mount(
        f"/{STATIC_DIR}",
        StaticFiles(directory=str(base_dir / STATIC_DIR)),
        name=STATIC_DIR,
    )

    from .routes_auth import router as auth_router
    from .routes_dashboard import router as dashboard_router
    from .routes_monitors import router as monitors_router

    app.include_router(auth_router)
    app.include_router(monitors_router)
    app.include_router(dashboard_router)

    _register_error_handlers(app)
    _register_health(app)
    return app


def _register_health(app: FastAPI) -> None:
    @app.get("/healthz", include_in_schema=False)
    async def healthz(request: Request) -> JSONResponse:
        """Liveness and readiness for Docker.

        Reports unhealthy when the monitor loop is not running, so a wedged
        scheduler triggers a restart instead of a silent outage.
        """
        ctx = getattr(request.app.state, "ctx", None)
        if ctx is None:
            return JSONResponse({"status": "starting"}, status_code=503)

        scheduler = ctx.scheduler.health()
        healthy = bool(scheduler["running"])
        payload = {
            "status": "ok" if healthy else "degraded",
            "scheduler": scheduler,
            "monitors": await ctx.monitors.count(),
            "discord_webhook": ctx.settings.discord.webhook_configured,
            "timezone": ctx.settings.timezone.key,
        }
        return JSONResponse(payload, status_code=200 if healthy else 503)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> JSONResponse:
        return JSONResponse({}, status_code=204)


def _register_error_handlers(app: FastAPI) -> None:
    from fastapi.exceptions import HTTPException as FastAPIHTTPException

    @app.exception_handler(FastAPIHTTPException)
    async def http_error(request: Request, exc: FastAPIHTTPException) -> HTMLResponse:
        # A redirect raised as an exception should stay a redirect, so the
        # browser ends up on the login page instead of an error body.
        if exc.status_code == 303 and "Location" in (exc.headers or {}):
            from fastapi.responses import RedirectResponse

            return RedirectResponse(exc.headers["Location"], status_code=303)

        ctx = getattr(request.app.state, "ctx", None)
        if ctx is None:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return ctx.templates.TemplateResponse(
            request,
            "error.html",
            {
                "status_code": exc.status_code,
                "detail": exc.detail,
                "state": ctx.settings.describe_public_state(),
            },
            status_code=exc.status_code,
        )


def _state_labels() -> dict[str, str]:
    return {
        "up": "UP",
        "down": "DOWN",
        "paused": "DIJEDA",
        "unknown": "Belum dicek",
    }


def _base_dir():
    from pathlib import Path

    return Path(__file__).resolve().parent.parent
