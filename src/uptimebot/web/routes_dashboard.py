"""Dashboard, history and SSL views."""

from __future__ import annotations

import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..models import MonitorState
from .deps import AppContext, get_context, require_auth

log = logging.getLogger(__name__)

router = APIRouter(tags=["dashboard"])

# range key -> (window, chart points, human label)
HISTORY_RANGES: dict[str, tuple[timedelta, int, str]] = {
    "24h": (timedelta(hours=24), 96, "24 jam"),
    "7d": (timedelta(days=7), 96, "7 hari"),
    "30d": (timedelta(days=30), 96, "30 hari"),
}
DEFAULT_RANGE = "24h"


def _range(range_key: str) -> tuple[timedelta, int, str]:
    return HISTORY_RANGES.get(range_key, HISTORY_RANGES[DEFAULT_RANGE])


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session=Depends(require_auth)) -> HTMLResponse:
    ctx = get_context(request)
    rows = await ctx.dashboard_rows()
    return ctx.templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "rows": rows,
            "counts": _summarise(rows),
            "session": session,
            "state": ctx.settings.describe_public_state(),
            "scheduler": ctx.scheduler.health(),
        },
    )


@router.get("/partials/monitor-table", response_class=HTMLResponse)
async def monitor_table(request: Request, session=Depends(require_auth)) -> HTMLResponse:
    """The fragment the dashboard polls, so live data updates without a reload."""
    ctx = get_context(request)
    return ctx.templates.TemplateResponse(
        request,
        "partials/monitor_table.html",
        {"rows": await ctx.dashboard_rows()},
    )


@router.get("/ssl", response_class=HTMLResponse)
async def ssl_overview(request: Request, session=Depends(require_auth)) -> HTMLResponse:
    ctx = get_context(request)
    return ctx.templates.TemplateResponse(
        request,
        "ssl.html",
        {
            "rows": await ctx.ssl_state.list_all(),
            "session": session,
            "state": ctx.settings.describe_public_state(),
        },
    )


@router.get("/monitors/{monitor_id}/history", response_class=HTMLResponse)
async def history_page(
    request: Request,
    monitor_id: str,
    session=Depends(require_auth),
    range_key: str = Query(default=DEFAULT_RANGE, alias="range"),
) -> HTMLResponse:
    ctx = get_context(request)
    monitor = await _require_monitor(ctx, monitor_id)
    window, _points, label = _range(range_key)
    return ctx.templates.TemplateResponse(
        request,
        "history.html",
        {
            "monitor": monitor,
            "stats": await ctx.checks.stats(monitor_id, window, label),
            "range_key": range_key if range_key in HISTORY_RANGES else DEFAULT_RANGE,
            "ranges": {key: value[2] for key, value in HISTORY_RANGES.items()},
            "failures": await ctx.checks.recent_failures(monitor_id, 20),
            "ssl": await ctx.ssl_state.get(monitor_id),
            "session": session,
        },
    )


@router.get("/api/history/{monitor_id}")
async def history_data(
    request: Request,
    monitor_id: str,
    session=Depends(require_auth),
    range_key: str = Query(default=DEFAULT_RANGE, alias="range"),
) -> JSONResponse:
    """Chart series, aggregated server-side so the payload stays small.

    Sending raw rows would mean ~3k points for a 24-hour view at a 30-second
    interval; bucketing keeps it at a fixed 96 points per range.
    """
    ctx = get_context(request)
    await _require_monitor(ctx, monitor_id)
    window, points, label = _range(range_key)
    buckets = await ctx.checks.buckets(monitor_id, window, target_points=points)
    stats = await ctx.checks.stats(monitor_id, window, label)
    return JSONResponse(
        {
            "range": range_key,
            "label": label,
            "buckets": [
                {
                    "t": b.bucket_start.isoformat(),
                    "uptime": round(b.uptime_percent, 3),
                    "total": b.total,
                    "successful": b.successful,
                    "latency": round(b.avg_latency_ms, 1) if b.avg_latency_ms is not None else None,
                }
                for b in buckets
            ],
            "stats": {
                "uptime_percent": stats.uptime_percent,
                "avg_latency_ms": stats.avg_latency_ms,
                "p95_latency_ms": stats.p95_latency_ms,
                "total": stats.total,
            },
        }
    )


@router.get("/api/users")
async def autocomplete_users(
    request: Request,
    session=Depends(require_auth),
    q: str = Query(default="", max_length=64),
) -> JSONResponse:
    """``@username`` autocomplete for the mention picker.

    Served from the local cache. Refreshing against Discord is a separate,
    explicitly triggered action, so typing never triggers a Discord request.
    """
    ctx = get_context(request)
    query = q.strip().lstrip("@")
    if not query:
        return JSONResponse({"users": [], "source": "cache"})
    if ctx.resolver is not None and ctx.resolver.cached():
        return JSONResponse({"users": await ctx.resolver.find(query), "source": "memory"})
    return JSONResponse({"users": await ctx.discord_users.search(query), "source": "db"})


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request, session=Depends(require_auth)) -> HTMLResponse:
    ctx = get_context(request)
    return ctx.templates.TemplateResponse(
        request,
        "audit.html",
        {"entries": await ctx.audit.recent(100), "session": session},
    )


def _summarise(rows) -> dict[str, int]:
    """Headline counts for the status tiles."""
    counts = {"total": len(rows), "up": 0, "down": 0, "paused": 0, "unknown": 0}
    buckets = {
        MonitorState.UP: "up",
        MonitorState.DOWN: "down",
        MonitorState.PAUSED: "paused",
        MonitorState.UNKNOWN: "unknown",
    }
    for item in rows:
        counts[buckets.get(item.effective_state, "unknown")] += 1
    return counts


async def _require_monitor(ctx: AppContext, monitor_id: str):
    monitor = await ctx.monitors.get(monitor_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="monitor tidak ditemukan")
    return monitor


__all__ = ["router", "HISTORY_RANGES", "DEFAULT_RANGE"]
