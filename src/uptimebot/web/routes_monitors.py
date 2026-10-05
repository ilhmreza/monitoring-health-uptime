"""Monitor CRUD, pause/resume and Discord test actions."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..db import ValidationError
from ..discord import ResolveError
from .deps import get_context, require_auth, require_csrf
from .forms import form_view, parse_monitor_form

log = logging.getLogger(__name__)

router = APIRouter(tags=["monitors"])


@router.get("/monitors/new", response_class=HTMLResponse)
async def new_form(request: Request, session=Depends(require_auth)) -> HTMLResponse:
    ctx = get_context(request)
    return ctx.templates.TemplateResponse(
        request,
        "monitor_form.html",
        {
            "is_new": True,
            "f": form_view(None, {}, ctx.settings),
            "errors": [],
            "session": session,
            "state": ctx.settings.describe_public_state(),
            "resolver_ready": ctx.resolver is not None and ctx.resolver.configured,
        },
    )


@router.post("/monitors", response_class=HTMLResponse)
async def create_monitor(request: Request, session=Depends(require_auth)) -> HTMLResponse:
    ctx = get_context(request)
    form = await request.form()
    require_csrf(session, form)

    result = parse_monitor_form(form, ctx.settings, existing=None)
    if not result.ok:
        return _form_error(ctx, request, session, None, result)

    monitor = result.monitor
    assert monitor is not None
    try:
        created = await ctx.monitors.create(monitor)
    except ValidationError as exc:
        return _form_error(ctx, request, session, None, _with_error(result, str(exc)))

    await ctx.audit.record(session.username, "monitor.create", created.id, {"name": created.name})
    ctx.scheduler.notify_config_changed()
    log.info("monitor %s created by %s", created.id, session.username)
    return RedirectResponse(f"/monitors/{created.id}?created=1", status_code=303)


@router.get("/monitors/{monitor_id}", response_class=HTMLResponse)
async def edit_form(
    request: Request, monitor_id: str, session=Depends(require_auth)
) -> HTMLResponse:
    ctx = get_context(request)
    monitor = await _require(ctx, monitor_id)
    return ctx.templates.TemplateResponse(
        request,
        "monitor_form.html",
        {
            "is_new": False,
            "f": form_view(monitor, {}, ctx.settings),
            "errors": [],
            "session": session,
            "flash": "Simpan perubahan sudah tersimpan."
            if request.query_params.get("saved") == "1"
            else "Monitor dibuat.",
            "notice": request.query_params.get("error"),
            "state": ctx.settings.describe_public_state(),
            "resolver_ready": ctx.resolver is not None and ctx.resolver.configured,
            "ssl": await ctx.ssl_state.get(monitor_id),
            "rows": await ctx.checks.recent_failures(monitor_id, 5),
        },
    )


@router.post("/monitors/{monitor_id}", response_class=HTMLResponse)
async def update_monitor(
    request: Request, monitor_id: str, session=Depends(require_auth)
) -> HTMLResponse:
    ctx = get_context(request)
    form = await request.form()
    require_csrf(session, form)

    existing = await _require(ctx, monitor_id)
    result = parse_monitor_form(form, ctx.settings, existing=existing)
    if not result.ok:
        return _form_error(ctx, request, session, existing, result)

    monitor = result.monitor
    assert monitor is not None
    try:
        await ctx.monitors.update(monitor)
    except ValidationError as exc:
        return _form_error(ctx, request, session, existing, _with_error(result, str(exc)))

    await ctx.audit.record(session.username, "monitor.update", monitor_id, {"name": monitor.name})
    ctx.scheduler.notify_config_changed()
    log.info("monitor %s updated by %s", monitor_id, session.username)
    return RedirectResponse(f"/monitors/{monitor_id}?saved=1", status_code=303)


@router.post("/monitors/{monitor_id}/delete")
async def delete_monitor(
    request: Request, monitor_id: str, session=Depends(require_auth)
) -> RedirectResponse:
    ctx = get_context(request)
    form = await request.form()
    require_csrf(session, form)

    monitor = await _require(ctx, monitor_id)
    await ctx.monitors.delete(monitor_id)
    await ctx.audit.record(session.username, "monitor.delete", monitor_id, {"name": monitor.name})
    ctx.scheduler.notify_config_changed()
    log.info("monitor %s deleted by %s", monitor_id, session.username)

    # Best-effort notice; a dead webhook must not block the delete.
    if ctx.webhook.configured:
        await ctx.webhook.send(ctx.embeds.monitor_deleted(monitor.id, monitor.name))
    return RedirectResponse("/?deleted=1", status_code=303)


@router.post("/monitors/{monitor_id}/toggle")
async def toggle_monitor(
    request: Request, monitor_id: str, session=Depends(require_auth)
) -> RedirectResponse:
    ctx = get_context(request)
    form = await request.form()
    require_csrf(session, form)

    monitor = await _require(ctx, monitor_id)
    now_enabled = not monitor.enabled
    await ctx.monitors.set_enabled(monitor_id, now_enabled)
    await ctx.audit.record(
        session.username,
        "monitor.toggle",
        monitor_id,
        {"enabled": now_enabled},
    )
    ctx.scheduler.notify_config_changed()
    if ctx.webhook.configured:
        await ctx.webhook.send(ctx.embeds.pause_state(monitor, not now_enabled, session.username))
    return RedirectResponse(f"/monitors/{monitor_id}?toggled=1", status_code=303)


@router.post("/monitors/{monitor_id}/test")
async def test_notification(
    request: Request, monitor_id: str, session=Depends(require_auth)
) -> RedirectResponse:
    """Send a synthetic alert. Never touches monitor state."""
    ctx = get_context(request)
    form = await request.form()
    require_csrf(session, form)

    monitor = await _require(ctx, monitor_id)
    note = str(form.get("note") or "Tes manual dari dashboard").strip()[:300]
    if not ctx.webhook.configured:
        return RedirectResponse(
            f"/monitors/{monitor_id}?error=webhook+belum+dikonfigurasi", status_code=303
        )
    result = await ctx.webhook.send(ctx.embeds.test_alert(monitor, note))
    await ctx.audit.record(
        session.username,
        "monitor.test",
        monitor_id,
        {"delivered": result.ok, "status": result.status_code, "error": result.error},
    )
    if result.ok:
        return RedirectResponse(f"/monitors/{monitor_id}?tested=1", status_code=303)
    return RedirectResponse(
        f"/monitors/{monitor_id}?error={_quote(result.error or 'gagal mengirim')}",
        status_code=303,
    )


@router.post("/monitors/{monitor_id}/test-mention")
async def test_mention(
    request: Request, monitor_id: str, session=Depends(require_auth)
) -> RedirectResponse:
    ctx = get_context(request)
    form = await request.form()
    require_csrf(session, form)

    monitor = await _require(ctx, monitor_id)
    if not ctx.webhook.configured:
        return RedirectResponse(
            f"/monitors/{monitor_id}?error=webhook+belum+dikonfigurasi", status_code=303
        )
    result = await ctx.webhook.send(ctx.embeds.test_mention(monitor))
    await ctx.audit.record(
        session.username, "monitor.test_mention", monitor_id, {"delivered": result.ok}
    )
    if result.ok:
        return RedirectResponse(f"/monitors/{monitor_id}?mentioned=1", status_code=303)
    return RedirectResponse(
        f"/monitors/{monitor_id}?error={_quote(result.error or 'gagal mengirim')}",
        status_code=303,
    )


@router.post("/discord/refresh-users")
async def refresh_discord_users(request: Request, session=Depends(require_auth)) -> JSONResponse:
    """Re-scan channel history to rebuild the ``@username`` cache."""
    ctx = get_context(request)
    form = await request.form()
    require_csrf(session, form)

    if ctx.resolver is None or not ctx.resolver.configured:
        raise HTTPException(
            status_code=400,
            detail=(
                "Resolver belum dikonfigurasi. Set DISCORD_BOT_TOKEN, "
                "DISCORD_GUILD_ID dan DISCORD_REPORT_CHANNEL_ID di .env"
            ),
        )
    try:
        users = await ctx.resolver.refresh()
    except ResolveError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)

    stored = await ctx.discord_users.upsert_many(users, ctx.resolver.channel_id)
    await ctx.audit.record(session.username, "discord.refresh_users", None, {"count": stored})
    return JSONResponse({"ok": True, "count": stored})


@router.post("/api/resolve-user")
async def resolve_user(
    request: Request, session=Depends(require_auth)
) -> JSONResponse:
    """Turn a typed ``@name`` into a numeric User ID."""
    ctx = get_context(request)
    payload = await request.json()
    query = str(payload.get("q", "")).strip()
    if not query:
        return JSONResponse({"ok": False, "error": "Isi nama username Discord"}, status_code=400)

    if query.isdigit() and 15 <= len(query) <= 25:
        return JSONResponse({"ok": True, "user_id": query, "username": None, "verbatim": True})

    if ctx.resolver is None or not ctx.resolver.configured:
        return JSONResponse(
            {
                "ok": False,
                "error": "Auto-resolve belum aktif. Isi User ID Discord secara manual.",
            },
            status_code=400,
        )
    try:
        found = await ctx.resolver.resolve(query)
    except ResolveError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)
    return JSONResponse(
        {
            "ok": True,
            "user_id": found.user_id,
            "username": found.username,
            "global_name": found.global_name,
        }
    )


# ---------------------------------------------------------------------------

def _quote(value: str) -> str:
    from urllib.parse import quote_plus

    return quote_plus(value[:200])


def _with_error(result, message: str):
    result.errors.append(message)
    result.monitor = None
    return result


def _form_error(ctx, request: Request, session, existing, result) -> HTMLResponse:
    """Re-render the editor with the operator's input and the error list.

    ``existing`` is passed through so an edit that fails validation keeps the
    same id and action URL instead of silently turning into a create.
    """
    return ctx.templates.TemplateResponse(
        request,
        "monitor_form.html",
        {
            "is_new": existing is None,
            "f": form_view(existing, result.values, ctx.settings),
            "errors": result.errors,
            "session": session,
            "state": ctx.settings.describe_public_state(),
            "resolver_ready": ctx.resolver is not None and ctx.resolver.configured,
        },
        status_code=400,
    )


async def _require(ctx, monitor_id: str):
    monitor = await ctx.monitors.get(monitor_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="monitor tidak ditemukan")
    return monitor


__all__ = ["router"]
