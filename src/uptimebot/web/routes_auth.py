"""Login and logout."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .auth import AuthError, LoginThrottle, build_session, client_key, verify_password
from .deps import get_context

log = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])

# One message for every failure mode, so the form cannot be used to
# enumerate usernames.
GENERIC_FAILURE = "Username atau password salah."


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request) -> HTMLResponse:
    ctx = get_context(request)
    if not ctx.settings.auth_configured:
        return ctx.templates.TemplateResponse(
            request,
            "login.html",
            {
                "configured": False,
                "state": ctx.settings.describe_public_state(),
            },
            status_code=503,
        )
    from .deps import current_session

    if await current_session(request) is not None:
        return RedirectResponse("/", status_code=303)
    return ctx.templates.TemplateResponse(
        request, "login.html", {"configured": True, "error": None}
    )


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request, username: str = Form(default=""), password: str = Form(default="")
) -> HTMLResponse:
    ctx = get_context(request)
    if not ctx.settings.auth_configured:
        return ctx.templates.TemplateResponse(
            request,
            "login.html",
            {"configured": False, "state": ctx.settings.describe_public_state()},
            status_code=503,
        )

    key = client_key(request, trust_proxy=ctx.settings.trust_proxy)
    try:
        ctx.throttle.check(key)
    except AuthError as exc:
        # 429, not 401: a lockout is not a wrong password, and anything in front
        # of this app should be able to tell the two apart.
        return _login_error(ctx, request, str(exc), status_code=429)

    # The env hash is the only credential: it is what the session signature is
    # validated against later, so a second source of truth here would produce a
    # session that is rejected on the very next request.
    password_hash = ctx.password_hash
    expected_user = ctx.settings.ui_username

    if not verify_password(password, password_hash) or username.strip() != expected_user:
        remaining = ctx.throttle.record_failure(key)
        suffix = f" ({remaining} percobaan lagi sebelum dikunci)" if remaining else ""
        log.warning("failed login for %r from %s", username, key)
        return _login_error(ctx, request, GENERIC_FAILURE + suffix)

    ctx.throttle.record_success(key)
    session = build_session(expected_user, password_hash)
    # The whole session lives under one key so a stale top-level field can
    # never be mistaken for a valid one.
    request.session.clear()
    request.session["__session__"] = session.to_dict()
    log.info("admin %s logged in from %s", expected_user, key)
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    """Drop the session.

    CSRF is not required here: the worst outcome is that an attacker logs the
    admin out, and the cookie is already ``SameSite=Lax`` so a cross-site form
    post cannot carry it.
    """
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


def _login_error(
    ctx, request: Request, message: str, *, status_code: int = 401
) -> HTMLResponse:
    response = ctx.templates.TemplateResponse(
        request, "login.html", {"configured": True, "error": message}
    )
    response.status_code = status_code
    return response


__all__ = ["router", "LoginThrottle"]
