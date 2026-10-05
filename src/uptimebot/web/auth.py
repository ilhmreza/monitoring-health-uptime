"""Authentication for the admin UI.

Threat model: the UI is reachable from the internet behind HTTPS, behind a
single shared password. What that implies:

* The password is stored only as a bcrypt hash. Comparison is constant-time
  via bcrypt itself, and an unknown username still runs a hash comparison
  against a dummy value so response timing does not reveal which accounts
  exist.
* Login is rate limited per client IP, and errors are deliberately identical
  for a wrong password and an unknown user. The client key is the immediate
  peer unless ``TRUST_PROXY`` is on and the proxy overwrites
  ``X-Forwarded-For``; see :func:`client_key` for why that default matters.
* The session lives in a signed, ``HttpOnly``, ``SameSite=Lax`` cookie with
  ``Secure`` when served over HTTPS. It holds a CSRF token, which every
  state-changing form must echo back. ``/login`` and ``/logout`` are the two
  exceptions, deliberately: ``/login`` has no session to abuse and this is a
  single shared account, so a forced login has nothing to gain, and a
  cross-site form post cannot carry a ``SameSite=Lax`` cookie anyway.
* Changing the password invalidates every session, because the token is
  derived from the current password hash.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import bcrypt

log = logging.getLogger(__name__)

SESSION_COOKIE = "uptimebot_session"
CSRF_FIELD = "csrf_token"
SESSION_MAX_AGE = 60 * 60 * 12  # 12 hours

# A valid bcrypt hash of a value nobody knows, used to equalise timing.
_DUMMY_HASH = b"$2b$12$C6UzMDM.H6dfI/f/IKcEeO1ZUXH2O9Kk1Aq2B1oLpXvN7J8n3ZgZi"


class AuthError(RuntimeError):
    """Authentication failed. The message is always user-safe."""


def hash_password(password: str, *, rounds: int = 12) -> str:
    if len(password or "") < 10:
        raise ValueError("password minimal 10 karakter")
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def make_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def token_signature(username: str, csrf: str, password_hash: str) -> str:
    """Derive a session signature bound to the current credential.

    Rotating the password therefore invalidates existing sessions, without
    needing a session store.
    """
    material = f"{username}|{csrf}|{password_hash}".encode("utf-8")
    return hmac.new(_derived_key(password_hash), material, "sha256").hexdigest()


def _derived_key(password_hash: str) -> bytes:
    return bcrypt.hashpw(b"session-key-derivation", password_hash.encode("ascii"))[:32]


def safe_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left or "", right or "")


# ---------------------------------------------------------------------------
# Login throttling
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class _Attempt:
    count: int = 0
    first_at: float = field(default_factory=time.monotonic)
    locked_until: float = 0.0


class LoginThrottle:
    """In-memory per-IP throttle.

    In-memory is the right scope here: the container is a single process, and
    a restart resetting the counters is an acceptable trade against adding a
    shared store for a single-admin tool.
    """

    def __init__(self, *, max_attempts: int = 5, lockout_seconds: int = 300) -> None:
        self._max_attempts = max_attempts
        self._lockout = lockout_seconds
        self._attempts: dict[str, _Attempt] = {}

    def check(self, client_key: str) -> None:
        """Raise :class:`AuthError` when the client is currently locked out."""
        record = self._attempts.get(client_key)
        if record is None:
            return
        now = time.monotonic()
        if record.locked_until > now:
            remaining = int(record.locked_until - now)
            raise AuthError(
                f"Terlalu banyak percobaan login. Coba lagi dalam {remaining} detik."
            )
        if now - record.first_at > self._lockout:
            # Window elapsed with no new attempt; let the counter reset.
            self._attempts.pop(client_key, None)

    def record_failure(self, client_key: str) -> int:
        now = time.monotonic()
        record = self._attempts.get(client_key)
        if record is None or now - record.first_at > self._lockout:
            record = _Attempt(first_at=now)
        record.count += 1
        if record.count >= self._max_attempts:
            record.locked_until = now + self._lockout
        self._attempts[client_key] = record
        return max(0, self._max_attempts - record.count)

    def record_success(self, client_key: str) -> None:
        self._attempts.pop(client_key, None)

    def reset(self) -> None:
        self._attempts.clear()

    @property
    def tracked_clients(self) -> int:
        return len(self._attempts)


# ---------------------------------------------------------------------------
# Session payload
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Session:
    username: str
    csrf_token: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            CSRF_FIELD: self.csrf_token,
            "sig": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "Session | None":
        if not isinstance(data, dict):
            return None
        username = data.get("username")
        csrf = data.get(CSRF_FIELD)
        signature = data.get("sig")
        if not (isinstance(username, str) and isinstance(csrf, str) and isinstance(signature, str)):
            return None
        return cls(username=username, csrf_token=csrf, signature=signature)


def build_session(username: str, password_hash: str) -> Session:
    csrf = make_csrf_token()
    return Session(
        username=username,
        csrf_token=csrf,
        signature=token_signature(username, csrf, password_hash),
    )


def validate_session(session: Session | None, password_hash: str) -> Session | None:
    """Accept a session only if its signature matches the current password."""
    if session is None:
        return None
    expected = token_signature(session.username, session.csrf_token, password_hash)
    if not safe_equals(expected, session.signature):
        return None
    return session


def client_key(request: Any, *, trust_proxy: bool = False) -> str:
    """Identify a client for throttling.

    By default the immediate peer is used, not ``X-Forwarded-For``: that header
    is client-controlled unless a proxy is known to overwrite it. When the app
    sits behind Caddy the peer is always the proxy, so that default makes every
    visitor share one throttle bucket and a single unauthenticated attacker can
    lock the single admin out indefinitely by spending the attempt budget on
    purpose.

    ``trust_proxy=True`` opts into reading the header, and is only safe when the
    proxy is known to *replace* it. The shipped Caddyfile does exactly that
    (``header_up X-Forwarded-For {remote_host}``), which is what makes the flag
    safe here. A proxy that merely appends to a client-supplied value would
    still let an attacker forge a fresh key per request, which is worse than
    the shared bucket: the throttle would reset on every attempt.
    """
    if trust_proxy:
        forwarded = _header(request, "x-forwarded-for")
        candidate = forwarded.split(",")[0].strip() if forwarded else ""
        if _is_ip(candidate):
            return candidate
        # A malformed or absent header falls back to the peer rather than
        # trusting whatever arrived.
    client = getattr(request, "client", None)
    host = getattr(client, "host", None)
    return str(host or "unknown")


def _header(request: Any, name: str) -> str:
    headers = getattr(request, "headers", None)
    if headers is None:
        return ""
    try:
        return str(headers.get(name) or "")
    except AttributeError:  # pragma: no cover - exotic request object
        return ""


def _is_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True

