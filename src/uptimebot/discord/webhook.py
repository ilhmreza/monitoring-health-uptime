"""Discord webhook delivery.

Alerting must never be able to take down monitoring, and it must never be
able to hammer Discord. So delivery runs on a bounded queue drained by a small
pool of workers that:

* pace themselves to stay well under Discord's per-route rate limit,
* honour ``Retry-After`` on HTTP 429 instead of guessing,
* retry 5xx and transport errors with exponential backoff plus jitter,
* drop the message after a few attempts and log loudly, rather than growing
  an unbounded backlog,
* survive a dead webhook, so one misconfigured URL cannot stop the probes.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from .embeds import DiscordMessage

log = logging.getLogger(__name__)

# Discord rate limits are per-route and per-webhook; staying this far under is
# comfortable and leaves headroom for the UI's test button.
MIN_SEND_INTERVAL = 0.6
MAX_ATTEMPTS = 5
BACKOFF_BASE = 1.5
BACKOFF_CAP = 30.0
REQUEST_TIMEOUT = 15.0

# Messages that are worth keeping if Discord is briefly unhappy.
RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})


class WebhookNotConfigured(RuntimeError):
    """No webhook URL is set, so there is nowhere to report."""


@dataclass(slots=True)
class DeliveryResult:
    ok: bool
    status_code: int | None = None
    error: str | None = None
    attempts: int = 0
    rate_limited_ms: int | None = None


class WebhookClient:
    """Queue-based webhook sender with rate limiting and retry."""

    def __init__(
        self,
        webhook_url: str,
        *,
        client: httpx.AsyncClient | None = None,
        queue_size: int = 200,
        workers: int = 2,
        min_interval: float = MIN_SEND_INTERVAL,
    ) -> None:
        self._webhook_url = webhook_url
        self._external_client = client
        self._client = client
        self._owns_client = client is None
        self._queue: asyncio.Queue[tuple[DiscordMessage, asyncio.Future[DeliveryResult]]] = (
            asyncio.Queue(maxsize=queue_size)
        )
        self._workers: list[asyncio.Task[None]] = []
        self._min_interval = min_interval
        self._worker_count = workers
        self._pacer_lock = asyncio.Lock()
        self._last_send = 0.0
        self._closing = False

    # ----- lifecycle -------------------------------------------------------

    @property
    def configured(self) -> bool:
        return bool(self._webhook_url)

    async def start(self, worker_count: int | None = None) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(REQUEST_TIMEOUT),
                trust_env=False,
                follow_redirects=False,
            )
            self._owns_client = True
        count = worker_count or self._worker_count
        self._closing = False
        self._workers = [
            asyncio.create_task(self._worker(i), name=f"webhook-worker-{i}")
            for i in range(count)
        ]
        log.info("webhook sender started with %s workers", count)

    async def close(self) -> None:
        """Drain what is queued, then stop the workers."""
        self._closing = True
        try:
            await asyncio.wait_for(self._queue.join(), timeout=15.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            log.warning("webhook queue did not drain in time; discarding remainder")
        for task in self._workers:
            task.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None
        log.info("webhook sender stopped")

    # ----- public API ------------------------------------------------------

    async def send(self, message: DiscordMessage, *, timeout: float = 20.0) -> DeliveryResult:
        """Queue a message and wait for its delivery result.

        A full queue means Discord has been unreachable for a while; the
        message is dropped rather than blocking a probe.
        """
        if not self.configured:
            return DeliveryResult(ok=False, error="webhook belum dikonfigurasi")
        if self._closing or not self._workers:
            return DeliveryResult(ok=False, error="webhook sender sedang berhenti")

        loop = asyncio.get_running_loop()
        future: asyncio.Future[DeliveryResult] = loop.create_future()
        try:
            self._queue.put_nowait((message, future))
        except asyncio.QueueFull:
            log.error("webhook queue full, dropping message")
            return DeliveryResult(ok=False, error="antrean webhook penuh")

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            return DeliveryResult(ok=False, error="timeout menunggu pengiriman webhook")

    # ----- worker ----------------------------------------------------------

    async def _worker(self, index: int) -> None:
        while True:
            message, future = await self._queue.get()
            try:
                result = await self._deliver(message)
                if not future.done():
                    future.set_result(result)
            except asyncio.CancelledError:
                if not future.done():
                    future.set_result(DeliveryResult(ok=False, error="dibatalkan"))
                raise
            except Exception as exc:  # noqa: BLE001 - a worker must not die
                log.exception("webhook worker %s crashed on one message", index)
                if not future.done():
                    future.set_result(DeliveryResult(ok=False, error=f"{type(exc).__name__}: {exc}"))
            finally:
                self._queue.task_done()

    async def _pace(self) -> None:
        """Space out sends so a burst cannot trip the rate limiter."""
        async with self._pacer_lock:
            loop = asyncio.get_running_loop()
            wait = self._min_interval - (loop.time() - self._last_send)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_send = loop.time()

    async def _deliver(self, message: DiscordMessage) -> DeliveryResult:
        assert self._client is not None
        body = message.payload()
        delay = BACKOFF_BASE

        for attempt in range(1, MAX_ATTEMPTS + 1):
            await self._pace()
            try:
                response = await self._client.post(self._webhook_url, json=body)
            except httpx.HTTPError as exc:
                log.warning(
                    "webhook request failed (attempt %s/%s): %s", attempt, MAX_ATTEMPTS, exc
                )
                if attempt == MAX_ATTEMPTS:
                    return DeliveryResult(ok=False, error=str(exc), attempts=attempt)
                await asyncio.sleep(_jittered(delay))
                delay = min(delay * 2, BACKOFF_CAP)
                continue

            if response.status_code in (200, 201, 204):
                return DeliveryResult(ok=True, status_code=response.status_code, attempts=attempt)

            if response.status_code == 429:
                # Trust Discord's own number rather than inventing one.
                retry_after = _retry_after_seconds(response)
                log.warning(
                    "webhook rate limited; retry_after=%.2fs (attempt %s/%s)",
                    retry_after,
                    attempt,
                    MAX_ATTEMPTS,
                )
                if attempt == MAX_ATTEMPTS:
                    return DeliveryResult(
                        ok=False,
                        status_code=429,
                        error="rate limited",
                        attempts=attempt,
                        rate_limited_ms=int(retry_after * 1000),
                    )
                await asyncio.sleep(min(retry_after + 0.25, 65.0))
                continue

            detail = _error_detail(response)
            if response.status_code in RETRYABLE_STATUS and attempt < MAX_ATTEMPTS:
                log.warning(
                    "webhook returned %s (attempt %s/%s): %s",
                    response.status_code,
                    attempt,
                    MAX_ATTEMPTS,
                    detail,
                )
                await asyncio.sleep(_jittered(delay))
                delay = min(delay * 2, BACKOFF_CAP)
                continue

            # 400 means the payload itself is wrong; retrying cannot help.
            log.error("webhook rejected message with %s: %s", response.status_code, detail)
            return DeliveryResult(
                ok=False,
                status_code=response.status_code,
                error=detail,
                attempts=attempt,
            )

        return DeliveryResult(ok=False, error="kehabisan percobaan", attempts=MAX_ATTEMPTS)


def _jittered(delay: float) -> float:
    """Full-jitter backoff, so parallel monitors do not resynchronise."""
    return random.uniform(0, min(delay, BACKOFF_CAP))


def _retry_after_seconds(response: httpx.Response) -> float:
    """Parse ``Retry-After``, which Discord sends as seconds or as an HTTP date."""
    raw = response.headers.get("retry-after", "").strip()
    if not raw:
        # Discord also reports the budget in the JSON body on some routes.
        try:
            body = response.json()
            raw = str(body.get("retry_after", "")).strip()
        except (ValueError, AttributeError):
            raw = ""
        if not raw:
            return 2.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return 2.0
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _error_detail(response: httpx.Response) -> str:
    """A short, log-safe excerpt of Discord's error body.

    The body can contain the webhook URL, so it is never logged in full.
    """
    try:
        body: Any = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    if isinstance(body, dict):
        message = body.get("message") or body.get("error") or ""
        code = body.get("code", "")
        if message and code:
            return f"HTTP {response.status_code}: {message} (code {code})"
        if message:
            return f"HTTP {response.status_code}: {message}"
    return f"HTTP {response.status_code}"
