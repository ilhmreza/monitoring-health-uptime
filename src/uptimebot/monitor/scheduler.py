"""The monitoring loop.

One asyncio task per monitor plus one maintenance task. Design points:

* **No polling of a config file.** Monitors live in SQLite, and the web UI
  sets a single :class:`asyncio.Event` after any mutation. Tasks re-read the
  enabled monitors when it fires, so a change from the UI applies without a
  restart and without a file watcher.
* **Notification is decoupled from probing.** A Discord outage slows alerts
  but never skips a probe or blocks the state machine.
* **History queries are bounded.** The 24-hour stats used in every report are
  a single aggregate, and only computed for a monitor that actually has an
  alert to send.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime, timedelta, timezone

from ..db import CheckRepo, Database, MonitorRepo, SslStateRepo, StateRepo
from ..discord import DiscordMessage, EmbedBuilder, WebhookClient, build_message, event_for_action
from ..models import CheckResult, Monitor, MonitorState, NotifyEvent, SslInfo
from ..settings import Settings
from .checker import Checker
from .sslcheck import SslChecker
from .statemachine import Action, ActionKind, evaluate_check, evaluate_ssl

log = logging.getLogger(__name__)

UTC = timezone.utc

STATS_WINDOW = timedelta(hours=24)
# Cadence of the maintenance task: pruning, optimiser, and a stalled-worker check.
MAINTENANCE_INTERVAL = timedelta(hours=6)
# A monitor whose task has not ticked in this long is restarted.
STALL_TIMEOUT_MULTIPLIER = 6.0
STALL_TIMEOUT_FLOOR = timedelta(minutes=5)
# Safety net: reconcile at least this often even if no change was signalled,
# so a monitor edited outside the UI is still picked up.
RECONCILE_INTERVAL = timedelta(seconds=30)
# One form save can mutate several things; coalesce the burst into one pass.
RECONCILE_DEBOUNCE = 0.25


class Scheduler:
    """Owns the lifecycle of every monitoring task."""

    def __init__(
        self,
        *,
        settings: Settings,
        db: Database,
        monitors: MonitorRepo,
        state: StateRepo,
        checks: CheckRepo,
        ssl_state: SslStateRepo,
        webhook: WebhookClient,
        embeds: EmbedBuilder,
    ) -> None:
        self.settings = settings
        self.db = db
        self.monitors = monitors
        self.state = state
        self.checks = checks
        self.ssl_state = ssl_state
        self.webhook = webhook
        self.embeds = embeds

        self.checker = Checker(allow_private_network=settings.allow_private_network)
        self.ssl_checker = SslChecker(
            timeout=min(15.0, float(settings.default_timeout_seconds)),
            allow_private_network=settings.allow_private_network,
        )

        self._tasks: dict[str, asyncio.Task[None]] = {}
        # One wake flag per task. A single shared Event cannot work here: the
        # first waiter to observe it clears it and the rest keep sleeping, so
        # an edit would reach an arbitrary subset of monitors.
        self._wake: dict[str, asyncio.Event] = {}
        self._config_event = asyncio.Event()
        self._last_ticks: dict[str, datetime] = {}
        self._maintenance_task: asyncio.Task[None] | None = None
        self._config_task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self.started_at: datetime | None = None
        self._last_error: str | None = None
        self._reconcile_runs = 0

    # ----- lifecycle -------------------------------------------------------

    async def start(self) -> None:
        await self.checker.start()
        await self.webhook.start()
        self.started_at = datetime.now(UTC)
        self._stopping.clear()
        await self._reconcile()
        self._maintenance_task = asyncio.create_task(
            self._maintenance_loop(), name="scheduler-maintenance"
        )
        self._config_task = asyncio.create_task(
            self._config_loop(), name="scheduler-config"
        )
        log.info("scheduler started with %s monitor task(s)", len(self._tasks))

    async def stop(self) -> None:
        self._stopping.set()
        self._config_event.set()
        for event in list(self._wake.values()):
            event.set()
        tasks = list(self._tasks.values())
        extra = [t for t in (self._maintenance_task, self._config_task) if t is not None]
        for task in extra:
            task.cancel()
        for task in tasks:
            task.cancel()
        pending = tasks + extra
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._tasks.clear()
        self._wake.clear()
        self._maintenance_task = None
        self._config_task = None
        await self.webhook.close()
        await self.checker.close()
        log.info("scheduler stopped")

    def notify_config_changed(self) -> None:
        """Called by the web UI after any monitor mutation.

        Only sets a flag. The coordinator task performs the reconciliation, so
        every task-map mutation happens in one place, on the event loop, and
        concurrent saves cannot interleave a half-applied task set.
        """
        self._config_event.set()

    # ----- reconciliation --------------------------------------------------

    async def _config_loop(self) -> None:
        """Turn change notifications and the periodic tick into reconciles."""
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(
                    self._config_event.wait(),
                    timeout=RECONCILE_INTERVAL.total_seconds(),
                )
            except asyncio.TimeoutError:
                pass
            if self._stopping.is_set():
                return
            self._config_event.clear()
            # Debounce, so one save that touched several rows reconciles once.
            await asyncio.sleep(RECONCILE_DEBOUNCE)
            if self._stopping.is_set():
                return
            try:
                await self._reconcile()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - never let this loop die
                log.exception("reconcile after config change failed")

    async def _reconcile(self) -> None:
        """Start, stop and refresh tasks so they match the database."""
        wanted = {m.id: m for m in await self.monitors.list_all()}

        for monitor_id in list(self._tasks):
            monitor = wanted.get(monitor_id)
            if monitor is None or not monitor.enabled:
                await self._cancel_task(monitor_id)
                if monitor is not None:
                    # Preserve the outage, but stop treating it as live.
                    await self.state.reset_for_pause(monitor_id, datetime.now(UTC))
                    log.info("paused monitor %s", monitor_id)

        for monitor_id, monitor in wanted.items():
            if not monitor.enabled:
                continue
            existing = self._tasks.get(monitor_id)
            if existing is None:
                self._spawn(monitor)
            elif existing.done():
                log.warning("monitor task for %s exited; restarting", monitor_id)
                self._wake.pop(monitor_id, None)
                self._spawn(monitor)

        # Wake every survivor so an edited interval or threshold takes effect
        # now instead of at the end of the current sleep.
        for monitor_id in list(self._tasks):
            self._wake[monitor_id].set()

        self._reconcile_runs += 1
        log.info("task set reconciled: %s active", len(self._tasks))

    def _spawn(self, monitor: Monitor) -> None:
        self._wake[monitor.id] = asyncio.Event()
        self._tasks[monitor.id] = asyncio.create_task(
            self._monitor_loop(monitor.id), name=f"monitor-{monitor.id}"
        )
        self._last_ticks[monitor.id] = datetime.now(UTC)

    async def _cancel_task(self, monitor_id: str) -> None:
        task = self._tasks.pop(monitor_id, None)
        self._wake.pop(monitor_id, None)
        self._last_ticks.pop(monitor_id, None)
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _maintenance_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=MAINTENANCE_INTERVAL.total_seconds())
                return  # stopping
            except asyncio.TimeoutError:
                pass
            try:
                await self._run_maintenance()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - maintenance must not kill the loop
                log.exception("scheduled maintenance failed")

    async def _run_maintenance(self) -> None:
        deleted = await self.db.prune_checks(self.settings.retention_days)
        log.info("maintenance: pruned %s rows, %s monitor task(s)", deleted, len(self._tasks))
        await self._restart_stalled_tasks()

    async def _restart_stalled_tasks(self) -> None:
        """Recover from a task wedged on a socket that never resolves."""
        now = datetime.now(UTC)
        for monitor_id, task in list(self._tasks.items()):
            if task.done():
                log.warning("monitor task %s finished unexpectedly", monitor_id)
                self._tasks.pop(monitor_id, None)
                monitor = await self.monitors.get(monitor_id)
                if monitor and monitor.enabled:
                    self._spawn(monitor)
                continue

            last = self._last_ticks.get(monitor_id)
            if last is None:
                continue
            monitor = await self.monitors.get(monitor_id)
            if monitor is None:
                continue
            budget = max(
                STALL_TIMEOUT_FLOOR,
                timedelta(seconds=monitor.interval_seconds * STALL_TIMEOUT_MULTIPLIER),
            )
            if now - last <= budget:
                continue
            log.error(
                "monitor %s has not ticked for %s; restarting its task",
                monitor_id,
                now - last,
            )
            await self._cancel_task(monitor_id)
            if monitor.enabled:
                self._spawn(monitor)

    # ----- per-monitor loop ------------------------------------------------

    async def _monitor_loop(self, monitor_id: str) -> None:
        """Probe, advance state, and report, forever."""
        next_run = datetime.now(UTC)
        next_ssl_run = datetime.now(UTC)  # check the certificate promptly on boot

        while not self._stopping.is_set():
            wake = self._wake.get(monitor_id)
            if wake is None:
                # Cancelled and replaced while we were waiting.
                return
            try:
                monitor = await self.monitors.get(monitor_id)
                if monitor is None or not monitor.enabled:
                    log.info("monitor %s disabled or removed; task exiting", monitor_id)
                    return

                now = datetime.now(UTC)

                if now >= next_ssl_run:
                    next_ssl_run = now + timedelta(
                        seconds=self.settings.ssl_check_interval_seconds
                    )
                    await self._run_ssl_check(monitor)

                if now >= next_run:
                    next_run = now + timedelta(seconds=monitor.interval_seconds)
                    await self._run_check(monitor)

                self._last_ticks[monitor_id] = datetime.now(UTC)

                # Wake early if the UI changed something, so edits apply now.
                delay = max(
                    0.5,
                    min(
                        (next_run - datetime.now(UTC)).total_seconds(),
                        self.settings.default_interval_seconds,
                    ),
                )
                wake.clear()
                try:
                    await asyncio.wait_for(wake.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    pass
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - one bad monitor must not stop the rest
                log.exception("monitor loop error for %s; continuing", monitor_id)
                await asyncio.sleep(min(5.0, self.settings.default_interval_seconds))

    async def _run_check(self, monitor: Monitor) -> None:
        result = await self.checker.check(monitor)
        await self.checks.record(monitor.id, result)

        state_row = await self.state.get(monitor.id)
        now = datetime.now(UTC)
        decision = evaluate_check(
            current_state=state_row.state,
            consecutive_failures=state_row.consecutive_failures,
            down_since=state_row.down_since,
            last_ok_at=state_row.last_ok_at,
            result=result,
            failure_threshold=monitor.failure_threshold,
            reminder_interval=timedelta(minutes=self.settings.reminder_interval_minutes),
            last_reminder_at=state_row.last_reminder_at,
            now=now,
            up_since=state_row.up_since,
        )

        await self.state.record_check(
            monitor.id,
            ok=result.ok,
            state=decision.state,
            consecutive_failures=decision.consecutive_failures,
            down_since=decision.down_since,
            up_since=decision.up_since,
            at=result.checked_at,
        )
        if decision.reminder_due:
            await self.state.record_reminder(monitor.id, now)

        for action in decision.actions:
            await self._dispatch(monitor, action)

    async def _run_ssl_check(self, monitor: Monitor) -> None:
        if not monitor.ssl_check or not monitor.host:
            return
        info = await self.ssl_checker.check(monitor)

        state_row = await self.state.get(monitor.id)
        decision = evaluate_ssl(
            days_left=info.days_left,
            warn_days=tuple(monitor.ssl_warn_days),
            notified_severity=state_row.ssl_notified_severity,
            inspection_ok=info.ok,
        )
        await self._persist_ssl(monitor, info, decision.severity)
        await self.state.set_ssl_notified_severity(monitor.id, decision.notified_severity)
        if decision.should_notify:
            await self._dispatch(
                monitor,
                Action(
                    kind=ActionKind.ALERT_SSL,
                    ssl=info,
                    ssl_severity=decision.severity,
                    ssl_label=decision.label,
                ),
            )

    async def _persist_ssl(self, monitor: Monitor, info: SslInfo, severity: int = 0) -> None:
        await self.ssl_state.upsert(
            monitor.id,
            not_after=info.not_after,
            days_left=info.days_left,
            issuer=info.issuer,
            subject_cn=info.subject_cn,
            tls_version=info.tls_version,
            chain_ok=info.chain_ok,
            checked_at=info.checked_at,
            error=info.error,
            severity=severity,
        )

    # ----- notification ----------------------------------------------------

    async def _dispatch(self, monitor: Monitor, action: Action) -> None:
        """Send an alert if the monitor subscribes to that event type."""
        event = event_for_action(action)
        if event not in monitor.wants:
            log.debug(
                "monitor %s does not subscribe to %s; state still updated", monitor.id, event.value
            )
            return

        stats = await self._stats_24h(monitor.id)
        message: DiscordMessage = build_message(self.embeds, monitor, action, stats)

        result = await self.webhook.send(message)
        if result.ok:
            await self.state.record_alert(monitor.id, datetime.now(UTC))
            log.info(
                "alert sent: monitor=%s kind=%s", monitor.id, action.kind.value
            )
        else:
            # The state transition already happened, so this is not retried as
            # an alert; it would be re-derived as a reminder on the next pass.
            self._last_error = f"{action.kind.value}: {result.error}"
            log.error(
                "failed to send %s alert for %s: %s", action.kind.value, monitor.id, result.error
            )

    async def _stats_24h(self, monitor_id: str):
        try:
            return await self.checks.stats(monitor_id, STATS_WINDOW, "24 jam")
        except Exception as exc:  # noqa: BLE001 - stats are decoration, never load-bearing
            log.debug("stats lookup failed for %s: %s", monitor_id, exc)
            return None

    # ----- introspection for /healthz and the dashboard ---------------------

    def health(self) -> dict[str, object]:
        now = datetime.now(UTC)
        active = [t for t in self._tasks.values() if not t.done()]
        # The *oldest* tick is what reveals a wedged task, so pick the minimum.
        stalest = min(self._last_ticks.values(), default=None)
        maintenance_alive = self._maintenance_task is not None and not self._maintenance_task.done()
        config_alive = self._config_task is not None and not self._config_task.done()
        return {
            # Not started at all (tests) or stopping both count as unhealthy,
            # so Docker restarts a scheduler that lost its loops.
            "running": not self._stopping.is_set() and maintenance_alive and config_alive,
            "monitor_tasks": len(active),
            "expected_tasks": len(self._tasks),
            "reconcile_runs": self._reconcile_runs,
            "oldest_tick_age_seconds": (
                int((now - stalest).total_seconds()) if stalest else None
            ),
            "uptime_seconds": (
                int((now - self.started_at).total_seconds()) if self.started_at else None
            ),
            "last_delivery_error": self._last_error,
        }


__all__ = ["Scheduler", "Action", "ActionKind", "NotifyEvent", "CheckResult", "MonitorState"]
