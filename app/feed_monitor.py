"""Feed monitor (Celery task interface) for Fortis Intelligence Hub.

Phase 3: Monitor CRUD operations persist state via :mod:`app.redis_store`
and automatically schedule Celery polling tasks when monitors are created
or resumed.
"""

import logging
import uuid
from datetime import datetime
from typing import Any

from app.redis_store import (
    MonitorConfig,
    MonitorFinding,
    get_monitor_store,
    get_finding_store,
)

log = logging.getLogger(__name__)


class FeedMonitor:
    """Manage feed monitors and their findings.

    Phase 3: monitors can be created, paused, resumed, and deleted via
    the Redis-backed store. Creating or resuming a monitor automatically
    schedules the first Celery poll task.
    """

    def __init__(self):
        self._monitors = get_monitor_store()
        self._findings = get_finding_store()
        log.info("FeedMonitor initialised (Phase 3)")

    # ------------------------------------------------------------------
    # Task scheduling helper
    # ------------------------------------------------------------------

    @staticmethod
    def _schedule_poll(monitor_id: str, delay_seconds: int = 5) -> bool:
        """Schedule a poll_monitor Celery task.

        Args:
            monitor_id: The monitor to poll.
            delay_seconds: Seconds to wait before executing (default 5).

        Returns:
            True if the task was submitted successfully.
        """
        try:
            from app.tasks import poll_monitor
            poll_monitor.apply_async(
                args=[monitor_id],
                countdown=delay_seconds,
            )
            log.info(
                "Scheduled poll for monitor %s in %d seconds",
                monitor_id, delay_seconds,
            )
            return True
        except Exception as exc:
            log.warning(
                "Failed to schedule poll for monitor %s: %s "
                "(Celery worker may not be running)",
                monitor_id, exc,
            )
            return False

    # ------------------------------------------------------------------
    # Monitor CRUD
    # ------------------------------------------------------------------

    def create_monitor(self, config: dict[str, Any]) -> dict[str, Any]:
        """Create a new feed monitor.

        Args:
            config: Dict with ``monitor_type``, ``query``, ``platforms``,
                ``interval_minutes``, and optional ``alert_threshold``
                and ``created_by`` keys.

        Returns:
            Dict with the created monitor's details including its
            ``monitor_id``.
        """
        monitor_id = f"mon_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()

        platforms = config.get("platforms", [])
        if isinstance(platforms, list):
            import json
            platforms_json = json.dumps(platforms)
        else:
            platforms_json = str(platforms)

        monitor = MonitorConfig(
            monitor_id=monitor_id,
            monitor_type=config.get("monitor_type", "keyword"),
            query=config.get("query", ""),
            platforms=platforms_json,
            interval_minutes=config.get("interval_minutes", 60),
            created_at=now,
            created_by=config.get("created_by", "system"),
            last_poll="",
            status="active",
            alert_threshold=config.get("alert_threshold", "all"),
        )
        self._monitors.save(monitor)
        log.info("Created monitor %s: type=%s query=%r", monitor_id,
                 monitor.monitor_type, monitor.query)

        # Schedule the first poll task
        poll_scheduled = self._schedule_poll(monitor_id)

        return {
            "monitor_id": monitor_id,
            "status": "active",
            "created_at": now,
            "poll_scheduled": poll_scheduled,
            "message": "Monitor created and first poll scheduled",
        }

    def pause_monitor(self, monitor_id: str) -> dict[str, Any]:
        """Pause an active monitor.

        Args:
            monitor_id: The monitor to pause.

        Returns:
            Status dict.
        """
        ok = self._monitors.update_status(monitor_id, "paused")
        if not ok:
            log.warning("Failed to pause monitor %s — not found", monitor_id)
            return {"success": False, "error": f"Monitor {monitor_id} not found"}
        log.info("Paused monitor %s", monitor_id)
        return {"success": True, "monitor_id": monitor_id, "status": "paused"}

    def resume_monitor(self, monitor_id: str) -> dict[str, Any]:
        """Resume a paused monitor.

        Args:
            monitor_id: The monitor to resume.

        Returns:
            Status dict.
        """
        ok = self._monitors.update_status(monitor_id, "active")
        if not ok:
            log.warning("Failed to resume monitor %s — not found", monitor_id)
            return {"success": False, "error": f"Monitor {monitor_id} not found"}
        log.info("Resumed monitor %s", monitor_id)

        # Schedule poll immediately on resume
        poll_scheduled = self._schedule_poll(monitor_id)

        return {
            "success": True,
            "monitor_id": monitor_id,
            "status": "active",
            "poll_scheduled": poll_scheduled,
        }

    def delete_monitor(self, monitor_id: str) -> dict[str, Any]:
        """Delete a monitor and all its findings.

        Args:
            monitor_id: The monitor to delete.

        Returns:
            Status dict.
        """
        ok = self._monitors.delete(monitor_id)
        if not ok:
            log.warning("Failed to delete monitor %s", monitor_id)
            return {"success": False, "error": f"Monitor {monitor_id} not found"}
        log.info("Deleted monitor %s", monitor_id)
        return {"success": True, "monitor_id": monitor_id, "status": "deleted"}

    def list_monitors(self) -> list[dict[str, Any]]:
        """List all monitors (active, paused, and expired).

        Returns:
            List of monitor dicts.
        """
        monitors = self._monitors.list_all()
        results = []
        for mon in monitors:
            import json as _json
            results.append({
                "monitor_id": mon.monitor_id,
                "monitor_type": mon.monitor_type,
                "query": mon.query,
                "platforms": _json.loads(mon.platforms) if mon.platforms else [],
                "interval_minutes": mon.interval_minutes,
                "status": mon.status,
                "created_at": mon.created_at,
                "created_by": mon.created_by,
                "last_poll": mon.last_poll,
                "alert_threshold": mon.alert_threshold,
            })
        return results

    # ------------------------------------------------------------------
    # Finding management
    # ------------------------------------------------------------------

    def get_pending_findings(self) -> list[dict[str, Any]]:
        """Return all findings awaiting human review.

        Returns:
            List of finding dicts with ``status == 'pending_review'``.
        """
        findings = self._findings.list_pending()
        return [self._finding_to_dict(f) for f in findings]

    def approve_finding(self, finding_id: str) -> dict[str, Any]:
        """Approve a finding for inclusion in reports.

        Args:
            finding_id: The finding to approve.

        Returns:
            Status dict.
        """
        ok = self._findings.update_status(
            finding_id, "approved",
            reviewed_at=datetime.utcnow().isoformat(),
        )
        if not ok:
            log.warning("Failed to approve finding %s — not found", finding_id)
            return {"success": False, "error": f"Finding {finding_id} not found"}
        log.info("Approved finding %s", finding_id)
        return {"success": True, "finding_id": finding_id, "status": "approved"}

    def dismiss_finding(
        self,
        finding_id: str,
        reason: str,
    ) -> dict[str, Any]:
        """Dismiss a finding with a reason.

        Args:
            finding_id: The finding to dismiss.
            reason: Explanation for why the finding was dismissed.

        Returns:
            Status dict.
        """
        ok = self._findings.update_status(
            finding_id, "dismissed",
            reviewed_at=datetime.utcnow().isoformat(),
            dismiss_reason=reason,
        )
        if not ok:
            log.warning("Failed to dismiss finding %s — not found", finding_id)
            return {"success": False, "error": f"Finding {finding_id} not found"}
        log.info("Dismissed finding %s: %s", finding_id, reason)
        return {"success": True, "finding_id": finding_id, "status": "dismissed"}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_to_dict(finding: MonitorFinding) -> dict[str, Any]:
        """Convert a MonitorFinding dataclass to a plain dict."""
        import json as _json
        return {
            "finding_id": finding.finding_id,
            "monitor_id": finding.monitor_id,
            "content_type": finding.content_type,
            "platform": finding.platform,
            "content_summary": finding.content_summary,
            "geo_data": _json.loads(finding.geo_data) if finding.geo_data else {},
            "metadata": _json.loads(finding.metadata) if finding.metadata else {},
            "analysis_text": finding.analysis_text,
            "status": finding.status,
            "created_at": finding.created_at,
            "reviewed_at": finding.reviewed_at,
            "reviewed_by": finding.reviewed_by,
            "dismiss_reason": finding.dismiss_reason,
        }
