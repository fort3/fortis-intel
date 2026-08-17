"""Celery tasks for feed monitoring in Fortis Intelligence Hub.

Phase 3: Background polling tasks that drive the feed monitor lifecycle.
Each monitor is polled on its configured interval; new findings are
persisted, optionally enriched via LLM triage, and analysts are notified.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta

from app.celery_app import celery_app
from app.redis_store import (
    MonitorFinding,
    get_finding_store,
    get_monitor_store,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _existing_post_ids(monitor_id: str) -> set[str]:
    """Return the set of post_ids already stored as findings for *monitor_id*.

    Scans all findings (pending, approved, dismissed) so that the same
    content is not re-ingested across poll cycles.
    """
    store = get_finding_store()
    ids: set[str] = set()
    try:
        all_findings = store.list_all(limit=500)
        for f in all_findings:
            if f.monitor_id == monitor_id:
                # post_id is stored inside the metadata JSON blob
                try:
                    meta = json.loads(f.metadata) if f.metadata else {}
                except (json.JSONDecodeError, TypeError):
                    meta = {}
                pid = meta.get("post_id", "")
                if pid:
                    ids.add(pid)
    except Exception as exc:
        log.warning("Could not load existing findings for %s: %s", monitor_id, exc)
    return ids


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

@celery_app.task(
    name="app.tasks.poll_monitor",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    acks_late=True,
)
def poll_monitor(self, monitor_id: str) -> dict:
    """Execute a single poll cycle for a feed monitor.

    1. Load monitor config from redis_store.
    2. Skip if monitor is not active.
    3. Use SocialClient to search for new content.
    4. De-duplicate against previous findings (by post_id).
    5. Store each new finding as a MonitorFinding with status="pending_review".
    6. Optionally run MetadataExtractor on findings.
    7. Notify analysts of high-confidence findings.
    8. Update the monitor's last_poll timestamp.
    9. Schedule the next poll based on the monitor's interval.

    Args:
        monitor_id: The monitor to poll.

    Returns:
        Summary dict with counts.
    """
    monitor_store = get_monitor_store()
    finding_store = get_finding_store()

    # 1. Load monitor config
    monitor = monitor_store.get(monitor_id)
    if monitor is None:
        log.warning("poll_monitor: monitor %s not found, skipping", monitor_id)
        return {"monitor_id": monitor_id, "status": "not_found", "new_findings": 0}

    # 2. Skip if not active
    if monitor.status != "active":
        log.info("poll_monitor: monitor %s is %s, skipping", monitor_id, monitor.status)
        return {"monitor_id": monitor_id, "status": monitor.status, "new_findings": 0}

    log.info("poll_monitor: polling monitor %s (query=%r)", monitor_id, monitor.query)

    # 3. Use SocialClient to search
    try:
        from app.social_client import SocialClient

        client = SocialClient()
        platforms = json.loads(monitor.platforms) if monitor.platforms else None
        poll_config = {
            "query": monitor.query,
            "platforms": platforms,
            "monitor_type": monitor.monitor_type,
        }

        # If we have a last_poll timestamp, pass it as date_from
        if monitor.last_poll:
            poll_config["date_from"] = monitor.last_poll

        results = client.poll(poll_config)
    except Exception as exc:
        log.error("poll_monitor: SocialClient error for %s: %s", monitor_id, exc)
        # Notify on error
        try:
            from app.notifications import notify_monitor_error
            notify_monitor_error(monitor.query, str(exc))
        except Exception:
            pass
        # Retry with exponential backoff
        raise self.retry(exc=exc)

    # 4. De-duplicate against previous findings
    known_ids = _existing_post_ids(monitor_id)
    new_results = []
    for item in results:
        post_id = item.get("post_id", "")
        url = item.get("url", "")
        # Use post_id as primary dedup key, fall back to url
        dedup_key = post_id or url
        if dedup_key and dedup_key not in known_ids:
            new_results.append(item)
            known_ids.add(dedup_key)

    log.info(
        "poll_monitor: %s returned %d results, %d new",
        monitor_id, len(results), len(new_results),
    )

    # 5. Store each new finding
    new_count = 0
    finding_ids = []
    for item in new_results:
        finding_id = f"find_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()

        # Build metadata from the social post dict
        meta = {
            "post_id": item.get("post_id", ""),
            "url": item.get("url", ""),
            "author_username": item.get("author_username", ""),
            "timestamp": item.get("timestamp", ""),
            "likes": item.get("likes", 0),
            "shares": item.get("shares", 0),
            "replies": item.get("replies", 0),
            "hashtags": item.get("hashtags", []),
            "mentions": item.get("mentions", []),
            "media_urls": item.get("media_urls", []),
        }

        # Determine content type
        content_type = "post"
        if item.get("user_id"):
            content_type = "profile"

        # Build geo_data JSON
        geo = item.get("geo") or {}

        finding = MonitorFinding(
            finding_id=finding_id,
            monitor_id=monitor_id,
            content_type=content_type,
            platform=item.get("platform", "unknown"),
            content_summary=_truncate(item.get("content", ""), 500),
            geo_data=json.dumps(geo) if geo else "{}",
            metadata=json.dumps(meta),
            analysis_text="",
            status="pending_review",
            created_at=now,
        )
        if finding_store.save(finding):
            new_count += 1
            finding_ids.append(finding_id)
        else:
            log.warning("Failed to save finding %s", finding_id)

    # 6. Optional enrichment via MetadataExtractor
    if new_results:
        try:
            from app.metadata_extractor import MetadataExtractor

            extractor = MetadataExtractor()
            content_items = [
                {"id": item.get("post_id", ""), "type": "text", "data": item.get("content", "")}
                for item in new_results
                if item.get("content")
            ]
            if content_items:
                bundles = extractor.extract_all(content_items)
                log.info(
                    "poll_monitor: enriched %d items for monitor %s",
                    len(bundles), monitor_id,
                )
        except Exception as exc:
            log.warning("poll_monitor: metadata enrichment failed: %s", exc)

    # 6b. Civilian harm scoring (Bellingcat methodology)
    if new_results:
        try:
            from app.civilian_harm import (
                get_civilian_harm_classifier,
                CIVILIAN_HARM_ENABLED,
            )
            if CIVILIAN_HARM_ENABLED:
                classifier = get_civilian_harm_classifier()
                for i, item in enumerate(new_results):
                    content = item.get("content", "")
                    if content and len(content.strip()) >= 20:
                        harm = classifier.score_text(content)
                        if harm.score >= 0.35 and i < len(finding_ids):
                            fid = finding_ids[i]
                            existing = finding_store.get(fid)
                            if existing:
                                try:
                                    meta = json.loads(existing.metadata) if existing.metadata else {}
                                except (json.JSONDecodeError, TypeError):
                                    meta = {}
                                meta["harm_score"] = {
                                    "score": harm.score,
                                    "classification": harm.classification,
                                    "matched_concepts": harm.matched_concepts[:3],
                                }
                                existing.metadata = json.dumps(meta)
                                finding_store.save(existing)
                log.info(
                    "poll_monitor: civilian harm scoring complete for %s",
                    monitor_id,
                )
        except Exception as exc:
            log.warning("poll_monitor: civilian harm scoring failed: %s", exc)

    # 7. Notify for findings based on alert_threshold
    if finding_ids:
        try:
            from app.notifications import notify_new_finding

            alert_threshold = monitor.alert_threshold or "all"
            for fid in finding_ids:
                if alert_threshold == "all":
                    notify_new_finding(monitor.query, monitor.monitor_type, fid)
                elif alert_threshold == "high_confidence":
                    # Only notify for the first few (most likely relevant)
                    if finding_ids.index(fid) < 3:
                        notify_new_finding(monitor.query, monitor.monitor_type, fid)
        except Exception as exc:
            log.warning("poll_monitor: notification failed: %s", exc)

    # 8. Update last_polled timestamp
    now_ts = datetime.utcnow().isoformat()
    monitor_store.update_status(
        monitor_id,
        "active",
        last_poll=now_ts,
    )
    log.info("poll_monitor: updated last_poll for %s to %s", monitor_id, now_ts)

    # 9. Schedule next poll based on interval
    interval = monitor.interval_minutes or 60
    try:
        poll_monitor.apply_async(
            args=[monitor_id],
            countdown=interval * 60,
        )
        log.info(
            "poll_monitor: scheduled next poll for %s in %d minutes",
            monitor_id, interval,
        )
    except Exception as exc:
        log.warning("poll_monitor: failed to schedule next poll: %s", exc)

    return {
        "monitor_id": monitor_id,
        "status": "polled",
        "total_results": len(results),
        "new_findings": new_count,
        "finding_ids": finding_ids,
    }


@celery_app.task(
    name="app.tasks.poll_all_monitors",
    bind=True,
)
def poll_all_monitors(self) -> dict:
    """Periodic task: check all active monitors and submit polls for those due.

    1. Load all active monitors from redis_store.
    2. For each, check if it is due for polling based on interval and last_poll.
    3. Submit poll_monitor.delay(monitor_id) for due monitors.

    Returns:
        Summary dict with counts.
    """
    monitor_store = get_monitor_store()
    all_monitors = monitor_store.list_all()
    now = datetime.utcnow()

    submitted = 0
    skipped = 0

    for monitor in all_monitors:
        # Only poll active monitors
        if monitor.status != "active":
            skipped += 1
            continue

        # Check if due for polling
        interval = monitor.interval_minutes or 60
        if monitor.last_poll:
            try:
                last_poll_dt = datetime.fromisoformat(monitor.last_poll)
                next_due = last_poll_dt + timedelta(minutes=interval)
                if now < next_due:
                    skipped += 1
                    continue
            except (ValueError, TypeError):
                # Invalid last_poll value -- poll it now
                pass

        # Submit poll task
        try:
            poll_monitor.delay(monitor.monitor_id)
            submitted += 1
            log.info(
                "poll_all_monitors: submitted poll for %s",
                monitor.monitor_id,
            )
        except Exception as exc:
            log.error(
                "poll_all_monitors: failed to submit poll for %s: %s",
                monitor.monitor_id, exc,
            )

    log.info(
        "poll_all_monitors: submitted=%d, skipped=%d, total=%d",
        submitted, skipped, len(all_monitors),
    )

    return {
        "total_monitors": len(all_monitors),
        "submitted": submitted,
        "skipped": skipped,
    }


@celery_app.task(
    name="app.tasks.analyze_finding",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def analyze_finding(self, finding_id: str) -> dict:
    """Run LLM-based triage analysis on a finding.

    1. Load the finding from redis_store.
    2. Load the parent monitor config for context.
    3. Run through the monitor_alert chain (LLM analysis).
    4. Update the finding with analysis results.

    Args:
        finding_id: The finding to analyse.

    Returns:
        Summary dict.
    """
    finding_store = get_finding_store()
    monitor_store = get_monitor_store()

    # 1. Load finding
    finding = finding_store.get(finding_id)
    if finding is None:
        log.warning("analyze_finding: finding %s not found", finding_id)
        return {"finding_id": finding_id, "status": "not_found"}

    # 2. Load parent monitor for context
    monitor = monitor_store.get(finding.monitor_id)
    monitor_context = ""
    if monitor:
        monitor_context = (
            f"Type: {monitor.monitor_type}, Query: {monitor.query}, "
            f"Platforms: {monitor.platforms}, "
            f"Threshold: {monitor.alert_threshold}"
        )
    else:
        monitor_context = f"Monitor {finding.monitor_id} not found"

    # 3. Run through monitor_alert chain
    try:
        from app.chains import get_monitor_alert_chain

        chain = get_monitor_alert_chain()

        # Load historical context (recent findings for the same monitor)
        historical = ""
        try:
            all_findings = finding_store.list_all(limit=20)
            related = [
                f for f in all_findings
                if f.monitor_id == finding.monitor_id
                and f.finding_id != finding_id
            ]
            if related:
                summaries = [
                    f"[{f.created_at}] {f.platform}: {_truncate(f.content_summary, 100)}"
                    for f in related[:5]
                ]
                historical = "\n".join(summaries)
            else:
                historical = "No prior findings for this monitor."
        except Exception:
            historical = "Historical context unavailable."

        analysis_input = {
            "monitor_config": monitor_context,
            "new_content": (
                f"Platform: {finding.platform}\n"
                f"Content: {finding.content_summary}\n"
                f"Geo: {finding.geo_data}\n"
                f"Metadata: {finding.metadata}"
            ),
            "historical_context": historical,
        }

        analysis_text = chain.invoke(analysis_input)
        log.info("analyze_finding: LLM analysis complete for %s", finding_id)

    except Exception as exc:
        log.error("analyze_finding: LLM chain failed for %s: %s", finding_id, exc)
        analysis_text = f"[Analysis failed: {exc}]"
        # Retry if it was a transient error
        if "rate" in str(exc).lower() or "timeout" in str(exc).lower():
            raise self.retry(exc=exc)

    # 4. Update finding with analysis
    finding.analysis_text = analysis_text
    finding_store.save(finding)
    log.info("analyze_finding: saved analysis for %s", finding_id)

    return {
        "finding_id": finding_id,
        "status": "analyzed",
        "analysis_length": len(analysis_text),
    }


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _truncate(text: str, max_len: int = 500) -> str:
    """Truncate *text* to *max_len* characters, appending ellipsis if cut."""
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
