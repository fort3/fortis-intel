"""Redis-backed store for Fortis Intelligence Hub with in-memory fallback.

Adapted from Multi-Agent-Setup's redis_store.py. Provides persistence
for monitor configurations and monitor findings using the ``fortis:``
key prefix. Findings have a 7-day TTL.
"""

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


# ---------------------------------------------------------------------------
# TTL constants
# ---------------------------------------------------------------------------

FINDINGS_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days
MONITOR_TTL_SECONDS = 90 * 24 * 60 * 60  # 90 days (long-lived)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MonitorConfig:
    """Configuration for a feed monitor."""

    monitor_id: str
    monitor_type: str  # keyword, username, hashtag, location_radius
    query: str
    platforms: str  # JSON-encoded list of platform keys
    interval_minutes: int
    created_at: str
    created_by: str
    last_poll: str
    status: str  # active, paused, expired
    alert_threshold: str  # all, high_confidence, geo_match


@dataclass
class MonitorFinding:
    """A single finding produced by a feed monitor poll cycle."""

    finding_id: str
    monitor_id: str
    content_type: str  # post, article, profile, image, etc.
    platform: str
    content_summary: str
    geo_data: str  # JSON-encoded dict
    metadata: str  # JSON-encoded dict
    analysis_text: str
    status: str  # pending_review, approved, dismissed
    created_at: str
    reviewed_at: str | None = None
    reviewed_by: str | None = None
    dismiss_reason: str | None = None


# ---------------------------------------------------------------------------
# Generic Redis/memory store
# ---------------------------------------------------------------------------

class _BaseStore:
    """Redis-backed store with transparent in-memory fallback.

    Subclasses set ``_key_prefix``, ``_ttl``, ``_dataclass``, and
    ``_pending_set_key`` to specialise behaviour.
    """

    _key_prefix: str = "fortis:generic:"
    _ttl: int = FINDINGS_TTL_SECONDS
    _dataclass: type = MonitorFinding  # overridden by subclasses
    _pending_set_key: str = ""  # optional: set used for pending-item lookups

    def __init__(self):
        self._redis_client = None
        self._memory_store: dict[str, dict] = {}
        self._init_redis()

    def _init_redis(self):
        """Initialise Redis client if available and configured."""
        if not REDIS_AVAILABLE:
            log.warning("redis package not installed — using in-memory store")
            return

        redis_url = os.getenv("REDIS_URL", "")

        if not redis_url or redis_url.lower() in ("", "memory://", "none"):
            log.info("Redis not configured — using in-memory store")
            return

        try:
            self._redis_client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            self._redis_client.ping()
            safe_url = redis_url.split("@")[-1] if "@" in redis_url else redis_url
            log.info("Connected to Redis at %s (prefix=%s)", safe_url, self._key_prefix)
        except Exception as exc:
            log.warning("Redis connection failed: %s — using in-memory store", exc)
            self._redis_client = None

    def _key(self, record_id: str) -> str:
        """Generate a Redis key for *record_id*."""
        return f"{self._key_prefix}{record_id}"

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def save(self, record) -> bool:
        """Persist a record (dataclass instance).

        Args:
            record: A dataclass instance with a field whose name matches
                the first field of ``_dataclass`` (used as the record ID).

        Returns:
            ``True`` if saved successfully.
        """
        try:
            record_dict = asdict(record)
            record_json = json.dumps(record_dict)
            record_id = self._record_id(record)

            if self._redis_client:
                key = self._key(record_id)
                self._redis_client.setex(key, self._ttl, record_json)
                if self._pending_set_key and self._is_pending(record):
                    self._redis_client.sadd(self._pending_set_key, record_id)
            else:
                self._memory_store[record_id] = record_dict

            return True
        except Exception as exc:
            log.error("Failed to save record: %s", exc)
            return False

    def get(self, record_id: str):
        """Retrieve a record by ID.

        Returns:
            A dataclass instance or ``None``.
        """
        try:
            if self._redis_client:
                key = self._key(record_id)
                record_json = self._redis_client.get(key)
                if not record_json:
                    return None
                record_dict = json.loads(record_json)
            else:
                record_dict = self._memory_store.get(record_id)
                if not record_dict:
                    return None

            return self._dataclass(**record_dict)
        except Exception as exc:
            log.error("Failed to get record %s: %s", record_id, exc)
            return None

    def update_status(self, record_id: str, status: str, **kwargs) -> bool:
        """Update a record's status and optional fields.

        Args:
            record_id: Record identifier.
            status: New status value.
            **kwargs: Additional field updates.

        Returns:
            ``True`` if updated successfully.
        """
        record = self.get(record_id)
        if not record:
            return False

        record.status = status
        for key, value in kwargs.items():
            if hasattr(record, key):
                setattr(record, key, value)

        # Remove from pending set if no longer pending
        if self._pending_set_key and not self._is_pending(record):
            if self._redis_client:
                self._redis_client.srem(self._pending_set_key, record_id)

        return self.save(record)

    def delete(self, record_id: str) -> bool:
        """Delete a record by ID.

        Returns:
            ``True`` if deleted successfully.
        """
        try:
            if self._redis_client:
                key = self._key(record_id)
                self._redis_client.delete(key)
                if self._pending_set_key:
                    self._redis_client.srem(self._pending_set_key, record_id)
            else:
                self._memory_store.pop(record_id, None)
            return True
        except Exception as exc:
            log.error("Failed to delete record %s: %s", record_id, exc)
            return False

    def list_pending(self, limit: int = 50) -> list:
        """List records with pending status.

        Args:
            limit: Maximum records to return.

        Returns:
            List of dataclass instances sorted by ``created_at`` descending.
        """
        try:
            if self._redis_client and self._pending_set_key:
                pending_ids = self._redis_client.smembers(self._pending_set_key)
                records = []
                for record_id in list(pending_ids)[:limit]:
                    record = self.get(record_id)
                    if record:
                        records.append(record)
                records.sort(key=lambda r: r.created_at, reverse=True)
                return records
            else:
                records = [
                    self._dataclass(**data)
                    for data in self._memory_store.values()
                    if self._is_pending_dict(data)
                ]
                records.sort(key=lambda r: r.created_at, reverse=True)
                return records[:limit]
        except Exception as exc:
            log.error("Failed to list pending records: %s", exc)
            return []

    def list_all(self, limit: int = 200) -> list:
        """List all records regardless of status.

        Args:
            limit: Maximum records to return.

        Returns:
            List of dataclass instances sorted by ``created_at`` descending.
        """
        try:
            if self._redis_client:
                # Scan for keys matching our prefix
                records = []
                cursor = 0
                pattern = f"{self._key_prefix}*"
                while True:
                    cursor, keys = self._redis_client.scan(
                        cursor=cursor, match=pattern, count=100
                    )
                    for key in keys:
                        record_json = self._redis_client.get(key)
                        if record_json:
                            try:
                                record_dict = json.loads(record_json)
                                records.append(self._dataclass(**record_dict))
                            except Exception:
                                pass
                    if cursor == 0:
                        break
                records.sort(key=lambda r: r.created_at, reverse=True)
                return records[:limit]
            else:
                records = [
                    self._dataclass(**data) for data in self._memory_store.values()
                ]
                records.sort(key=lambda r: r.created_at, reverse=True)
                return records[:limit]
        except Exception as exc:
            log.error("Failed to list all records: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Internal helpers (override in subclasses if needed)
    # ------------------------------------------------------------------

    def _record_id(self, record) -> str:
        """Extract the primary ID from a record."""
        # Uses the first field of the dataclass
        fields = list(asdict(record).keys())
        return getattr(record, fields[0])

    def _is_pending(self, record) -> bool:
        """Check if a record is in a pending state."""
        return getattr(record, "status", "") == "pending_review"

    def _is_pending_dict(self, data: dict) -> bool:
        """Check if a raw dict represents a pending record."""
        return data.get("status") == "pending_review"


# ---------------------------------------------------------------------------
# Specialised stores
# ---------------------------------------------------------------------------

class MonitorConfigStore(_BaseStore):
    """Store for feed monitor configurations."""

    _key_prefix = "fortis:monitor:"
    _ttl = MONITOR_TTL_SECONDS
    _dataclass = MonitorConfig
    _pending_set_key = ""  # Monitors don't use a pending set

    def _is_pending(self, record) -> bool:
        return False

    def _is_pending_dict(self, data: dict) -> bool:
        return False


class MonitorFindingStore(_BaseStore):
    """Store for feed monitor findings with 7-day TTL."""

    _key_prefix = "fortis:finding:"
    _ttl = FINDINGS_TTL_SECONDS
    _dataclass = MonitorFinding
    _pending_set_key = "fortis:findings:pending"


# ---------------------------------------------------------------------------
# Global singleton accessors
# ---------------------------------------------------------------------------

_monitor_store: MonitorConfigStore | None = None
_finding_store: MonitorFindingStore | None = None


def get_monitor_store() -> MonitorConfigStore:
    """Return the global :class:`MonitorConfigStore` singleton."""
    global _monitor_store
    if _monitor_store is None:
        _monitor_store = MonitorConfigStore()
    return _monitor_store


def get_finding_store() -> MonitorFindingStore:
    """Return the global :class:`MonitorFindingStore` singleton."""
    global _finding_store
    if _finding_store is None:
        _finding_store = MonitorFindingStore()
    return _finding_store
