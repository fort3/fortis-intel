"""Persistent store for OSINT analysis reports, investigation subjects,
geo data points, and entity relationships.

Uses SQLite with WAL journal mode for concurrent read access.
"""

import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional


@dataclass
class AnalysisReport:
    report_id: str
    source_route: str
    report_type: str  # investigation, enrichment, triangulation, batch, rag, monitor
    analysis_text: str
    subject_identifier: str | None = None
    identifier_type: str | None = None  # username, email, phone, domain, name, keyword
    sensitivity_level: str = "INTERNAL"  # PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL
    platforms_queried: str | None = None  # JSON array
    geo_data: str | None = None  # JSON: primary location, confidence, radius
    entity_count: int = 0
    source_count: int = 0
    created_at: str = ""
    created_by: str | None = None  # hashed user email
    in_knowledge_base: bool = False
    kb_chunk_count: int = 0
    monitor_record_id: str | None = None
    tags: str | None = None  # JSON array


@dataclass
class InvestigationSubject:
    subject_id: str
    identifier: str
    identifier_type: str
    first_seen: str = ""
    last_investigated: str = ""
    investigation_count: int = 0
    known_aliases: str | None = None  # JSON array
    known_platforms: str | None = None  # JSON array
    last_known_location: str | None = None  # JSON object
    notes: str | None = None
    created_by: str | None = None


@dataclass
class GeoDataPoint:
    point_id: str
    investigation_id: str  # FK to analysis_reports.report_id
    subject_identifier: str | None = None
    latitude: float = 0.0
    longitude: float = 0.0
    source: str = ""
    source_detail: str | None = None
    confidence: float = 0.0
    point_type: str = ""  # exact, approximate, inferred
    timestamp: str | None = None
    collected_at: str = ""
    raw_metadata: str | None = None  # JSON


@dataclass
class EntityRelationship:
    relationship_id: str
    source_entity: str
    source_type: str
    target_entity: str
    target_type: str
    relationship_type: str
    confidence: float = 0.0
    evidence_source: str | None = None
    first_observed: str = ""
    last_observed: str = ""
    observation_count: int = 1


# ── Schema ──────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_reports (
    report_id           TEXT PRIMARY KEY,
    source_route        TEXT NOT NULL,
    report_type         TEXT NOT NULL,
    subject_identifier  TEXT,
    identifier_type     TEXT,
    analysis_text       TEXT NOT NULL,
    sensitivity_level   TEXT DEFAULT 'INTERNAL',
    platforms_queried   TEXT,
    geo_data            TEXT,
    entity_count        INTEGER DEFAULT 0,
    source_count        INTEGER DEFAULT 0,
    created_at          TEXT NOT NULL,
    created_by          TEXT,
    in_knowledge_base   INTEGER DEFAULT 0,
    kb_chunk_count      INTEGER DEFAULT 0,
    monitor_record_id   TEXT,
    tags                TEXT
);

CREATE TABLE IF NOT EXISTS investigation_subjects (
    subject_id          TEXT PRIMARY KEY,
    identifier          TEXT NOT NULL,
    identifier_type     TEXT NOT NULL,
    first_seen          TEXT NOT NULL,
    last_investigated   TEXT NOT NULL,
    investigation_count INTEGER DEFAULT 0,
    known_aliases       TEXT,
    known_platforms     TEXT,
    last_known_location TEXT,
    notes               TEXT,
    created_by          TEXT
);

CREATE TABLE IF NOT EXISTS geo_data_points (
    point_id            TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL,
    subject_identifier  TEXT,
    latitude            REAL NOT NULL,
    longitude           REAL NOT NULL,
    source              TEXT NOT NULL,
    source_detail       TEXT,
    confidence          REAL DEFAULT 0.0,
    point_type          TEXT,
    timestamp           TEXT,
    collected_at        TEXT NOT NULL,
    raw_metadata        TEXT,
    FOREIGN KEY (investigation_id) REFERENCES analysis_reports(report_id)
);

CREATE TABLE IF NOT EXISTS entity_relationships (
    relationship_id     TEXT PRIMARY KEY,
    source_entity       TEXT NOT NULL,
    source_type         TEXT NOT NULL,
    target_entity       TEXT NOT NULL,
    target_type         TEXT NOT NULL,
    relationship_type   TEXT NOT NULL,
    confidence          REAL DEFAULT 0.0,
    evidence_source     TEXT,
    first_observed      TEXT NOT NULL,
    last_observed       TEXT NOT NULL,
    observation_count   INTEGER DEFAULT 1
);

-- analysis_reports indexes
CREATE INDEX IF NOT EXISTS idx_reports_created
    ON analysis_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_type
    ON analysis_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_in_kb
    ON analysis_reports(in_knowledge_base);
CREATE INDEX IF NOT EXISTS idx_reports_subject
    ON analysis_reports(subject_identifier);
CREATE INDEX IF NOT EXISTS idx_reports_sensitivity
    ON analysis_reports(sensitivity_level);
CREATE INDEX IF NOT EXISTS idx_reports_identifier_type
    ON analysis_reports(identifier_type);

-- investigation_subjects indexes
CREATE INDEX IF NOT EXISTS idx_subjects_identifier
    ON investigation_subjects(identifier);
CREATE INDEX IF NOT EXISTS idx_subjects_type
    ON investigation_subjects(identifier_type);
CREATE INDEX IF NOT EXISTS idx_subjects_last_investigated
    ON investigation_subjects(last_investigated DESC);

-- geo_data_points indexes
CREATE INDEX IF NOT EXISTS idx_geo_investigation
    ON geo_data_points(investigation_id);
CREATE INDEX IF NOT EXISTS idx_geo_subject
    ON geo_data_points(subject_identifier);
CREATE INDEX IF NOT EXISTS idx_geo_coords
    ON geo_data_points(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_geo_source
    ON geo_data_points(source);

-- entity_relationships indexes
CREATE INDEX IF NOT EXISTS idx_rel_source
    ON entity_relationships(source_entity, source_type);
CREATE INDEX IF NOT EXISTS idx_rel_target
    ON entity_relationships(target_entity, target_type);
CREATE INDEX IF NOT EXISTS idx_rel_type
    ON entity_relationships(relationship_type);
CREATE INDEX IF NOT EXISTS idx_rel_confidence
    ON entity_relationships(confidence DESC);
"""


# ── ReportStore ─────────────────────────────────────────────────────

class ReportStore:

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path or os.getenv(
            "REPORT_STORE_DB", os.path.join("data", "report_store.db")
        )
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    # ── Report CRUD ─────────────────────────────────────────────────

    def save(self, report: AnalysisReport) -> bool:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO analysis_reports
                   (report_id, source_route, report_type, subject_identifier,
                    identifier_type, analysis_text, sensitivity_level,
                    platforms_queried, geo_data, entity_count, source_count,
                    created_at, created_by, in_knowledge_base, kb_chunk_count,
                    monitor_record_id, tags)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    report.report_id,
                    report.source_route,
                    report.report_type,
                    report.subject_identifier,
                    report.identifier_type,
                    report.analysis_text,
                    report.sensitivity_level,
                    report.platforms_queried,
                    report.geo_data,
                    report.entity_count,
                    report.source_count,
                    report.created_at,
                    report.created_by,
                    int(report.in_knowledge_base),
                    report.kb_chunk_count,
                    report.monitor_record_id,
                    report.tags,
                ),
            )
            conn.commit()
            return True
        except Exception as exc:
            print(f"[ReportStore] save failed: {exc}")
            return False
        finally:
            conn.close()

    def get(self, report_id: str) -> AnalysisReport | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM analysis_reports WHERE report_id = ?", (report_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_report(row)
        finally:
            conn.close()

    def list_reports(
        self,
        limit: int = 50,
        offset: int = 0,
        report_type: str | None = None,
        in_kb: bool | None = None,
        sensitivity_level: str | None = None,
        identifier_type: str | None = None,
        subject_identifier: str | None = None,
    ) -> list[AnalysisReport]:
        conn = self._connect()
        try:
            query = "SELECT * FROM analysis_reports WHERE 1=1"
            params: list = []
            if report_type:
                query += " AND report_type = ?"
                params.append(report_type)
            if in_kb is not None:
                query += " AND in_knowledge_base = ?"
                params.append(int(in_kb))
            if sensitivity_level:
                query += " AND sensitivity_level = ?"
                params.append(sensitivity_level)
            if identifier_type:
                query += " AND identifier_type = ?"
                params.append(identifier_type)
            if subject_identifier:
                query += " AND subject_identifier = ?"
                params.append(subject_identifier)
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_report(r) for r in rows]
        finally:
            conn.close()

    def delete(self, report_id: str) -> bool:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "DELETE FROM analysis_reports WHERE report_id = ?", (report_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def toggle_kb(self, report_id: str, in_kb: bool) -> bool:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE analysis_reports SET in_knowledge_base = ? WHERE report_id = ?",
                (int(in_kb), report_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def get_stats(self) -> dict:
        conn = self._connect()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM analysis_reports"
            ).fetchone()[0]
            in_kb = conn.execute(
                "SELECT COUNT(*) FROM analysis_reports WHERE in_knowledge_base = 1"
            ).fetchone()[0]
            total_chunks = conn.execute(
                "SELECT COALESCE(SUM(kb_chunk_count), 0) FROM analysis_reports WHERE in_knowledge_base = 1"
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT report_type, COUNT(*) as cnt FROM analysis_reports GROUP BY report_type"
            ).fetchall()
            by_type = {r["report_type"]: r["cnt"] for r in type_rows}

            sensitivity_rows = conn.execute(
                "SELECT sensitivity_level, COUNT(*) as cnt FROM analysis_reports GROUP BY sensitivity_level"
            ).fetchall()
            by_sensitivity = {r["sensitivity_level"]: r["cnt"] for r in sensitivity_rows}

            newest = conn.execute(
                "SELECT MAX(created_at) FROM analysis_reports"
            ).fetchone()[0]
            oldest = conn.execute(
                "SELECT MIN(created_at) FROM analysis_reports"
            ).fetchone()[0]

            total_subjects = conn.execute(
                "SELECT COUNT(*) FROM investigation_subjects"
            ).fetchone()[0]
            total_geo_points = conn.execute(
                "SELECT COUNT(*) FROM geo_data_points"
            ).fetchone()[0]
            total_relationships = conn.execute(
                "SELECT COUNT(*) FROM entity_relationships"
            ).fetchone()[0]

            return {
                "total_reports": total,
                "in_knowledge_base": in_kb,
                "total_chunks": total_chunks,
                "by_type": by_type,
                "by_sensitivity": by_sensitivity,
                "newest": newest,
                "oldest": oldest,
                "total_subjects": total_subjects,
                "total_geo_points": total_geo_points,
                "total_relationships": total_relationships,
            }
        finally:
            conn.close()

    def get_all_in_kb(self) -> list[AnalysisReport]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM analysis_reports WHERE in_knowledge_base = 1 ORDER BY created_at"
            ).fetchall()
            return [self._row_to_report(r) for r in rows]
        finally:
            conn.close()

    def archive_stale(self, max_age_days: int | None = None) -> int:
        if max_age_days is None:
            max_age_days = int(os.getenv("KB_RETENTION_DAYS", "90"))
        if max_age_days <= 0:
            return 0
        cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=max_age_days)).isoformat()
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE analysis_reports SET in_knowledge_base = 0 "
                "WHERE in_knowledge_base = 1 AND created_at < ?",
                (cutoff,),
            )
            conn.commit()
            archived = cursor.rowcount
            if archived > 0:
                print(f"[KB RETENTION] Archived {archived} report(s) older than {max_age_days} days")
            return archived
        finally:
            conn.close()

    def count(self) -> int:
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM analysis_reports"
            ).fetchone()[0]
        finally:
            conn.close()

    # ── Investigation Subjects ──────────────────────────────────────

    def save_subject(self, subject: InvestigationSubject) -> bool:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO investigation_subjects
                   (subject_id, identifier, identifier_type, first_seen,
                    last_investigated, investigation_count, known_aliases,
                    known_platforms, last_known_location, notes, created_by)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    subject.subject_id,
                    subject.identifier,
                    subject.identifier_type,
                    subject.first_seen,
                    subject.last_investigated,
                    subject.investigation_count,
                    subject.known_aliases,
                    subject.known_platforms,
                    subject.last_known_location,
                    subject.notes,
                    subject.created_by,
                ),
            )
            conn.commit()
            return True
        except Exception as exc:
            print(f"[ReportStore] save_subject failed: {exc}")
            return False
        finally:
            conn.close()

    def get_subject(self, subject_id: str) -> InvestigationSubject | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM investigation_subjects WHERE subject_id = ?",
                (subject_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_subject(row)
        finally:
            conn.close()

    def find_subject_by_identifier(
        self, identifier: str, identifier_type: str | None = None
    ) -> list[InvestigationSubject]:
        conn = self._connect()
        try:
            query = "SELECT * FROM investigation_subjects WHERE identifier = ?"
            params: list = [identifier]
            if identifier_type:
                query += " AND identifier_type = ?"
                params.append(identifier_type)
            query += " ORDER BY last_investigated DESC"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_subject(r) for r in rows]
        finally:
            conn.close()

    def list_subjects(
        self,
        limit: int = 50,
        offset: int = 0,
        identifier_type: str | None = None,
    ) -> list[InvestigationSubject]:
        conn = self._connect()
        try:
            query = "SELECT * FROM investigation_subjects WHERE 1=1"
            params: list = []
            if identifier_type:
                query += " AND identifier_type = ?"
                params.append(identifier_type)
            query += " ORDER BY last_investigated DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_subject(r) for r in rows]
        finally:
            conn.close()

    def delete_subject(self, subject_id: str) -> bool:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "DELETE FROM investigation_subjects WHERE subject_id = ?",
                (subject_id,),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def increment_subject_investigation(self, subject_id: str) -> bool:
        """Update investigation count and last_investigated timestamp."""
        now = datetime.now(tz=timezone.utc).isoformat()
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE investigation_subjects "
                "SET investigation_count = investigation_count + 1, "
                "    last_investigated = ? "
                "WHERE subject_id = ?",
                (now, subject_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    # ── Geo Data Points ─────────────────────────────────────────────

    def save_geo_point(self, point: GeoDataPoint) -> bool:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO geo_data_points
                   (point_id, investigation_id, subject_identifier, latitude,
                    longitude, source, source_detail, confidence, point_type,
                    timestamp, collected_at, raw_metadata)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    point.point_id,
                    point.investigation_id,
                    point.subject_identifier,
                    point.latitude,
                    point.longitude,
                    point.source,
                    point.source_detail,
                    point.confidence,
                    point.point_type,
                    point.timestamp,
                    point.collected_at,
                    point.raw_metadata,
                ),
            )
            conn.commit()
            return True
        except Exception as exc:
            print(f"[ReportStore] save_geo_point failed: {exc}")
            return False
        finally:
            conn.close()

    def save_geo_points_batch(self, points: list[GeoDataPoint]) -> int:
        """Insert multiple geo data points in a single transaction."""
        if not points:
            return 0
        conn = self._connect()
        try:
            conn.executemany(
                """INSERT OR REPLACE INTO geo_data_points
                   (point_id, investigation_id, subject_identifier, latitude,
                    longitude, source, source_detail, confidence, point_type,
                    timestamp, collected_at, raw_metadata)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        p.point_id, p.investigation_id, p.subject_identifier,
                        p.latitude, p.longitude, p.source, p.source_detail,
                        p.confidence, p.point_type, p.timestamp, p.collected_at,
                        p.raw_metadata,
                    )
                    for p in points
                ],
            )
            conn.commit()
            return len(points)
        except Exception as exc:
            print(f"[ReportStore] save_geo_points_batch failed: {exc}")
            return 0
        finally:
            conn.close()

    def get_geo_points_for_investigation(
        self, investigation_id: str
    ) -> list[GeoDataPoint]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM geo_data_points WHERE investigation_id = ? "
                "ORDER BY collected_at DESC",
                (investigation_id,),
            ).fetchall()
            return [self._row_to_geo_point(r) for r in rows]
        finally:
            conn.close()

    def get_geo_points_for_subject(
        self, subject_identifier: str
    ) -> list[GeoDataPoint]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM geo_data_points WHERE subject_identifier = ? "
                "ORDER BY collected_at DESC",
                (subject_identifier,),
            ).fetchall()
            return [self._row_to_geo_point(r) for r in rows]
        finally:
            conn.close()

    def delete_geo_points_for_investigation(self, investigation_id: str) -> int:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "DELETE FROM geo_data_points WHERE investigation_id = ?",
                (investigation_id,),
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    # ── Entity Relationships ────────────────────────────────────────

    def save_relationship(self, rel: EntityRelationship) -> bool:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO entity_relationships
                   (relationship_id, source_entity, source_type, target_entity,
                    target_type, relationship_type, confidence, evidence_source,
                    first_observed, last_observed, observation_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    rel.relationship_id,
                    rel.source_entity,
                    rel.source_type,
                    rel.target_entity,
                    rel.target_type,
                    rel.relationship_type,
                    rel.confidence,
                    rel.evidence_source,
                    rel.first_observed,
                    rel.last_observed,
                    rel.observation_count,
                ),
            )
            conn.commit()
            return True
        except Exception as exc:
            print(f"[ReportStore] save_relationship failed: {exc}")
            return False
        finally:
            conn.close()

    def save_relationships_batch(self, rels: list[EntityRelationship]) -> int:
        """Insert multiple entity relationships in a single transaction."""
        if not rels:
            return 0
        conn = self._connect()
        try:
            conn.executemany(
                """INSERT OR REPLACE INTO entity_relationships
                   (relationship_id, source_entity, source_type, target_entity,
                    target_type, relationship_type, confidence, evidence_source,
                    first_observed, last_observed, observation_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        r.relationship_id, r.source_entity, r.source_type,
                        r.target_entity, r.target_type, r.relationship_type,
                        r.confidence, r.evidence_source, r.first_observed,
                        r.last_observed, r.observation_count,
                    )
                    for r in rels
                ],
            )
            conn.commit()
            return len(rels)
        except Exception as exc:
            print(f"[ReportStore] save_relationships_batch failed: {exc}")
            return 0
        finally:
            conn.close()

    def get_relationships_for_entity(
        self, entity: str, entity_type: str | None = None
    ) -> list[EntityRelationship]:
        conn = self._connect()
        try:
            query = (
                "SELECT * FROM entity_relationships "
                "WHERE (source_entity = ? OR target_entity = ?)"
            )
            params: list = [entity, entity]
            if entity_type:
                query += " AND (source_type = ? OR target_type = ?)"
                params.extend([entity_type, entity_type])
            query += " ORDER BY confidence DESC"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_relationship(r) for r in rows]
        finally:
            conn.close()

    def get_relationships_by_type(
        self, relationship_type: str, min_confidence: float = 0.0
    ) -> list[EntityRelationship]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM entity_relationships "
                "WHERE relationship_type = ? AND confidence >= ? "
                "ORDER BY confidence DESC",
                (relationship_type, min_confidence),
            ).fetchall()
            return [self._row_to_relationship(r) for r in rows]
        finally:
            conn.close()

    def delete_relationship(self, relationship_id: str) -> bool:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "DELETE FROM entity_relationships WHERE relationship_id = ?",
                (relationship_id,),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    # ── Row converters ──────────────────────────────────────────────

    @staticmethod
    def _row_to_report(row: sqlite3.Row) -> AnalysisReport:
        return AnalysisReport(
            report_id=row["report_id"],
            source_route=row["source_route"],
            report_type=row["report_type"],
            subject_identifier=row["subject_identifier"],
            identifier_type=row["identifier_type"],
            analysis_text=row["analysis_text"],
            sensitivity_level=row["sensitivity_level"],
            platforms_queried=row["platforms_queried"],
            geo_data=row["geo_data"],
            entity_count=row["entity_count"],
            source_count=row["source_count"],
            created_at=row["created_at"],
            created_by=row["created_by"],
            in_knowledge_base=bool(row["in_knowledge_base"]),
            kb_chunk_count=row["kb_chunk_count"],
            monitor_record_id=row["monitor_record_id"],
            tags=row["tags"],
        )

    @staticmethod
    def _row_to_subject(row: sqlite3.Row) -> InvestigationSubject:
        return InvestigationSubject(
            subject_id=row["subject_id"],
            identifier=row["identifier"],
            identifier_type=row["identifier_type"],
            first_seen=row["first_seen"],
            last_investigated=row["last_investigated"],
            investigation_count=row["investigation_count"],
            known_aliases=row["known_aliases"],
            known_platforms=row["known_platforms"],
            last_known_location=row["last_known_location"],
            notes=row["notes"],
            created_by=row["created_by"],
        )

    @staticmethod
    def _row_to_geo_point(row: sqlite3.Row) -> GeoDataPoint:
        return GeoDataPoint(
            point_id=row["point_id"],
            investigation_id=row["investigation_id"],
            subject_identifier=row["subject_identifier"],
            latitude=row["latitude"],
            longitude=row["longitude"],
            source=row["source"],
            source_detail=row["source_detail"],
            confidence=row["confidence"],
            point_type=row["point_type"],
            timestamp=row["timestamp"],
            collected_at=row["collected_at"],
            raw_metadata=row["raw_metadata"],
        )

    @staticmethod
    def _row_to_relationship(row: sqlite3.Row) -> EntityRelationship:
        return EntityRelationship(
            relationship_id=row["relationship_id"],
            source_entity=row["source_entity"],
            source_type=row["source_type"],
            target_entity=row["target_entity"],
            target_type=row["target_type"],
            relationship_type=row["relationship_type"],
            confidence=row["confidence"],
            evidence_source=row["evidence_source"],
            first_observed=row["first_observed"],
            last_observed=row["last_observed"],
            observation_count=row["observation_count"],
        )


# ── Module-level singleton ──────────────────────────────────────────

_store: ReportStore | None = None


def get_report_store() -> ReportStore:
    global _store
    if _store is None:
        _store = ReportStore()
    return _store
