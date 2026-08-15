"""Entity export format converters for Fortis Intelligence Hub.

Converts OSINT entity data to industry-standard formats:
- STIX 2.1 (Structured Threat Information Expression)
- CSV (tabular format for spreadsheets and SIEMs)
- JSON (API/automation friendly)

Entity types: person, organization, location, account, domain, event, media
"""

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Optional


# STIX 2.1 SDO type mapping for OSINT entities
_ENTITY_TO_STIX_TYPE = {
    "person": "identity",
    "organization": "identity",
    "location": "location",
    "account": "user-account",
    "domain": "domain-name",
    "event": "note",
    "media": "artifact",
}

# STIX identity_class for person/org
_IDENTITY_CLASS = {
    "person": "individual",
    "organization": "organization",
}


def convert_to_stix21(entities: list[dict], investigation: dict | None = None) -> dict:
    """Convert OSINT entities to a STIX 2.1 bundle.

    STIX 2.1 Spec: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

    Creates proper STIX SDOs for each entity type:
    - person/organization -> identity SDO
    - location -> location SDO
    - account -> user-account SCO wrapped in observed-data
    - domain -> domain-name SCO wrapped in observed-data
    - event -> note SDO
    - media -> artifact SDO

    Args:
        entities: List of entity dicts with at minimum {type, value/name}.
        investigation: Optional investigation context dict for metadata.

    Returns:
        dict: STIX 2.1 bundle with typed objects and relationships
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    inv_name = ""
    if investigation:
        inv_name = investigation.get("name", investigation.get("query", ""))

    objects = []
    entity_id_map: dict[str, str] = {}  # local key -> STIX id for relationships

    for entity in entities:
        entity_type = (entity.get("type") or "unknown").lower()
        entity_name = entity.get("name") or entity.get("value") or ""
        if not entity_name:
            continue

        confidence = _calculate_confidence(entity)
        source = entity.get("source", "")
        context = entity.get("context", "")
        local_key = f"{entity_type}:{entity_name}"

        if entity_type in ("person", "organization"):
            stix_id = f"identity--{uuid.uuid4()}"
            obj = {
                "type": "identity",
                "spec_version": "2.1",
                "id": stix_id,
                "created": timestamp,
                "modified": timestamp,
                "name": entity_name,
                "identity_class": _IDENTITY_CLASS.get(entity_type, "unknown"),
                "description": _build_description(entity, inv_name),
                "confidence": confidence,
                "x_osint_entity_type": entity_type,
                "x_osint_source": source,
            }
            # Add optional fields
            if entity.get("aliases"):
                obj["x_osint_aliases"] = entity["aliases"]
            if entity.get("platform"):
                obj["x_osint_platform"] = entity["platform"]
            objects.append(obj)
            entity_id_map[local_key] = stix_id

        elif entity_type == "location":
            stix_id = f"location--{uuid.uuid4()}"
            obj = {
                "type": "location",
                "spec_version": "2.1",
                "id": stix_id,
                "created": timestamp,
                "modified": timestamp,
                "name": entity_name,
                "description": _build_description(entity, inv_name),
                "confidence": confidence,
                "x_osint_source": source,
            }
            # Add coordinates if available
            if entity.get("latitude") is not None:
                obj["latitude"] = float(entity["latitude"])
            if entity.get("longitude") is not None:
                obj["longitude"] = float(entity["longitude"])
            if entity.get("country"):
                obj["country"] = entity["country"]
            objects.append(obj)
            entity_id_map[local_key] = stix_id

        elif entity_type == "account":
            # Wrap user-account SCO inside observed-data SDO
            account_id = f"user-account--{uuid.uuid4()}"
            account_sco = {
                "type": "user-account",
                "id": account_id,
                "account_login": entity_name,
                "x_osint_platform": entity.get("platform", ""),
                "x_osint_profile_url": entity.get("url", ""),
            }
            if entity.get("display_name"):
                account_sco["display_name"] = entity["display_name"]

            obs_id = f"observed-data--{uuid.uuid4()}"
            obs = {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs_id,
                "created": timestamp,
                "modified": timestamp,
                "first_observed": entity.get("first_seen", timestamp),
                "last_observed": entity.get("last_seen", timestamp),
                "number_observed": 1,
                "object_refs": [account_id],
                "confidence": confidence,
                "x_osint_source": source,
            }
            objects.append(account_sco)
            objects.append(obs)
            entity_id_map[local_key] = obs_id

        elif entity_type == "domain":
            domain_id = f"domain-name--{uuid.uuid4()}"
            domain_sco = {
                "type": "domain-name",
                "id": domain_id,
                "value": entity_name,
            }
            obs_id = f"observed-data--{uuid.uuid4()}"
            obs = {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs_id,
                "created": timestamp,
                "modified": timestamp,
                "first_observed": entity.get("first_seen", timestamp),
                "last_observed": entity.get("last_seen", timestamp),
                "number_observed": 1,
                "object_refs": [domain_id],
                "confidence": confidence,
                "x_osint_source": source,
            }
            objects.append(domain_sco)
            objects.append(obs)
            entity_id_map[local_key] = obs_id

        elif entity_type == "event":
            stix_id = f"note--{uuid.uuid4()}"
            obj = {
                "type": "note",
                "spec_version": "2.1",
                "id": stix_id,
                "created": timestamp,
                "modified": timestamp,
                "content": entity_name,
                "abstract": context[:200] if context else "",
                "confidence": confidence,
                "x_osint_source": source,
                "x_osint_entity_type": "event",
            }
            if entity.get("event_date"):
                obj["x_osint_event_date"] = entity["event_date"]
            objects.append(obj)
            entity_id_map[local_key] = stix_id

        elif entity_type == "media":
            stix_id = f"artifact--{uuid.uuid4()}"
            obj = {
                "type": "artifact",
                "spec_version": "2.1",
                "id": stix_id,
                "x_osint_description": entity_name,
                "x_osint_source": source,
                "x_osint_entity_type": "media",
            }
            if entity.get("url"):
                obj["url"] = entity["url"]
            if entity.get("mime_type"):
                obj["mime_type"] = entity["mime_type"]
            objects.append(obj)
            entity_id_map[local_key] = stix_id

        else:
            # Generic: wrap as a custom note
            stix_id = f"note--{uuid.uuid4()}"
            obj = {
                "type": "note",
                "spec_version": "2.1",
                "id": stix_id,
                "created": timestamp,
                "modified": timestamp,
                "content": f"{entity_type}: {entity_name}",
                "abstract": context[:200] if context else "",
                "confidence": confidence,
                "x_osint_entity_type": entity_type,
                "x_osint_source": source,
            }
            objects.append(obj)
            entity_id_map[local_key] = stix_id

    # Build relationship objects from entity links
    for entity in entities:
        relationships = entity.get("relationships", [])
        entity_type = (entity.get("type") or "unknown").lower()
        entity_name = entity.get("name") or entity.get("value") or ""
        source_key = f"{entity_type}:{entity_name}"
        source_id = entity_id_map.get(source_key)
        if not source_id:
            continue

        for rel in relationships:
            target_type = (rel.get("target_type") or "unknown").lower()
            target_name = rel.get("target_name") or rel.get("target_value") or ""
            target_key = f"{target_type}:{target_name}"
            target_id = entity_id_map.get(target_key)
            if not target_id:
                continue

            rel_type = rel.get("relationship_type", "related-to")
            rel_obj = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": timestamp,
                "modified": timestamp,
                "relationship_type": rel_type,
                "source_ref": source_id,
                "target_ref": target_id,
            }
            objects.append(rel_obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }

    return bundle


def convert_to_csv(entities: list[dict]) -> str:
    """Convert OSINT entities to CSV format.

    CSV Columns: type, name, platform, source, confidence, context,
                 location, url, first_seen, last_seen

    Args:
        entities: List of entity dicts

    Returns:
        str: CSV data ready for download
    """
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "type", "name", "platform", "source", "confidence",
        "context", "location", "url", "first_seen", "last_seen",
    ])

    for entity in entities:
        entity_type = (entity.get("type") or "unknown").lower()
        entity_name = entity.get("name") or entity.get("value") or ""

        writer.writerow([
            entity_type,
            entity_name,
            entity.get("platform", ""),
            entity.get("source", ""),
            entity.get("confidence", 0),
            (entity.get("context") or "")[:200],
            entity.get("location", ""),
            entity.get("url", ""),
            entity.get("first_seen", ""),
            entity.get("last_seen", ""),
        ])

    return output.getvalue()


def convert_to_json(entities: list[dict], investigation: dict | None = None) -> str:
    """Convert OSINT entities to a structured JSON export.

    Args:
        entities: List of entity dicts
        investigation: Optional investigation context

    Returns:
        str: JSON string with metadata and entities
    """
    export = {
        "export_format": "fortis_osint_entities",
        "version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat() + "Z",
        "entity_count": len(entities),
    }

    if investigation:
        export["investigation"] = {
            "name": investigation.get("name", ""),
            "query": investigation.get("query", ""),
            "created_at": investigation.get("created_at", ""),
        }

    # Group entities by type
    by_type: dict[str, list[dict]] = {}
    for entity in entities:
        entity_type = (entity.get("type") or "unknown").lower()
        by_type.setdefault(entity_type, []).append(entity)

    export["entity_summary"] = {etype: len(elist) for etype, elist in by_type.items()}
    export["entities"] = entities

    return json.dumps(export, indent=2, default=str)


def _calculate_confidence(entity: dict) -> int:
    """Calculate STIX confidence level (0-100) for an OSINT entity.

    Based on:
    - Explicit confidence score if provided
    - Source reliability
    - Corroboration (number of sources confirming the entity)

    Args:
        entity: Entity dict

    Returns:
        int: Confidence level 0-100
    """
    # Use explicit confidence if provided
    explicit = entity.get("confidence")
    if explicit is not None:
        try:
            return max(0, min(100, int(explicit)))
        except (ValueError, TypeError):
            pass

    source = (entity.get("source") or "").lower()
    corroboration = entity.get("corroboration_count", 1)

    # Base confidence from source type
    if "verified" in source or "official" in source:
        base = 85
    elif "social" in source or "osint" in source:
        base = 55
    elif "public" in source or "web" in source:
        base = 45
    elif "inferred" in source or "derived" in source:
        base = 30
    else:
        base = 40

    # Boost for multiple corroborating sources (max +20)
    if corroboration >= 4:
        base = min(95, base + 20)
    elif corroboration >= 2:
        base = min(90, base + 10)

    return base


def _build_description(entity: dict, investigation_name: str = "") -> str:
    """Build a description string for a STIX object.

    Args:
        entity: Entity dict
        investigation_name: Name of the investigation for context

    Returns:
        str: Description text
    """
    parts = []
    if investigation_name:
        parts.append(f"Extracted during investigation: {investigation_name}")
    if entity.get("context"):
        parts.append(entity["context"])
    if entity.get("platform"):
        parts.append(f"Platform: {entity['platform']}")
    if entity.get("source"):
        parts.append(f"Source: {entity['source']}")
    return " | ".join(parts) if parts else ""


def _escape_stix_string(s: str) -> str:
    """Escape special characters for STIX patterns.

    Args:
        s: String to escape

    Returns:
        str: Escaped string safe for STIX pattern
    """
    return s.replace("\\", "\\\\").replace("'", "\\'")
