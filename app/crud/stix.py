"""
Cyber Atlas - STIX CRUD Operations
"""

from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.models.stix_object import STIXObject
from app.models.stix_relationship import STIXRelationship


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _truncate_text(value: Optional[str], max_len: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


async def save_stix_bundle(
    db: AsyncSession,
    bundle: Dict,
    connector_id: str,
    connector_name: str,
) -> Dict:
    """Save STIX bundle to database."""
    stats = {
        "objects": 0,
        "indicators": 0,
        "observables": 0,
        "relationships": 0,
        "new": 0,
        "updated": 0,
    }

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type")

        if obj_type == "identity":
            continue

        if obj_type == "relationship":
            await _save_relationship(db, obj)
            stats["relationships"] += 1
        else:
            is_new = await _save_stix_object(db, obj, connector_id, connector_name)
            stats["objects"] += 1
            stats["new" if is_new else "updated"] += 1

            if obj_type == "indicator":
                stats["indicators"] += 1
            elif obj_type in [
                "ipv4-addr",
                "ipv6-addr",
                "domain-name",
                "url",
                "file",
                "email-addr",
            ]:
                stats["observables"] += 1

    return stats


async def _save_stix_object(
    db: AsyncSession,
    obj: Dict,
    connector_id: str,
    connector_name: str,
) -> bool:
    """Save STIX object, return True if new."""
    obj_id = obj.get("id")
    if not obj_id:
        return False

    existing_result = await db.execute(select(STIXObject).where(STIXObject.id == obj_id))
    existing = existing_result.scalar_one_or_none()

    obs_type = None
    obs_value = None

    obj_type = obj.get("type")
    if obj_type in ["ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"]:
        obs_type = obj_type
        obs_value = obj.get("value")
    elif obj_type == "file":
        obs_type = "file"
        hashes = obj.get("hashes", {}) or {}
        if hashes:
            hash_type = list(hashes.keys())[0]
            obs_value = f"{hash_type}:{hashes[hash_type]}"

    obs_value = _truncate_text(obs_value, 512)

    created_value = _parse_datetime(obj.get("created")) or _parse_datetime(obj.get("modified")) or datetime.now(
        timezone.utc
    )
    modified_value = _parse_datetime(obj.get("modified")) or created_value

    if existing:
        existing.modified = modified_value
        existing.stix_data = obj
        existing.confidence = obj.get("confidence", existing.confidence)
        existing.labels = obj.get("labels", existing.labels)
        existing.external_references = obj.get("external_references", existing.external_references)
        existing.pattern = obj.get("pattern", existing.pattern)
        existing.pattern_type = obj.get("pattern_type", existing.pattern_type)
        existing.valid_from = _parse_datetime(obj.get("valid_from")) or existing.valid_from
        existing.valid_until = _parse_datetime(obj.get("valid_until")) or existing.valid_until
        existing.observable_type = obs_type or existing.observable_type
        existing.observable_value = obs_value or existing.observable_value
        existing.connector_id = connector_id or existing.connector_id
        existing.connector_name = connector_name or existing.connector_name
        return False

    stix_obj = STIXObject(
        id=obj_id,
        type=obj_type,
        spec_version=obj.get("spec_version", "2.1"),
        created=created_value,
        modified=modified_value,
        name=_truncate_text(obj.get("name"), 255),
        description=obj.get("description"),
        confidence=obj.get("confidence"),
        stix_data=obj,
        created_by_ref=obj.get("created_by_ref"),
        labels=obj.get("labels"),
        external_references=obj.get("external_references"),
        pattern=obj.get("pattern"),
        pattern_type=obj.get("pattern_type"),
        valid_from=_parse_datetime(obj.get("valid_from")),
        valid_until=_parse_datetime(obj.get("valid_until")),
        observable_type=obs_type,
        observable_value=obs_value,
        connector_id=connector_id,
        connector_name=connector_name,
    )
    db.add(stix_obj)
    return True


async def _save_relationship(db: AsyncSession, obj: Dict) -> None:
    """Save relationship."""
    rel_id = obj.get("id")
    if not rel_id:
        return

    existing_result = await db.execute(select(STIXRelationship).where(STIXRelationship.id == rel_id))
    existing = existing_result.scalar_one_or_none()

    if existing:
        return

    rel = STIXRelationship(
        id=rel_id,
        type="relationship",
        spec_version=obj.get("spec_version", "2.1"),
        created=_parse_datetime(obj.get("created")) or datetime.now(timezone.utc),
        modified=_parse_datetime(obj.get("modified")) or datetime.now(timezone.utc),
        relationship_type=obj.get("relationship_type"),
        source_ref=obj.get("source_ref"),
        target_ref=obj.get("target_ref"),
        description=obj.get("description"),
        stix_data=obj,
    )
    db.add(rel)
    logger.debug(f"Saved STIX relationship: {rel_id}")
