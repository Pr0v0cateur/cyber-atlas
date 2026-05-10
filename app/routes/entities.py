"""
Cyber Atlas - Entity Detail Routes

Detail endpoints for CVEs, Threats, and Indicators.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, or_, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.core.database import get_db
from app.routes.auth import get_current_active_user
from app.routes.search import CVE_PATTERN, fetch_cve_details
from app.models.ioc import IOC
from app.models.mitre import MitreGroup, MitreSoftware, MitreTechnique, mitre_relationships
from app.models.stix_object import STIXObject
from app.models.stix_relationship import STIXRelationship


router = APIRouter(
    prefix="/api/entities",
    tags=["Entities"],
    dependencies=[Depends(get_current_active_user)],
)


def _format_datetime(value: Optional[datetime]) -> Optional[str]:
    if not value:
        return None
    return value.isoformat()


def _parse_aliases(text: Optional[str]) -> List[str]:
    if not text:
        return []
    cleaned = text.strip()
    if not cleaned:
        return []
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned.strip("[]")
    return [item.strip(" '\"\n\r\t") for item in cleaned.split(",") if item.strip()]


def _parse_cvss_vector(vector: Optional[str]) -> Dict[str, Optional[str]]:
    if not vector:
        return {}
    parts = vector.split("/")
    if parts and parts[0].startswith("CVSS"):
        parts = parts[1:]
    values = {}
    for part in parts:
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        values[key] = val

    lookup = {
        "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
        "AC": {"L": "Low", "H": "High"},
        "PR": {"N": "None", "L": "Low", "H": "High"},
        "UI": {"N": "None", "R": "Required"},
        "S": {"U": "Unchanged", "C": "Changed"},
        "C": {"N": "None", "L": "Low", "H": "High"},
        "I": {"N": "None", "L": "Low", "H": "High"},
        "A": {"N": "None", "L": "Low", "H": "High"},
    }

    return {
        "attack_vector": lookup["AV"].get(values.get("AV")),
        "attack_complexity": lookup["AC"].get(values.get("AC")),
        "privileges_required": lookup["PR"].get(values.get("PR")),
        "user_interaction": lookup["UI"].get(values.get("UI")),
        "scope": lookup["S"].get(values.get("S")),
        "confidentiality": lookup["C"].get(values.get("C")),
        "integrity": lookup["I"].get(values.get("I")),
        "availability": lookup["A"].get(values.get("A")),
    }


def _extract_external_id(references: Optional[List[Any]]) -> Optional[str]:
    if not references:
        return None
    for ref in references:
        if isinstance(ref, dict) and ref.get("external_id"):
            return ref["external_id"]
    return None


async def _fetch_relationships(
    db: AsyncSession, stix_ids: List[str], limit: int = 12
) -> List[Dict[str, Any]]:
    if not stix_ids:
        return []

    result = await db.execute(
        select(
            STIXRelationship.id,
            STIXRelationship.relationship_type,
            STIXRelationship.source_ref,
            STIXRelationship.target_ref,
            STIXRelationship.created,
        )
        .where(
            or_(
                STIXRelationship.source_ref.in_(stix_ids),
                STIXRelationship.target_ref.in_(stix_ids),
            )
        )
        .order_by(desc(STIXRelationship.created))
        .limit(limit)
    )
    rows = result.all()
    if not rows:
        return []

    related_ids = {
        row.source_ref for row in rows if row.source_ref
    } | {
        row.target_ref for row in rows if row.target_ref
    }

    name_result = await db.execute(
        select(
            STIXObject.id,
            STIXObject.name,
            STIXObject.type,
            STIXObject.observable_value,
        )
        .where(STIXObject.id.in_(related_ids))
    )
    name_map = {
        row.id: {
            "name": row.name or row.observable_value or row.id,
            "type": row.type,
        }
        for row in name_result.all()
    }

    relationships = []
    for row in rows:
        source = name_map.get(row.source_ref, {"name": row.source_ref, "type": "unknown"})
        target = name_map.get(row.target_ref, {"name": row.target_ref, "type": "unknown"})
        relationships.append(
            {
                "id": row.id,
                "relationship_type": row.relationship_type,
                "source": source,
                "target": target,
                "created": _format_datetime(row.created),
            }
        )
    return relationships


async def _fetch_mitre_relationships(
    db: AsyncSession, stix_id: str, limit: int = 12
) -> List[Dict[str, Any]]:
    result = await db.execute(
        select(
            mitre_relationships.c.relationship_type,
            mitre_relationships.c.source_ref,
            mitre_relationships.c.target_ref,
        )
        .where(
            or_(
                mitre_relationships.c.source_ref == stix_id,
                mitre_relationships.c.target_ref == stix_id,
            )
        )
        .limit(limit)
    )
    rows = result.all()
    if not rows:
        return []

    related_ids = {row.source_ref for row in rows} | {row.target_ref for row in rows}

    names = {}
    group_result = await db.execute(
        select(MitreGroup.stix_id, MitreGroup.name).where(MitreGroup.stix_id.in_(related_ids))
    )
    for row in group_result.all():
        names[row.stix_id] = {"name": row.name, "type": "group"}

    software_result = await db.execute(
        select(MitreSoftware.stix_id, MitreSoftware.name, MitreSoftware.is_malware).where(
            MitreSoftware.stix_id.in_(related_ids)
        )
    )
    for row in software_result.all():
        names[row.stix_id] = {
            "name": row.name,
            "type": "malware" if row.is_malware else "tool",
        }

    technique_result = await db.execute(
        select(MitreTechnique.stix_id, MitreTechnique.external_id, MitreTechnique.name).where(
            MitreTechnique.stix_id.in_(related_ids)
        )
    )
    for row in technique_result.all():
        label = row.external_id or row.name
        names[row.stix_id] = {"name": label, "type": "technique"}

    relationships = []
    for row in rows:
        source = names.get(row.source_ref, {"name": row.source_ref, "type": "unknown"})
        target = names.get(row.target_ref, {"name": row.target_ref, "type": "unknown"})
        relationships.append(
            {
                "relationship_type": row.relationship_type,
                "source": source,
                "target": target,
            }
        )
    return relationships


@router.get("/cves/{cve_id}")
async def get_cve_detail(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
):
    """CVE detail endpoint."""
    normalized = cve_id.strip().upper()
    if not CVE_PATTERN.match(normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CVE format",
        )

    details = await fetch_cve_details(normalized)
    if not details:
        return {"found": False, "query": normalized}

    ioc_result = await db.execute(
        select(IOC)
        .where(IOC.tags.ilike(f"%{normalized}%"))
        .order_by(desc(IOC.last_seen))
        .limit(25)
    )
    iocs = ioc_result.scalars().all()

    relationships = [
        {
            "relationship_type": "related-to",
            "source": {"name": ioc.value, "type": ioc.type},
            "target": {"name": normalized, "type": "vulnerability"},
            "created": ioc.last_seen.isoformat() if ioc.last_seen else None,
        }
        for ioc in iocs
    ]

    cvss = details.get("cvss") or {}
    vector_data = _parse_cvss_vector(cvss.get("vector"))

    affected = details.get("affected") or []
    primary_vendor = affected[0].get("vendor") if affected else None
    primary_product = affected[0].get("product") if affected else None

    return {
        "found": True,
        "query": normalized,
        "summary": {
            "total_reports": len(iocs),
            "total_relationships": len(relationships),
            "total_sightings": 0,
        },
        "cve": {
            "id": details.get("id"),
            "title": details.get("title"),
            "description": details.get("description"),
            "published": details.get("published"),
            "updated": details.get("updated"),
            "cvss": cvss,
            "epss": None,
            "vendor": primary_vendor,
            "product": primary_product,
            "affected": affected,
            "references": details.get("references") or [],
            "vector": vector_data,
        },
        "meta": {
            "confidence": 50,
            "reliability": "B - Reliable",
            "processing_status": "Processed",
            "labels": [],
            "creator": details.get("cna") or "Unknown",
        },
        "relationships": relationships,
        "external_references": details.get("references") or [],
        "history": [],
    }


@router.get("/threats/{threat_id}")
async def get_threat_detail(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Threat/Actor/Malware detail endpoint."""
    normalized = threat_id.strip()

    group = None
    software = None
    stix_entity = None

    if normalized:
        result = await db.execute(
            select(MitreGroup).where(MitreGroup.stix_id == normalized)
        )
        group = result.scalar_one_or_none()

        if not group:
            result = await db.execute(
                select(MitreSoftware).where(MitreSoftware.stix_id == normalized)
            )
            software = result.scalar_one_or_none()

    if not group and not software:
        result = await db.execute(
            select(MitreGroup)
            .where(MitreGroup.name.ilike(normalized))
            .limit(1)
        )
        group = result.scalar_one_or_none()

    if not group and not software:
        result = await db.execute(
            select(MitreSoftware)
            .where(MitreSoftware.name.ilike(normalized))
            .limit(1)
        )
        software = result.scalar_one_or_none()

    if not group and not software:
        result = await db.execute(
            select(MitreGroup)
            .where(MitreGroup.name.ilike(f"%{normalized}%"))
            .limit(1)
        )
        group = result.scalar_one_or_none()

    if not group and not software:
        result = await db.execute(
            select(MitreSoftware)
            .where(MitreSoftware.name.ilike(f"%{normalized}%"))
            .limit(1)
        )
        software = result.scalar_one_or_none()

    if not group and not software:
        threat_types = [
            "intrusion-set",
            "threat-actor",
            "campaign",
            "malware",
            "tool",
            "report",
            "indicator",
        ]
        result = await db.execute(
            select(STIXObject)
            .where(STIXObject.type.in_(threat_types))
            .where(
                or_(
                    STIXObject.id == normalized,
                    STIXObject.name.ilike(normalized),
                    STIXObject.name.ilike(f"%{normalized}%"),
                )
            )
            .order_by(desc(STIXObject.modified))
            .limit(1)
        )
        stix_entity = result.scalar_one_or_none()

    if not group and not software and not stix_entity:
        return {"found": False, "query": normalized}

    if stix_entity:
        relationships = await _fetch_relationships(db, [stix_entity.id])
        external_refs = (
            stix_entity.external_references
            if isinstance(stix_entity.external_references, list)
            else []
        )
        external_id = _extract_external_id(external_refs)
        return {
            "found": True,
            "query": normalized,
            "entity": {
                "id": stix_entity.id,
                "name": stix_entity.name or normalized,
                "type": stix_entity.type,
                "description": stix_entity.description or "",
                "first_seen": _format_datetime(stix_entity.created),
                "last_seen": _format_datetime(stix_entity.modified),
                "external_id": external_id,
                "labels": stix_entity.labels or [],
                "confidence": stix_entity.confidence or 0,
            },
            "summary": {
                "total_reports": 0,
                "total_relationships": len(relationships),
                "total_sightings": 0,
            },
            "meta": {
                "status": "Active",
                "author": stix_entity.connector_name or "Unknown",
                "labels": stix_entity.labels or [],
                "created": _format_datetime(stix_entity.created),
                "modified": _format_datetime(stix_entity.modified),
            },
            "relationships": relationships,
            "external_references": external_refs,
            "history": [],
        }

    entity_type = "group" if group else ("malware" if software and software.is_malware else "tool")
    entity = group or software

    relationships = await _fetch_mitre_relationships(db, entity.stix_id)

    return {
        "found": True,
        "query": normalized,
        "entity": {
            "id": entity.stix_id,
            "name": entity.name,
            "type": entity_type,
            "description": entity.description or "",
            "first_seen": entity.created,
            "last_seen": entity.modified,
            "external_id": entity.external_id,
            "labels": _parse_aliases(entity.aliases),
            "confidence": 50,
        },
        "summary": {
            "total_reports": 0,
            "total_relationships": len(relationships),
            "total_sightings": 0,
        },
        "meta": {
            "status": "Active",
            "labels": _parse_aliases(entity.aliases),
            "author": "MITRE ATT&CK",
            "created": entity.created,
            "modified": entity.modified,
        },
        "relationships": relationships,
        "external_references": [entity.url] if entity.url else [],
        "history": [],
    }


@router.get("/indicators/{indicator_type}/{indicator_value}")
async def get_indicator_detail(
    indicator_type: str,
    indicator_value: str,
    db: AsyncSession = Depends(get_db),
):
    """Indicator detail endpoint (domain/ip/url)."""
    indicator_type = indicator_type.lower().strip()
    allowed = {"domain", "ip", "url"}
    if indicator_type not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported indicator type",
        )

    value = indicator_value.strip()
    observable_types = {
        "domain": ["domain-name"],
        "ip": ["ipv4-addr", "ipv6-addr"],
        "url": ["url"],
    }[indicator_type]

    observable_result = await db.execute(
        select(STIXObject)
        .where(STIXObject.observable_type.in_(observable_types))
        .where(func.lower(STIXObject.observable_value) == value.lower())
        .limit(1)
    )
    observable = observable_result.scalar_one_or_none()

    indicator_result = await db.execute(
        select(STIXObject)
        .where(STIXObject.type == "indicator")
        .where(STIXObject.pattern.ilike(f"%{value}%"))
        .order_by(desc(STIXObject.created))
        .limit(1)
    )
    indicator = indicator_result.scalar_one_or_none()

    stix_ids = []
    if observable:
        stix_ids.append(observable.id)
    if indicator:
        stix_ids.append(indicator.id)

    relationships = await _fetch_relationships(db, stix_ids)

    stix_data = indicator.stix_data if indicator else {}
    indicator_types = stix_data.get("indicator_types") if isinstance(stix_data, dict) else []
    description = indicator.description if indicator else ""
    pattern = indicator.pattern if indicator else f"[{observable_types[0]}:value = '{value}']"

    return {
        "found": True if indicator or observable else False,
        "query": value,
        "indicator": {
            "value": value,
            "pattern": pattern,
            "valid_from": _format_datetime(indicator.valid_from) if indicator else None,
            "valid_until": _format_datetime(indicator.valid_until) if indicator else None,
            "score": indicator.confidence if indicator else None,
            "description": description,
            "indicator_types": indicator_types or [],
            "observable_type": observable.observable_type if observable else observable_types[0],
        },
        "meta": {
            "marking": "TLP:CLEAR",
            "author": indicator.connector_name if indicator else "Unknown",
            "reliability": "C - Fair",
            "confidence": indicator.confidence if indicator else 0,
            "processing_status": "Processed" if indicator else "Unknown",
            "labels": indicator.labels if indicator else [],
            "created": _format_datetime(indicator.created) if indicator else None,
            "modified": _format_datetime(indicator.modified) if indicator else None,
            "stix_id": indicator.id if indicator else None,
        },
        "relationships": relationships,
        "external_references": indicator.external_references if indicator else [],
        "history": [],
    }
