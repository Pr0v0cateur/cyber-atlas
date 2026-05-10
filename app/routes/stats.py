"""
Cyber Atlas - Statistics Routes

Endpoints for IOC statistics and analytics.
"""

from typing import Optional
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query
from sqlalchemy import cast, desc, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.routes.auth import get_current_active_user
from app.models.user import User
from app.models.stix_object import STIXObject
from app.models.mitre import MitreGroup, MitreSoftware, MitreTechnique, mitre_relationships
from app.crud import iocs as ioc_crud
from app.core.config import settings
from app.utils_geoip import get_country_code


router = APIRouter(prefix="/api/stats", tags=["Statistics"])


@router.get("/summary")
async def get_summary_stats(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get summary statistics for IOCs.
    
    Returns total counts, counts by type, source, country, and risk level.
    """
    stats = await ioc_crud.get_ioc_stats(db)
    stix_counts = await _get_stix_counts(db)
    mitre_counts = await _get_mitre_counts(db)
    
    return {
        "total_iocs": stats["total_count"],
        "by_type": stats["by_type"],
        "by_source": stats["by_source"],
        "by_country_top20": stats["by_country"],
        "by_risk_level": stats["by_risk"],
        "stix": stix_counts,
        "mitre": mitre_counts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/sources")
async def get_source_stats(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get IOC counts grouped by source.
    
    Returns the number of IOCs from each threat feed source.
    """
    sources = await ioc_crud.get_iocs_by_source(db)
    stix_sources = await _get_stix_indicator_sources(db, limit=20)
    
    raw_sources = sources if sources else stix_sources
    total = sum(raw_sources.values())
    source_stats = []
    
    for source, count in raw_sources.items():
        source_stats.append({
            "source": source,
            "count": count,
            "percentage": round((count / total * 100), 2) if total > 0 else 0,
        })
    
    # Sort by count descending
    source_stats.sort(key=lambda x: x["count"], reverse=True)
    
    return {
        "total_iocs": total,
        "source_count": len(raw_sources),
        "sources": source_stats,
        "stix_sources": stix_sources,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/countries")
async def get_country_stats(
    limit: int = Query(50, ge=1, le=200, description="Maximum countries to return"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get IOC counts grouped by country.
    
    Returns geographic distribution of IOCs.
    Only IP-based IOCs with geo-enrichment are included.
    """
    countries = await ioc_crud.get_iocs_by_country(db, limit=limit)
    if not countries:
        countries = await _get_stix_country_stats(db, limit=limit)
    
    # Calculate total and percentages
    total = sum(countries.values())
    country_stats = []
    
    for country, count in countries.items():
        country_stats.append({
            "country_code": country,
            "count": count,
            "percentage": round((count / total * 100), 2) if total > 0 else 0,
        })
    
    return {
        "total_geo_enriched": total,
        "country_count": len(countries),
        "countries": country_stats,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/timeline")
async def get_timeline_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    group_by_type: bool = Query(False, description="Group by IOC type"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get IOC counts over time.
    
    Returns daily IOC counts for the specified period.
    Optionally groups counts by IOC type.
    """
    timeline = await ioc_crud.get_ioc_timeline(
        db,
        days=days,
        group_by_type=group_by_type,
    )
    
    # Calculate totals
    total = sum(day["count"] for day in timeline)
    
    return {
        "period_days": days,
        "total_iocs": total,
        "daily_average": round(total / days, 2) if days > 0 else 0,
        "data_points": len(timeline),
        "timeline": timeline,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/risk-distribution")
async def get_risk_distribution(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get IOC distribution by risk level.
    
    Returns counts for each risk score (1-10).
    """
    stats = await ioc_crud.get_ioc_stats(db)
    risk_data = stats["by_risk"]
    
    # Ensure all risk levels are present
    distribution = []
    total = sum(risk_data.values())
    
    for level in range(1, 11):
        count = risk_data.get(level, 0)
        distribution.append({
            "risk_level": level,
            "count": count,
            "percentage": round((count / total * 100), 2) if total > 0 else 0,
            "label": get_risk_label(level),
        })
    
    return {
        "total_with_risk": total,
        "distribution": distribution,
        "high_risk_count": sum(risk_data.get(l, 0) for l in range(8, 11)),
        "medium_risk_count": sum(risk_data.get(l, 0) for l in range(4, 8)),
        "low_risk_count": sum(risk_data.get(l, 0) for l in range(1, 4)),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def get_risk_label(risk_level: int) -> str:
    """Get human-readable label for risk level."""
    if risk_level >= 8:
        return "Critical"
    elif risk_level >= 6:
        return "High"
    elif risk_level >= 4:
        return "Medium"
    elif risk_level >= 2:
        return "Low"
    else:
        return "Info"


@router.get("/type-distribution")
async def get_type_distribution(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get IOC distribution by type.
    
    Returns counts for each IOC type (ip, domain, url, hash, etc.).
    """
    stats = await ioc_crud.get_ioc_stats(db)
    type_data = stats["by_type"]
    
    total = sum(type_data.values())
    distribution = []
    
    for ioc_type, count in sorted(type_data.items(), key=lambda x: x[1], reverse=True):
        distribution.append({
            "type": ioc_type,
            "count": count,
            "percentage": round((count / total * 100), 2) if total > 0 else 0,
        })
    
    return {
        "total_iocs": total,
        "type_count": len(type_data),
        "distribution": distribution,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/recent-activity")
async def get_recent_activity(
    limit: int = Query(10, ge=1, le=100, description="Number of recent IOCs"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get recently added IOCs.
    
    Returns the most recently created IOCs.
    """
    from app.schemas.ioc import IOCResponse
    
    iocs = await ioc_crud.get_iocs(
        db,
        skip=0,
        limit=limit,
        order_by="created_at",
        order_desc=True,
    )
    
    return {
        "count": len(iocs),
        "recent_iocs": [IOCResponse.model_validate(ioc) for ioc in iocs],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/dashboard")
async def get_dashboard_stats(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get comprehensive dashboard statistics.
    
    Combines multiple statistics endpoints for dashboard display.
    """
    stats = await ioc_crud.get_ioc_stats(db)
    sources = await ioc_crud.get_iocs_by_source(db)
    stix_counts = await _get_stix_counts(db)
    mitre_counts = await _get_mitre_counts(db)
    stix_sources = await _get_stix_indicator_sources(db, limit=5)
    top_intrusion_sets = await _get_mitre_top_intrusion_sets(db, limit=5)
    countries = await ioc_crud.get_iocs_by_country(db, limit=10)
    if not countries:
        countries = await _get_stix_country_stats(db, limit=10)
    timeline = await _get_stix_timeline(db, days=7)
    if not timeline:
        timeline = await ioc_crud.get_ioc_timeline(db, days=7)
    malware_families = await _get_stix_top_malware(db, limit=8)
    if not malware_families:
        malware_families = await _get_mitre_top_malware(db, limit=8)
    if not malware_families:
        malware_families = await ioc_crud.get_top_malware_families(db, limit=8)
    vulnerabilities = await _get_stix_top_cves(db, limit=8)
    if not vulnerabilities:
        vulnerabilities = await _get_ioc_top_cves(db, limit=8)
    top_tools = await _get_mitre_top_tools(db, limit=7)
    top_ttps = await _get_mitre_top_ttps(db, limit=6)
    
    # Recent IOCs
    recent_iocs = await ioc_crud.get_iocs(
        db,
        skip=0,
        limit=5,
        order_by="created_at",
        order_desc=True,
    )
    
    return {
        "summary": {
            "total_iocs": stats["total_count"],
            "source_count": len(sources) if sources else len(stix_sources),
            "country_count": len(countries),
            "high_risk_count": sum(
                stats["by_risk"].get(l, 0) for l in range(8, 11)
            ),
            "total_indicators": stix_counts.get("indicators", 0),
            "total_observables": stix_counts.get("observables", 0),
            "threat_actor_count": mitre_counts.get("threat_actor_count", 0),
            "intrusion_set_count": mitre_counts.get("intrusion_set_count", 0),
            "campaign_count": stix_counts.get("campaign_count", 0),
            "malware_count": mitre_counts.get("malware_count", 0),
            "tool_count": mitre_counts.get("tool_count", 0),
        },
        "by_type": stats["by_type"],
        "top_sources": stix_sources or dict(list(sources.items())[:5]),
        "top_intrusion_sets": top_intrusion_sets,
        "top_countries": dict(list(countries.items())[:5]),
        "top_malware": malware_families,
        "top_tools": top_tools,
        "top_ttps": top_ttps,
        "weekly_timeline": timeline,
        "vulnerabilities": vulnerabilities,
        "recent_iocs": [
            {
                "id": ioc.id,
                "type": ioc.type,
                "value": ioc.value[:50] + "..." if len(ioc.value) > 50 else ioc.value,
                "source": ioc.source,
                "risk": ioc.risk,
                "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
            }
            for ioc in recent_iocs
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


async def _get_stix_counts(db: AsyncSession) -> dict:
    total_result = await db.execute(select(func.count(STIXObject.id)))
    total = total_result.scalar_one()

    indicator_result = await db.execute(
        select(func.count(STIXObject.id)).where(STIXObject.type == "indicator")
    )
    indicators = indicator_result.scalar_one()

    observable_result = await db.execute(
        select(func.count(STIXObject.id)).where(STIXObject.observable_type.isnot(None))
    )
    observables = observable_result.scalar_one()

    campaign_result = await db.execute(
        select(func.count(func.distinct(STIXObject.name))).where(
            STIXObject.type == "indicator",
            STIXObject.name.isnot(None),
        )
    )
    campaigns = campaign_result.scalar_one()

    return {
        "total_objects": total,
        "indicators": indicators,
        "observables": observables,
        "campaign_count": campaigns,
    }


async def _get_mitre_counts(db: AsyncSession) -> dict:
    groups_result = await db.execute(select(func.count(MitreGroup.id)))
    group_count = groups_result.scalar_one()

    malware_result = await db.execute(
        select(func.count(MitreSoftware.id)).where(MitreSoftware.is_malware.is_(True))
    )
    malware_count = malware_result.scalar_one()

    tool_result = await db.execute(
        select(func.count(MitreSoftware.id)).where(MitreSoftware.is_malware.is_(False))
    )
    tool_count = tool_result.scalar_one()

    return {
        "threat_actor_count": group_count,
        "intrusion_set_count": group_count,
        "malware_count": malware_count,
        "tool_count": tool_count,
    }


async def _get_stix_indicator_sources(db: AsyncSession, limit: int = 5) -> dict:
    result = await db.execute(
        select(STIXObject.connector_name, func.count(STIXObject.id))
        .where(STIXObject.type == "indicator")
        .where(STIXObject.connector_name.isnot(None))
        .group_by(STIXObject.connector_name)
        .order_by(desc(func.count(STIXObject.id)))
        .limit(limit)
    )
    name_map = {
        "URLhausSTIXConnector": "URLhaus",
        "ThreatFoxSTIXConnector": "ThreatFox",
        "OTXSTIXConnector": "AlienVault OTX",
    }
    output = {}
    for connector, count in result.all():
        if not connector:
            continue
        label = name_map.get(connector, connector)
        output[label] = count
    return output


async def _get_stix_top_malware(db: AsyncSession, limit: int = 8) -> dict:
    result = await db.execute(
        select(STIXObject.name, func.count(STIXObject.id))
        .where(STIXObject.type == "malware")
        .where(STIXObject.name.isnot(None))
        .group_by(STIXObject.name)
        .order_by(desc(func.count(STIXObject.id)))
        .limit(limit)
    )
    return {row[0]: row[1] for row in result.all() if row[0]}


async def _get_mitre_top_intrusion_sets(db: AsyncSession, limit: int = 5) -> dict:
    result = await db.execute(
        select(MitreGroup.name, func.count())
        .select_from(mitre_relationships.join(MitreGroup, mitre_relationships.c.source_ref == MitreGroup.stix_id))
        .where(mitre_relationships.c.relationship_type == "uses")
        .group_by(MitreGroup.name)
        .order_by(desc(func.count()))
        .limit(limit)
    )
    return {row[0]: row[1] for row in result.all() if row[0]}


async def _get_mitre_top_malware(db: AsyncSession, limit: int = 8) -> dict:
    result = await db.execute(
        select(MitreSoftware.name, func.count())
        .select_from(mitre_relationships.join(MitreSoftware, mitre_relationships.c.target_ref == MitreSoftware.stix_id))
        .where(mitre_relationships.c.relationship_type == "uses")
        .where(MitreSoftware.is_malware.is_(True))
        .group_by(MitreSoftware.name)
        .order_by(desc(func.count()))
        .limit(limit)
    )
    return {row[0]: row[1] for row in result.all() if row[0]}


async def _get_mitre_top_tools(db: AsyncSession, limit: int = 7) -> dict:
    result = await db.execute(
        select(MitreSoftware.name, func.count())
        .select_from(mitre_relationships.join(MitreSoftware, mitre_relationships.c.target_ref == MitreSoftware.stix_id))
        .where(mitre_relationships.c.relationship_type == "uses")
        .where(MitreSoftware.is_malware.is_(False))
        .group_by(MitreSoftware.name)
        .order_by(desc(func.count()))
        .limit(limit)
    )
    return {row[0]: row[1] for row in result.all() if row[0]}


async def _get_mitre_top_ttps(db: AsyncSession, limit: int = 6) -> dict:
    result = await db.execute(
        select(MitreTechnique.external_id, func.count())
        .select_from(mitre_relationships.join(MitreTechnique, mitre_relationships.c.target_ref == MitreTechnique.stix_id))
        .where(mitre_relationships.c.relationship_type == "uses")
        .where(MitreTechnique.external_id.isnot(None))
        .group_by(MitreTechnique.external_id)
        .order_by(desc(func.count()))
        .limit(limit)
    )
    return {row[0]: row[1] for row in result.all() if row[0]}


async def _get_stix_timeline(db: AsyncSession, days: int = 7) -> list:
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(
            func.date(STIXObject.created).label("date"),
            func.count(STIXObject.id).label("count"),
        )
        .where(STIXObject.type == "indicator")
        .where(STIXObject.created.isnot(None))
        .where(STIXObject.created >= start_date)
        .group_by(func.date(STIXObject.created))
        .order_by(func.date(STIXObject.created))
    )
    return [{"date": str(row.date), "count": row.count} for row in result.all()]


async def _get_stix_top_cves(db: AsyncSession, limit: int = 8) -> list:
    labels_expr = func.jsonb_array_elements_text(cast(STIXObject.labels, JSONB)).label("label")
    labels_subquery = (
        select(labels_expr)
        .where(STIXObject.type == "indicator")
        .where(STIXObject.labels.isnot(None))
        .subquery()
    )

    result = await db.execute(
        select(labels_subquery.c.label, func.count().label("count"))
        .where(labels_subquery.c.label.ilike("CVE-%"))
        .group_by(labels_subquery.c.label)
        .order_by(desc(func.count()))
        .limit(limit)
    )

    return [{"value": row.label, "count": row.count} for row in result.all()]


async def _get_ioc_top_cves(db: AsyncSession, limit: int = 8) -> list:
    cves = {}
    recent = await ioc_crud.get_iocs(db, skip=0, limit=500, order_by="created_at", order_desc=True)
    for ioc in recent:
        if not ioc.tags:
            continue
        for tag in ioc.tags.split(","):
            tag = tag.strip().upper()
            if tag.startswith("CVE-"):
                cves[tag] = cves.get(tag, 0) + 1

    items = sorted(cves.items(), key=lambda item: item[1], reverse=True)[:limit]
    return [{"value": name, "count": count} for name, count in items]


async def _get_stix_country_stats(db: AsyncSession, limit: int = 20) -> dict:
    counts: dict[str, int] = {}
    geoip_available = Path(settings.geoip_database_path).exists()

    if geoip_available:
        result = await db.execute(
            select(STIXObject.observable_value)
            .where(STIXObject.observable_type.in_(["ipv4-addr", "ipv6-addr"]))
            .where(STIXObject.observable_value.isnot(None))
            .limit(5000)
        )
        for value in result.scalars().all():
            country = get_country_code(value)
            if country:
                counts[country] = counts.get(country, 0) + 1

    result = await db.execute(
        select(STIXObject.observable_value)
        .where(STIXObject.observable_type.in_(["domain-name", "url"]))
        .where(STIXObject.observable_value.isnot(None))
        .limit(10000)
    )
    for value in result.scalars().all():
        country = _extract_country_from_domain(value)
        if country:
            counts[country] = counts.get(country, 0) + 1

    if not counts:
        return {}

    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
    return {code: count for code, count in sorted_counts}


def _extract_country_from_domain(value: str) -> Optional[str]:
    if not value:
        return None

    text = value.strip().lower()
    if not text:
        return None

    host = None
    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname
    else:
        host = text.split("/")[0]

    if not host or "." not in host:
        return None

    tld = host.rsplit(".", 1)[-1]
    if len(tld) == 2 and tld.isalpha():
        return tld.upper()
    return None
