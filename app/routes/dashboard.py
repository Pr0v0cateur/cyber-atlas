"""
Cyber Atlas - Dashboard Data Routes

Granular endpoints for populating each dashboard widget.
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
import httpx
import ipaddress
from sqlalchemy import cast, desc, func, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.logging import logger
from app.crud import iocs as ioc_crud
from app.models.ioc import IOC
from app.models.mitre import MitreGroup, MitreSoftware, MitreTechnique, mitre_relationships
from app.models.stix_object import STIXObject
from app.routes.auth import get_current_active_user
from app.utils_geoip import get_country_code


router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(get_current_active_user)],
)


async def _count_stix_type(
    db: AsyncSession, obj_type: str, since: Optional[datetime] = None
) -> int:
    query = select(func.count(STIXObject.id)).where(STIXObject.type == obj_type)
    if since:
        query = query.where(STIXObject.created >= since)
    result = await db.execute(query)
    return result.scalar_one()


async def _count_observables(
    db: AsyncSession, since: Optional[datetime] = None
) -> int:
    query = select(func.count(STIXObject.id)).where(STIXObject.observable_type.isnot(None))
    if since:
        query = query.where(STIXObject.created >= since)
    result = await db.execute(query)
    return result.scalar_one()


async def _count_indicator_names(
    db: AsyncSession, since: Optional[datetime] = None
) -> int:
    query = select(func.count(func.distinct(STIXObject.name))).where(
        STIXObject.type == "indicator",
        STIXObject.name.isnot(None),
    )
    if since:
        query = query.where(STIXObject.created >= since)
    result = await db.execute(query)
    return result.scalar_one()


async def _set_statement_timeout(db: AsyncSession, ms: int = 12000) -> None:
    """
    Keep dashboard endpoints responsive when the DB is under heavy load.
    """
    try:
        await db.execute(text(f"SET LOCAL statement_timeout = {int(ms)}"))
    except Exception:
        # Not fatal; fallback logic below still protects the endpoint.
        pass


async def _count_iocs(
    db: AsyncSession,
    ioc_type: Optional[str] = None,
    since: Optional[datetime] = None,
) -> int:
    query = select(func.count(IOC.id))
    if ioc_type:
        query = query.where(IOC.type == ioc_type)
    if since:
        query = query.where(IOC.created_at >= since)
    result = await db.execute(query)
    return int(result.scalar_one() or 0)


async def _ioc_top_cves(db: AsyncSession, limit: int = 10) -> list[dict]:
    query = text(
        """
        SELECT
            UPPER((regexp_matches(tag, '(CVE-[0-9]{4}-[0-9]+)', 'g'))[1]) AS cve,
            COUNT(*)::int AS count
        FROM (
            SELECT unnest(string_to_array(tags, ',')) AS tag
            FROM iocs
            WHERE tags IS NOT NULL
        ) t
        WHERE tag ~* 'CVE-[0-9]{4}-[0-9]+'
        GROUP BY cve
        ORDER BY count DESC
        LIMIT :limit
        """
    )
    result = await db.execute(query, {"limit": int(limit)})
    rows = result.all()
    return [{"cve": row.cve, "count": row.count} for row in rows if row.cve]


def _safe_labels(value) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


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


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return False


async def _lookup_ipapi_countries(values: list[str]) -> dict[str, int]:
    if not values:
        return {}

    counts: dict[str, int] = {}
    endpoint = "http://ip-api.com/batch?fields=status,countryCode"
    chunks = [values[i : i + 100] for i in range(0, len(values), 100)]

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            for chunk in chunks:
                response = await client.post(endpoint, json=chunk)
                if response.status_code != 200:
                    continue
                for item in response.json():
                    if item.get("status") != "success":
                        continue
                    code = item.get("countryCode")
                    if code:
                        counts[code] = counts.get(code, 0) + 1
    except Exception as exc:
        logger.warning(f"IP-API lookup failed: {exc}")
        return {}

    return counts


async def _get_country_counts(db: AsyncSession, limit: int = 20) -> dict:
    # IOC-first path: faster and resilient even when STIX tables are degraded.
    try:
        ioc_countries = await ioc_crud.get_iocs_by_country(db, limit=limit)
        if ioc_countries:
            return dict(ioc_countries)
    except Exception:
        pass

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

    if not geoip_available:
        ip_result = await db.execute(
            select(STIXObject.observable_value)
            .where(STIXObject.observable_type.in_(["ipv4-addr", "ipv6-addr"]))
            .where(STIXObject.observable_value.isnot(None))
            .limit(200)
        )
        ip_values = [value for value in ip_result.scalars().all() if _is_public_ip(value)]
        ip_counts = await _lookup_ipapi_countries(ip_values)
        for country, count in ip_counts.items():
            counts[country] = counts.get(country, 0) + count

    if not counts:
        return {}

    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
    return {code: count for code, count in sorted_counts}


@router.get("/kpis")
async def get_kpis(db: AsyncSession = Depends(get_db)):
    """Get KPI card metrics with 24h deltas."""
    try:
        now = datetime.now(timezone.utc)
        since = now - timedelta(days=1)

        threat_actor_total = await db.execute(select(func.count(MitreGroup.id)))
        threat_actors = threat_actor_total.scalar_one()

        malware_total = await db.execute(
            select(func.count(MitreSoftware.id)).where(MitreSoftware.is_malware.is_(True))
        )
        malware = malware_total.scalar_one()

        tools_total = await db.execute(
            select(func.count(MitreSoftware.id)).where(MitreSoftware.is_malware.is_(False))
        )
        tools = tools_total.scalar_one()

        indicators_total = await _count_iocs(db)
        indicators_24h = await _count_iocs(db, since=since)

        observables_total = await _count_iocs(db, ioc_type="ip")
        observables_total += await _count_iocs(db, ioc_type="domain")
        observables_total += await _count_iocs(db, ioc_type="url")
        observables_total += await _count_iocs(db, ioc_type="hash")

        observables_24h = await _count_iocs(db, ioc_type="ip", since=since)
        observables_24h += await _count_iocs(db, ioc_type="domain", since=since)
        observables_24h += await _count_iocs(db, ioc_type="url", since=since)
        observables_24h += await _count_iocs(db, ioc_type="hash", since=since)

        campaign_total = await _count_iocs(db, ioc_type="domain")
        campaign_24h = await _count_iocs(db, ioc_type="domain", since=since)

        return {
            "threat_actors": {"total": threat_actors, "change_24h": 0},
            "intrusion_sets": {"total": threat_actors, "change_24h": 0},
            "campaigns": {"total": campaign_total, "change_24h": campaign_24h},
            "malware": {"total": malware, "change_24h": 0},
            "indicators": {"total": indicators_total, "change_24h": indicators_24h},
            "observables": {"total": observables_total, "change_24h": observables_24h},
            "tools": {"total": tools, "change_24h": 0},
        }
    except Exception as exc:
        logger.error(f"Dashboard KPIs failed: {exc}")
        now = datetime.now(timezone.utc)
        since = now - timedelta(days=1)
        try:
            indicators_total = await _count_iocs(db)
            indicators_24h = await _count_iocs(db, since=since)
            observables_total = await _count_iocs(db, ioc_type="ip")
            observables_total += await _count_iocs(db, ioc_type="domain")
            observables_total += await _count_iocs(db, ioc_type="url")
            observables_total += await _count_iocs(db, ioc_type="hash")
            observables_24h = await _count_iocs(db, ioc_type="ip", since=since)
            observables_24h += await _count_iocs(db, ioc_type="domain", since=since)
            observables_24h += await _count_iocs(db, ioc_type="url", since=since)
            observables_24h += await _count_iocs(db, ioc_type="hash", since=since)
            return {
                "threat_actors": {"total": 0, "change_24h": 0},
                "intrusion_sets": {"total": 0, "change_24h": 0},
                "campaigns": {"total": 0, "change_24h": 0},
                "malware": {"total": 0, "change_24h": 0},
                "indicators": {"total": indicators_total, "change_24h": indicators_24h},
                "observables": {"total": observables_total, "change_24h": observables_24h},
                "tools": {"total": 0, "change_24h": 0},
            }
        except Exception as fallback_exc:
            logger.error(f"Dashboard KPI fallback failed: {fallback_exc}")
            return {
                "threat_actors": {"total": 0, "change_24h": 0},
                "intrusion_sets": {"total": 0, "change_24h": 0},
                "campaigns": {"total": 0, "change_24h": 0},
                "malware": {"total": 0, "change_24h": 0},
                "indicators": {"total": 0, "change_24h": 0},
                "observables": {"total": 0, "change_24h": 0},
                "tools": {"total": 0, "change_24h": 0},
            }


@router.get("/targeted-regions")
async def get_targeted_regions(db: AsyncSession = Depends(get_db)):
    """Bar chart: indicator distribution by region."""
    try:
        region_map = {
            "N.AMERICA": ["US", "CA", "MX"],
            "S.AMERICA": ["BR", "AR", "CL", "CO", "PE", "VE"],
            "EUROPE": ["GB", "DE", "FR", "IT", "ES", "NL", "SE", "NO", "FI", "PL", "RO", "UA"],
            "ASIA": ["CN", "JP", "KR", "SG", "IN", "HK", "TW", "VN", "TH", "ID", "PK"],
            "AFRICA": ["ZA", "EG", "NG", "KE", "MA"],
            "OCEANIA": ["AU", "NZ"],
        }
        region_counts = {key: 0 for key in region_map}
        region_counts["OTHER"] = 0

        country_counts = await _get_country_counts(db, limit=50)
        for country, count in country_counts.items():
            matched = False
            for region, codes in region_map.items():
                if country in codes:
                    region_counts[region] += count
                    matched = True
                    break
            if not matched:
                region_counts["OTHER"] += count

        data = [
            {"region": region, "count": count}
            for region, count in sorted(region_counts.items(), key=lambda item: item[1], reverse=True)
            if count > 0
        ]
        return {"data": data}
    except Exception as exc:
        logger.error(f"Dashboard regions failed: {exc}")
        try:
            countries = await ioc_crud.get_iocs_by_country(db, limit=50)
            if not countries:
                return {"data": []}
            region_map = {
                "N.AMERICA": ["US", "CA", "MX"],
                "S.AMERICA": ["BR", "AR", "CL", "CO", "PE", "VE"],
                "EUROPE": ["GB", "DE", "FR", "IT", "ES", "NL", "SE", "NO", "FI", "PL", "RO", "UA"],
                "ASIA": ["CN", "JP", "KR", "SG", "IN", "HK", "TW", "VN", "TH", "ID", "PK"],
                "AFRICA": ["ZA", "EG", "NG", "KE", "MA"],
                "OCEANIA": ["AU", "NZ"],
            }
            region_counts = {key: 0 for key in region_map}
            region_counts["OTHER"] = 0
            for code, count in countries.items():
                found = False
                for region, code_list in region_map.items():
                    if code in code_list:
                        region_counts[region] += count
                        found = True
                        break
                if not found:
                    region_counts["OTHER"] += count
            data = [
                {"region": region, "count": count}
                for region, count in sorted(region_counts.items(), key=lambda item: item[1], reverse=True)
                if count > 0
            ]
            return {"data": data}
        except Exception:
            return {"data": []}


@router.get("/targeted-countries")
async def get_targeted_countries(db: AsyncSession = Depends(get_db)):
    """Top targeted countries."""
    try:
        country_counts = await _get_country_counts(db, limit=20)
        data = [{"country": code, "count": count} for code, count in country_counts.items()]
        return {"data": data}
    except Exception as exc:
        logger.error(f"Dashboard countries failed: {exc}")
        countries = await ioc_crud.get_iocs_by_country(db, limit=20)
        return {"data": [{"country": code, "count": count} for code, count in countries.items()]}


@router.get("/targeted-countries-map")
async def get_countries_map(db: AsyncSession = Depends(get_db)):
    """Country heatmap data for map visualization."""
    try:
        country_counts = await _get_country_counts(db, limit=50)
        return {
            "data": [
                {"country_code": code, "count": count}
                for code, count in country_counts.items()
            ]
        }
    except Exception as exc:
        logger.error(f"Dashboard map failed: {exc}")
        countries = await ioc_crud.get_iocs_by_country(db, limit=50)
        return {
            "data": [{"country_code": code, "count": count} for code, count in countries.items()]
        }


@router.get("/active-intrusion-sets")
async def get_active_intrusion_sets(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Active intrusion sets ranked by MITRE usage relationships."""
    try:
        await _set_statement_timeout(db)
        result = await db.execute(
            select(MitreGroup.stix_id, MitreGroup.name, func.count())
            .select_from(
                mitre_relationships.join(
                    MitreGroup, mitre_relationships.c.source_ref == MitreGroup.stix_id
                )
            )
            .where(mitre_relationships.c.relationship_type == "uses")
            .group_by(MitreGroup.stix_id, MitreGroup.name)
            .order_by(desc(func.count()))
            .limit(limit)
        )
        return {
            "data": [
                {"id": row[0], "name": row[1], "count": row[2]}
                for row in result.all()
                if row[1]
            ]
        }
    except Exception as exc:
        logger.error(f"Dashboard intrusion sets failed: {exc}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/active-malware")
async def get_active_malware(
    limit: int = Query(12, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Active malware families from MITRE usage relationships."""
    try:
        await _set_statement_timeout(db)
        result = await db.execute(
            select(MitreSoftware.name, func.count())
            .select_from(
                mitre_relationships.join(
                    MitreSoftware, mitre_relationships.c.target_ref == MitreSoftware.stix_id
                )
            )
            .where(mitre_relationships.c.relationship_type == "uses")
            .where(MitreSoftware.is_malware.is_(True))
            .group_by(MitreSoftware.name)
            .order_by(desc(func.count()))
            .limit(limit)
        )
        rows = result.all()
        total = sum(row[1] for row in rows)
        return {
            "data": [
                {
                    "name": row[0],
                    "count": row[1],
                    "percentage": round((row[1] / total) * 100, 1) if total else 0,
                }
                for row in rows
                if row[0]
            ]
        }
    except Exception as exc:
        logger.error(f"Dashboard malware failed: {exc}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/targeted-sectors")
async def get_targeted_sectors(db: AsyncSession = Depends(get_db)):
    """Targeted sectors derived from STIX labels."""
    try:
        sector_keywords = {
            "finance": "Finance",
            "energy": "Energy",
            "transport": "Transport",
            "government": "Government",
            "administration": "Administration",
            "health": "Health",
            "healthcare": "Healthcare",
            "technology": "Technology",
            "education": "Education",
            "retail": "Retail",
            "manufacturing": "Manufacturing",
            "telecommunications": "Telecommunications",
            "defense": "Defense",
        }
        counts = {name: 0 for name in sector_keywords.values()}
        iocs = await ioc_crud.get_iocs(db, skip=0, limit=3000, order_by="created_at", order_desc=True)
        for ioc in iocs:
            if not ioc.tags:
                continue
            tags = [t.strip().lower() for t in ioc.tags.split(",")]
            for key, label in sector_keywords.items():
                if key in tags:
                    counts[label] += 1
        data = [{"sector": k, "count": v} for k, v in counts.items() if v > 0]
        data.sort(key=lambda x: x["count"], reverse=True)
        return {"data": data}
    except Exception as exc:
        logger.error(f"Dashboard sectors failed: {exc}")
        return {"data": []}


@router.get("/timeline")
async def get_timeline(
    days: int = Query(30, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
):
    """Daily IOC timeline."""
    try:
        fallback = await ioc_crud.get_ioc_timeline(db, days=days, group_by_type=False)
        return {"data": fallback}
    except Exception as exc:
        logger.error(f"Dashboard timeline failed: {exc}")
        return {"data": []}


@router.get("/active-vulnerabilities")
async def get_active_vulnerabilities(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Most referenced CVEs from IOC tags."""
    try:
        return {"data": await _ioc_top_cves(db, limit=limit)}
    except Exception as exc:
        logger.error(f"Dashboard vulnerabilities failed: {exc}")
        return {"data": []}


@router.get("/active-tools")
async def get_active_tools(
    limit: int = Query(12, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Active attack tools from MITRE usage relationships."""
    try:
        await _set_statement_timeout(db)
        result = await db.execute(
            select(MitreSoftware.name, func.count())
            .select_from(
                mitre_relationships.join(
                    MitreSoftware, mitre_relationships.c.target_ref == MitreSoftware.stix_id
                )
            )
            .where(mitre_relationships.c.relationship_type == "uses")
            .where(MitreSoftware.is_malware.is_(False))
            .group_by(MitreSoftware.name)
            .order_by(desc(func.count()))
            .limit(limit)
        )
        rows = result.all()
        total = sum(row[1] for row in rows)
        return {
            "data": [
                {
                    "name": row[0],
                    "count": row[1],
                    "percentage": round((row[1] / total) * 100, 1) if total else 0,
                }
                for row in rows
                if row[0]
            ]
        }
    except Exception as exc:
        logger.error(f"Dashboard tools failed: {exc}")
        return {"data": []}


@router.get("/active-ttps")
async def get_active_ttps(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Top TTPs from MITRE technique usage."""
    try:
        await _set_statement_timeout(db)
        result = await db.execute(
            select(MitreTechnique.external_id, func.count())
            .select_from(
                mitre_relationships.join(
                    MitreTechnique, mitre_relationships.c.target_ref == MitreTechnique.stix_id
                )
            )
            .where(mitre_relationships.c.relationship_type == "uses")
            .where(MitreTechnique.external_id.isnot(None))
            .group_by(MitreTechnique.external_id)
            .order_by(desc(func.count()))
            .limit(limit)
        )
        return {
            "data": [
                {"ttp": row[0], "count": row[1]}
                for row in result.all()
                if row[0]
            ]
        }
    except Exception as exc:
        logger.error(f"Dashboard TTPs failed: {exc}")
        return {"data": []}


@router.get("/most-active-threats")
async def get_most_active_threats(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Most active threats (groups + malware/tools) based on MITRE usage."""
    try:
        await _set_statement_timeout(db)
        group_result = await db.execute(
            select(MitreGroup.stix_id, MitreGroup.name, func.count().label("count"))
            .select_from(
                mitre_relationships.join(
                    MitreGroup, mitre_relationships.c.source_ref == MitreGroup.stix_id
                )
            )
            .where(mitre_relationships.c.relationship_type == "uses")
            .group_by(MitreGroup.stix_id, MitreGroup.name)
            .order_by(desc(func.count()))
            .limit(limit)
        )
        groups = [
            {"id": row.stix_id, "name": row.name, "type": "group", "count": row.count}
            for row in group_result.all()
            if row.name
        ]

        software_result = await db.execute(
            select(
                MitreSoftware.stix_id,
                MitreSoftware.name,
                MitreSoftware.is_malware,
                func.count().label("count"),
            )
            .select_from(
                mitre_relationships.join(
                    MitreSoftware, mitre_relationships.c.source_ref == MitreSoftware.stix_id
                )
            )
            .where(mitre_relationships.c.relationship_type == "uses")
            .group_by(MitreSoftware.stix_id, MitreSoftware.name, MitreSoftware.is_malware)
            .order_by(desc(func.count()))
            .limit(limit)
        )
        software = [
            {
                "id": row.stix_id,
                "name": row.name,
                "type": "malware" if row.is_malware else "tool",
                "count": row.count,
            }
            for row in software_result.all()
            if row.name
        ]

        combined = sorted(groups + software, key=lambda item: item["count"], reverse=True)
        return {"data": combined[:limit]}
    except Exception as exc:
        logger.error(f"Dashboard active threats failed: {exc}")
        return {"data": []}


@router.get("/indicator-sources")
async def get_indicator_sources(db: AsyncSession = Depends(get_db)):
    """Indicators grouped by source connector."""
    try:
        sources = await ioc_crud.get_iocs_by_source(db)
        return {
            "data": [{"source": source, "count": count} for source, count in sources.items()]
        }
    except Exception as exc:
        logger.error(f"Dashboard sources failed: {exc}")
        return {"data": []}


@router.get("/latest-campaigns")
async def get_latest_campaigns(
    limit: int = Query(5, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
):
    """Recent campaign activity."""
    try:
        iocs = await ioc_crud.get_iocs(
            db,
            skip=0,
            limit=limit,
            order_by="created_at",
            order_desc=True,
        )
        return {
            "data": [
                {
                    "id": ioc.id,
                    "name": ioc.value,
                    "description": ioc.notes or "",
                    "modified": ioc.created_at.isoformat() if ioc.created_at else None,
                }
                for ioc in iocs
            ]
        }
    except Exception as exc:
        logger.error(f"Dashboard campaigns failed: {exc}")
        return {"data": []}


@router.get("/recent-reports")
async def get_recent_reports(
    limit: int = Query(8, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Recent threat reports (fallback to indicators)."""
    try:
        iocs = await ioc_crud.get_iocs(
            db,
            skip=0,
            limit=limit,
            order_by="created_at",
            order_desc=True,
        )
        return {
            "data": [
                {
                    "id": ioc.id,
                    "title": ioc.value or "IOC report",
                    "date": ioc.created_at.isoformat() if ioc.created_at else None,
                    "source": ioc.source or "Unknown",
                    "labels": _safe_labels(ioc.tags.split(",") if ioc.tags else []),
                    "confidence": ioc.confidence or 50,
                }
                for ioc in iocs
            ]
        }
    except Exception as exc:
        logger.error(f"Dashboard reports failed: {exc}")
        return {"data": []}
