"""
Cyber Atlas - Search Routes

IOC search and retrieval endpoints.
"""

import re
import ipaddress
from typing import Optional, List, Dict, Any
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.logging import logger
from app.routes.auth import get_current_active_user
from app.models.user import User
from app.models.ioc import IOC
from app.models.mitre import MitreGroup, MitreSoftware
from app.models.stix_object import STIXObject
from app.crud import iocs as ioc_crud
from app.schemas.ioc import (
    IOCResponse,
    IOCListResponse,
    IOCSearchParams,
    IOCCreate,
    IOCUpdate,
    IOCBulkCreate,
    IOCBulkResponse,
)
from app.middleware.ratelimit import rate_limiter, search_rate_limit


router = APIRouter(prefix="/api/search", tags=["IOC Search"])

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
HASH_PATTERN = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


@router.get("/iocs", response_model=IOCListResponse)
@rate_limiter.limit(search_rate_limit)
async def search_iocs(
    request: Request,  # Required by slowapi for rate limiting
    response: Response,  # Required by slowapi
    q: Optional[str] = Query(None, max_length=512, description="Search query"),
    type: Optional[str] = Query(None, description="IOC type filter"),
    source: Optional[str] = Query(None, description="Source filter"),
    country: Optional[str] = Query(None, max_length=8, description="Country code filter"),
    risk_min: Optional[int] = Query(None, ge=1, le=10, description="Minimum risk score"),
    risk_max: Optional[int] = Query(None, ge=1, le=10, description="Maximum risk score"),
    malware_family: Optional[str] = Query(None, description="Malware family filter"),
    first_seen_after: Optional[datetime] = Query(None, description="First seen after"),
    first_seen_before: Optional[datetime] = Query(None, description="First seen before"),
    last_seen_after: Optional[datetime] = Query(None, description="Last seen after"),
    last_seen_before: Optional[datetime] = Query(None, description="Last seen before"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    sort_by: str = Query("last_seen", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order (asc/desc)"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Search IOCs with filters and pagination.
    
    Supports filtering by:
    - **q**: Full-text search across value, notes, tags, and malware family
    - **type**: IOC type (ip, cidr, domain, url, hash, email)
    - **source**: Threat feed source name
    - **country**: ISO country code
    - **risk_min/risk_max**: Risk score range
    - **malware_family**: Associated malware family
    - **first_seen_after/before**: First observation date range
    - **last_seen_after/before**: Last observation date range
    
    Pagination:
    - **page**: Page number (1-indexed)
    - **page_size**: Items per page (max 100)
    
    Sorting:
    - **sort_by**: Field to sort by (default: last_seen)
    - **sort_order**: asc or desc (default: desc)
    """
    # Validate sort order
    if sort_order not in ["asc", "desc"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="sort_order must be 'asc' or 'desc'",
        )
    
    # Validate type
    valid_types = ["ip", "cidr", "domain", "url", "hash", "email"]
    if type and type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid type. Must be one of: {valid_types}",
        )
    
    # Build search params
    params = IOCSearchParams(
        q=q,
        type=type,
        source=source,
        country=country,
        risk_min=risk_min,
        risk_max=risk_max,
        malware_family=malware_family,
        first_seen_after=first_seen_after,
        first_seen_before=first_seen_before,
        last_seen_after=last_seen_after,
        last_seen_before=last_seen_before,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    
    # Execute search
    iocs, total = await ioc_crud.search_iocs(db, params)
    
    # Calculate pagination info
    pages = (total + page_size - 1) // page_size if total > 0 else 0
    
    return IOCListResponse(
        items=[IOCResponse.model_validate(ioc) for ioc in iocs],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/iocs/{ioc_id}", response_model=IOCResponse)
async def get_ioc(
    ioc_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get a single IOC by ID.
    """
    ioc = await ioc_crud.get_ioc(db, ioc_id)
    
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found",
        )
    
    return IOCResponse.model_validate(ioc)


@router.post("/iocs", response_model=IOCResponse, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    ioc_data: IOCCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new IOC manually.
    
    Required fields:
    - **type**: IOC type (ip, cidr, domain, url, hash, email)
    - **value**: The IOC value
    - **source**: Source name (e.g., "manual", "internal")
    
    Optional fields:
    - **risk**: Risk score (1-10)
    - **country**: ISO country code
    - **notes**: Additional notes
    - **tags**: List of tags
    - **malware_family**: Associated malware family
    - **confidence**: Confidence level (1-100)
    """
    # Check for duplicate
    existing = await ioc_crud.check_ioc_exists(
        db,
        ioc_type=ioc_data.type,
        value=ioc_data.value,
        source=ioc_data.source,
    )
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"IOC already exists with ID: {existing.id}",
        )
    
    ioc = await ioc_crud.create_ioc(db, ioc_data)
    await db.commit()
    
    logger.info(f"IOC created manually by {current_user.email}: {ioc.type}:{ioc.value}")
    
    return IOCResponse.model_validate(ioc)


@router.post("/iocs/bulk", response_model=IOCBulkResponse, status_code=status.HTTP_201_CREATED)
async def create_iocs_bulk(
    bulk_data: IOCBulkCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create multiple IOCs in bulk.
    
    - **iocs**: List of IOC objects to create (max 1000)
    - **skip_duplicates**: If true, skip duplicates instead of erroring (default: true)
    """
    if not current_user.is_admin and len(bulk_data.iocs) > 100:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Non-admin users can only create up to 100 IOCs at once",
        )
    
    created, skipped, errors = await ioc_crud.create_iocs_bulk(
        db,
        bulk_data.iocs,
        skip_duplicates=bulk_data.skip_duplicates,
    )
    
    logger.info(
        f"Bulk IOC create by {current_user.email}: "
        f"{created} created, {skipped} skipped, {errors} errors"
    )
    
    return IOCBulkResponse(
        created=created,
        skipped=skipped,
        errors=errors,
    )


@router.put("/iocs/{ioc_id}", response_model=IOCResponse)
async def update_ioc(
    ioc_id: int,
    ioc_data: IOCUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update an existing IOC.
    
    Only the provided fields will be updated.
    """
    ioc = await ioc_crud.update_ioc(db, ioc_id, ioc_data)
    
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found",
        )
    
    await db.commit()
    
    logger.info(f"IOC {ioc_id} updated by {current_user.email}")
    
    return IOCResponse.model_validate(ioc)


@router.delete("/iocs/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ioc(
    ioc_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete an IOC (admin only).
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to delete IOCs",
        )
    
    success = await ioc_crud.delete_ioc(db, ioc_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IOC not found",
        )
    
    await db.commit()
    
    logger.info(f"IOC {ioc_id} deleted by {current_user.email}")


@router.get("/types")
async def get_ioc_types(
    current_user: User = Depends(get_current_active_user),
):
    """
    Get list of valid IOC types.
    """
    return {
        "types": [
            {"name": "ip", "description": "IPv4 or IPv6 address"},
            {"name": "cidr", "description": "CIDR notation IP range"},
            {"name": "domain", "description": "Domain name"},
            {"name": "url", "description": "Full URL"},
            {"name": "hash", "description": "File hash (MD5, SHA1, SHA256)"},
            {"name": "email", "description": "Email address"},
        ]
    }


@router.get("/suggest")
@rate_limiter.limit(search_rate_limit)
async def suggest_search(
    request: Request,
    response: Response,
    q: str = Query(..., min_length=2, max_length=200, description="Search query"),
    limit: int = Query(6, ge=1, le=20, description="Suggestions per type"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Autocomplete suggestions grouped by type."""
    query = q.strip()
    if not query:
        return {"query": q, "groups": {}}

    cve_results = []
    threat_results = []
    domain_results = []
    ip_results = []
    url_results = []

    if len(query) >= 3:
        tag_result = await db.execute(
            select(IOC.tags)
            .where(IOC.tags.isnot(None))
            .where(IOC.tags.ilike(f"%{query}%"))
            .limit(limit * 5)
        )
        cve_set = set()
        for tags in tag_result.scalars().all():
            for entry in (tags or "").split(","):
                entry = entry.strip().upper()
                if not entry:
                    continue
                if CVE_PATTERN.match(entry) and query.upper() in entry:
                    cve_set.add(entry)
        cve_results = [{"id": cve} for cve in sorted(cve_set)[:limit]]

    group_result = await db.execute(
        select(MitreGroup.stix_id, MitreGroup.name)
        .where(MitreGroup.name.ilike(f"%{query}%"))
        .order_by(MitreGroup.name.asc())
        .limit(limit)
    )
    threat_results.extend(
        [
            {"id": row.stix_id, "name": row.name, "type": "group"}
            for row in group_result.all()
            if row.name
        ]
    )

    software_result = await db.execute(
        select(MitreSoftware.stix_id, MitreSoftware.name, MitreSoftware.is_malware)
        .where(MitreSoftware.name.ilike(f"%{query}%"))
        .order_by(MitreSoftware.name.asc())
        .limit(limit)
    )
    threat_results.extend(
        [
            {
                "id": row.stix_id,
                "name": row.name,
                "type": "malware" if row.is_malware else "tool",
            }
            for row in software_result.all()
            if row.name
        ]
    )

    domain_result = await db.execute(
        select(STIXObject.observable_value)
        .where(STIXObject.observable_type == "domain-name")
        .where(STIXObject.observable_value.isnot(None))
        .where(STIXObject.observable_value.ilike(f"%{query}%"))
        .order_by(STIXObject.observable_value.asc())
        .limit(limit)
    )
    domain_results = [{"value": value} for value in domain_result.scalars().all()]

    ip_result = await db.execute(
        select(STIXObject.observable_value)
        .where(STIXObject.observable_type.in_(["ipv4-addr", "ipv6-addr"]))
        .where(STIXObject.observable_value.isnot(None))
        .where(STIXObject.observable_value.ilike(f"{query}%"))
        .order_by(STIXObject.observable_value.asc())
        .limit(limit)
    )
    ip_results = [{"value": value} for value in ip_result.scalars().all()]

    url_result = await db.execute(
        select(STIXObject.observable_value)
        .where(STIXObject.observable_type == "url")
        .where(STIXObject.observable_value.isnot(None))
        .where(STIXObject.observable_value.ilike(f"%{query}%"))
        .order_by(STIXObject.observable_value.asc())
        .limit(limit)
    )
    url_results = [{"value": value} for value in url_result.scalars().all()]

    return {
        "query": query,
        "groups": {
            "cve": cve_results,
            "threat": threat_results,
            "domain": domain_results,
            "ip": ip_results,
            "url": url_results,
        },
    }


@router.get("/cve/{cve_id}")
@rate_limiter.limit(search_rate_limit)
async def lookup_cve(
    request: Request,
    response: Response,
    cve_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """
    Lookup CVE record details from CVE Services API.
    """
    normalized = cve_id.strip().upper()
    if not CVE_PATTERN.match(normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CVE format. Expected CVE-YYYY-NNNN",
        )

    details = await fetch_cve_details(normalized)
    if not details:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CVE not found",
        )

    return {
        "query": normalized,
        "found": True,
        "type": "cve",
        "cve": details,
    }


@router.get("/hash/{hash_value}")
@rate_limiter.limit(search_rate_limit)
async def lookup_hash(
    request: Request,
    response: Response,
    hash_value: str,
    current_user: User = Depends(get_current_active_user),
):
    """
    Lookup hash intelligence from VirusTotal or OTX.
    """
    normalized = hash_value.strip()
    if not HASH_PATTERN.match(normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hash format. Expected MD5, SHA1, or SHA256",
        )

    details = await fetch_hash_details(normalized)
    if not details:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Hash not found",
        )

    return {
        "query": normalized,
        "found": True,
        "type": "hash",
        "hash": details,
    }


@router.get("/lookup/{value}")
async def quick_lookup(
    value: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Quick lookup for an IOC value.
    
    Searches across all IOC types for the given value.
    Returns matching IOCs from all sources.
    """
    params = IOCSearchParams(
        q=value,
        page=1,
        page_size=50,
        sort_by="last_seen",
        sort_order="desc",
    )
    
    iocs, total = await ioc_crud.search_iocs(db, params)

    ip_enrichment = None
    if _is_ip_address(value):
        ip_enrichment = await fetch_ip_api_details(value)

    payload = {
        "query": value,
        "found": total > 0,
        "count": total,
        "results": [IOCResponse.model_validate(ioc) for ioc in iocs],
    }
    if ip_enrichment:
        payload["enrichment"] = {"ip_api": ip_enrichment}

    return payload


def _infer_ip_usage(payload: Dict[str, Any]) -> str:
    if payload.get("hosting") is True:
        return "Hosting"
    if payload.get("proxy") is True:
        return "Proxy"
    if payload.get("mobile") is True:
        return "Mobile"
    return "Unknown"


async def fetch_ip_api_details(ip_address: str) -> Optional[Dict[str, Any]]:
    if not settings.ipapi_base_url:
        return None

    url = f"{settings.ipapi_base_url.rstrip('/')}/{ip_address}"
    params: Dict[str, Any] = {}
    if settings.ipapi_fields:
        params["fields"] = settings.ipapi_fields

    timeout_seconds = settings.ipapi_timeout_seconds
    timeout = httpx.Timeout(timeout_seconds, connect=min(5.0, timeout_seconds))

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, params=params)
    except httpx.HTTPError as exc:
        logger.warning(f"IP-API request failed for {ip_address}: {exc}")
        return None

    if response.status_code == 404:
        return None
    if response.status_code == 429:
        logger.warning("IP-API rate limit reached")
        return None

    response.raise_for_status()
    payload = response.json() or {}

    if payload.get("status") != "success":
        message = payload.get("message") or "Unknown error"
        logger.info(f"IP-API lookup failed for {ip_address}: {message}")
        return None

    as_text = payload.get("as") or ""
    asn = None
    as_name = payload.get("asname")
    if as_text.startswith("AS"):
        parts = as_text.split(" ", 1)
        asn = parts[0]
        if not as_name and len(parts) > 1:
            as_name = parts[1]

    return {
        "query": payload.get("query") or ip_address,
        "country": payload.get("country"),
        "country_code": payload.get("countryCode"),
        "region": payload.get("regionName") or payload.get("region"),
        "city": payload.get("city"),
        "zip": payload.get("zip"),
        "timezone": payload.get("timezone"),
        "isp": payload.get("isp") or payload.get("org"),
        "org": payload.get("org"),
        "asn": asn,
        "as_name": as_name,
        "as_raw": as_text or None,
        "lat": payload.get("lat"),
        "lon": payload.get("lon"),
        "reverse": payload.get("reverse"),
        "mobile": payload.get("mobile") is True,
        "proxy": payload.get("proxy") is True,
        "hosting": payload.get("hosting") is True,
        "usage": _infer_ip_usage(payload),
    }


async def fetch_cve_details(cve_id: str) -> Optional[Dict[str, Any]]:
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    timeout = httpx.Timeout(10.0, connect=5.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url)

    if response.status_code == 404:
        return None
    response.raise_for_status()

    payload = response.json()
    meta = payload.get("cveMetadata", {})
    containers = payload.get("containers", {})
    cna = containers.get("cna", {})

    cna_name = (
        cna.get("providerMetadata", {}).get("shortName")
        or meta.get("assignerShortName")
        or "Unknown"
    )

    description = _pick_description(cna.get("descriptions", []))
    cvss = _extract_cvss(cna.get("metrics", [])) or _extract_cvss_from_adp(containers.get("adp", []))

    affected_items = []
    for item in cna.get("affected", []) or []:
        affected_items.append(
            {
                "vendor": item.get("vendor"),
                "product": item.get("product"),
                "versions": _format_versions(item.get("versions", [])),
                "default_status": item.get("defaultStatus"),
            }
        )

    references = [ref.get("url") for ref in cna.get("references", []) if ref.get("url")]

    return {
        "id": meta.get("cveId", cve_id),
        "title": cna.get("title") or meta.get("cveId"),
        "cna": cna_name,
        "published": meta.get("datePublished") or meta.get("dateReserved"),
        "updated": meta.get("dateUpdated"),
        "description": description,
        "cvss": cvss or {},
        "affected": affected_items,
        "references": references,
    }


async def fetch_hash_details(hash_value: str) -> Optional[Dict[str, Any]]:
    if settings.virustotal_key:
        try:
            vt_data = await fetch_hash_from_virustotal(hash_value)
            if vt_data:
                return vt_data
            if not settings.otx_key:
                return None
        except HTTPException:
            if not settings.otx_key:
                raise

    if settings.otx_key:
        return await fetch_hash_from_otx(hash_value)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="No hash intelligence provider configured",
    )


async def fetch_hash_from_virustotal(hash_value: str) -> Optional[Dict[str, Any]]:
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    timeout = httpx.Timeout(15.0, connect=5.0)
    headers = {"x-apikey": settings.virustotal_key}

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 404:
        return None
    if response.status_code in {401, 403}:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="VirusTotal API key rejected",
        )
    response.raise_for_status()

    payload = response.json()
    attributes = payload.get("data", {}).get("attributes", {})

    stats = attributes.get("last_analysis_stats", {}) or {}
    detected = int(stats.get("malicious", 0) + stats.get("suspicious", 0))
    total = int(sum(stats.values())) if stats else 0

    vendors = []
    for vendor, result in (attributes.get("last_analysis_results") or {}).items():
        if not isinstance(result, dict):
            continue
        vendors.append(
            {
                "vendor": vendor,
                "category": result.get("category") or "undetected",
                "result": result.get("result") or "Clean",
            }
        )

    popular = attributes.get("popular_threat_classification", {}) or {}
    threat_categories = [
        item.get("value")
        for item in popular.get("popular_threat_category", [])
        if item.get("value")
    ]
    family_labels = [
        item.get("value")
        for item in popular.get("popular_threat_name", [])
        if item.get("value")
    ]

    return {
        "source": "virustotal",
        "value": hash_value,
        "detected": detected,
        "total": total,
        "stats": stats,
        "size": attributes.get("size"),
        "file_type": attributes.get("type_description") or attributes.get("type_extension"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "first_submission_date": attributes.get("first_submission_date"),
        "reputation": attributes.get("reputation"),
        "tags": attributes.get("tags") or [],
        "popular_threat_label": popular.get("suggested_threat_label"),
        "threat_categories": threat_categories,
        "family_labels": family_labels,
        "vendors": vendors,
    }


async def fetch_hash_from_otx(hash_value: str) -> Optional[Dict[str, Any]]:
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/analysis"
    timeout = httpx.Timeout(15.0, connect=5.0)
    headers = {"X-OTX-API-KEY": settings.otx_key}

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 404:
        return None
    response.raise_for_status()

    payload = response.json()
    analysis = payload.get("analysis", {}) or {}
    info = analysis.get("info", {}).get("results", {}) or {}
    plugins = analysis.get("plugins", {}) or {}

    vendors, detected, total, tags = _extract_otx_vendors(plugins)

    return {
        "source": "otx",
        "value": hash_value,
        "detected": detected,
        "total": total,
        "stats": {"malicious": detected, "undetected": max(total - detected, 0)},
        "size": info.get("filesize"),
        "file_type": info.get("file_type") or analysis.get("page_type"),
        "last_analysis_date": analysis.get("datetime_int"),
        "tags": tags,
        "vendors": vendors,
    }


def _pick_description(descriptions: List[Dict[str, Any]]) -> str:
    for item in descriptions or []:
        if item.get("lang") == "en" and item.get("value"):
            return item["value"]
    if descriptions:
        return descriptions[0].get("value") or ""
    return ""


def _extract_cvss(metrics_list: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for metric in metrics_list or []:
        if not isinstance(metric, dict):
            continue
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            data = metric.get(key)
            if isinstance(data, dict):
                return {
                    "score": data.get("baseScore"),
                    "severity": data.get("baseSeverity"),
                    "version": data.get("version"),
                    "vector": data.get("vectorString"),
                }
    return None


def _extract_cvss_from_adp(adp_list: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for adp in adp_list or []:
        if not isinstance(adp, dict):
            continue
        metrics = adp.get("metrics")
        cvss = _extract_cvss(metrics or [])
        if cvss:
            return cvss
    return None


def _format_versions(versions: List[Dict[str, Any]]) -> List[str]:
    formatted = []
    for entry in versions or []:
        if not isinstance(entry, dict):
            continue
        status = entry.get("status") or "affected"
        version = entry.get("version")
        less_than = entry.get("lessThan") or entry.get("lessThanOrEqual")
        version_type = entry.get("versionType")

        if less_than:
            if version and version != "0":
                text = f"{status} from {version} before {less_than}"
            else:
                text = f"{status} before {less_than}"
        elif version:
            text = f"{status} {version}"
        else:
            text = status

        if version_type:
            text = f"{text} ({version_type})"
        formatted.append(text)
    return formatted


def _extract_otx_vendors(plugins: Dict[str, Any]) -> tuple:
    vendor_map = {
        "msdefender": "Microsoft Defender",
        "avast": "Avast",
        "clamav": "ClamAV",
        "yarad": "YARA",
        "cuckoo": "Cuckoo",
    }

    vendors = []
    detected = 0
    tags = []

    yara_detections = (
        plugins.get("yarad", {})
        .get("results", {})
        .get("detection", [])
    )
    for detection in yara_detections:
        rule_name = detection.get("rule_name")
        if rule_name:
            tags.append(rule_name)

    for key, name in vendor_map.items():
        plugin = plugins.get(key)
        if not plugin:
            continue
        result_text, is_detected = _parse_otx_plugin_results(plugin.get("results"))
        if is_detected:
            detected += 1
        vendors.append(
            {
                "vendor": name,
                "category": "malicious" if is_detected else "undetected",
                "result": result_text or "No detection",
            }
        )

    total = len(vendors)
    return vendors, detected, total, tags


def _parse_otx_plugin_results(results: Any) -> tuple:
    if not results:
        return "", False
    if isinstance(results, dict):
        detections = results.get("detection")
        if isinstance(detections, list) and detections:
            labels = []
            for item in detections:
                if not isinstance(item, dict):
                    continue
                label = item.get("rule_name") or item.get("result")
                if label:
                    labels.append(label)
            if labels:
                return ", ".join(labels), True

        if "result" in results and results.get("result"):
            return str(results.get("result")), True

        if "info" in results and isinstance(results.get("info"), dict):
            score = results["info"].get("combined_score")
            if isinstance(score, (int, float)) and score > 0:
                return f"Score {score}", True
            return "No detection", False

    if isinstance(results, list) and results:
        return str(results[0]), True

    return "", False
