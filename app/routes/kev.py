"""
Cyber Atlas - CISA KEV (Known Exploited Vulnerabilities) Routes

Fetches and normalizes the KEV catalog for frontend use.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.logging import logger
from app.routes.auth import get_current_active_user


KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
KEV_CACHE_TTL_SECONDS = 6 * 60 * 60

_kev_cache: dict[str, Any] = {"ts": None, "data": None}
_kev_lock = asyncio.Lock()


router = APIRouter(
    prefix="/api/kev",
    tags=["KEV"],
    dependencies=[Depends(get_current_active_user)],
)


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _kev_score(entry: dict[str, Any]) -> int:
    text = " ".join(
        part
        for part in [
            entry.get("vulnerabilityName", ""),
            entry.get("shortDescription", ""),
            entry.get("notes", ""),
            entry.get("requiredAction", ""),
        ]
        if part
    ).lower()

    score = 0
    ransomware = str(entry.get("knownRansomwareCampaignUse", "")).lower()
    if ransomware == "known":
        score += 120

    if "remote code execution" in text or " rce " in f" {text} ":
        score += 35
    if "privilege escalation" in text:
        score += 25
    if "auth bypass" in text or "authentication bypass" in text:
        score += 20
    if "command injection" in text:
        score += 20
    if "sql injection" in text or "sqli" in text:
        score += 15
    if "buffer overflow" in text:
        score += 10
    if "deserialization" in text:
        score += 10
    if "path traversal" in text or "directory traversal" in text:
        score += 10

    return score


def _normalize(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    cve = entry.get("cveID")
    if not cve:
        return None

    date_added = entry.get("dateAdded")
    date_dt = _parse_date(date_added)

    normalized = {
        "cve": cve,
        "vendor": entry.get("vendorProject"),
        "product": entry.get("product"),
        "name": entry.get("vulnerabilityName"),
        "date_added": date_added,
        "due_date": entry.get("dueDate"),
        "ransomware": entry.get("knownRansomwareCampaignUse"),
        "notes": entry.get("notes"),
        "description": entry.get("shortDescription") or entry.get("vulnerabilityName"),
        "critical_score": _kev_score(entry),
        "_date_added": date_dt,
    }
    return normalized


async def _fetch_kev_feed() -> dict[str, Any]:
    headers = {
        "User-Agent": "CyberAtlas-KEV/1.0",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        response = await client.get(KEV_FEED_URL, headers=headers)
        response.raise_for_status()
        return response.json()


async def _get_kev_feed() -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    cached_ts = _kev_cache.get("ts")
    if cached_ts and _kev_cache.get("data"):
        age = (now - cached_ts).total_seconds()
        if age < KEV_CACHE_TTL_SECONDS:
            return _kev_cache["data"]

    async with _kev_lock:
        cached_ts = _kev_cache.get("ts")
        if cached_ts and _kev_cache.get("data"):
            age = (now - cached_ts).total_seconds()
            if age < KEV_CACHE_TTL_SECONDS:
                return _kev_cache["data"]

        try:
            data = await _fetch_kev_feed()
            _kev_cache["data"] = data
            _kev_cache["ts"] = now
            return data
        except Exception as exc:
            logger.error(f"KEV feed fetch failed: {exc}")
            if _kev_cache.get("data"):
                logger.warning("Using stale KEV cache after fetch failure.")
                return _kev_cache["data"]
            raise HTTPException(status_code=502, detail="KEV feed unavailable") from exc


@router.get("/cves")
async def list_kev_cves(
    sort: str = Query("latest", pattern="^(latest|critical)$"),
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """
    Return KEV CVEs.
    sort=latest -> date_added desc
    sort=critical -> last N days, critical_score desc
    """
    try:
        feed = await _get_kev_feed()
        raw_items = feed.get("vulnerabilities", [])

        normalized: list[dict[str, Any]] = []
        for entry in raw_items:
            item = _normalize(entry)
            if item:
                normalized.append(item)

        now = datetime.now(timezone.utc)
        if sort == "critical":
            cutoff = now - timedelta(days=days)
            filtered = [
                item
                for item in normalized
                if item["_date_added"] and item["_date_added"] >= cutoff
            ]
            filtered.sort(
                key=lambda item: (item["critical_score"], item["_date_added"]),
                reverse=True,
            )
            available = len(filtered)
            items = filtered[offset:offset + limit]
        else:
            normalized.sort(
                key=lambda item: item["_date_added"] or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            available = len(normalized)
            items = normalized[offset:offset + limit]

        for item in items:
            item.pop("_date_added", None)

        return {
            "data": items,
            "meta": {
                "available": available,
                "returned": len(items),
                "sort": sort,
                "days": days if sort == "critical" else None,
                "limit": limit,
                "offset": offset,
            },
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"KEV list failed: {exc}")
        raise HTTPException(status_code=500, detail="Internal server error") from exc
