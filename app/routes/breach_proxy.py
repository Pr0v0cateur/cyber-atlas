"""
Cyber Atlas - Breach Proxy Route

Proxies breach checks to an external service (default: local Flask scraper).
"""

import os
from typing import Any, Dict, Optional
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.logging import logger
from app.routes.auth import get_current_active_user


BREACH_SERVICE_URL = os.getenv("BREACH_SERVICE_URL")

router = APIRouter(
    prefix="/api/breach",
    tags=["Breach"],
    dependencies=[Depends(get_current_active_user)],
)


def _extract_breaches(payload: Dict[str, Any]) -> Any:
    breaches: Any = payload.get("Breaches")
    if breaches is None:
        breaches = payload.get("breaches")
    if breaches is None and isinstance(payload.get("BreachSearch"), dict):
        breaches = payload["BreachSearch"].get("Breaches") or payload["BreachSearch"].get("breaches")
    return breaches


def _normalize_breaches(payload: Dict[str, Any]) -> Dict[str, Any]:
    breaches: Any = _extract_breaches(payload)

    if breaches is None:
        breaches = []

    if isinstance(breaches, list) and breaches and isinstance(breaches[0], str):
        payload["Breaches"] = [
            {
                "Name": item,
                "Title": item,
                "BreachDate": None,
                "Description": "",
                "LogoPath": "",
                "DataClasses": [],
                "IsVerified": False,
                "PwnCount": None,
            }
            for item in breaches
        ]
    elif isinstance(breaches, list):
        payload["Breaches"] = breaches
    else:
        payload["Breaches"] = []

    return payload


async def _fetch_external(email: str) -> Dict[str, Any]:
    if not BREACH_SERVICE_URL:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Breach service is not configured. Set BREACH_SERVICE_URL.",
        )

    url = BREACH_SERVICE_URL
    method = "POST"
    json_payload: Optional[Dict[str, Any]] = {"email": email}
    if "{email}" in url:
        url = url.format(email=quote(email))
        method = "GET"
        json_payload = None

    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            response = await client.request(
                method,
                url,
                json=json_payload,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "CyberAtlas/1.0 (+https://cyberatlas.local)",
                },
            )
    except httpx.RequestError as exc:
        logger.error(f"Breach service unreachable: {exc}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Breach service is unavailable.",
        )

    try:
        data = response.json()
    except ValueError:
        data = {}

    if response.status_code >= 400:
        logger.error(f"Breach service error {response.status_code}: {data}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=data.get("error") or "Breach service error.",
        )

    normalized = _normalize_breaches(data or {})
    normalized.setdefault("Breaches", [])
    return normalized


@router.get("/check")
async def breach_check(email: str = Query(...)):
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required.",
        )

    return await _fetch_external(email)


@router.post("/check")
async def breach_check_post(payload: Dict[str, Any]):
    email = payload.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required.",
        )

    return await _fetch_external(email)
