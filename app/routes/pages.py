"""
Cyber Atlas - HTML Page Routes

Serve static entity detail pages for clean URLs.
"""

from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import FileResponse


router = APIRouter(tags=["Pages"])

BASE_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = BASE_DIR / "frontend_static"


def _page(path: str) -> FileResponse:
    return FileResponse(FRONTEND_DIR / path)


@router.get("/cves/{cve_id}")
async def cve_detail_page(cve_id: str):
    return _page("cve-detail.html")


@router.get("/threats/{threat_id}")
async def threat_detail_page(threat_id: str):
    return _page("threat-detail.html")


@router.get("/indicators/domain/{domain}")
async def domain_detail_page(domain: str):
    return _page("domain-detail.html")


@router.get("/indicators/ip/{ip_value}")
async def ip_detail_page(ip_value: str):
    return _page("domain-detail.html")


@router.get("/indicators/url/{url_value}")
async def url_detail_page(url_value: str):
    return _page("domain-detail.html")
