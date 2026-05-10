"""
Cyber Atlas - Threat Feed Collectors

Celery tasks for collecting and processing threat intelligence feeds.
"""

import asyncio
import csv
import io
import re
import zipfile
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception, retry_if_exception_type
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.logging import logger, log_feed_activity
from app.models.ioc import IOC
from app.schemas.ioc import IOCCreate
from app.crud.iocs import create_iocs_bulk
from app.utils_geoip import get_country_code
from app.tasks.celery_app import celery_app
from app.services.connector_manager import STIXConnectorManager


# -----------------------------------------------------------------------------
# Constants & Configuration
# -----------------------------------------------------------------------------
TIMEOUT = float(settings.feed_timeout_seconds)
USER_AGENT = f"CyberAtlas/{settings.app_version} (ThreatIntelPlatform)"
HEADERS = {"User-Agent": USER_AGENT}


# -----------------------------------------------------------------------------
# Base Collection Logic
# -----------------------------------------------------------------------------

def _should_retry(exc: Exception) -> bool:
    if isinstance(exc, (httpx.RequestError, httpx.TimeoutException)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status in {429, 500, 502, 503, 504}
    return False


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=20),
    retry=retry_if_exception(_should_retry),
    reraise=True,
)
async def fetch_url(client: httpx.AsyncClient, url: str, method: str = "GET", **kwargs) -> httpx.Response:
    """Fetch URL with retry logic."""
    response = await client.request(
        method,
        url,
        timeout=TIMEOUT,
        follow_redirects=True,
        **kwargs,
    )
    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                await asyncio.sleep(min(int(retry_after), 60))
            except ValueError:
                pass
    response.raise_for_status()
    return response


async def process_batch(session: AsyncSession, iocs: List[IOCCreate], source: str):
    """Process and save a batch of IOCs."""
    if not iocs:
        return 0, 0, 0
        
    created, skipped, errors = await create_iocs_bulk(session, iocs, skip_duplicates=True)
    return created, skipped, errors


async def _collect_stix_for_source(source_name: str) -> Optional[Dict[str, Any]]:
    source_key = source_name.strip().lower()
    source_map = {
        "urlhaus": "urlhaus",
        "threatfox": "threatfox",
        "alienvault otx": "otx",
    }
    connector_key = source_map.get(source_key)
    if not connector_key:
        return None

    try:
        manager = STIXConnectorManager()
        if connector_key not in manager.connectors:
            return None
        return await manager.collect_selected([connector_key])
    except Exception as exc:
        logger.warning(f"STIX collection failed for {source_name}: {exc}")
        return None


class FeedCollector:
    """Base class/namespace for feed collection logic."""
    
    @staticmethod
    def _normalize_type(raw_type: str) -> str:
        """Map feed-specific types to Cyber Atlas types."""
        type_map = {
            "ip:port": "ip",
            "ip": "ip",
            "ipv4": "ip",
            "ipv6": "ip",
            "domain": "domain",
            "url": "url",
            "sha256": "hash",
            "md5": "hash",
            "sha1": "hash",
            "payload_delivery": "url",
            "payload_url": "url",
        }
        return type_map.get(raw_type.lower(), raw_type.lower())

    @staticmethod
    def _extract_ip(value: str) -> Optional[str]:
        """Extract IP from value if possible (e.g., from ip:port)."""
        # Simple regex for IPv4
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', value)
        if ip_match:
            return ip_match.group(0)
        return None


def truncate_text(value: Optional[str], max_length: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    if len(text) <= max_length:
        return text
    if max_length <= 3:
        return text[:max_length]
    return text[:max_length - 3] + "..."


def limit_tags(tags: Optional[List[Any]], max_length: int = 512) -> List[str]:
    if not tags:
        return []
    cleaned: List[str] = []
    total = 0
    for tag in tags:
        if tag is None:
            continue
        text = str(tag).strip()
        if not text:
            continue
        if len(text) > max_length:
            continue
        extra = len(text) + (1 if cleaned else 0)
        if total + extra > max_length:
            break
        cleaned.append(text)
        total += extra
    return cleaned


# -----------------------------------------------------------------------------
# Individual Feed Collectors
# -----------------------------------------------------------------------------

async def fetch_urlhaus(client: httpx.AsyncClient) -> List[IOCCreate]:
    """
    Collect from URLhaus (CSV Recent).
    Source: https://urlhaus.abuse.ch/downloads/csv_recent/
    """
    feed_map = {
        "recent": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "online": "https://urlhaus.abuse.ch/downloads/csv_online/",
        "full": "https://urlhaus.abuse.ch/downloads/csv/"
    }
    url = feed_map.get(settings.urlhaus_feed, feed_map["recent"])
    response = await fetch_url(client, url)

    content_bytes = response.content
    if content_bytes[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content_bytes)) as zf:
            csv_name = next(
                (name for name in zf.namelist() if name.lower().endswith(".csv")),
                zf.namelist()[0],
            )
            csv_text = zf.read(csv_name).decode("utf-8", errors="replace")
    else:
        csv_text = response.text

    # Skip comments
    content = [line for line in csv_text.splitlines() if not line.startswith("#")]
    reader = csv.reader(content)
    rows = list(reader)

    if not rows:
        return []

    header = [h.strip().lower() for h in rows[0]]
    has_header = "url" in header and "dateadded" in header

    if has_header:
        header_idx = {name: idx for idx, name in enumerate(header)}
        data_rows = rows[1:]
    else:
        header_idx = {
            "id": 0,
            "dateadded": 1,
            "url": 2,
            "url_status": 3,
            "last_online": 4,
            "threat": 5,
            "tags": 6,
            "urlhaus_reference": 7,
            "reporter": 8,
        }
        data_rows = rows

    iocs = []
    for row in data_rows:
        url_idx = header_idx.get("url")
        if url_idx is None or url_idx >= len(row):
            continue

        url_value = row[url_idx].strip()
        if not url_value:
            continue

        date_idx = header_idx.get("dateadded")
        date_value = row[date_idx].strip() if date_idx is not None and date_idx < len(row) else ""

        # Parse date
        try:
            first_seen = datetime.strptime(date_value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            first_seen = datetime.now(timezone.utc)

        if len(url_value) > 512:
            continue

        tags_idx = header_idx.get("tags")
        tags_value = row[tags_idx].strip() if tags_idx is not None and tags_idx < len(row) else ""

        threat_idx = header_idx.get("threat")
        threat_value = row[threat_idx].strip() if threat_idx is not None and threat_idx < len(row) else ""

        status_idx = header_idx.get("url_status")
        status_value = row[status_idx].strip() if status_idx is not None and status_idx < len(row) else ""

        tags_list = [t.strip() for t in tags_value.split(",") if t.strip()] if tags_value else []
        if len(",".join(tags_list)) > 512:
            tags_list = []

        notes_value = f"Threat: {threat_value}; Status: {status_value}"
        if len(notes_value) > 1024:
            notes_value = notes_value[:1021] + "..."

        raw_value = str(row)
        if len(raw_value) > 4000:
            raw_value = raw_value[:3997] + "..."

        ioc = IOCCreate(
            type="url",
            value=url_value,
            source="URLhaus",
            first_seen=first_seen,
            last_seen=None,  # URLhaus 'recent' implies current
            risk=8,  # High risk by default for URLhaus
            tags=tags_list,
            notes=notes_value,
            raw=raw_value,
        )
        iocs.append(ioc)
    
    return iocs


async def fetch_openphish(client: httpx.AsyncClient) -> List[IOCCreate]:
    """
    Collect from OpenPhish (Text feed).
    Source: https://openphish.com/feed.txt
    """
    url = "https://openphish.com/feed.txt"
    response = await fetch_url(client, url)
    
    iocs = []
    now = datetime.now(timezone.utc)
    
    for line in response.text.splitlines():
        if not line.strip():
            continue
            
        ioc = IOCCreate(
            type="url",
            value=line.strip(),
            source="OpenPhish",
            first_seen=now,
            last_seen=now,
            risk=7,
            tags=["phishing"],
            notes="OpenPhish Phishing Feed"
        )
        iocs.append(ioc)
        
    return iocs


async def fetch_malwarebazaar(client: httpx.AsyncClient) -> List[IOCCreate]:
    """
    Collect from MalwareBazaar (API Recent).
    Source: https://mb-api.abuse.ch/api/v1/
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_recent", "selector": "time"}  # Get recent
    if settings.malwarebazaar_limit:
        data["limit"] = settings.malwarebazaar_limit
    
    response = await fetch_url(client, url, method="POST", data=data)
    json_resp = response.json()
    
    if json_resp.get("query_status") != "ok" and "limit" in data:
        logger.warning("MalwareBazaar limit rejected, retrying without limit.")
        data.pop("limit", None)
        response = await fetch_url(client, url, method="POST", data=data)
        json_resp = response.json()

    if json_resp.get("query_status") != "ok":
        return []
        
    iocs = []
    for item in json_resp.get("data", []):
        if not item.get("sha256_hash"):
            continue
            
        # Parse date
        try:
            first_seen = datetime.strptime(item["first_seen"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except:
            first_seen = datetime.now(timezone.utc)

        tags = item.get("tags") or []
        
        ioc = IOCCreate(
            type="hash",
            value=item["sha256_hash"],
            source="MalwareBazaar",
            first_seen=first_seen,
            last_seen=datetime.now(timezone.utc),
            risk=9,
            tags=tags,
            malware_family=item.get("signature"),
            notes=f"File: {item.get('file_name', 'unknown')}; Type: {item.get('file_type', 'unknown')}",
            raw=str(item)
        )
        iocs.append(ioc)
        
    return iocs


async def fetch_threatfox(client: httpx.AsyncClient) -> List[IOCCreate]:
    """
    Collect from ThreatFox (API).
    Source: https://threatfox-api.abuse.ch/api/v1/
    """
    if not settings.threatfox_key:
        logger.warning("ThreatFox API key missing, skipping.")
        return []

    url = "https://threatfox-api.abuse.ch/api/v1/"
    # Get last 1 day
    days = settings.threatfox_days
    data = {"query": "get_iocs", "days": days}
    # Or API Key headers if required by specific endpoint, though get_iocs is public usually. 
    # Provided key suggests we should use it.
    headers = {**HEADERS, "API-KEY": settings.threatfox_key}

    response = await fetch_url(client, url, method="POST", json=data, headers=headers)
    json_resp = response.json()

    if json_resp.get("query_status") != "ok" and days > 7:
        logger.warning("ThreatFox days rejected, retrying with 7 days.")
        data["days"] = 7
        response = await fetch_url(client, url, method="POST", json=data, headers=headers)
        json_resp = response.json()

    if json_resp.get("query_status") != "ok" and data["days"] != 1:
        logger.warning("ThreatFox days rejected, retrying with 1 day.")
        data["days"] = 1
        response = await fetch_url(client, url, method="POST", json=data, headers=headers)
        json_resp = response.json()

    if json_resp.get("query_status") != "ok":
        return []

    iocs = []
    for item in json_resp.get("data", []):
        ioc_type = FeedCollector._normalize_type(item.get("ioc_type", ""))
        if ioc_type not in ["ip", "domain", "url", "hash"]:
            continue

        value = item.get("ioc_value")
        if not value:
            continue
            
        # Enrich IP
        country = None
        if ioc_type == "ip":
            # Strip port if present for geoip
            ip_only = FeedCollector._extract_ip(value)
            if ip_only:
                country = get_country_code(ip_only)

        try:
            first_seen = datetime.strptime(item["first_seen_utc"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except:
            first_seen = datetime.now(timezone.utc)            

        ioc = IOCCreate(
            type=ioc_type,
            value=value,
            source="ThreatFox",
            first_seen=first_seen,
            last_seen=datetime.now(timezone.utc),
            country=country,
            risk=9,
            tags=[item.get("threat_type")] if item.get("threat_type") else [],
            malware_family=item.get("malware_printable"),
            confidence=item.get("confidence_level"),
            notes=f"Threat: {item.get('threat_type')}",
            raw=str(item)
        )
        iocs.append(ioc)

    return iocs


async def fetch_otx(client: httpx.AsyncClient) -> List[IOCCreate]:
    """
    Collect from AlienVault OTX (Subscribed Pulses).
    Source: https://otx.alienvault.com/api/v1/pulses/subscribed
    """
    if not settings.otx_key:
        logger.warning("OTX API key missing, skipping.")
        return []
        
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    if settings.otx_start_date:
        start_dt = datetime.combine(settings.otx_start_date, datetime.min.time(), tzinfo=timezone.utc)
        modified_since = start_dt.isoformat()
    else:
        modified_since = (datetime.now(timezone.utc) - timedelta(days=settings.otx_lookback_days)).isoformat()
    headers = {**HEADERS, "X-OTX-API-KEY": settings.otx_key}
    
    iocs = []
    page = 1
    while True:
        params = {
            "limit": settings.otx_pulse_limit,
            "modified_since": modified_since,
            "page": page,
        }

        try:
            response = await fetch_url(client, url, headers=headers, params=params)
            json_resp = response.json()
        except Exception as e:
            if page > 1:
                logger.warning(f"OTX fetch failed on page {page}: {e}")
                break
            logger.warning(f"OTX fetch failed with current params: {e}. Retrying with safer defaults.")
            params["limit"] = min(10, settings.otx_pulse_limit)
            response = await fetch_url(client, url, headers=headers, params=params)
            json_resp = response.json()

        for pulse in json_resp.get("results", []):
            pulse_name = pulse.get("name")
            tags = limit_tags(pulse.get("tags", []), 512)
            
            for indicator in pulse.get("indicators", []):
                raw_type = indicator.get("type", "").lower()
                
                # Map OTX types
                type_map = {
                    "ipv4": "ip", 
                    "ipv6": "ip",
                    "domain": "domain",
                    "url": "url",
                    "hostname": "domain",
                    "filehash-sha256": "hash",
                    "filehash-md5": "hash",
                    "filehash-sha1": "hash",
                    "email": "email"
                }
                
                if raw_type not in type_map:
                    continue
                    
                ioc_type = type_map[raw_type]
                value = indicator.get("indicator")
                if not value:
                    continue
                if len(str(value)) > 512:
                    continue
                
                # GeoIP for IPs
                country = None
                if ioc_type == "ip":
                    country = get_country_code(value)

                try:
                    created = datetime.strptime(indicator["created"], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                except:
                    created = datetime.now(timezone.utc)

                notes = truncate_text(f"Pulse: {pulse_name}" if pulse_name else "Pulse: OTX", 1024)
                ioc = IOCCreate(
                    type=ioc_type,
                    value=value,
                    source="AlienVault OTX",
                    first_seen=created,
                    last_seen=datetime.now(timezone.utc),
                    country=country,
                    risk=5, # OTX risk varies, default medium
                    tags=tags,
                    notes=notes,
                    raw=str(indicator)
                )
                iocs.append(ioc)

        has_next = bool(json_resp.get("next"))
        if not has_next:
            break
        page += 1
        if settings.otx_max_pages and page > settings.otx_max_pages:
            logger.warning(f"OTX pagination stopped at page {settings.otx_max_pages}")
            break

    return iocs


async def fetch_abuseipdb(client: httpx.AsyncClient) -> List[IOCCreate]:
    """
    Collect from AbuseIPDB (Blacklist).
    Source: https://api.abuseipdb.com/api/v2/blacklist
    """
    if not settings.abuseipdb_key:
        logger.warning("AbuseIPDB API key missing, skipping.")
        return []
        
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {**HEADERS, "Key": settings.abuseipdb_key, "Accept": "application/json"}
    limits = [settings.abuseipdb_limit]
    if settings.abuseipdb_limit > 1000:
        limits.append(1000)
    if settings.abuseipdb_limit > 100:
        limits.append(100)

    json_resp = None
    last_error = None
    for limit in limits:
        params = {"limit": limit}
        try:
            response = await fetch_url(client, url, headers=headers, params=params)
            json_resp = response.json()
            break
        except Exception as e:
            last_error = e
            logger.warning(f"AbuseIPDB fetch failed with limit={limit}: {e}")

    if json_resp is None:
        logger.error(f"AbuseIPDB fetch failed after retries: {last_error}")
        return []
    
    iocs = []
    now = datetime.now(timezone.utc)
    
    for item in json_resp.get("data", []):
        ip = item.get("ipAddress")
        country = item.get("countryCode")
        abuse_score = item.get("abuseConfidenceScore")
        
        if not ip:
            continue
            
        ioc = IOCCreate(
            type="ip",
            value=ip,
            source="AbuseIPDB",
            first_seen=now, # Blacklist usually doesn't have first_seen per IP in this endpoint
            last_seen=item.get("lastReportedAt") or now,
            country=country,
            risk=min(10, max(1, abuse_score // 10)), # Scale 0-100 to 1-10
            confidence=abuse_score,
            tags=["abuse", "blacklist"],
            notes=f"Abuse Score: {abuse_score}",
            raw=str(item)
        )
        iocs.append(ioc)
        
    return iocs


# -----------------------------------------------------------------------------
# Main Async Execution Wrapper
# -----------------------------------------------------------------------------

async def _run_collection(source_name: str, fetch_func) -> Dict[str, Any]:
    """
    Run a specific collector function and save results.
    """
    start_time = datetime.now(timezone.utc)
    stats = {"source": source_name, "total": 0, "created": 0, "skipped": 0, "errors": 0, "duration": 0.0}
    
    logger.info(f"Starting {source_name} collection...")
    
    try:
        stix_stats = await _collect_stix_for_source(source_name)
        if stix_stats:
            stats["stix"] = stix_stats

        async with httpx.AsyncClient(verify=False) as client:
            iocs = await fetch_func(client)
            stats["total"] = len(iocs)
            
            if iocs:
                async with AsyncSessionLocal() as session:
                    # Process in batches of 500
                    batch_size = 500
                    for i in range(0, len(iocs), batch_size):
                        batch = iocs[i:i + batch_size]
                        c, s, e = await process_batch(session, batch, source_name)
                        stats["created"] += c
                        stats["skipped"] += s
                        stats["errors"] += e
                        
    except Exception as e:
        logger.error(f"Error collecting from {source_name}: {e}")
        stats["error"] = str(e)
    
    end_time = datetime.now(timezone.utc)
    stats["duration"] = (end_time - start_time).total_seconds()
    
    log_feed_activity(
        feed_name=source_name,
        action="pull",
        ioc_count=stats["created"],
        duration_seconds=stats["duration"],
        error=stats.get("error")
    )
    
    return stats


# -----------------------------------------------------------------------------
# Celery Tasks
# -----------------------------------------------------------------------------

@celery_app.task(bind=True)
def collect_urlhaus(self):
    """Celery task for URLhaus."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run_collection("URLhaus", fetch_urlhaus))

@celery_app.task(bind=True)
def collect_openphish(self):
    """Celery task for OpenPhish."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run_collection("OpenPhish", fetch_openphish))

@celery_app.task(bind=True)
def collect_malwarebazaar(self):
    """Celery task for MalwareBazaar."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run_collection("MalwareBazaar", fetch_malwarebazaar))

@celery_app.task(bind=True)
def collect_threatfox(self):
    """Celery task for ThreatFox."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run_collection("ThreatFox", fetch_threatfox))

@celery_app.task(bind=True)
def collect_otx(self):
    """Celery task for AlienVault OTX."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run_collection("AlienVault OTX", fetch_otx))

@celery_app.task(bind=True)
def collect_abuseipdb(self):
    """Celery task for AbuseIPDB."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run_collection("AbuseIPDB", fetch_abuseipdb))


@celery_app.task(bind=True)
def collect_mitre(self):
    """Celery task for MITRE ATT&CK."""
    from app.services.mitre import run_mitre_sync
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(run_mitre_sync())


@celery_app.task(bind=True)
def collect_stix_all(self):
    """
    Celery task for STIX 2.1 collection from all sources.
    Collects maximum data from URLhaus, ThreatFox, and OTX.
    """
    async def _run():
        manager = STIXConnectorManager()
        return await manager.collect_all()
    
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(_run())
    log_feed_activity("STIX Collection", True, f"Collected {result.get('total_objects', 0)} objects")
    return result


@celery_app.task(bind=True)
def collect_all_feeds(self, sources: List[str] = None):
    """
    Master task to run all or selected collectors.
    """
    source_map = {
        "urlhaus": collect_urlhaus,
        "openphish": collect_openphish,
        "malwarebazaar": collect_malwarebazaar,
        "threatfox": collect_threatfox,
        "otx": collect_otx,
        "abuseipdb": collect_abuseipdb,
    }
    
    if not sources:
        sources = list(source_map.keys())
    
    results = {}
    for source in sources:
        source_key = source.lower()
        if source_key in source_map:
            # Run synchronously/sequentially to avoid overwhelming DB/Network in this simple worker setup
            # In production, these should be chained or grouped
            try:
                task = source_map[source_key].delay()
                results[source] = {"status": "queued", "task_id": str(task.id)}
            except Exception as e:
                results[source] = {"status": "failed", "error": str(e)}
        else:
             results[source] = {"status": "skipped", "reason": "unknown source"}
             
    return results


def run_collectors_sync(sources: List[str] = None):
    """
    Run collectors synchronously (non-Celery fallback).
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    source_map = {
        "urlhaus": fetch_urlhaus,
        "openphish": fetch_openphish,
        "malwarebazaar": fetch_malwarebazaar,
        "threatfox": fetch_threatfox,
        "otx": fetch_otx,
        "abuseipdb": fetch_abuseipdb,
    }
    
    if not sources:
        sources = list(source_map.keys())
        
    results = {}
    for source in sources:
        source_key = source.lower()
        if source_key in source_map:
            # Map nice name
            name_map = {
                "urlhaus": "URLhaus",
                "openphish": "OpenPhish",
                "malwarebazaar": "MalwareBazaar",
                "threatfox": "ThreatFox",
                "otx": "AlienVault OTX",
                "abuseipdb": "AbuseIPDB"
            }
            results[source] = loop.run_until_complete(_run_collection(name_map[source_key], source_map[source_key]))
            
    loop.close()
    return results
