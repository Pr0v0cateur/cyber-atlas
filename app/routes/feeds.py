"""
Cyber Atlas - Threat Feed Routes

Endpoints for managing threat feed collection.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.logging import logger
from app.routes.auth import get_current_admin_user
from app.models.user import User
from app.middleware.ratelimit import rate_limiter, feed_rate_limit


router = APIRouter(prefix="/api/feeds", tags=["Threat Feeds"])


# Store last pull status in memory (in production, use Redis)
feed_status = {
    "last_pull": None,
    "last_pull_status": "never",
    "feeds": {
        "urlhaus": {"last_run": None, "status": "idle", "iocs": 0},
        "openphish": {"last_run": None, "status": "idle", "iocs": 0},
        "malwarebazaar": {"last_run": None, "status": "idle", "iocs": 0},
        "threatfox": {"last_run": None, "status": "idle", "iocs": 0},
        "otx": {"last_run": None, "status": "idle", "iocs": 0},
        "abuseipdb": {"last_run": None, "status": "idle", "iocs": 0},
    },
}


@router.post("/pull")
@rate_limiter.limit(feed_rate_limit)
async def pull_feeds(
    request: Request,
    response: Response,  
    background_tasks: BackgroundTasks,
    sources: Optional[list[str]] = Query(None, description="Optional list of specific feeds to pull"),
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger manual threat feed collection (admin only).
    
    Runs feed collectors in the background. Check /status for progress.
    
    - **sources**: Optional list of specific feeds to pull.
      If not provided, pulls from all configured feeds.
    
    Available sources:
    - urlhaus
    - openphish
    - malwarebazaar
    - threatfox
    - otx
    - abuseipdb
    """
    available_sources = list(feed_status["feeds"].keys())
    
    if sources:
        # Validate source names
        invalid = [s for s in sources if s.lower() not in available_sources]
        if invalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid sources: {invalid}. Available: {available_sources}",
            )
        sources = [s.lower() for s in sources]
    else:
        sources = available_sources
    
    # Update status
    feed_status["last_pull"] = datetime.now(timezone.utc).isoformat()
    feed_status["last_pull_status"] = "running"
    
    for source in sources:
        feed_status["feeds"][source]["status"] = "queued"
    
    # Trigger Celery task for feed collection
    try:
        from app.tasks.celery_app import celery_app
        from app.tasks.collectors import collect_all_feeds
        
        # Send task to Celery
        task = collect_all_feeds.delay(sources)
        
        logger.info(f"Feed pull triggered by {current_user.email}, task_id: {task.id}")
        
        return {
            "message": "Feed collection started",
            "task_id": task.id,
            "sources": sources,
            "triggered_at": feed_status["last_pull"],
            "triggered_by": current_user.email,
        }
    except Exception as e:
        # If Celery is not available, run synchronously
        logger.warning(f"Celery not available, running sync: {e}")
        
        # Add to background tasks (FastAPI's built-in)
        from app.tasks.collectors import run_collectors_sync
        background_tasks.add_task(run_collectors_sync, sources)
        
        return {
            "message": "Feed collection started (sync mode)",
            "sources": sources,
            "triggered_at": feed_status["last_pull"],
            "triggered_by": current_user.email,
        }


@router.get("/status")
async def get_feed_status(
    current_user: User = Depends(get_current_admin_user),
):
    """
    Get the status of threat feed collectors (admin only).
    
    Returns last pull timestamp and status for each configured feed.
    """
    return {
        "last_pull": feed_status["last_pull"],
        "status": feed_status["last_pull_status"],
        "feeds": feed_status["feeds"],
    }


@router.get("/sources")
async def list_available_sources(
    current_user: User = Depends(get_current_admin_user),
):
    """
    List all available threat feed sources (admin only).
    """
    return {
        "sources": [
            {
                "name": "urlhaus",
                "description": "URLhaus - Malicious URL tracker by abuse.ch",
                "url": "https://urlhaus.abuse.ch/",
                "ioc_types": ["url", "domain", "ip"],
                "api_key_required": False,
            },
            {
                "name": "openphish",
                "description": "OpenPhish - Phishing URL feed",
                "url": "https://openphish.com/",
                "ioc_types": ["url"],
                "api_key_required": False,
            },
            {
                "name": "malwarebazaar",
                "description": "MalwareBazaar - Malware sample database by abuse.ch",
                "url": "https://bazaar.abuse.ch/",
                "ioc_types": ["hash"],
                "api_key_required": False,
            },
            {
                "name": "threatfox",
                "description": "ThreatFox - IOC sharing platform by abuse.ch",
                "url": "https://threatfox.abuse.ch/",
                "ioc_types": ["ip", "domain", "url", "hash"],
                "api_key_required": True,
            },
            {
                "name": "otx",
                "description": "AlienVault OTX - Open Threat Exchange",
                "url": "https://otx.alienvault.com/",
                "ioc_types": ["ip", "domain", "url", "hash", "email"],
                "api_key_required": True,
            },
            {
                "name": "abuseipdb",
                "description": "AbuseIPDB - IP address abuse reports",
                "url": "https://www.abuseipdb.com/",
                "ioc_types": ["ip"],
                "api_key_required": True,
            },
        ]
    }


@router.post("/sources/{source}/test")
async def test_feed_source(
    source: str,
    current_user: User = Depends(get_current_admin_user),
):
    """
    Test connectivity to a specific threat feed source (admin only).
    """
    available_sources = list(feed_status["feeds"].keys())
    
    if source.lower() not in available_sources:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown source: {source}. Available: {available_sources}",
        )
    
    from app.tasks.collectors import test_feed_connectivity
    
    try:
        result = await test_feed_connectivity(source.lower())
        return {
            "source": source,
            "status": "success" if result["success"] else "failed",
            "message": result["message"],
            "response_time_ms": result.get("response_time_ms"),
        }
    except Exception as e:
        return {
            "source": source,
            "status": "error",
            "message": str(e),
        }


@router.get("/schedule")
async def get_feed_schedule(
    current_user: User = Depends(get_current_admin_user),
):
    """
    Get the automated feed collection schedule (admin only).
    """
    return {
        "schedule": {
            "feed_collection": {
                "interval": "6 hours",
                "next_run": "calculated_by_celery_beat",
                "enabled": True,
            },
            "database_cleanup": {
                "interval": "24 hours",
                "retention_days": 90,
                "enabled": True,
            },
            "stats_recalculation": {
                "interval": "1 hour",
                "enabled": True,
            },
        }
    }
