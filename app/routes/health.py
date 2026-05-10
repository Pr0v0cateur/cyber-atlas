"""
Cyber Atlas - Health Check Routes

System health and status endpoints.
"""

from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db
from app.core.config import settings
from app.core.logging import logger


router = APIRouter(prefix="/api", tags=["Health"])


@router.get("/health")
async def health_check():
    """
    Basic health check endpoint.
    
    Returns a simple status indicating the API is running.
    Does not check dependencies.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": settings.app_version,
    }


@router.get("/health/ready")
async def readiness_check(
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Readiness check endpoint.
    
    Verifies all dependencies are available:
    - Database (PostgreSQL)
    - Cache (Redis)
    - Search (OpenSearch)
    
    Returns detailed status for each component.
    """
    checks = {
        "database": await check_database(db),
        "redis": await check_redis(),
        "opensearch": await check_opensearch(),
    }
    
    # Determine overall status
    all_healthy = all(check["status"] == "healthy" for check in checks.values())
    
    return {
        "status": "ready" if all_healthy else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": settings.app_version,
        "checks": checks,
    }


@router.get("/health/live")
async def liveness_check():
    """
    Liveness check endpoint.
    
    Indicates if the application process is alive and should not be restarted.
    Returns 200 if the process is running.
    """
    return {
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def check_database(db: AsyncSession) -> Dict[str, Any]:
    """Check PostgreSQL database connectivity."""
    try:
        result = await db.execute(text("SELECT 1"))
        result.scalar()
        return {
            "status": "healthy",
            "message": "Database connection successful",
            "latency_ms": None,  # Could measure actual latency
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}",
        }


async def check_redis() -> Dict[str, Any]:
    """Check Redis connectivity."""
    try:
        import redis.asyncio as redis
        
        client = redis.from_url(
            settings.redis_connection_url,
            encoding="utf-8",
            decode_responses=True,
        )
        
        await client.ping()
        await client.close()
        
        return {
            "status": "healthy",
            "message": "Redis connection successful",
        }
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {
            "status": "unhealthy",
            "message": f"Redis connection failed: {str(e)}",
        }


async def check_opensearch() -> Dict[str, Any]:
    """Check OpenSearch connectivity."""
    try:
        from opensearchpy import AsyncOpenSearch
        
        client = AsyncOpenSearch(
            hosts=[{
                "host": settings.opensearch_host,
                "port": settings.opensearch_port,
            }],
            http_auth=(settings.opensearch_user, settings.opensearch_password),
            use_ssl=True,
            verify_certs=settings.opensearch_verify_certs,
            ssl_show_warn=False,
        )
        
        info = await client.info()
        await client.close()
        
        return {
            "status": "healthy",
            "message": "OpenSearch connection successful",
            "version": info.get("version", {}).get("number"),
        }
    except Exception as e:
        logger.warning(f"OpenSearch health check failed: {e}")
        return {
            "status": "degraded",
            "message": f"OpenSearch not available: {str(e)}",
        }


@router.get("/info")
async def get_app_info():
    """
    Get application information.
    
    Returns version, environment, and configuration details.
    Does not expose sensitive information.
    """
    return {
        "app_name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
        "debug_mode": settings.debug,
        "api_docs": "/docs",
        "redoc": "/redoc",
        "features": {
            "rate_limiting": True,
            "jwt_auth": True,
            "api_key_auth": True,
            "geoip_enrichment": True,
            "threat_feeds": [
                "urlhaus",
                "openphish",
                "malwarebazaar",
                "threatfox",
                "otx",
                "abuseipdb",
            ],
        },
    }
