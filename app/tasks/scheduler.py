"""
Cyber Atlas - Task Scheduler

Defines the schedule for periodic background tasks.
"""

import asyncio
from celery.schedules import crontab

from app.tasks.celery_app import celery_app
from app.core.logging import logger
from app.core.database import AsyncSessionLocal
from app.crud.iocs import cleanup_old_iocs, get_ioc_stats


# -----------------------------------------------------------------------------
# Periodic Tasks Logic
# -----------------------------------------------------------------------------

async def _run_db_cleanup():
    """Run database cleanup logic."""
    async with AsyncSessionLocal() as session:
        # Delete IOCs older than 90 days
        deleted = await cleanup_old_iocs(session, days_old=90, dry_run=False)
        logger.info(f"Daily Maintenance: Cleaned up {deleted} old IOCs")


async def _run_stats_recalc():
    """Run statistics recalculation (cache warming)."""
    async with AsyncSessionLocal() as session:
        stats = await get_ioc_stats(session)
        logger.info(f"Hourly Stats: Total IOCs: {stats['total_count']}")
        # In a real app, we would cache this result in Redis here
        # redis.set("stats_cache", json.dumps(stats))


# -----------------------------------------------------------------------------
# Celery Tasks
# -----------------------------------------------------------------------------

@celery_app.task
def database_maintenance():
    """Daily database maintenance task."""
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_run_db_cleanup())


@celery_app.task
def recalculate_statistics():
    """Hourly statistics recalculation task."""
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_run_stats_recalc())


# -----------------------------------------------------------------------------
# Beat Schedule
# -----------------------------------------------------------------------------

def setup_periodic_tasks(app):
    """
    Configure periodic tasks for Celery Beat.
    
    Args:
        app: Celery application instance
    """
    app.conf.beat_schedule = CELERY_BEAT_SCHEDULE
    logger.info("✓ Periodic tasks configured")


CELERY_BEAT_SCHEDULE = {
    # STIX Collection - Every 3 hours (Maximum data collection)
    "collect-stix-3h": {
        "task": "app.tasks.collectors.collect_stix_all",
        "schedule": crontab(minute=0, hour="*/3"),
        "options": {"queue": "collectors"},
    },
    
    # Legacy Feed Collection - Every 6 hours (backup for non-STIX sources)
    "collect-all-feeds-6h": {
        "task": "app.tasks.collectors.collect_all_feeds",
        "schedule": crontab(minute=30, hour="*/6"),
        "options": {"queue": "collectors"},
    },
    
    # Database Cleanup - Daily at 02:00 UTC
    "database-maintenance-daily": {
        "task": "app.tasks.scheduler.database_maintenance",
        "schedule": crontab(minute=0, hour=2),
        "options": {"queue": "scheduler"},
    },
    
    # Stats Recalculation - Every 30 minutes
    "recalculate-stats-30min": {
        "task": "app.tasks.scheduler.recalculate_statistics",
        "schedule": crontab(minute="*/30"),
        "options": {"queue": "scheduler"},
    },

    # MITRE Sync - Daily at 03:00 UTC
    "mitre-sync-daily": {
        "task": "app.tasks.collectors.collect_mitre",
        "schedule": crontab(minute=0, hour=3),
        "options": {"queue": "collectors"},
    },
}
