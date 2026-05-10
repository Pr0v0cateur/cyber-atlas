"""
Cyber Atlas - Celery Application Configuration

Configures Celery for background task processing with Redis as broker.
"""

from celery import Celery

from app.core.config import settings


# Create Celery application
celery_app = Celery(
    "cyber_atlas",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "app.tasks.collectors",
        "app.tasks.scheduler",
    ],
)

# Celery configuration
celery_app.conf.update(
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Task execution settings
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_time_limit=3600,  
    task_soft_time_limit=3300,  
    
    # Worker settings
    worker_prefetch_multiplier=1,
    worker_concurrency=4,
    worker_max_tasks_per_child=100,
    
    # Result backend settings
    result_expires=86400, 
    result_extended=True,
    
    # Task routing
    task_routes={
        "app.tasks.collectors.*": {"queue": "collectors"},
        "app.tasks.scheduler.*": {"queue": "scheduler"},
    },
    
    # Beat scheduler settings
    beat_scheduler="celery.beat:PersistentScheduler",
    beat_schedule_filename="./celerybeat-schedule",
    
    # Retry settings
    task_default_retry_delay=60,  # 1 minute
    task_max_retries=3,
    
    # Security
    task_annotations={
        "*": {
            "rate_limit": "10/m",
        },
        "app.tasks.collectors.collect_all_feeds": {
            "rate_limit": "1/h",
        },
    },
)

# Import beat schedule
from app.tasks.scheduler import CELERY_BEAT_SCHEDULE
celery_app.conf.beat_schedule = CELERY_BEAT_SCHEDULE


@celery_app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery connectivity."""
    print(f"Request: {self.request!r}")
    return {"status": "ok", "worker": self.request.hostname}
