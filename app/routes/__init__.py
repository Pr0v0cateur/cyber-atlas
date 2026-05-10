"""
API Routes for Cyber Atlas.
"""

from .auth import router as auth_router
from .feeds import router as feeds_router
from .search import router as search_router
from .stats import router as stats_router
from .health import router as health_router

__all__ = [
    "auth_router",
    "feeds_router",
    "search_router",
    "stats_router",
    "health_router",
]
