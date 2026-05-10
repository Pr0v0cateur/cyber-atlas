"""
CRUD operations for Cyber Atlas.
"""

from .iocs import (
    get_ioc,
    get_iocs,
    create_ioc,
    create_iocs_bulk,
    update_ioc,
    delete_ioc,
    search_iocs,
    get_ioc_stats,
    get_iocs_by_source,
    get_iocs_by_country,
    get_ioc_timeline,
    check_ioc_exists,
)
from .users import (
    get_user,
    get_user_by_email,
    get_users,
    create_user,
    update_user,
    delete_user,
    authenticate_user,
    create_default_admin,
)

__all__ = [
    # IOC CRUD
    "get_ioc",
    "get_iocs",
    "create_ioc",
    "create_iocs_bulk",
    "update_ioc",
    "delete_ioc",
    "search_iocs",
    "get_ioc_stats",
    "get_iocs_by_source",
    "get_iocs_by_country",
    "get_ioc_timeline",
    "check_ioc_exists",
    # User CRUD
    "get_user",
    "get_user_by_email",
    "get_users",
    "create_user",
    "update_user",
    "delete_user",
    "authenticate_user",
    "create_default_admin",
]
