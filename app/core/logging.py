"""
Cyber Atlas - Logging Configuration

Loguru-based logging with file rotation, formatting, and context support.
"""

import sys
from pathlib import Path
from loguru import logger

from .config import settings


def setup_logging() -> None:
    """
    Configure Loguru logger for the application.
    
    Sets up:
    - Console logging with colors
    - File logging with rotation
    - Structured format for production
    """
    # Remove default handler
    logger.remove()
    
    # Define log format
    console_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )
    
    file_format = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
        "{level: <8} | "
        "{name}:{function}:{line} | "
        "{message}"
    )
    
    # Add console handler
    logger.add(
        sys.stderr,
        format=console_format,
        level=settings.log_level,
        colorize=True,
        backtrace=True,
        diagnose=settings.debug,
    )
    
    # Ensure log directory exists
    log_path = Path(settings.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Add file handler with rotation
    logger.add(
        settings.log_file,
        format=file_format,
        level=settings.log_level,
        rotation=settings.log_rotation,
        retention=settings.log_retention,
        compression="gz",
        backtrace=True,
        diagnose=settings.debug,
        enqueue=True,  # Thread-safe logging
    )
    
    # Add separate error log file
    error_log_path = log_path.parent / "errors.log"
    logger.add(
        str(error_log_path),
        format=file_format,
        level="ERROR",
        rotation=settings.log_rotation,
        retention=settings.log_retention,
        compression="gz",
        backtrace=True,
        diagnose=True,
        enqueue=True,
    )
    
    logger.info(f"Logging configured - Level: {settings.log_level}, File: {settings.log_file}")


class LogContext:
    """
    Context manager for adding contextual information to logs.
    
    Usage:
        with LogContext(request_id="abc123", user_id=42):
            logger.info("Processing request")
    """
    
    def __init__(self, **kwargs):
        self.context = kwargs
    
    def __enter__(self):
        logger.configure(extra=self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.configure(extra={})
        return False


def log_request(
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    client_ip: str | None = None,
) -> None:
    """
    Log an HTTP request.
    
    Args:
        method: HTTP method
        path: Request path
        status_code: Response status code
        duration_ms: Request duration in milliseconds
        client_ip: Client IP address
    """
    log_level = "INFO"
    if status_code >= 500:
        log_level = "ERROR"
    elif status_code >= 400:
        log_level = "WARNING"
    
    logger.log(
        log_level,
        f"{method} {path} - {status_code} - {duration_ms:.2f}ms - {client_ip or 'unknown'}"
    )


def log_security_event(
    event_type: str,
    message: str,
    client_ip: str | None = None,
    user_email: str | None = None,
    **extra,
) -> None:
    """
    Log a security-related event.
    
    Args:
        event_type: Type of security event (login, logout, failed_login, etc.)
        message: Event description
        client_ip: Client IP address
        user_email: User email if applicable
        **extra: Additional context
    """
    logger.warning(
        f"SECURITY [{event_type}] - {message} | "
        f"IP: {client_ip or 'unknown'} | "
        f"User: {user_email or 'anonymous'} | "
        f"Extra: {extra}"
    )


def log_feed_activity(
    feed_name: str,
    action: str,
    ioc_count: int = 0,
    duration_seconds: float = 0,
    error: str | None = None,
) -> None:
    """
    Log threat feed collection activity.
    
    Args:
        feed_name: Name of the threat feed
        action: Action performed (pull, process, error)
        ioc_count: Number of IOCs processed
        duration_seconds: Duration of the operation
        error: Error message if applicable
    """
    if error:
        logger.error(
            f"FEED [{feed_name}] - {action} - Error: {error} - Duration: {duration_seconds:.2f}s"
        )
    else:
        logger.info(
            f"FEED [{feed_name}] - {action} - IOCs: {ioc_count} - Duration: {duration_seconds:.2f}s"
        )


# Initialize logging on module import
setup_logging()


__all__ = [
    "logger",
    "setup_logging",
    "LogContext",
    "log_request",
    "log_security_event",
    "log_feed_activity",
]
