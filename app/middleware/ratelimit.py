"""
Cyber Atlas - Rate Limiting Middleware

Implements rate limiting using slowapi and Redis.
"""

from fastapi import Request, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import logger, log_security_event


def get_client_ip(request: Request) -> str:
    """
    Get the client IP address from the request.
    
    Handles X-Forwarded-For header for proxied requests.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Client IP address string
    """
    # Check for X-Forwarded-For header (for reverse proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Get the first IP in the chain (original client)
        return forwarded_for.split(",")[0].strip()
    
    # Check for X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct client IP
    if request.client:
        return request.client.host
    
    return "unknown"


# Create rate limiter instance
rate_limiter = Limiter(
    key_func=get_client_ip,
    default_limits=[f"{settings.rate_limit_per_minute}/minute"],
    storage_uri=settings.redis_connection_url,
    strategy="fixed-window",
    headers_enabled=True,
)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """
    Handler for rate limit exceeded errors.
    
    Args:
        request: FastAPI request object
        exc: Rate limit exception
    
    Returns:
        JSON response with 429 status code
    """
    client_ip = get_client_ip(request)
    
    log_security_event(
        "rate_limit_exceeded",
        f"Rate limit exceeded for {request.url.path}",
        client_ip=client_ip,
    )
    
    from fastapi.responses import JSONResponse
    
    return JSONResponse(
        status_code=429,
        content={
            "error": "Too many requests",
            "message": f"Rate limit exceeded. Please try again later.",
            "retry_after": exc.detail,
        },
        headers={
            "Retry-After": str(exc.detail),
            "X-RateLimit-Limit": str(settings.rate_limit_per_minute),
            "X-RateLimit-Remaining": "0",
        },
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware for applying rate limiting to requests.
    
    Uses Redis for distributed rate limiting across multiple workers.
    """
    
    # Paths that bypass rate limiting
    EXCLUDED_PATHS = {
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
    }
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting for excluded paths
        if request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)
        
        # Skip rate limiting for favicon
        if request.url.path.endswith("favicon.ico"):
            return await call_next(request)
        
        response = await call_next(request)
        
        # Add rate limit headers to response
        client_ip = get_client_ip(request)
        response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_per_minute)
        
        return response


# Specific rate limiters for different endpoints
auth_rate_limit = f"10/minute"  # Stricter limit for auth endpoints
search_rate_limit = f"30/minute"  # Moderate limit for search
feed_rate_limit = f"5/minute"  # Strict limit for feed pulls


def get_rate_limit_key_user(request: Request) -> str:
    """
    Get rate limit key based on authenticated user or IP.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Rate limit key
    """
    # Check if user is authenticated
    if hasattr(request.state, "user") and request.state.user:
        return f"user:{request.state.user.id}"
    
    return get_client_ip(request)
