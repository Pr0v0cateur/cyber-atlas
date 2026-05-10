"""
Cyber Atlas - Request Size Limits Middleware

Limits request body size to prevent DoS attacks.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from app.core.logging import logger


# Maximum request body size in bytes (10 MB)
MAX_REQUEST_SIZE = 10 * 1024 * 1024


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that limits request body size.
    
    Prevents large payloads from consuming server resources.
    Default limit: 10 MB
    """
    
    def __init__(self, app, max_size: int = MAX_REQUEST_SIZE):
        super().__init__(app)
        self.max_size = max_size
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Check Content-Length header
        content_length = request.headers.get("content-length")
        
        if content_length:
            try:
                size = int(content_length)
                if size > self.max_size:
                    logger.warning(
                        f"Request body too large: {size} bytes "
                        f"(max: {self.max_size} bytes) from {request.client.host}"
                    )
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "Request body too large",
                            "message": f"Request body exceeds maximum size of {self.max_size} bytes",
                            "max_size_mb": self.max_size / (1024 * 1024),
                        },
                    )
            except ValueError:
                pass
        
        return await call_next(request)


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces request timeout.
    
    Prevents long-running requests from blocking resources.
    """
    
    def __init__(self, app, timeout_seconds: int = 30):
        super().__init__(app)
        self.timeout_seconds = timeout_seconds
    
    async def dispatch(self, request: Request, call_next) -> Response:
        import asyncio
        
        try:
            response = await asyncio.wait_for(
                call_next(request),
                timeout=self.timeout_seconds,
            )
            return response
        except asyncio.TimeoutError:
            logger.warning(
                f"Request timeout: {request.url.path} from {request.client.host}"
            )
            return JSONResponse(
                status_code=504,
                content={
                    "error": "Gateway Timeout",
                    "message": "Request processing took too long",
                },
            )
