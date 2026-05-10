"""
Cyber Atlas - Main Application Entry Point

Initializes the FastAPI application, middleware, and routes.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.authentication import AuthenticationMiddleware

from app.core.config import settings
from app.core.database import init_db, close_db
from app.core.logging import logger
from app.crud.users import create_default_admin
from app.middleware.security_hardening import SecurityHeadersMiddleware
from app.middleware.ratelimit import RateLimitMiddleware, rate_limiter, rate_limit_exceeded_handler
from app.middleware.limits import RequestSizeLimitMiddleware
from app.routes import auth, feeds, search, stats, health, mitre, dashboard, breach_proxy, kev
from app.routes import entities, pages
from app.routes import entities
from app.routes import stix as stix_router
from slowapi.errors import RateLimitExceeded


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("Initializing Cyber Atlas...")
    
    # Initialize database
    await init_db()
    
    # Create default admin user (only if not found)
    from app.core.database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        await create_default_admin(session)
        await session.commit()  # Commit the transaction to persist the user
        
    logger.info("Cyber Atlas started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Cyber Atlas...")
    await close_db()


# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Cyber Atlas Threat Intelligence Platform",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan,
)


# -----------------------------------------------------------------------------
# Middleware Configuration
# -----------------------------------------------------------------------------

# 1. Security Headers (First to ensure headers are always present)
app.add_middleware(SecurityHeadersMiddleware)

# 2. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Rate Limiting
app.state.limiter = rate_limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
app.add_middleware(RateLimitMiddleware)

# 4. Request Limits
app.add_middleware(RequestSizeLimitMiddleware, max_size=10 * 1024 * 1024)  # 10 MB


# -----------------------------------------------------------------------------
# Router Configuration
# -----------------------------------------------------------------------------

app.include_router(auth.router)
app.include_router(feeds.router)
app.include_router(search.router)
app.include_router(stats.router)
app.include_router(health.router)
app.include_router(mitre.router)
app.include_router(dashboard.router)
app.include_router(breach_proxy.router)
app.include_router(kev.router)
app.include_router(entities.router)
app.include_router(pages.router)
app.include_router(stix_router.router, prefix="/api")

# Mount Static Files (Frontend)
app.mount("/static", StaticFiles(directory="frontend_static", html=True), name="static")


@app.get("/", tags=["General"])
async def root():
    """Root endpoint redirecting to documentation or info."""
    return {
        "message": f"Welcome to {settings.app_name}",
        "version": settings.app_version,
        "docs": "/docs",
        "status": "online"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
