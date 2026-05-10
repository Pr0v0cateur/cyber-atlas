"""
Cyber Atlas - Configuration Management

Pydantic Settings for type-safe configuration loading from environment variables.
"""

from datetime import date
from functools import lru_cache
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All settings are validated using Pydantic for type safety.
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # -------------------------------------------------------------------------
    # Application Settings
    # -------------------------------------------------------------------------
    app_name: str = Field(default="Cyber Atlas", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    app_env: str = Field(default="development", description="Environment (development/production)")
    debug: bool = Field(default=False, description="Debug mode flag")
    
    # -------------------------------------------------------------------------
    # API Keys (Threat Intelligence Sources)
    # -------------------------------------------------------------------------
    threatfox_key: str = Field(default="", description="ThreatFox API key")
    otx_key: str = Field(default="", description="AlienVault OTX API key")
    abuseipdb_key: str = Field(default="", description="AbuseIPDB API key")
    virustotal_key: str = Field(default="", description="VirusTotal API key")
    
    # -------------------------------------------------------------------------
    # Security Configuration
    # -------------------------------------------------------------------------
    jwt_secret_key: str = Field(..., min_length=32, description="JWT signing secret (256-bit minimum)")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiration_minutes: int = Field(default=1440, ge=1, description="JWT token expiration in minutes")
    session_secret_key: str = Field(..., min_length=32, description="Session secret key (256-bit minimum)")
    session_ttl_seconds: int = Field(default=86400, ge=60, description="Session TTL in seconds")
    
    # -------------------------------------------------------------------------
    # Database Configuration
    # -------------------------------------------------------------------------
    postgres_user: str = Field(default="atlas_user", description="PostgreSQL username")
    postgres_password: str = Field(..., description="PostgreSQL password")
    postgres_db: str = Field(default="cyber_atlas", description="PostgreSQL database name")
    postgres_host: str = Field(default="postgres", description="PostgreSQL host")
    postgres_port: int = Field(default=5432, description="PostgreSQL port")
    database_url: Optional[str] = Field(default=None, description="Full database URL (overrides individual settings)")
    database_url_async: Optional[str] = Field(default=None, description="Async database URL")
    
    # -------------------------------------------------------------------------
    # Redis Configuration
    # -------------------------------------------------------------------------
    redis_password: str = Field(..., description="Redis password")
    redis_host: str = Field(default="redis", description="Redis host")
    redis_port: int = Field(default=6379, description="Redis port")
    redis_url: Optional[str] = Field(default=None, description="Full Redis URL")
    
    # -------------------------------------------------------------------------
    # OpenSearch Configuration
    # -------------------------------------------------------------------------
    opensearch_host: str = Field(default="opensearch", description="OpenSearch host")
    opensearch_port: int = Field(default=9200, description="OpenSearch port")
    opensearch_user: str = Field(default="admin", description="OpenSearch username")
    opensearch_password: str = Field(..., description="OpenSearch password")
    opensearch_url: Optional[str] = Field(default=None, description="Full OpenSearch URL")
    opensearch_verify_certs: bool = Field(default=False, description="Verify SSL certificates")
    
    # -------------------------------------------------------------------------
    # CORS & Security Headers
    # -------------------------------------------------------------------------
    frontend_origins: str = Field(
        default="http://localhost:5500,http://127.0.0.1:5500",
        description="Comma-separated list of allowed origins"
    )
    trusted_hosts: str = Field(default="*", description="Comma-separated list of trusted hosts")
    https_only: bool = Field(default=False, description="Require HTTPS")
    
    # -------------------------------------------------------------------------
    # Default Admin Account
    # -------------------------------------------------------------------------
    default_admin_email: str = Field(
        default="admin@cyberatlas.local",
        description="Default admin email"
    )
    default_admin_password: str = Field(..., description="Default admin password")
    
    # -------------------------------------------------------------------------
    # Logging Configuration
    # -------------------------------------------------------------------------
    log_level: str = Field(default="INFO", description="Log level")
    log_file: str = Field(default="./logs/cyber_atlas.log", description="Log file path")
    log_rotation: str = Field(default="10 MB", description="Log rotation size")
    log_retention: str = Field(default="7 days", description="Log retention period")
    
    # -------------------------------------------------------------------------
    # Rate Limiting
    # -------------------------------------------------------------------------
    rate_limit_per_minute: int = Field(
        default=100,
        ge=1,
        description="Maximum requests per minute per IP"
    )
    
    # -------------------------------------------------------------------------
    # GeoIP
    # -------------------------------------------------------------------------
    geoip_database_path: str = Field(
        default="./data/GeoLite2-City.mmdb",
        description="Path to GeoLite2 database"
    )

    # -------------------------------------------------------------------------
    # IP Enrichment (IP-API)
    # -------------------------------------------------------------------------
    ipapi_base_url: str = Field(
        default="http://ip-api.com/json",
        description="IP-API base URL"
    )
    ipapi_timeout_seconds: float = Field(
        default=5.0,
        ge=1.0,
        le=30.0,
        description="IP-API timeout in seconds"
    )
    ipapi_fields: str = Field(
        default=(
            "status,message,query,country,countryCode,region,regionName,city,zip,"
            "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
        ),
        description="Comma-separated IP-API fields to request"
    )

    # -------------------------------------------------------------------------
    # Feed Collection Tuning
    # -------------------------------------------------------------------------
    feed_timeout_seconds: float = Field(
        default=60.0,
        ge=5.0,
        le=300.0,
        description="HTTP timeout for feed requests (seconds)"
    )
    urlhaus_feed: str = Field(
        default="recent",
        description="URLhaus feed type: recent|online|full"
    )
    threatfox_days: int = Field(
        default=30,
        ge=1,
        le=30,
        description="ThreatFox lookback days"
    )
    otx_lookback_days: int = Field(
        default=30,
        ge=1,
        le=90,
        description="OTX lookback days for pulses"
    )
    otx_start_date: Optional[date] = Field(
        default=None,
        description="OTX modified_since override (YYYY-MM-DD)"
    )
    otx_pulse_limit: int = Field(
        default=100,
        ge=1,
        le=200,
        description="OTX pulse limit per request"
    )
    otx_max_pages: int = Field(
        default=0,
        ge=0,
        le=500,
        description="Max OTX pages to fetch (0=all)"
    )
    malwarebazaar_limit: int = Field(
        default=1000,
        ge=1,
        le=1000,
        description="MalwareBazaar recent limit"
    )
    abuseipdb_limit: int = Field(
        default=10000,
        ge=1,
        le=10000,
        description="AbuseIPDB blacklist limit"
    )
    
    # -------------------------------------------------------------------------
    # Computed Properties
    # -------------------------------------------------------------------------
    @property
    def cors_origins(self) -> List[str]:
        """Parse comma-separated CORS origins into a list."""
        return [origin.strip() for origin in self.frontend_origins.split(",") if origin.strip()]
    
    @property
    def trusted_host_list(self) -> List[str]:
        """Parse comma-separated trusted hosts into a list."""
        return [host.strip() for host in self.trusted_hosts.split(",") if host.strip()]
    
    @property
    def sync_database_url(self) -> str:
        """Get synchronous database URL."""
        if self.database_url:
            return self.database_url
        return f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
    
    @property
    def async_database_url(self) -> str:
        """Get asynchronous database URL."""
        if self.database_url_async:
            return self.database_url_async
        return f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
    
    @property
    def redis_connection_url(self) -> str:
        """Get Redis connection URL."""
        if self.redis_url:
            return self.redis_url
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/0"
    
    @property
    def celery_broker_url(self) -> str:
        """Get Celery broker URL (Redis)."""
        return self.redis_connection_url
    
    @property
    def celery_result_backend(self) -> str:
        """Get Celery result backend URL (Redis)."""
        return self.redis_connection_url
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is a valid Python logging level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.upper()
        if upper_v not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return upper_v
    
    @field_validator("jwt_algorithm")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm."""
        valid_algorithms = {"HS256", "HS384", "HS512"}
        if v not in valid_algorithms:
            raise ValueError(f"JWT algorithm must be one of: {valid_algorithms}")
        return v

    @field_validator("urlhaus_feed")
    @classmethod
    def validate_urlhaus_feed(cls, v: str) -> str:
        """Validate URLhaus feed type."""
        valid = {"recent", "online", "full"}
        feed = v.lower().strip()
        if feed not in valid:
            raise ValueError(f"URLhaus feed must be one of: {valid}")
        return feed


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Using lru_cache ensures we only load settings once.
    """
    return Settings()


# Global settings instance
settings = get_settings()
