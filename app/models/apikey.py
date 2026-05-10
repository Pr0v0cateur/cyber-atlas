"""
Cyber Atlas - API Key Model

Database model for API key authentication.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Integer, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class APIKey(Base):
    """
    API Key database model for programmatic access.
    
    API keys are used for machine-to-machine authentication.
    The actual key is only shown once at creation; only the hash is stored.
    
    Attributes:
        id: Primary key
        name: Human-readable name for the key
        key_hash: SHA256 hash of the API key
        key_prefix: First 8 characters of the key for identification
        user_id: Owner of the API key
        is_active: Whether the key is active
        expires_at: Optional expiration timestamp
        last_used: Timestamp of last use
        usage_count: Number of times the key has been used
        rate_limit: Custom rate limit for this key
        scopes: Comma-separated list of allowed scopes
        created_at: Record creation timestamp
    """
    
    __tablename__ = "api_keys"
    
    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Key identification
    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Human-readable name for the key"
    )
    key_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
        comment="SHA256 hash of the API key"
    )
    key_prefix: Mapped[str] = mapped_column(
        String(16),
        index=True,
        nullable=False,
        comment="First characters of the key for identification"
    )
    
    # Ownership
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
        comment="Owner of the API key"
    )
    
    # Status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether the key is active"
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Optional expiration timestamp"
    )
    
    # Usage tracking
    last_used: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of last use"
    )
    usage_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Number of times the key has been used"
    )
    
    # Permissions
    rate_limit: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Custom rate limit (requests per minute)"
    )
    scopes: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
        comment="Comma-separated list of allowed scopes"
    )
    
    # Record timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Record creation timestamp"
    )
    
    def __repr__(self) -> str:
        return f"<APIKey(id={self.id}, name='{self.name}', prefix='{self.key_prefix}')>"
    
    def to_dict(self) -> dict:
        """Convert API Key to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "user_id": self.user_id,
            "is_active": self.is_active,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "usage_count": self.usage_count,
            "rate_limit": self.rate_limit,
            "scopes": self.scopes.split(",") if self.scopes else [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
    
    def is_expired(self) -> bool:
        """Check if the API key has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(self.expires_at.tzinfo) > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if the API key is valid for use."""
        return self.is_active and not self.is_expired()
    
    def has_scope(self, scope: str) -> bool:
        """Check if the API key has a specific scope."""
        if self.scopes is None:
            return True  # No scope restrictions
        return scope in self.scopes.split(",")
    
    def get_scopes(self) -> list[str]:
        """Get list of allowed scopes."""
        if self.scopes is None:
            return []
        return [s.strip() for s in self.scopes.split(",") if s.strip()]
