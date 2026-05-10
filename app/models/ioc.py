"""
Cyber Atlas - IOC (Indicator of Compromise) Model

Database model for storing threat intelligence indicators.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Integer, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.core.database import Base


class IOC(Base):
    """
    Indicator of Compromise (IOC) database model.
    
    Stores threat intelligence indicators collected from various feeds.
    
    Attributes:
        id: Primary key
        type: IOC type (ip, cidr, domain, url, hash, email)
        value: The actual indicator value
        source: Name of the threat feed source
        first_seen: When the IOC was first observed
        last_seen: When the IOC was last observed
        country: Country code for IP-based IOCs
        risk: Risk score (1-10 scale)
        notes: Additional notes or context
        raw: Raw data from the source feed
        tags: Comma-separated tags
        malware_family: Associated malware family if known
        confidence: Confidence level (1-100)
        created_at: Record creation timestamp
        updated_at: Record last update timestamp
    """
    
    __tablename__ = "iocs"
    
    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Core IOC fields
    type: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
        comment="IOC type: ip, cidr, domain, url, hash, email"
    )
    value: Mapped[str] = mapped_column(
        String(512),
        index=True,
        nullable=False,
        comment="The actual indicator value"
    )
    source: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
        comment="Threat feed source name"
    )
    
    # Temporal fields
    first_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=True,
        comment="When the IOC was first observed"
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=True,
        comment="When the IOC was last observed"
    )
    
    # Enrichment fields
    country: Mapped[Optional[str]] = mapped_column(
        String(8),
        index=True,
        nullable=True,
        comment="ISO country code for IP-based IOCs"
    )
    risk: Mapped[Optional[int]] = mapped_column(
        Integer,
        index=True,
        nullable=True,
        comment="Risk score (1-10 scale)"
    )
    
    # Additional metadata
    notes: Mapped[Optional[str]] = mapped_column(
        String(1024),
        nullable=True,
        comment="Additional notes or context"
    )
    raw: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Raw data from the source feed"
    )
    tags: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
        comment="Comma-separated tags"
    )
    malware_family: Mapped[Optional[str]] = mapped_column(
        String(128),
        index=True,
        nullable=True,
        comment="Associated malware family"
    )
    confidence: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Confidence level (1-100)"
    )
    
    # Record timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Record creation timestamp"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        comment="Record last update timestamp"
    )
    
    # Composite indexes for common queries
    __table_args__ = (
        Index("ix_iocs_type_value", "type", "value"),
        Index("ix_iocs_source_type", "source", "type"),
        Index("ix_iocs_country_risk", "country", "risk"),
        Index("ix_iocs_last_seen_type", "last_seen", "type"),
    )
    
    def __repr__(self) -> str:
        return f"<IOC(id={self.id}, type='{self.type}', value='{self.value[:50]}...', source='{self.source}')>"
    
    def to_dict(self) -> dict:
        """Convert IOC to dictionary representation."""
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "country": self.country,
            "risk": self.risk,
            "notes": self.notes,
            "tags": self.tags.split(",") if self.tags else [],
            "malware_family": self.malware_family,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
    
    @classmethod
    def get_valid_types(cls) -> list[str]:
        """Get list of valid IOC types."""
        return ["ip", "cidr", "domain", "url", "hash", "email"]
