"""
Cyber Atlas - STIX 2.1 Object Model

Stores STIX objects alongside existing IOC tables.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Integer, JSON, Text, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class STIXObject(Base):
    """
    STIX 2.1 object storage (runs alongside existing iocs table).
    Stores all STIX object types with full fidelity.
    """

    __tablename__ = "stix_objects"

    # Primary identification
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    type: Mapped[str] = mapped_column(String(50), index=True)
    spec_version: Mapped[str] = mapped_column(String(10), default="2.1")

    # Timestamps
    created: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    modified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Common STIX properties
    name: Mapped[Optional[str]] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text)
    confidence: Mapped[Optional[int]] = mapped_column(Integer)

    # Complete STIX object as JSON
    stix_data: Mapped[dict] = mapped_column(JSON)

    # Source tracking
    created_by_ref: Mapped[Optional[str]] = mapped_column(String(255))
    labels: Mapped[Optional[list]] = mapped_column(JSON)
    external_references: Mapped[Optional[list]] = mapped_column(JSON)

    # For Indicators
    pattern: Mapped[Optional[str]] = mapped_column(Text)
    pattern_type: Mapped[Optional[str]] = mapped_column(String(50))
    valid_from: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # For Observables (quick search)
    observable_type: Mapped[Optional[str]] = mapped_column(String(50))
    observable_value: Mapped[Optional[str]] = mapped_column(String(512), index=True)

    # Connector info
    connector_id: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    connector_name: Mapped[Optional[str]] = mapped_column(String(100))

    __table_args__ = (
        Index("idx_type_created", "type", "created"),
        Index("idx_observable_lookup", "observable_type", "observable_value"),
        Index("idx_connector", "connector_id"),
    )
