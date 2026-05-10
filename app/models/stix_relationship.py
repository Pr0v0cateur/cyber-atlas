"""
Cyber Atlas - STIX 2.1 Relationship Model
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, JSON, Text, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class STIXRelationship(Base):
    """STIX Relationship objects"""

    __tablename__ = "stix_relationships"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    type: Mapped[str] = mapped_column(String(50), default="relationship")
    spec_version: Mapped[str] = mapped_column(String(10), default="2.1")

    created: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    modified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    relationship_type: Mapped[str] = mapped_column(String(50), index=True)
    source_ref: Mapped[str] = mapped_column(String(255), index=True)
    target_ref: Mapped[str] = mapped_column(String(255), index=True)

    description: Mapped[Optional[str]] = mapped_column(Text)
    stix_data: Mapped[dict] = mapped_column(JSON)

    __table_args__ = (
        Index("idx_relationship_lookup", "source_ref", "target_ref", "relationship_type"),
    )
