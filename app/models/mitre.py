"""
Cyber Atlas - MITRE ATT&CK Models

Database models for storing MITRE ATT&CK data (Tactics, Techniques, Groups, Software, Mitigations).
"""

from typing import Optional, List
from sqlalchemy import String, Text, Boolean, Integer, ForeignKey, Index, UniqueConstraint, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

# Relationship Association Table (Generic STIX Relationship)
# Used for:
# - Technique uses Malware
# - Group uses Technique
# - Mitigation mitigates Technique
# - Technique sub-technique-of Technique
# - Tactic includes Technique (though that's often a direct mapping, in STIX it's often kill_chain_phases)

mitre_relationships = Table(
    "mitre_relationships",
    Base.metadata,
    Column("id", Integer, primary_key=True),
    Column("source_ref", String(64), index=True, nullable=False, comment="Source STIX ID"),
    Column("target_ref", String(64), index=True, nullable=False, comment="Target STIX ID"),
    Column("relationship_type", String(32), nullable=False, comment="Type: uses, mitigates, subtechnique-of"),
    Column("description", Text, nullable=True),
    UniqueConstraint("source_ref", "target_ref", "relationship_type", name="uq_mitre_relationship"),
)


class MitreBase(Base):
    """Base model for MITRE objects."""
    __abstract__ = True
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # STIX Fields
    stix_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created: Mapped[Optional[str]] = mapped_column(String(32), nullable=True) # ISO format
    modified: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Common ATT&CK fields
    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)


class MitreTactic(MitreBase):
    """
    MITRE ATT&CK Tactic (e.g., Initial Access).
    """
    __tablename__ = "mitre_tactics"
    
    short_name: Mapped[str] = mapped_column(String(64), index=True, nullable=False) # e.g. initial-access
    external_id: Mapped[Optional[str]] = mapped_column(String(32), index=True, nullable=True) # TA0001
    
    # Relationships
    # Techniques linked via kill_chain_phases often, usually modeled as M:N
    techniques: Mapped[List["MitreTechnique"]] = relationship(
        "MitreTechnique",
        secondary="mitre_tactic_technique",
        back_populates="tactics"
    )

class MitreTechnique(MitreBase):
    """
    MITRE ATT&CK Technique (e.g., Phishing).
    """
    __tablename__ = "mitre_techniques"
    
    external_id: Mapped[Optional[str]] = mapped_column(String(32), index=True, nullable=True) # T1566
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    platforms: Mapped[Optional[str]] = mapped_column(String(512), nullable=True) # CSV
    detection: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Relationships
    tactics: Mapped[List["MitreTactic"]] = relationship(
        "MitreTactic",
        secondary="mitre_tactic_technique",
        back_populates="techniques"
    )

class MitreGroup(MitreBase):
    """
    MITRE ATT&CK Group (e.g., APT29).
    """
    __tablename__ = "mitre_groups"
    
    external_id: Mapped[Optional[str]] = mapped_column(String(32), index=True, nullable=True) # G0016
    aliases: Mapped[Optional[str]] = mapped_column(Text, nullable=True) # JSON list or CSV

class MitreSoftware(MitreBase):
    """
    MITRE ATT&CK Software (Malware/Tools) (e.g., Cobalt Strike).
    """
    __tablename__ = "mitre_software"
    
    external_id: Mapped[Optional[str]] = mapped_column(String(32), index=True, nullable=True) # S0015
    is_malware: Mapped[bool] = mapped_column(Boolean, default=True) # vs Tool
    platforms: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    aliases: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class MitreMitigation(MitreBase):
    """
    MITRE ATT&CK Mitigation.
    """
    __tablename__ = "mitre_mitigations"
    
    external_id: Mapped[Optional[str]] = mapped_column(String(32), index=True, nullable=True) # M1015

# Join Table for Tactic <-> Technique
# This is explicitly needed because "Kill Chain Phases" in STIX map techniques to tactics
mitre_tactic_technique = Table(
    "mitre_tactic_technique",
    Base.metadata,
    Column("tactic_id", Integer, ForeignKey("mitre_tactics.id"), primary_key=True),
    Column("technique_id", Integer, ForeignKey("mitre_techniques.id"), primary_key=True),
)
