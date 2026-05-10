"""
Cyber Atlas - MITRE ATT&CK Ingestion Service

Handles fetching, parsing, and persisting MITRE ATT&CK data from TAXII.
"""

from datetime import datetime, timezone
import logging
from typing import List, Dict, Any, Set, Tuple

import requests
from stix2 import MemoryStore, Filter
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from app.models.mitre import (
    MitreTactic, MitreTechnique, MitreGroup, MitreSoftware, MitreMitigation,
    mitre_relationships, mitre_tactic_technique
)
from app.core.database import AsyncSessionLocal
from app.core.config import settings

logger = logging.getLogger(__name__)

# TAXII Server URL
# MITRE GitHub Raw JSON URLs
MITRE_JSON_URLS = [
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
]


class MitreIngestor:
    def __init__(self, db: AsyncSession):
        self.db = db
        # Cache for deduplication during run
        self.seen_ids = set()

    @staticmethod
    def _get_field(obj, key: str, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def _get_list(self, obj, key: str) -> List[Any]:
        value = self._get_field(obj, key)
        if not value:
            return []
        if isinstance(value, list):
            return value
        return list(value) if isinstance(value, (set, tuple)) else []
        
    async def run_ingestion(self):
        """Main entry point for ingestion."""
        logger.info("Starting MITRE ATT&CK ingestion from GitHub...")
        
        for url in MITRE_JSON_URLS:
            try:
                logger.info(f"Fetching from: {url}")
                resp = requests.get(url, verify=False) # Skip SSL verify just in case
                resp.raise_for_status()
                bundle = resp.json()
                await self.process_bundle(bundle)
            except Exception as e:
                logger.error(f"Failed to ingest from {url}: {e}")
                # Continue to next URL even if one fails
                continue
                
        logger.info("MITRE ingestion completed.")

    async def process_bundle(self, bundle: Dict[str, Any]):
        """Process a single STIX bundle."""
        objects = bundle.get("objects", [])
        
        src = MemoryStore(stix_data=objects)
        
        # 1. Ingest Tactics (x-mitre-tactic)
        tactics = list(src.query([Filter("type", "=", "x-mitre-tactic")]))
        await self.ingest_tactics(tactics)
        
        # 2. Ingest Techniques (attack-pattern)
        techniques = list(src.query([Filter("type", "=", "attack-pattern")]))
        await self.ingest_techniques(src, techniques)
        
        # 3. Ingest Groups (intrusion-set)
        groups = list(src.query([Filter("type", "=", "intrusion-set")]))
        await self.ingest_groups(groups)
        
        # 4. Ingest Software (malware, tool)
        software = list(src.query([Filter("type", "in", ["malware", "tool"])]))
        await self.ingest_software(software)
        
        # 5. Ingest Mitigations (course-of-action)
        mitigations = list(src.query([Filter("type", "=", "course-of-action")]))
        await self.ingest_mitigations(mitigations)
        
        # 6. Ingest Relationships
        relationships = list(src.query([Filter("type", "=", "relationship")]))
        await self.ingest_relationships(relationships)

    def _get_external_id(self, stix_obj) -> str:
        """Extract Txxxx/Gxxxx ID from external_references."""
        references = self._get_list(stix_obj, "external_references")
        if not references:
            return None
        for ref in references:
            if ref.get("source_name") in ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]:
                return ref.get("external_id")
        return None

    async def ingest_tactics(self, objects: List[Dict]):
        for obj in objects:
            data = {
                "stix_id": self._get_field(obj, "id"),
                "name": self._get_field(obj, "name"),
                "description": self._get_field(obj, "description"),
                "short_name": self._get_field(obj, "x_mitre_shortname", ""),
                "external_id": self._get_external_id(obj),
                "url": self._get_url(obj),
                "created": str(self._get_field(obj, "created")) if self._get_field(obj, "created") else None,
                "modified": str(self._get_field(obj, "modified")) if self._get_field(obj, "modified") else None,
            }
            stmt = insert(MitreTactic).values(data)
            stmt = stmt.on_conflict_do_update(
                index_elements=["stix_id"],
                set_=data
            )
            await self.db.execute(stmt)
        await self.db.flush()

    async def ingest_techniques(self, src: MemoryStore, objects: List[Dict]):
        # First pass: Upsert Techniques
        for obj in objects:
            data = {
                "stix_id": self._get_field(obj, "id"),
                "name": self._get_field(obj, "name"),
                "description": self._get_field(obj, "description"),
                "external_id": self._get_external_id(obj),
                "is_subtechnique": self._get_field(obj, "x_mitre_is_subtechnique", False),
                "platforms": ",".join(self._get_list(obj, "x_mitre_platforms")),
                "detection": self._get_field(obj, "x_mitre_detection"),
                "url": self._get_url(obj),
                "created": str(self._get_field(obj, "created")) if self._get_field(obj, "created") else None,
                "modified": str(self._get_field(obj, "modified")) if self._get_field(obj, "modified") else None,
            }
            stmt = insert(MitreTechnique).values(data)
            stmt = stmt.on_conflict_do_update(
                index_elements=["stix_id"],
                set_=data
            )
            await self.db.execute(stmt)
            
        await self.db.flush() # Ensure techniques exist
        
        for obj in objects:
            phases = self._get_field(obj, "kill_chain_phases")
            if not phases:
                continue
                
            # Find the technique DB ID
            tech_result = await self.db.execute(
                select(MitreTechnique.id).where(MitreTechnique.stix_id == self._get_field(obj, "id"))
            )
            tech_id = tech_result.scalars().first()
            if not tech_id: 
                continue

            for phase in phases:
                if phase.get("kill_chain_name") in ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]:
                    phase_name = phase.get("phase_name")
                    # Find tactic by short_name
                    tac_result = await self.db.execute(
                        select(MitreTactic.id).where(MitreTactic.short_name == phase_name)
                    )
                    tac_id = tac_result.scalars().first()
                    
                    if tac_id:
                        # Insert into link table
                        try:
                            stmt = insert(mitre_tactic_technique).values(
                                tactic_id=tac_id, technique_id=tech_id
                            ).on_conflict_do_nothing()
                            await self.db.execute(stmt)
                        except Exception:
                            pass # Already exists or concurrency

    async def ingest_groups(self, objects: List[Dict]):
        for obj in objects:
            data = {
                "stix_id": self._get_field(obj, "id"),
                "name": self._get_field(obj, "name"),
                "description": self._get_field(obj, "description"),
                "external_id": self._get_external_id(obj),
                "aliases": ",".join(self._get_list(obj, "aliases")),
                "url": self._get_url(obj),
                "created": str(self._get_field(obj, "created")) if self._get_field(obj, "created") else None,
                "modified": str(self._get_field(obj, "modified")) if self._get_field(obj, "modified") else None,
            }
            stmt = insert(MitreGroup).values(data)
            stmt = stmt.on_conflict_do_update(index_elements=["stix_id"], set_=data)
            await self.db.execute(stmt)
            
    async def ingest_software(self, objects: List[Dict]):
        for obj in objects:
            data = {
                "stix_id": self._get_field(obj, "id"),
                "name": self._get_field(obj, "name"),
                "description": self._get_field(obj, "description"),
                "external_id": self._get_external_id(obj),
                "is_malware": (self._get_field(obj, "type") == "malware"),
                "platforms": ",".join(self._get_list(obj, "x_mitre_platforms")),
                "aliases": ",".join(self._get_list(obj, "aliases") or self._get_list(obj, "x_mitre_aliases")),
                "url": self._get_url(obj),
                "created": str(self._get_field(obj, "created")) if self._get_field(obj, "created") else None,
                "modified": str(self._get_field(obj, "modified")) if self._get_field(obj, "modified") else None,
            }
            stmt = insert(MitreSoftware).values(data)
            stmt = stmt.on_conflict_do_update(index_elements=["stix_id"], set_=data)
            await self.db.execute(stmt)

    async def ingest_mitigations(self, objects: List[Dict]):
        for obj in objects:
            data = {
                "stix_id": self._get_field(obj, "id"),
                "name": self._get_field(obj, "name"),
                "description": self._get_field(obj, "description"),
                "external_id": self._get_external_id(obj),
                "url": self._get_url(obj),
                "created": str(self._get_field(obj, "created")) if self._get_field(obj, "created") else None,
                "modified": str(self._get_field(obj, "modified")) if self._get_field(obj, "modified") else None,
            }
            stmt = insert(MitreMitigation).values(data)
            stmt = stmt.on_conflict_do_update(index_elements=["stix_id"], set_=data)
            await self.db.execute(stmt)

    async def ingest_relationships(self, objects: List[Dict]):
        # "uses", "mitigates", "subtechnique-of", "attributed-to"
        # We store them all in the generic table
        for obj in objects:
            data = {
                "source_ref": self._get_field(obj, "source_ref"),
                "target_ref": self._get_field(obj, "target_ref"),
                "relationship_type": self._get_field(obj, "relationship_type"),
                "description": self._get_field(obj, "description"),
            }
            
            # Simple upsert based on constraint
            stmt = insert(mitre_relationships).values(data)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_mitre_relationship",
                set_=data
            )
            await self.db.execute(stmt)

    def _get_url(self, obj) -> str:
        references = self._get_list(obj, "external_references")
        if not references:
            return None
        for ref in references:
            if ref.get("url"):
                return ref.get("url")
        return None

async def run_mitre_sync():
    """Wrapper to run ingestion from a task."""
    async with AsyncSessionLocal() as session:
        try:
            ingestor = MitreIngestor(session)
            await ingestor.run_ingestion()
            await session.commit()
        except Exception as e:
            logger.error(f"MITRE Sync failed: {e}")
            await session.rollback()
            raise
