from abc import ABC, abstractmethod
from typing import List, Dict
from datetime import datetime, timezone
import uuid

from loguru import logger


class STIXConnector(ABC):
    """Base class for STIX 2.1 connectors"""

    def __init__(self, config: dict):
        self.config = config
        self.id = f"connector--{uuid.uuid4()}"
        self.name = self.__class__.__name__
        self.enabled = config.get("enabled", True)

    @abstractmethod
    async def collect(self) -> Dict:
        """Collect and return STIX bundle"""
        raise NotImplementedError

    @abstractmethod
    def get_identity(self) -> Dict:
        """Return source identity"""
        raise NotImplementedError

    def supports_historical(self) -> bool:
        """Check if connector supports historical data collection"""
        return False

    async def collect_historical(self, start_date: datetime, end_date: datetime) -> Dict:
        """
        Collect historical data between dates.
        Override this in child connectors if they support date ranges.
        """
        logger.warning(f"{self.name} does not support historical collection, running current collection")
        return await self.collect()

    def create_indicator(self, pattern: str, **kwargs) -> Dict:
        """Create STIX Indicator"""
        now = datetime.now(timezone.utc)
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now.isoformat(),
            "modified": now.isoformat(),
            "pattern": pattern,
            "pattern_type": kwargs.get("pattern_type", "stix"),
            "valid_from": (kwargs.get("valid_from") or now).isoformat(),
            "indicator_types": kwargs.get("indicator_types", ["malicious-activity"]),
            "confidence": kwargs.get("confidence", 50),
            "name": kwargs.get("name", "Unknown Indicator"),
            **{
                k: v
                for k, v in kwargs.items()
                if k not in ["pattern_type", "valid_from", "indicator_types", "confidence", "name"]
            },
        }

    def create_observable(self, obs_type: str, value: str, **kwargs) -> Dict:
        """Create STIX Observable"""
        obs = {
            "type": obs_type,
            "spec_version": "2.1",
            "id": f"{obs_type}--{uuid.uuid4()}",
        }

        if obs_type in ["ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"]:
            obs["value"] = value
        elif obs_type == "file":
            obs["hashes"] = kwargs.get("hashes", {"SHA-256": value})

        return obs

    def create_relationship(self, source_ref: str, target_ref: str, rel_type: str, **kwargs) -> Dict:
        """Create STIX Relationship"""
        now = datetime.now(timezone.utc)
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now.isoformat(),
            "modified": now.isoformat(),
            "relationship_type": rel_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            **kwargs,
        }

    def create_bundle(self, objects: List[Dict]) -> Dict:
        """Wrap in STIX bundle"""
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [self.get_identity()] + objects,
        }

    @property
    @abstractmethod
    def required_config_keys(self) -> List[str]:
        raise NotImplementedError
