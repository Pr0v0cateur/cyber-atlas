import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.logging import logger
from app.connectors import (
    URLhausSTIXConnector,
    ThreatFoxSTIXConnector,
    OTXSTIXConnector,
)
from app.crud.stix import save_stix_bundle


class STIXConnectorManager:
    """Manages STIX connectors"""

    def __init__(self) -> None:
        self.connectors: Dict[str, object] = {}
        self._load_connectors()

    def _load_connectors(self) -> None:
        self.connectors["urlhaus"] = URLhausSTIXConnector({"enabled": True})

        if settings.threatfox_key:
            self.connectors["threatfox"] = ThreatFoxSTIXConnector(
                {"enabled": True, "api_key": settings.threatfox_key}
            )
        else:
            logger.warning("ThreatFox STIX connector disabled (missing API key).")

        if settings.otx_key:
            self.connectors["otx"] = OTXSTIXConnector({"enabled": True, "api_key": settings.otx_key})
        else:
            logger.warning("OTX STIX connector disabled (missing API key).")

        logger.info(f"Loaded {len(self.connectors)} STIX connectors")

    async def collect_all(self) -> Dict:
        """Collect from all connectors - maximum data"""
        logger.info("Starting maximum data collection from all STIX connectors...")
        return await self.collect_selected(list(self.connectors.keys()))

    async def collect_historical_all(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict:
        """
        Collect historical data from all connectors.
        
        Args:
            start_date: Start date for historical collection (default: Nov 1, 2024)
            end_date: End date for historical collection (default: now)
        
        Returns:
            Dictionary with collection statistics
        """
        if start_date is None:
            start_date = datetime(2024, 11, 1, tzinfo=timezone.utc)
        if end_date is None:
            end_date = datetime.now(timezone.utc)
        
        logger.info(f"Starting historical collection: {start_date.date()} → {end_date.date()}")
        
        tasks = []
        for key, connector in self.connectors.items():
            if connector.enabled:
                tasks.append(self._collect_connector_historical(connector, start_date, end_date))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        total_stats = {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "total_objects": 0,
            "total_indicators": 0,
            "total_observables": 0,
            "total_relationships": 0,
            "connectors_success": 0,
            "connectors_failed": 0,
            "details": {},
        }
        
        for result in results:
            if isinstance(result, Exception):
                total_stats["connectors_failed"] += 1
                logger.error(f"STIX connector error: {result}")
                continue
            
            total_stats["total_objects"] += result.get("objects", 0)
            total_stats["total_indicators"] += result.get("indicators", 0)
            total_stats["total_observables"] += result.get("observables", 0)
            total_stats["total_relationships"] += result.get("relationships", 0)
            total_stats["connectors_success"] += 1
            total_stats["details"][result.get("connector", "unknown")] = result
        
        logger.success(f"Historical collection complete: {total_stats}")
        return total_stats

    async def _collect_connector_historical(
        self,
        connector,
        start_date: datetime,
        end_date: datetime
    ) -> Dict:
        """Collect historical data from single connector."""
        logger.info(f"Collecting historical from {connector.name}...")
        
        if connector.supports_historical():
            bundle = await connector.collect_historical(start_date, end_date)
        else:
            logger.info(f"{connector.name}: Historical not supported, running current collection")
            bundle = await connector.collect()
        
        async with AsyncSessionLocal() as session:
            stats = await save_stix_bundle(session, bundle, connector.id, connector.name)
            await session.commit()
        
        stats["connector"] = connector.name
        logger.success(f"{connector.name}: {stats}")
        return stats

    async def collect_selected(self, sources: List[str]) -> Dict:
        """Collect from selected connectors."""
        tasks = []
        for source in sources:
            key = source.lower()
            connector = self.connectors.get(key)
            if connector and connector.enabled:
                tasks.append(self._collect_connector(connector))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        total_stats = {
            "total_objects": 0,
            "total_indicators": 0,
            "total_observables": 0,
            "total_relationships": 0,
            "connectors_success": 0,
            "connectors_failed": 0,
            "details": {},
        }

        for result in results:
            if isinstance(result, Exception):
                total_stats["connectors_failed"] += 1
                logger.error(f"STIX connector error: {result}")
                continue

            total_stats["total_objects"] += result["objects"]
            total_stats["total_indicators"] += result["indicators"]
            total_stats["total_observables"] += result["observables"]
            total_stats["total_relationships"] += result["relationships"]
            total_stats["connectors_success"] += 1
            total_stats["details"][result["connector"]] = result

        logger.success(f"STIX collection complete: {total_stats}")
        return total_stats

    async def _collect_connector(self, connector) -> Dict:
        """Collect from single connector."""
        logger.info(f"Collecting from {connector.name}...")
        bundle = await connector.collect()

        async with AsyncSessionLocal() as session:
            stats = await save_stix_bundle(session, bundle, connector.id, connector.name)
            await session.commit()

        stats["connector"] = connector.name
        logger.success(f"{connector.name}: {stats}")
        return stats

