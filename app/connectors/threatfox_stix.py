from datetime import datetime, timezone, timedelta
from typing import Dict, List
import asyncio

import httpx
from loguru import logger

from .base import STIXConnector


class ThreatFoxSTIXConnector(STIXConnector):
    """ThreatFox STIX connector - maximum data with historical support"""

    required_config_keys: List[str] = ["api_key"]

    def get_identity(self) -> Dict:
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--threatfox-abuse-ch",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "ThreatFox - abuse.ch",
            "identity_class": "organization",
        }

    def supports_historical(self) -> bool:
        """ThreatFox supports historical collection up to 90 days per API call"""
        return True

    async def collect_historical(self, start_date: datetime, end_date: datetime) -> Dict:
        """Collect ThreatFox data from date range (max 90 days per API call)"""
        headers = {"API-KEY": self.config["api_key"]}
        
        # Calculate days between dates
        days_diff = (end_date - start_date).days
        
        all_stix_objects: List[Dict] = []
        malware_cache: Dict[str, Dict] = {}
        
        # ThreatFox max is 90 days, so we may need multiple requests
        for chunk_start in range(0, days_diff, 90):
            chunk_days = min(90, days_diff - chunk_start)
            
            payload = {"query": "get_iocs", "days": chunk_days}
            
            logger.info(f"ThreatFox: Fetching {chunk_days} days of historical data (chunk starting at day {chunk_start})")
            
            try:
                async with httpx.AsyncClient(timeout=120.0) as client:
                    resp = await client.post(
                        "https://threatfox-api.abuse.ch/api/v1/",
                        headers=headers,
                        json=payload,
                    )
                    data = resp.json()
                
                if data.get("query_status") == "ok":
                    chunk_objects = self._process_iocs(data.get("data", []), malware_cache)
                    all_stix_objects.extend(chunk_objects)
                    logger.info(f"ThreatFox chunk: {len(chunk_objects)} objects from {chunk_days} days")
                else:
                    logger.warning(f"ThreatFox API returned status: {data.get('query_status')}")
                
                # Rate limiting between chunks
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"ThreatFox historical chunk failed: {e}")
                continue
        
        logger.success(f"ThreatFox historical: {len(all_stix_objects)} total objects")
        return self.create_bundle(all_stix_objects)

    async def collect(self) -> Dict:
        """Pull maximum IOCs from ThreatFox (max 90 days - API limit)"""
        headers = {"API-KEY": self.config["api_key"]}
        # ThreatFox API max is 90 days
        payload = {"query": "get_iocs", "days": 90}

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                headers=headers,
                json=payload,
            )
            data = resp.json()

        malware_cache: Dict[str, Dict] = {}
        stix_objects = self._process_iocs(data.get("data", []), malware_cache)

        logger.success(f"ThreatFox: Collected {len(data.get('data', []))} IOCs, {len(stix_objects)} STIX objects")
        return self.create_bundle(stix_objects)

    def _process_iocs(self, iocs: list, malware_cache: Dict[str, Dict]) -> List[Dict]:
        """Extract IOC processing logic for reuse"""
        stix_objects: List[Dict] = []

        for ioc_data in iocs:
            ioc_value = ioc_data.get("ioc") or ioc_data.get("ioc_value")
            ioc_type = ioc_data.get("ioc_type")
            malware = ioc_data.get("malware_printable", "Unknown")
            threat_type = ioc_data.get("threat_type", "unknown")
            confidence = ioc_data.get("confidence_level", 50)

            if not ioc_value or not ioc_type:
                continue

            if ioc_type == "ip:port":
                obs_type = "ipv4-addr"
                value = ioc_value.split(":")[0]
                pattern = f"[ipv4-addr:value = '{value}']"
            elif ioc_type == "domain":
                obs_type = "domain-name"
                value = ioc_value
                pattern = f"[domain-name:value = '{value}']"
            elif ioc_type == "url":
                obs_type = "url"
                value = ioc_value
                pattern = f"[url:value = '{value}']"
            elif ioc_type in ["md5_hash", "sha256_hash"]:
                obs_type = "file"
                value = ioc_value
                hash_type = "MD5" if ioc_type == "md5_hash" else "SHA-256"
                pattern = f"[file:hashes.'{hash_type}' = '{value}']"
            else:
                continue

            indicator = self.create_indicator(
                pattern=pattern,
                name=f"{malware} - {threat_type}",
                description=f"ThreatFox IOC: {malware} malware",
                indicator_types=["malicious-activity"],
                confidence=confidence,
                labels=[threat_type.lower(), malware.lower().replace(" ", "-")],
            )
            stix_objects.append(indicator)

            if obs_type == "file":
                obs = self.create_observable(obs_type, value, hashes={hash_type: value})
            else:
                obs = self.create_observable(obs_type, value)
            stix_objects.append(obs)

            stix_objects.append(self.create_relationship(indicator["id"], obs["id"], "based-on"))

            if malware not in malware_cache:
                malware_obj = {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": f"malware--{malware.lower().replace(' ', '-')}",
                    "created": datetime.now(timezone.utc).isoformat(),
                    "modified": datetime.now(timezone.utc).isoformat(),
                    "name": malware,
                    "is_family": True,
                    "malware_types": [threat_type.lower()],
                }
                malware_cache[malware] = malware_obj
                stix_objects.append(malware_obj)

            stix_objects.append(
                self.create_relationship(indicator["id"], malware_cache[malware]["id"], "indicates")
            )

        return stix_objects

