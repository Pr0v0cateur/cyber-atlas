from datetime import datetime, timezone, timedelta
from typing import Dict, List

import httpx
from loguru import logger

from .base import STIXConnector


class OTXSTIXConnector(STIXConnector):
    """AlienVault OTX STIX connector - pull maximum pulses with historical support"""

    required_config_keys: List[str] = ["api_key"]

    # Maximum data collection settings
    MAX_PAGES = 500
    PULSES_PER_PAGE = 200
    # Default: Collect from November 1, 2024 for historical
    DEFAULT_HISTORICAL_START = datetime(2024, 11, 1, tzinfo=timezone.utc)

    def get_identity(self) -> Dict:
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--alienvault-otx",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "AlienVault OTX",
            "identity_class": "organization",
        }

    def supports_historical(self) -> bool:
        """OTX supports historical collection with modified_since parameter"""
        return True

    async def collect_historical(self, start_date: datetime, end_date: datetime) -> Dict:
        """Collect OTX pulses from date range"""
        headers = {"X-OTX-API-KEY": self.config["api_key"]}
        base_url = "https://otx.alienvault.com/api/v1"
        
        stix_objects: List[Dict] = []
        modified_since = start_date.isoformat()
        
        logger.info(f"OTX: Fetching historical pulses from {start_date.date()} to {end_date.date()}")
        
        async with httpx.AsyncClient(timeout=120.0, headers=headers) as client:
            page = 1
            total_pulses = 0
            
            while page <= self.MAX_PAGES:
                try:
                    resp = await client.get(
                        f"{base_url}/pulses/subscribed",
                        params={
                            "modified_since": modified_since,
                            "limit": self.PULSES_PER_PAGE,
                            "page": page,
                        },
                    )
                    data = resp.json()
                    pulses = data.get("results", [])
                    
                    if not pulses:
                        break
                    
                    total_pulses += len(pulses)
                    logger.info(f"OTX Historical: Page {page} - Processing {len(pulses)} pulses (total: {total_pulses})")
                    
                    for pulse in pulses:
                        pulse_objects = await self._process_pulse(pulse)
                        stix_objects.extend(pulse_objects)
                    
                    if not data.get("next"):
                        break
                    
                    page += 1
                    
                except Exception as e:
                    logger.warning(f"OTX Historical: Error on page {page}: {e}")
                    break
        
        logger.success(f"OTX Historical: Collected {len(stix_objects)} STIX objects from {total_pulses} pulses")
        return self.create_bundle(stix_objects)

    async def collect(self) -> Dict:
        """Pull ALL pulses since configured start date with pagination"""
        headers = {"X-OTX-API-KEY": self.config["api_key"]}
        base_url = "https://otx.alienvault.com/api/v1"

        stix_objects: List[Dict] = []
        modified_since = self.DEFAULT_HISTORICAL_START.isoformat()

        async with httpx.AsyncClient(timeout=120.0, headers=headers) as client:
            page = 1
            total_pulses = 0

            while page <= self.MAX_PAGES:
                try:
                    resp = await client.get(
                        f"{base_url}/pulses/subscribed",
                        params={
                            "modified_since": modified_since,
                            "limit": self.PULSES_PER_PAGE,
                            "page": page,
                        },
                    )
                    data = resp.json()
                    pulses = data.get("results", [])
                    
                    if not pulses:
                        break

                    total_pulses += len(pulses)
                    logger.info(f"OTX: Page {page} - Processing {len(pulses)} pulses (total: {total_pulses})")

                    for pulse in pulses:
                        pulse_objects = await self._process_pulse(pulse)
                        stix_objects.extend(pulse_objects)

                    # Check if there's a next page
                    if not data.get("next"):
                        break

                    page += 1

                except Exception as e:
                    logger.warning(f"OTX: Error on page {page}: {e}")
                    break

        logger.success(f"OTX: Collected {len(stix_objects)} STIX objects from {total_pulses} pulses")
        return self.create_bundle(stix_objects)

    async def _process_pulse(self, pulse: dict) -> List[Dict]:
        """Convert OTX pulse to STIX objects"""
        objects: List[Dict] = []

        pulse_name = pulse.get("name", "Unknown Pulse")
        description = pulse.get("description", "")
        tags = pulse.get("tags", [])

        for indicator in pulse.get("indicators", []):
            ind_type = indicator.get("type")
            ind_value = indicator.get("indicator")

            if not ind_value:
                continue

            if ind_type in ["IPv4", "IPv6"]:
                obs_type = "ipv4-addr" if ind_type == "IPv4" else "ipv6-addr"
                pattern = f"[{obs_type}:value = '{ind_value}']"
            elif ind_type == "domain":
                obs_type = "domain-name"
                pattern = f"[domain-name:value = '{ind_value}']"
            elif ind_type == "URL":
                obs_type = "url"
                pattern = f"[url:value = '{ind_value}']"
            elif ind_type == "FileHash-SHA256":
                obs_type = "file"
                pattern = f"[file:hashes.'SHA-256' = '{ind_value}']"
            elif ind_type == "FileHash-MD5":
                obs_type = "file"
                pattern = f"[file:hashes.'MD5' = '{ind_value}']"
            elif ind_type == "email":
                obs_type = "email-addr"
                pattern = f"[email-addr:value = '{ind_value}']"
            else:
                continue

            stix_ind = self.create_indicator(
                pattern=pattern,
                name=pulse_name,
                description=description[:500],
                indicator_types=["malicious-activity"],
                confidence=70,
                labels=tags[:10],
            )
            objects.append(stix_ind)

            if obs_type == "file":
                hash_type = "SHA-256" if "SHA256" in ind_type else "MD5"
                obs = self.create_observable(obs_type, ind_value, hashes={hash_type: ind_value})
            else:
                obs = self.create_observable(obs_type, ind_value)
            objects.append(obs)

            objects.append(self.create_relationship(stix_ind["id"], obs["id"], "based-on"))

        return objects
