import re
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import urlparse

import httpx
from loguru import logger

from .base import STIXConnector


class URLhausSTIXConnector(STIXConnector):
    """URLhaus STIX connector - pulls maximum data"""

    required_config_keys: List[str] = []

    def supports_historical(self) -> bool:
        """URLhaus provides all recent data in one call, no date filtering supported."""
        return False

    async def collect_historical(self, start_date: datetime, end_date: datetime) -> Dict:
        """
        URLhaus doesn't support date-range queries.
        Collect all available data (same as collect).
        """
        logger.info(f"URLhaus: Historical collection not supported, collecting all available data")
        return await self.collect()

    def get_identity(self) -> Dict:
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--urlhaus-abuse-ch",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "URLhaus - abuse.ch",
            "identity_class": "organization",
        }

    async def collect(self) -> Dict:
        """
        Collect maximum data from URLhaus:
        1. Recent URLs (csv_recent)
        2. All payload hashes
        3. Payload URLs with metadata
        """
        stix_objects: List[Dict] = []

        logger.info("Fetching URLhaus recent URLs...")
        stix_objects.extend(await self._collect_recent_urls())

        logger.info("Fetching URLhaus payload hashes...")
        stix_objects.extend(await self._collect_payload_hashes())

        logger.info("Fetching URLhaus payload URLs...")
        stix_objects.extend(await self._collect_payload_urls())

        logger.success(f"URLhaus: Collected {len(stix_objects)} STIX objects")
        return self.create_bundle(stix_objects)

    async def _collect_recent_urls(self) -> List[Dict]:
        """Get recent malicious URLs"""
        objects: List[Dict] = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get("https://urlhaus.abuse.ch/downloads/csv_recent/")
            text = resp.text

        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue

            parts = line.split('","')
            if len(parts) < 8:
                continue

            url_value = parts[2].strip().strip('"')
            threat = parts[4].strip().strip('"')
            tags = parts[5].strip().strip('"')
            date_str = parts[1].strip().strip('"')

            if not url_value.startswith(("http://", "https://")):
                continue

            try:
                valid_from = datetime.fromisoformat(date_str.replace(" ", "T"))
                if valid_from.tzinfo is None:
                    valid_from = valid_from.replace(tzinfo=timezone.utc)
            except ValueError:
                valid_from = datetime.now(timezone.utc)

            indicator = self.create_indicator(
                pattern=f"[url:value = '{url_value}']",
                name=f"Malicious URL - {threat}",
                description=f"URLhaus detected malicious URL. Threat: {threat}, Tags: {tags}",
                indicator_types=["malicious-activity"],
                confidence=75,
                labels=self._parse_tags(tags),
                valid_from=valid_from,
            )
            objects.append(indicator)

            url_obs = self.create_observable("url", url_value)
            objects.append(url_obs)

            objects.append(self.create_relationship(indicator["id"], url_obs["id"], "based-on"))

            parsed = urlparse(url_value)
            if parsed.netloc:
                domain_obs = self.create_observable("domain-name", parsed.netloc)
                objects.append(domain_obs)
                objects.append(self.create_relationship(url_obs["id"], domain_obs["id"], "related-to"))

        return objects

    async def _collect_payload_hashes(self) -> List[Dict]:
        """Get all payload SHA256 hashes"""
        objects: List[Dict] = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get("https://urlhaus.abuse.ch/downloads/payloads/sha256/")
            text = resp.text

        sha256_pattern = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)

        for line in text.splitlines():
            hash_val = line.strip().lower()
            if not sha256_pattern.match(hash_val):
                continue

            indicator = self.create_indicator(
                pattern=f"[file:hashes.'SHA-256' = '{hash_val}']",
                name="Malware File Hash",
                description="Malicious file detected by URLhaus",
                indicator_types=["malicious-activity"],
                confidence=80,
                labels=["malware", "payload"],
            )
            objects.append(indicator)

            file_obs = self.create_observable("file", hash_val, hashes={"SHA-256": hash_val})
            objects.append(file_obs)

            objects.append(self.create_relationship(indicator["id"], file_obs["id"], "based-on"))

        logger.info(f"Collected {len(objects) // 3} payload hashes")
        return objects

    async def _collect_payload_urls(self) -> List[Dict]:
        """Get payload download URLs"""
        objects: List[Dict] = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get("https://urlhaus.abuse.ch/downloads/payloads/")
            text = resp.text

        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue

            parts = line.split('","')
            if len(parts) < 3:
                continue

            url_value = parts[1].strip().strip('"')
            host = parts[2].strip().strip('"')

            if not url_value.startswith(("http://", "https://")):
                continue

            indicator = self.create_indicator(
                pattern=f"[url:value = '{url_value}']",
                name="Malware Distribution URL",
                description=f"URLhaus payload distribution: {host}",
                indicator_types=["malicious-activity"],
                confidence=70,
                labels=["malware", "distribution"],
            )
            objects.append(indicator)

            url_obs = self.create_observable("url", url_value)
            objects.append(url_obs)

            domain_obs = self.create_observable("domain-name", host.lower())
            objects.append(domain_obs)

            objects.append(self.create_relationship(indicator["id"], url_obs["id"], "based-on"))
            objects.append(self.create_relationship(url_obs["id"], domain_obs["id"], "related-to"))

        return objects

    def _parse_tags(self, tags_str: str) -> List[str]:
        tags = [t.strip().lower() for t in tags_str.split(",") if t.strip()]
        return tags if tags else ["malware"]
