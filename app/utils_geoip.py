"""
Cyber Atlas - GeoIP Utilities

Utilities for IP address geolocation enrichment using MaxMind GeoLite2.
"""

import socket
from typing import Optional, Tuple
import geoip2.database
from geoip2.errors import AddressNotFoundError

from app.core.config import settings
from app.core.logging import logger


class GeoIPService:
    """Service for looking up IP address geolocation data."""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or settings.geoip_database_path
        self._reader = None
        self._initialized = False

    def initialize(self):
        """Initialize the GeoIP reader."""
        if self._initialized:
            return

        try:
            self._reader = geoip2.database.Reader(self.db_path)
            self._initialized = True
            logger.info(f"GeoIP database loaded from {self.db_path}")
        except FileNotFoundError:
            logger.warning(f"GeoIP database not found at {self.db_path}. IP enrichment disabled.")
        except Exception as e:
            logger.error(f"Failed to load GeoIP database: {e}")

    def close(self):
        """Close the GeoIP reader."""
        if self._reader:
            self._reader.close()
            self._initialized = False

    def lookup(self, ip_address: str) -> Optional[str]:
        """
        Lookup country code for an IP address.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            ISO 3166-1 alpha-2 country code (e.g., 'US', 'DE') or None if not found/error.
        """
        if not self._initialized:
            self.initialize()
            if not self._initialized:
                return None

        # Basic IP validation
        if not self._is_valid_ip(ip_address):
            return None

        try:
            response = self._reader.city(ip_address)
            return response.country.iso_code
        except AddressNotFoundError:
            return None
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
            return None

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False


# Global instance
geoip_service = GeoIPService()


def get_country_code(ip_address: str) -> Optional[str]:
    """
    Helper function to get country code for an IP.
    
    Args:
        ip_address: IP address string
        
    Returns:
        Two-letter ISO country code or None
    """
    return geoip_service.lookup(ip_address)
