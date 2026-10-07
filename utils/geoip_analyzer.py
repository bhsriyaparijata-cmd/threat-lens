"""
geoip_analyzer.py

Provides approximate location/network information for public IP addresses.

Backend priority:
1. MaxMind GeoLite2 local database, if configured.
2. ip-api.com live lookup, if network access is available.

All functions fail gracefully and should not crash the application.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Dict, List, Optional

GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "")

_reader = None
_reader_init_attempted = False


def _is_valid_ip(ip: str) -> bool:
    """Check whether the supplied value is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def _get_reader():
    """Initialize the MaxMind GeoLite2 reader if available."""
    global _reader
    global _reader_init_attempted

    if _reader_init_attempted:
        return _reader

    _reader_init_attempted = True

    if not GEOIP_DB_PATH:
        return None

    if not os.path.exists(GEOIP_DB_PATH):
        return None

    try:
        import geoip2.database

        _reader = geoip2.database.Reader(GEOIP_DB_PATH)

    except Exception:
        _reader = None

    return _reader


def _lookup_maxmind(ip: str) -> Optional[Dict[str, Any]]:
    """Look up an IP using MaxMind GeoLite2."""
    reader = _get_reader()

    if reader is None:
        return None

    try:
        response = reader.city(ip)

        return {
            "ip": ip,
            "country": response.country.name or "Unknown",
            "region": (
                response.subdivisions.most_specific.name
                or "Unknown"
            ),
            "city": response.city.name or "Unknown",
            "isp": "Not available in GeoLite2 City DB",
            "organization": "Not available in GeoLite2 City DB",
            "asn": "Unknown",
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "source": "MaxMind GeoLite2 (local database)",
        }

    except Exception:
        return None


def _lookup_http_api(
    ip: str,
    timeout: float = 3.0
) -> Optional[Dict[str, Any]]:
    """Look up an IP using ip-api.com."""

    try:
        import requests

        url = f"http://ip-api.com/json/{ip}"

        params = {
            "fields": (
                "status,country,regionName,city,"
                "isp,org,as,lat,lon,query"
            )
        }

        response = requests.get(
            url,
            params=params,
            timeout=timeout,
        )

        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            return None

        return {
            "ip": data.get("query", ip),
            "country": data.get("country", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "organization": data.get("org", "Unknown"),
            "asn": data.get("as", "Unknown"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "source": "ip-api.com (live lookup)",
        }

    except Exception:
        return None


def geoip_status() -> Dict[str, Any]:
    """Return the currently available GeoIP backend."""

    if _get_reader() is not None:
        return {
            "available": True,
            "backend": "MaxMind GeoLite2 (local database)",
        }

    return {
        "available": False,
        "backend": "ip-api.com (best effort)",
    }


def lookup_ip(ip: str) -> Dict[str, Any]:
    """Look up a single IP address without raising errors."""

    if not _is_valid_ip(ip):
        return {
            "ip": ip,
            "country": "Invalid IP",
            "region": "Invalid IP",
            "city": "Invalid IP",
            "isp": "Unavailable",
            "organization": "Unavailable",
            "asn": "Unavailable",
            "latitude": None,
            "longitude": None,
            "source": "Invalid IP address",
        }

    # 1. Try local MaxMind database
    result = _lookup_maxmind(ip)

    if result is not None:
        return result

    # 2. Try ip-api.com
    result = _lookup_http_api(ip)

    if result is not None:
        return result

    # 3. Graceful fallback
    return {
        "ip": ip,
        "country": "Unavailable",
        "region": "Unavailable",
        "city": "Unavailable",
        "isp": "Unavailable",
        "organization": "Unavailable",
        "asn": "Unavailable",
        "latitude": None,
        "longitude": None,
        "source": "GeoIP lookup unavailable",
    }


def lookup_ips(ips: List[str]) -> List[Dict[str, Any]]:
    """Look up multiple IP addresses."""

    return [lookup_ip(ip) for ip in ips]