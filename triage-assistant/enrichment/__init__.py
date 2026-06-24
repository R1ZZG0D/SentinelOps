"""Alert enrichment — adds context an analyst needs before triaging.

All sources here are mocked, self-contained lookups (no network) so the lab runs
offline and deterministically. In a real SOC these would hit GeoIP (MaxMind),
threat-intel platforms (MISP, VirusTotal, AbuseIPDB), and the asset CMDB.
"""

from __future__ import annotations

import ipaddress
from typing import Any

# Mock threat-intel: IPs/indicators known-bad in this lab's scenario.
_THREAT_INTEL = {
    "203.0.113.7": {
        "verdict": "malicious",
        "sources": ["AbuseIPDB (98% confidence)", "internal blocklist"],
        "categories": ["ssh-bruteforce", "scanner", "c2"],
        "first_seen": "2026-06-20",
    },
}

# Mock GeoIP / ASN data.
_GEOIP = {
    "203.0.113.7": {"country": "RU", "asn": "AS00000 ExampleHostingLLC", "is_hosting": True},
    "93.184.216.34": {"country": "US", "asn": "AS15133 EdgecastInc", "is_hosting": False},
}

# Mock asset CMDB: which hosts matter, and how much.
_ASSETS = {
    "web01": {"criticality": "high", "role": "internet-facing web server", "owner": "platform-team", "data": "customer PII"},
    "WIN-DC01": {"criticality": "critical", "role": "Active Directory domain controller", "owner": "it-infra", "data": "domain credentials"},
    "10.0.0.5": {"criticality": "high", "role": "internet-facing web server", "owner": "platform-team", "data": "customer PII"},
}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def geoip(ip: str) -> dict[str, Any]:
    # Explicit table wins (note: Python flags the 203.0.113.0/24 documentation
    # range as private, so check known IPs before the private-address fallback).
    if ip in _GEOIP:
        return _GEOIP[ip]
    if _is_private(ip):
        return {"country": "internal", "asn": "RFC1918 private", "is_hosting": False}
    return {"country": "unknown", "asn": "unknown", "is_hosting": False}


def threat_intel(ip: str) -> dict[str, Any]:
    return _THREAT_INTEL.get(ip, {"verdict": "unknown", "sources": [], "categories": []})


def asset_context(host: str) -> dict[str, Any]:
    return _ASSETS.get(host, {"criticality": "unknown", "role": "unknown", "owner": "unknown", "data": "unknown"})


def enrich(alert: dict[str, Any]) -> dict[str, Any]:
    """Return an enrichment block for an alert (source IP, destination host)."""
    src_ip = alert.get("source", {}).get("ip")
    host = alert.get("host", {}).get("name")
    return {
        "source_ip": {
            "value": src_ip,
            "geoip": geoip(src_ip) if src_ip else {},
            "threat_intel": threat_intel(src_ip) if src_ip else {},
        },
        "asset": {"value": host, **(asset_context(host) if host else {})},
    }
