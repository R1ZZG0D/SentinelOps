"""Normalized event schema (an Elastic Common Schema subset).

Every parser converts its source-specific format into the dict produced by
`build_event`, so detections and the triage assistant can rely on one shape
regardless of where the telemetry came from.
"""

from __future__ import annotations

from typing import Any, Optional


def build_event(
    *,
    timestamp: str,
    category: str,
    action: str,
    outcome: str,
    log_source: str,
    raw: str,
    source_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    dest_ip: Optional[str] = None,
    dest_port: Optional[int] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    os_name: Optional[str] = None,
    network_proto: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build one normalized event. Empty sub-objects are pruned for compactness."""
    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {"category": category, "action": action, "outcome": outcome},
        "source": {},
        "destination": {},
        "user": {},
        "host": {},
        "network": {},
        "log": {"source": log_source},
        "raw": raw,
    }
    if source_ip:
        event["source"]["ip"] = source_ip
    if source_port is not None:
        event["source"]["port"] = source_port
    if dest_ip:
        event["destination"]["ip"] = dest_ip
    if dest_port is not None:
        event["destination"]["port"] = dest_port
    if user:
        event["user"]["name"] = user
    if host:
        event["host"]["name"] = host
    if os_name:
        event["host"]["os"] = os_name
    if network_proto:
        event["network"]["transport"] = network_proto
    if extra:
        event["extra"] = extra

    # Drop empty containers so the output stays readable.
    for key in ("source", "destination", "user", "host", "network"):
        if not event[key]:
            del event[key]
    return event
