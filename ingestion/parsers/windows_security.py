"""Parser for Windows Security Event Logs flattened to key=value text.

Log shippers (Winlogbeat, NXLog, custom forwarders) commonly flatten EVTX records
to a single key=value line. Example:

    2026-06-24T14:03:11Z host=WIN-DC01 EventID=4625 TargetUserName=administrator \
        IpAddress=203.0.113.7 LogonType=3 Status=0xC000006A

We extract the fields with regex and map the EventID to a normalized action/outcome.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .normalize import build_event

SOURCE = "windows_security"

# Leading ISO-8601 timestamp, then space-separated key=value pairs.
_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(?P<rest>.*)$")
_KV_RE = re.compile(r"(\w+)=([^\s]+)")

# EventID -> (event.category, event.action, event.outcome)
_EVENT_MAP: dict[str, tuple[str, str, str]] = {
    "4624": ("authentication", "logon", "success"),
    "4625": ("authentication", "logon_failed", "failure"),
    "4688": ("process", "process_started", "success"),
    "4720": ("iam", "user_created", "success"),
    "4728": ("iam", "added_to_security_group", "success"),
    "7045": ("service", "service_installed", "success"),
}


def parse_line(line: str) -> Optional[dict[str, Any]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    m = _TS_RE.match(line)
    if not m:
        return None

    fields = dict(_KV_RE.findall(m.group("rest")))
    event_id = fields.get("EventID")
    if event_id is None:
        return None

    category, action, outcome = _EVENT_MAP.get(
        event_id, ("process", f"eventid_{event_id}", "unknown")
    )

    extra: dict[str, Any] = {"event_id": int(event_id)}
    if "LogonType" in fields:
        extra["logon_type"] = fields["LogonType"]
    if "Status" in fields:
        extra["status_code"] = fields["Status"]
    if "NewProcessName" in fields:
        extra["process_name"] = fields["NewProcessName"]
    if "ServiceName" in fields:
        extra["service_name"] = fields["ServiceName"]

    return build_event(
        timestamp=m.group("ts"),
        category=category,
        action=action,
        outcome=outcome,
        log_source=SOURCE,
        raw=line,
        source_ip=fields.get("IpAddress") if fields.get("IpAddress") not in ("-", None) else None,
        user=fields.get("TargetUserName") or fields.get("SubjectUserName"),
        host=fields.get("host"),
        os_name="windows",
        extra=extra,
    )


def parse(lines):
    """Yield normalized events for an iterable of raw log lines."""
    for line in lines:
        event = parse_line(line)
        if event is not None:
            yield event
